package hostadapter

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"
)

type DNSProvisionResult struct {
	Domain    string `json:"domain"`
	ZoneFile  string `json:"zone_file"`
	IndexFile string `json:"index_file"`
	Validated bool   `json:"validated"`
	Reloaded  bool   `json:"reloaded"`
}

func (a *Adapter) dnsFoundation() (zoneDir, index, mainConf, service string) {
	zoneDir = a.cfg.DNSZoneDir
	index = a.cfg.DNSIndexPath
	service = a.cfg.DNSService
	if strings.HasPrefix(index, "/etc/bind/") || strings.HasPrefix(zoneDir, "/etc/bind/") {
		if zoneDir == "" {
			zoneDir = "/etc/bind/privora-zones"
		}
		if index == "" {
			index = "/etc/bind/privora-zones.conf"
		}
		mainConf = "/etc/bind/named.conf.local"
		if service == "" {
			service = "bind9"
		}
	} else {
		if zoneDir == "" {
			zoneDir = "/etc/named/privora-zones"
		}
		if index == "" {
			index = "/etc/named/privora-zones.conf"
		}
		mainConf = "/etc/named.conf"
		if service == "" {
			service = "named"
		}
	}
	return
}

func (a *Adapter) validateBINDConfig(ctx context.Context) error {
	if a.cfg.CertificationMode {
		return nil
	}
	if _, ok := commandExists("named-checkconf"); ok {
		if _, err := a.run(ctx, "named-checkconf"); err != nil {
			return err
		}
	}
	return nil
}

func (a *Adapter) EnsureDNSFoundation(ctx context.Context) error {
	if !a.cfg.AllowMutations {
		return errors.New("host mutations disabled")
	}
	zoneDir, index, mainConf, _ := a.dnsFoundation()
	if err := os.MkdirAll(zoneDir, 0755); err != nil {
		return err
	}
	if _, err := os.Stat(index); errors.Is(err, os.ErrNotExist) {
		if err := AtomicWrite(index, []byte(""), 0644); err != nil {
			return err
		}
	} else if err != nil {
		return err
	}
	b, err := os.ReadFile(mainConf)
	if err != nil {
		if a.cfg.CertificationMode {
			return nil
		}
		return fmt.Errorf("authoritative DNS configuration unavailable: %w", err)
	}
	directive := fmt.Sprintf("include \"%s\";", index)
	if !strings.Contains(string(b), directive) {
		text := strings.TrimRight(string(b), "\n") + "\n\n// Privora-managed authoritative zones\n" + directive + "\n"
		if err := AtomicWrite(mainConf, []byte(text), 0644); err != nil {
			return err
		}
	}
	if err := a.validateBINDConfig(ctx); err != nil {
		return fmt.Errorf("BIND configuration validation failed: %w", err)
	}
	return nil
}

func (a *Adapter) reloadDNS(ctx context.Context, service string) error {
	if _, err := a.run(ctx, "systemctl", "reload", service); err != nil {
		if _, err2 := a.run(ctx, "systemctl", "restart", service); err2 != nil {
			return err
		}
	}
	return nil
}

func (a *Adapter) ProvisionBINDZone(ctx context.Context, domain string, records []DNSRecord) (DNSProvisionResult, error) {
	return a.provisionBINDZone(ctx, domain, "", "", records)
}

func (a *Adapter) ProvisionBINDZoneWithNameservers(ctx context.Context, domain, primaryNS, secondaryNS string, records []DNSRecord) (DNSProvisionResult, error) {
	return a.provisionBINDZone(ctx, domain, primaryNS, secondaryNS, records)
}

func (a *Adapter) provisionBINDZone(ctx context.Context, domain, primaryNS, secondaryNS string, records []DNSRecord) (DNSProvisionResult, error) {
	if !a.cfg.AllowMutations {
		return DNSProvisionResult{}, errors.New("host mutations disabled")
	}
	if err := a.requireCertified("authoritative-dns"); err != nil {
		return DNSProvisionResult{}, err
	}
	if !validDomain(domain) {
		return DNSProvisionResult{}, errors.New("invalid domain")
	}
	if _, ok := commandExists("named-checkzone"); !ok {
		return DNSProvisionResult{}, errors.New("named-checkzone not installed")
	}
	if _, ok := commandExists("systemctl"); !ok {
		return DNSProvisionResult{}, errors.New("systemctl not installed")
	}
	zoneDir, index, _, service := a.dnsFoundation()
	if err := a.EnsureDNSFoundation(ctx); err != nil {
		return DNSProvisionResult{}, err
	}
	zone, err := RenderDNSZoneWithNameservers(domain, primaryNS, secondaryNS, records, 0)
	if err != nil {
		return DNSProvisionResult{}, err
	}
	domain = strings.ToLower(strings.TrimSpace(domain))
	zonePath := filepath.Join(zoneDir, domain+".zone")
	oldZone, zoneHad := readIfExists(zonePath)
	oldIndex, indexHad := readIfExists(index)
	rollback := func() { restoreFile(zonePath, oldZone, zoneHad, 0644); restoreFile(index, oldIndex, indexHad, 0644) }
	if err := AtomicWrite(zonePath, []byte(zone), 0644); err != nil {
		return DNSProvisionResult{}, err
	}
	if _, err := a.run(ctx, "named-checkzone", domain, zonePath); err != nil {
		rollback()
		return DNSProvisionResult{}, fmt.Errorf("zone validation failed; rolled back: %w", err)
	}
	indexText := string(oldIndex)
	block := fmt.Sprintf("zone \"%s\" { type master; file \"%s\"; };", domain, zonePath)
	if !strings.Contains(strings.ToLower(indexText), `zone "`+domain+`"`) {
		if strings.TrimSpace(indexText) != "" && !strings.HasSuffix(indexText, "\n") {
			indexText += "\n"
		}
		indexText += block + "\n"
	}
	if err := AtomicWrite(index, []byte(indexText), 0644); err != nil {
		rollback()
		return DNSProvisionResult{}, err
	}
	if err := a.validateBINDConfig(ctx); err != nil {
		rollback()
		return DNSProvisionResult{}, fmt.Errorf("BIND configuration validation failed; rolled back: %w", err)
	}
	if err := a.reloadDNS(ctx, service); err != nil {
		rollback()
		return DNSProvisionResult{}, fmt.Errorf("DNS reload failed; rolled back: %w", err)
	}
	return DNSProvisionResult{Domain: domain, ZoneFile: zonePath, IndexFile: index, Validated: true, Reloaded: true}, nil
}

func (a *Adapter) DeleteBINDZone(ctx context.Context, domain string) error {
	if !a.cfg.AllowMutations {
		return errors.New("host mutations disabled")
	}
	if err := a.requireCertified("authoritative-dns"); err != nil {
		return err
	}
	domain = strings.ToLower(strings.TrimSpace(domain))
	if !validDomain(domain) {
		return errors.New("invalid domain")
	}
	zoneDir, index, _, service := a.dnsFoundation()
	zonePath := filepath.Join(zoneDir, domain+".zone")
	oldZone, zoneHad := readIfExists(zonePath)
	oldIndex, indexHad := readIfExists(index)
	rollback := func() { restoreFile(zonePath, oldZone, zoneHad, 0644); restoreFile(index, oldIndex, indexHad, 0644) }
	lines := strings.Split(string(oldIndex), "\n")
	kept := make([]string, 0, len(lines))
	needle := `zone "` + domain + `"`
	for _, line := range lines {
		if strings.Contains(strings.ToLower(line), needle) {
			continue
		}
		kept = append(kept, line)
	}
	if err := AtomicWrite(index, []byte(strings.TrimRight(strings.Join(kept, "\n"), "\n")+"\n"), 0644); err != nil {
		return err
	}
	if err := os.Remove(zonePath); err != nil && !errors.Is(err, os.ErrNotExist) {
		rollback()
		return err
	}
	if err := a.validateBINDConfig(ctx); err != nil {
		rollback()
		return fmt.Errorf("BIND configuration validation failed; rolled back: %w", err)
	}
	if err := a.reloadDNS(ctx, service); err != nil {
		rollback()
		return fmt.Errorf("DNS reload failed; rolled back: %w", err)
	}
	return nil
}

// UpsertBINDRecords safely updates records inside a Privora-managed BIND zone.
func (a *Adapter) UpsertBINDRecords(ctx context.Context, domain string, records []DNSRecord) (DNSProvisionResult, error) {
	if !a.cfg.AllowMutations {
		return DNSProvisionResult{}, errors.New("host mutations disabled")
	}
	domain = strings.ToLower(strings.TrimSpace(domain))
	if !validDomain(domain) {
		return DNSProvisionResult{}, errors.New("invalid domain")
	}
	zoneDir, index, _, service := a.dnsFoundation()
	zonePath := filepath.Join(zoneDir, domain+".zone")
	if _, err := os.Stat(zonePath); errors.Is(err, os.ErrNotExist) {
		return a.ProvisionBINDZone(ctx, domain, records)
	} else if err != nil {
		return DNSProvisionResult{}, err
	}
	old, err := os.ReadFile(zonePath)
	if err != nil {
		return DNSProvisionResult{}, err
	}
	lines := strings.Split(string(old), "\n")
	keys := map[string]bool{}
	for _, r := range records {
		keys[strings.ToLower(strings.TrimSpace(r.Name))+"|"+strings.ToUpper(strings.TrimSpace(r.Type))] = true
	}
	kept := make([]string, 0, len(lines)+len(records))
	for _, line := range lines {
		fields := strings.Fields(strings.TrimSpace(line))
		remove := false
		if len(fields) >= 4 {
			name := strings.ToLower(fields[0])
			typ := ""
			for i, f := range fields {
				if strings.EqualFold(f, "IN") && i+1 < len(fields) {
					typ = strings.ToUpper(fields[i+1])
					break
				}
			}
			if keys[name+"|"+typ] {
				remove = true
			}
		}
		if !remove {
			kept = append(kept, line)
		}
	}
	for _, r := range records {
		rendered, err := RenderDNSZone(domain, []DNSRecord{r}, uint32(time.Now().UTC().Unix()))
		if err != nil {
			return DNSProvisionResult{}, err
		}
		parts := strings.Split(strings.TrimSpace(rendered), "\n")
		kept = append(kept, parts[len(parts)-1])
	}
	joined := strings.Join(kept, "\n")
	soa := regexp.MustCompile(`(\(\s+)[0-9]+(\s+3600\s+900\s+1209600\s+300\s+\))`)
	joined = soa.ReplaceAllString(joined, fmt.Sprintf("${1}%d${2}", time.Now().UTC().Unix()))
	if !strings.HasSuffix(joined, "\n") {
		joined += "\n"
	}
	if err := AtomicWrite(zonePath, []byte(joined), 0644); err != nil {
		return DNSProvisionResult{}, err
	}
	rollback := func() { _ = AtomicWrite(zonePath, old, 0644) }
	if _, err := a.run(ctx, "named-checkzone", domain, zonePath); err != nil {
		rollback()
		return DNSProvisionResult{}, fmt.Errorf("zone validation failed; previous zone restored: %w", err)
	}
	if err := a.validateBINDConfig(ctx); err != nil {
		rollback()
		return DNSProvisionResult{}, fmt.Errorf("BIND validation failed; previous zone restored: %w", err)
	}
	if err := a.reloadDNS(ctx, service); err != nil {
		rollback()
		return DNSProvisionResult{}, fmt.Errorf("DNS reload failed; previous zone restored: %w", err)
	}
	return DNSProvisionResult{Domain: domain, ZoneFile: zonePath, IndexFile: index, Validated: true, Reloaded: true}, nil
}

type ManagedBINDZone struct {
	Domain   string      `json:"domain"`
	ZoneFile string      `json:"zone_file"`
	Records  []DNSRecord `json:"records"`
}

// parseBINDZoneFile parses a BIND master zone file for display/editing. SOA is
// intentionally omitted; apex NS records remain visible so the operator can
// inspect the effective delegation. The parser accepts inherited owners and
// both @ and FQDN apex notation used by legacy/provider-generated zones.
func parseBINDZoneFile(domain, zonePath string, b []byte) ManagedBINDZone {
	records := []DNSRecord{}
	inSOA := false
	lastOwner := ""
	for _, raw := range strings.Split(string(b), "\n") {
		ownerOmitted := len(raw) > 0 && (raw[0] == ' ' || raw[0] == '\t')
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(line, ";") || strings.HasPrefix(strings.ToUpper(line), "$TTL") || strings.HasPrefix(strings.ToUpper(line), "$ORIGIN") {
			continue
		}
		if inSOA {
			if strings.Contains(line, ")") {
				inSOA = false
			}
			continue
		}
		if strings.Contains(strings.ToUpper(line), " IN SOA ") {
			fields := strings.Fields(line)
			if len(fields) > 0 && !ownerOmitted {
				lastOwner = fields[0]
			}
			if strings.Contains(line, "(") && !strings.Contains(line, ")") {
				inSOA = true
			}
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 3 {
			continue
		}
		name := ""
		ttl := 3600
		typ := ""
		valueStart := 0
		if ownerOmitted && lastOwner != "" {
			name = lastOwner
			if strings.EqualFold(fields[0], "IN") && len(fields) >= 3 {
				typ = strings.ToUpper(fields[1])
				valueStart = 2
			} else if len(fields) >= 4 && strings.EqualFold(fields[1], "IN") {
				if n, err := strconv.Atoi(fields[0]); err == nil && n > 0 {
					ttl = n
				}
				typ = strings.ToUpper(fields[2])
				valueStart = 3
			}
		} else {
			name = fields[0]
			lastOwner = name
			if len(fields) >= 4 && strings.EqualFold(fields[1], "IN") {
				typ = strings.ToUpper(fields[2])
				valueStart = 3
			} else if len(fields) >= 5 && strings.EqualFold(fields[2], "IN") {
				if n, err := strconv.Atoi(fields[1]); err == nil && n > 0 {
					ttl = n
				}
				typ = strings.ToUpper(fields[3])
				valueStart = 4
			}
		}
		if typ == "" || name == "" || valueStart >= len(fields) {
			continue
		}
		value := strings.Join(fields[valueStart:], " ")
		if typ == "TXT" {
			value = parseBINDTXTValue(value)
		}
		records = append(records, DNSRecord{Type: typ, Name: name, Value: value, TTL: ttl})
	}
	return ManagedBINDZone{Domain: domain, ZoneFile: zonePath, Records: records}
}

// ReadBINDZoneFile reads a zone from a path discovered in BIND's effective
// configuration. It is used for read-only legacy/external zone visibility;
// mutation APIs still require a Privora-managed zone.
func (a *Adapter) ReadBINDZoneFile(domain, zonePath string) (ManagedBINDZone, error) {
	domain = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(domain)), ".")
	if !validDomain(domain) {
		return ManagedBINDZone{}, errors.New("invalid domain")
	}
	zonePath = filepath.Clean(strings.TrimSpace(zonePath))
	if zonePath == "." || zonePath == "" || !filepath.IsAbs(zonePath) {
		return ManagedBINDZone{}, errors.New("invalid zone file path")
	}
	b, err := os.ReadFile(zonePath)
	if err != nil {
		return ManagedBINDZone{}, err
	}
	return parseBINDZoneFile(domain, zonePath, b), nil
}

// ReadBINDZone reads records from a Privora-managed zone file. SOA is managed
// by Privora and intentionally omitted; authoritative NS records are returned
// read-only through the API so operators can see the complete delegation.
func (a *Adapter) ReadBINDZone(domain string) (ManagedBINDZone, error) {
	domain = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(domain)), ".")
	if !validDomain(domain) {
		return ManagedBINDZone{}, errors.New("invalid domain")
	}
	zoneDir, _, _, _ := a.dnsFoundation()
	zonePath := filepath.Join(zoneDir, domain+".zone")
	return a.ReadBINDZoneFile(domain, zonePath)
}

// RewriteBINDZoneNameservers updates the authoritative NS pair while retaining
// every editable non-authority record already present in the zone.
func (a *Adapter) RewriteBINDZoneNameservers(ctx context.Context, domain, primary, secondary string, extra []DNSRecord) (DNSProvisionResult, error) {
	zone, err := a.ReadBINDZone(domain)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return DNSProvisionResult{}, err
	}
	domain = strings.ToLower(strings.Trim(strings.TrimSpace(domain), "."))
	primary = strings.ToLower(strings.Trim(strings.TrimSpace(primary), "."))
	secondary = strings.ToLower(strings.Trim(strings.TrimSpace(secondary), "."))
	// Track in-bailiwick nameserver hosts from the previous NS pair so a domain
	// reassigned from ns1/ns2.example.org to ns1/ns2.example.com does not keep
	// publishing orphan A/AAAA glue for the retired .org nameserver hostnames.
	oldGlueLabels := map[string]bool{}
	if err == nil {
		for _, r := range zone.Records {
			if !strings.EqualFold(r.Type, "NS") || !isDNSZoneApexOwner(r.Name, domain) {
				continue
			}
			host := strings.ToLower(strings.Trim(strings.TrimSpace(r.Value), "."))
			if strings.HasSuffix(host, "."+domain) {
				label := strings.TrimSuffix(host, "."+domain)
				if label != "" && host != primary && host != secondary {
					oldGlueLabels[label] = true
				}
			}
		}
	}
	kept := []DNSRecord{}
	if err == nil {
		for _, r := range zone.Records {
			if strings.EqualFold(r.Type, "NS") && isDNSZoneApexOwner(r.Name, domain) {
				continue
			}
			name := strings.ToLower(strings.Trim(strings.TrimSpace(r.Name), "."))
			typ := strings.ToUpper(strings.TrimSpace(r.Type))
			if oldGlueLabels[name] && (typ == "A" || typ == "AAAA") {
				continue
			}
			kept = append(kept, r)
		}
	}
	keys := map[string]bool{}
	for _, r := range extra {
		keys[strings.ToLower(strings.TrimSpace(r.Name))+"|"+strings.ToUpper(strings.TrimSpace(r.Type))] = true
	}
	filtered := kept[:0]
	for _, r := range kept {
		if !keys[strings.ToLower(strings.TrimSpace(r.Name))+"|"+strings.ToUpper(strings.TrimSpace(r.Type))] {
			filtered = append(filtered, r)
		}
	}
	filtered = append(filtered, extra...)
	return a.ProvisionBINDZoneWithNameservers(ctx, domain, primary, secondary, filtered)
}

func sameDNSRecord(a, b DNSRecord) bool {
	nameA := strings.TrimSuffix(strings.ToLower(strings.TrimSpace(a.Name)), ".")
	nameB := strings.TrimSuffix(strings.ToLower(strings.TrimSpace(b.Name)), ".")
	if nameA == "" {
		nameA = "@"
	}
	if nameB == "" {
		nameB = "@"
	}
	return strings.EqualFold(strings.TrimSpace(a.Type), strings.TrimSpace(b.Type)) && nameA == nameB && strings.EqualFold(strings.TrimSpace(a.Value), strings.TrimSpace(b.Value)) && (b.TTL <= 0 || a.TTL == b.TTL)
}

func (a *Adapter) ReplaceBINDRecord(ctx context.Context, domain string, original, replacement DNSRecord) (DNSProvisionResult, error) {
	if !a.cfg.AllowMutations {
		return DNSProvisionResult{}, errors.New("host mutations disabled")
	}
	domain = strings.ToLower(strings.TrimSpace(domain))
	if !validDomain(domain) {
		return DNSProvisionResult{}, errors.New("invalid domain")
	}
	for _, r := range []DNSRecord{original, replacement} {
		typ := strings.ToUpper(strings.TrimSpace(r.Type))
		name := strings.TrimSuffix(strings.ToLower(strings.TrimSpace(r.Name)), ".")
		if typ == "SOA" || (typ == "NS" && (name == "" || name == "@" || name == domain)) {
			return DNSProvisionResult{}, errors.New("SOA and authoritative root NS records are protected")
		}
	}
	zone, err := a.ReadBINDZone(domain)
	if err != nil {
		return DNSProvisionResult{}, err
	}
	primary, secondary := "", ""
	rows := make([]DNSRecord, 0, len(zone.Records))
	replaced := false
	for _, r := range zone.Records {
		if strings.EqualFold(r.Type, "NS") && isDNSZoneApexOwner(r.Name, domain) {
			v := strings.TrimSuffix(strings.ToLower(strings.TrimSpace(r.Value)), ".")
			if primary == "" {
				primary = v
			} else if secondary == "" && v != primary {
				secondary = v
			}
			continue
		}
		if !replaced && sameDNSRecord(r, original) {
			rows = append(rows, replacement)
			replaced = true
			continue
		}
		rows = append(rows, r)
	}
	if !replaced {
		return DNSProvisionResult{}, errors.New("original DNS record not found; refresh the zone before editing")
	}
	if primary == "" || secondary == "" {
		return DNSProvisionResult{}, errors.New("managed zone does not contain a complete authoritative NS pair")
	}
	return a.ProvisionBINDZoneWithNameservers(ctx, domain, primary, secondary, rows)
}

func (a *Adapter) DeleteBINDRecord(ctx context.Context, domain string, record DNSRecord) (DNSProvisionResult, error) {
	if !a.cfg.AllowMutations {
		return DNSProvisionResult{}, errors.New("host mutations disabled")
	}
	domain = strings.ToLower(strings.TrimSpace(domain))
	record.Type = strings.ToUpper(strings.TrimSpace(record.Type))
	record.Name = strings.TrimSpace(record.Name)
	if record.Name == "" {
		record.Name = "@"
	}
	if !validDomain(domain) || record.Type == "SOA" {
		return DNSProvisionResult{}, errors.New("invalid or protected DNS record")
	}
	if record.Type == "NS" && record.Name == "@" {
		return DNSProvisionResult{}, errors.New("authoritative root NS records are managed by Nameserver Manager")
	}
	zoneDir, index, _, service := a.dnsFoundation()
	zonePath := filepath.Join(zoneDir, domain+".zone")
	old, err := os.ReadFile(zonePath)
	if err != nil {
		return DNSProvisionResult{}, err
	}
	lines := strings.Split(string(old), "\n")
	kept := make([]string, 0, len(lines))
	removed := false
	for _, line := range lines {
		fields := strings.Fields(strings.TrimSpace(line))
		if len(fields) < 4 {
			kept = append(kept, line)
			continue
		}
		name := fields[0]
		typ := ""
		valueStart := 0
		if strings.EqualFold(fields[1], "IN") {
			typ, valueStart = strings.ToUpper(fields[2]), 3
		} else if len(fields) >= 5 && strings.EqualFold(fields[2], "IN") {
			typ, valueStart = strings.ToUpper(fields[3]), 4
		}
		value := ""
		if valueStart > 0 && valueStart < len(fields) {
			value = strings.Join(fields[valueStart:], " ")
			if typ == "TXT" {
				value = strings.Trim(value, `"`)
			}
		}
		match := strings.EqualFold(name, record.Name) && typ == record.Type
		if match && strings.TrimSpace(record.Value) != "" {
			match = strings.EqualFold(strings.TrimSpace(value), strings.TrimSpace(record.Value))
		}
		if match && !removed {
			removed = true
			continue
		}
		kept = append(kept, line)
	}
	if !removed {
		return DNSProvisionResult{}, errors.New("DNS record not found")
	}
	joined := strings.Join(kept, "\n")
	soa := regexp.MustCompile(`(\(\s+)[0-9]+(\s+3600\s+900\s+1209600\s+300\s+\))`)
	joined = soa.ReplaceAllString(joined, fmt.Sprintf("${1}%d${2}", time.Now().UTC().Unix()))
	if !strings.HasSuffix(joined, "\n") {
		joined += "\n"
	}
	if err := AtomicWrite(zonePath, []byte(joined), 0644); err != nil {
		return DNSProvisionResult{}, err
	}
	rollback := func() { _ = AtomicWrite(zonePath, old, 0644) }
	if _, err := a.run(ctx, "named-checkzone", domain, zonePath); err != nil {
		rollback()
		return DNSProvisionResult{}, fmt.Errorf("zone validation failed; previous zone restored: %w", err)
	}
	if err := a.validateBINDConfig(ctx); err != nil {
		rollback()
		return DNSProvisionResult{}, fmt.Errorf("BIND validation failed; previous zone restored: %w", err)
	}
	if err := a.reloadDNS(ctx, service); err != nil {
		rollback()
		return DNSProvisionResult{}, fmt.Errorf("DNS reload failed; previous zone restored: %w", err)
	}
	return DNSProvisionResult{Domain: domain, ZoneFile: zonePath, IndexFile: index, Validated: true, Reloaded: true}, nil
}
