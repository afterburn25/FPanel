package hostadapter

import (
	"context"
	"net"
	"sort"
	"strings"
)

type NameserverSetupConfig struct {
	BaseDomain string
	Primary    string
	Secondary  string
	IPv4       string
	IPv6       string
	GlueStatus string
}

type NameserverSetupStatus struct {
	BaseDomain               string   `json:"base_domain"`
	Primary                  string   `json:"primary"`
	Secondary                string   `json:"secondary"`
	IPv4                     string   `json:"ipv4,omitempty"`
	IPv6                     string   `json:"ipv6,omitempty"`
	DNSZoneConfigured        bool     `json:"dns_zone_configured"`
	DNSZoneSource            string   `json:"dns_zone_source,omitempty"`
	NameserverServiceRunning bool     `json:"nameserver_service_running"`
	GlueRegistered           bool     `json:"glue_registered"`
	GlueIPv4Registered       bool     `json:"glue_ipv4_registered,omitempty"`
	GlueIPv6Registered       bool     `json:"glue_ipv6_registered,omitempty"`
	GlueSource               string   `json:"glue_source,omitempty"`
	DelegationActive         bool     `json:"delegation_active"`
	DelegatedNameservers     []string `json:"delegated_nameservers,omitempty"`
	Service                  string   `json:"service,omitempty"`
	Detail                   string   `json:"detail,omitempty"`
}

func isDNSZoneApexOwner(name, domain string) bool {
	name = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(name)), ".")
	domain = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(domain)), ".")
	return name == "@" || name == domain
}

func appendStatusDetail(current, next string) string {
	next = strings.TrimSpace(next)
	if next == "" {
		return current
	}
	if strings.TrimSpace(current) == "" {
		return next
	}
	return strings.TrimSpace(current) + "; " + next
}

func authoritativeNSFromDig(raw string) ([]string, bool) {
	authoritative := false
	values := []string{}
	seen := map[string]bool{}
	for _, rawLine := range strings.Split(raw, "\n") {
		line := strings.TrimSpace(rawLine)
		lower := strings.ToLower(line)
		if strings.Contains(lower, "flags:") {
			flagText := lower[strings.Index(lower, "flags:")+len("flags:"):]
			if i := strings.Index(flagText, ";"); i >= 0 {
				flagText = flagText[:i]
			}
			for _, flag := range strings.Fields(flagText) {
				if flag == "aa" {
					authoritative = true
				}
			}
		}
		if line == "" || strings.HasPrefix(line, ";") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) >= 5 && strings.EqualFold(fields[len(fields)-2], "NS") {
			v := strings.TrimSuffix(strings.ToLower(strings.TrimSpace(fields[len(fields)-1])), ".")
			if v != "" && !seen[v] {
				seen[v] = true
				values = append(values, v)
			}
		}
	}
	sort.Strings(values)
	return values, authoritative
}

func authoritativeSOAFromDig(raw, domain string) bool {
	domain = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(domain)), ".")
	authoritative := false
	hasExactSOA := false
	for _, rawLine := range strings.Split(raw, "\n") {
		line := strings.TrimSpace(rawLine)
		lower := strings.ToLower(line)
		if strings.Contains(lower, "flags:") {
			flagText := lower[strings.Index(lower, "flags:")+len("flags:"):]
			if i := strings.Index(flagText, ";"); i >= 0 {
				flagText = flagText[:i]
			}
			for _, flag := range strings.Fields(flagText) {
				if flag == "aa" {
					authoritative = true
				}
			}
		}
		if line == "" || strings.HasPrefix(line, ";") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) >= 5 {
			isSOA := false
			for _, field := range fields[1:] {
				if strings.EqualFold(field, "SOA") {
					isSOA = true
					break
				}
			}
			if isSOA {
				owner := strings.TrimSuffix(strings.ToLower(strings.TrimSpace(fields[0])), ".")
				if owner == domain {
					hasExactSOA = true
				}
			}
		}
	}
	return authoritative && hasExactSOA
}

func localDNSProbeServers() []string {
	values := []string{"127.0.0.1", "::1"}
	seen := map[string]bool{"127.0.0.1": true, "::1": true}
	ifaces, err := net.Interfaces()
	if err != nil {
		return values
	}
	for _, iface := range ifaces {
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}
		for _, addr := range addrs {
			raw := addr.String()
			if i := strings.LastIndex(raw, "/"); i >= 0 {
				raw = raw[:i]
			}
			ip := net.ParseIP(strings.TrimSpace(raw))
			if ip == nil || ip.IsUnspecified() {
				continue
			}
			v := ip.String()
			if !seen[v] {
				seen[v] = true
				values = append(values, v)
			}
		}
	}
	return values
}

func (a *Adapter) rndcZoneStatus(ctx context.Context, domain string) (bool, string) {
	if _, ok := commandExists("rndc"); !ok {
		return false, ""
	}
	raw, err := a.run(ctx, "rndc", "zonestatus", domain)
	if err != nil {
		return false, ""
	}
	for _, line := range strings.Split(raw, "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(strings.ToLower(line), "name:") {
			name := strings.TrimSuffix(strings.ToLower(strings.TrimSpace(strings.TrimPrefix(line, "name:"))), ".")
			if name != "" && name != domain {
				return false, ""
			}
		}
	}
	return true, "rndc-zonestatus"
}

// HasLocalAuthoritativeDNSZone asks BIND itself first and then probes every
// local interface on port 53. Some VPS/provider BIND configurations deliberately
// do not listen on 127.0.0.1; limiting discovery to loopback therefore created
// false "not configured" results for perfectly valid loaded zones.
func (a *Adapter) HasLocalAuthoritativeDNSZone(ctx context.Context, domain string) (bool, string) {
	domain = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(domain)), ".")
	if !validDomain(domain) {
		return false, "invalid domain"
	}
	if ok, source := a.rndcZoneStatus(ctx, domain); ok {
		return true, source
	}
	if _, ok := commandExists("dig"); !ok {
		return false, "dig unavailable and rndc zonestatus did not confirm the zone"
	}
	lastErr := ""
	for _, server := range localDNSProbeServers() {
		raw, err := a.run(ctx, "dig", "@"+server, "+time=2", "+tries=1", "+norecurse", domain, "SOA")
		if err != nil {
			lastErr = err.Error()
			continue
		}
		if authoritativeSOAFromDig(raw, domain) {
			return true, "local-authoritative-server:" + server
		}
	}
	if lastErr != "" {
		return false, "no local DNS listener returned an authoritative SOA; last probe error: " + lastErr
	}
	return false, "no local DNS listener returned an authoritative SOA for the exact domain"
}

func normalizeNSList(raw string) []string {
	out := []string{}
	seen := map[string]bool{}
	for _, line := range strings.Split(raw, "\n") {
		v := strings.TrimSuffix(strings.ToLower(strings.TrimSpace(line)), ".")
		if v == "" || seen[v] {
			continue
		}
		seen[v] = true
		out = append(out, v)
	}
	sort.Strings(out)
	return out
}

func containsNS(values []string, want string) bool {
	want = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(want)), ".")
	for _, v := range values {
		if strings.TrimSuffix(strings.ToLower(strings.TrimSpace(v)), ".") == want {
			return true
		}
	}
	return false
}

func outputHasAddress(raw, want string) bool {
	want = strings.TrimSpace(want)
	if want == "" {
		return true
	}
	for _, line := range strings.Split(raw, "\n") {
		if strings.TrimSpace(line) == want {
			return true
		}
	}
	return false
}

// InspectNameserverSetup summarizes local authoritative-DNS health plus public
// glue/delegation visibility. Public checks are advisory and never mutate DNS.
func (a *Adapter) InspectNameserverSetup(ctx context.Context, cfg NameserverSetupConfig) NameserverSetupStatus {
	out := NameserverSetupStatus{
		BaseDomain: cfg.BaseDomain,
		Primary:    cfg.Primary,
		Secondary:  cfg.Secondary,
		IPv4:       cfg.IPv4,
		IPv6:       cfg.IPv6,
	}

	_, _, _, service := a.dnsFoundation()
	out.Service = service
	if _, err := a.run(ctx, "systemctl", "is-active", "--quiet", service); err == nil {
		out.NameserverServiceRunning = true
	}

	zoneFound := false
	if zone, err := a.ReadBINDZone(cfg.BaseDomain); err == nil {
		zoneFound = true
		primary, secondary := false, false
		for _, rec := range zone.Records {
			if !strings.EqualFold(rec.Type, "NS") || !isDNSZoneApexOwner(rec.Name, cfg.BaseDomain) {
				continue
			}
			ns := strings.TrimSuffix(strings.ToLower(strings.TrimSpace(rec.Value)), ".")
			if ns == strings.TrimSuffix(strings.ToLower(strings.TrimSpace(cfg.Primary)), ".") {
				primary = true
			}
			if ns == strings.TrimSuffix(strings.ToLower(strings.TrimSpace(cfg.Secondary)), ".") {
				secondary = true
			}
		}
		if primary && secondary {
			out.DNSZoneConfigured = true
			out.DNSZoneSource = "managed-zone-file"
		}
	}

	// A valid pre-existing/imported BIND zone may live outside Privora's own
	// zone directory. Ask the local nameserver directly and require the AA
	// (authoritative answer) flag so a recursive/cache response cannot create
	// a false positive. This also verifies the zone is actually loaded.
	if out.NameserverServiceRunning {
		if loaded, source := a.rndcZoneStatus(ctx, strings.ToLower(strings.TrimSpace(cfg.BaseDomain))); loaded {
			out.DNSZoneConfigured = true
			out.DNSZoneSource = source
		}
		if _, ok := commandExists("dig"); ok {
			for _, server := range localDNSProbeServers() {
				raw, err := a.run(ctx, "dig", "@"+server, "+time=2", "+tries=1", "+norecurse", cfg.BaseDomain, "NS")
				if err != nil {
					continue
				}
				if localNS, authoritative := authoritativeNSFromDig(raw); authoritative && containsNS(localNS, cfg.Primary) && containsNS(localNS, cfg.Secondary) {
					out.DNSZoneConfigured = true
					out.DNSZoneSource = "local-authoritative-server:" + server
					break
				}
			}
		}
	}
	if !out.DNSZoneConfigured {
		if zoneFound {
			out.Detail = appendStatusDetail(out.Detail, "DNS zone exists, but its authoritative apex NS pair does not match the configured ns1/ns2 pair")
		} else {
			out.Detail = appendStatusDetail(out.Detail, "no matching Privora-managed or locally authoritative DNS zone was detected for the base domain")
		}
	}

	if cfg.GlueStatus == "registrar-glue-synced" {
		out.GlueRegistered = true
		out.GlueSource = "registrar"
	}

	if _, ok := commandExists("dig"); ok {
		if raw, err := a.run(ctx, "dig", "+time=2", "+tries=1", "+short", cfg.BaseDomain, "NS"); err == nil {
			delegated := normalizeNSList(raw)
			out.DelegatedNameservers = delegated
			out.DelegationActive = containsNS(delegated, cfg.Primary) && containsNS(delegated, cfg.Secondary)
		}

		// Because Privora requires in-bailiwick child nameservers, public
		// resolution of both child hosts to the configured address is useful
		// evidence that registry glue is functioning. A connected registrar
		// sync remains the stronger signal and is preferred above.
		if !out.GlueRegistered {
			p4, p6, s4, s6 := "", "", "", ""
			if cfg.IPv4 != "" {
				p4, _ = a.run(ctx, "dig", "+time=2", "+tries=1", "+short", cfg.Primary, "A")
				s4, _ = a.run(ctx, "dig", "+time=2", "+tries=1", "+short", cfg.Secondary, "A")
			}
			if cfg.IPv6 != "" {
				p6, _ = a.run(ctx, "dig", "+time=2", "+tries=1", "+short", cfg.Primary, "AAAA")
				s6, _ = a.run(ctx, "dig", "+time=2", "+tries=1", "+short", cfg.Secondary, "AAAA")
			}
			v4ok := cfg.IPv4 != "" && outputHasAddress(p4, cfg.IPv4) && outputHasAddress(s4, cfg.IPv4)
			v6ok := cfg.IPv6 != "" && outputHasAddress(p6, cfg.IPv6) && outputHasAddress(s6, cfg.IPv6)
			out.GlueIPv4Registered = v4ok
			out.GlueIPv6Registered = v6ok
			if v4ok || v6ok {
				out.GlueRegistered = true
				out.GlueSource = "public-dns"
				if cfg.IPv4 != "" && !v4ok {
					out.Detail = appendStatusDetail(out.Detail, "IPv6 glue is reachable but configured IPv4 glue was not confirmed")
				}
				if cfg.IPv6 != "" && !v6ok {
					out.Detail = appendStatusDetail(out.Detail, "IPv4 glue is reachable; configured IPv6 glue was not confirmed")
				}
			}
		}
	} else {
		out.Detail = appendStatusDetail(out.Detail, "dig is not installed; public glue/delegation checks are unavailable")
	}
	return out
}
