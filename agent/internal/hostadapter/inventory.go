package hostadapter

import (
	"bufio"
	"context"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

type LiveAccount struct {
	Username string `json:"username"`
	UID      int    `json:"uid"`
	GID      int    `json:"gid"`
	Home     string `json:"home"`
	Shell    string `json:"shell"`
	Status   string `json:"status"`
	Managed  bool   `json:"managed"`
	Source   string `json:"source"`
}

type LiveSite struct {
	Domain       string `json:"domain"`
	Username     string `json:"username"`
	DocumentRoot string `json:"document_root"`
	PHPVersion   string `json:"php_version"`
	Enabled      bool   `json:"enabled"`
	SSL          string `json:"ssl"`
	NginxConfig  string `json:"nginx_config"`
	Managed      bool   `json:"managed"`
	Source       string `json:"source"`
}

type LivePHPVersion struct {
	Version string `json:"version"`
	Service string `json:"service"`
	Status  string `json:"status"`
	Pools   int    `json:"pools"`
}

type LiveDatabase struct {
	Name   string `json:"name"`
	Engine string `json:"engine"`
	Owner  string `json:"owner,omitempty"`
	Source string `json:"source"`
}

type LiveDNSZone struct {
	Domain   string `json:"domain"`
	ZoneFile string `json:"zone_file"`
	Managed  bool   `json:"managed"`
	Source   string `json:"source"`
}

type LiveMailbox struct {
	Address string `json:"address"`
	Domain  string `json:"domain"`
	Maildir string `json:"maildir,omitempty"`
	Source  string `json:"source"`
}

type LiveCertificate struct {
	Domain    string    `json:"domain"`
	Provider  string    `json:"provider"`
	Status    string    `json:"status"`
	ExpiresAt time.Time `json:"expires_at"`
	AutoRenew bool      `json:"auto_renew"`
	CertPath  string    `json:"cert_path"`
	Source    string    `json:"source"`
}

type HostEnvironment struct {
	ControlPanel string   `json:"control_panel"`
	WebServer    string   `json:"web_server"`
	AccountModel string   `json:"account_model"`
	HomeBase     string   `json:"home_base"`
	Markers      []string `json:"markers"`
}

type HostInventory struct {
	CollectedAt  time.Time         `json:"collected_at"`
	Environment  HostEnvironment   `json:"environment"`
	Accounts     []LiveAccount     `json:"accounts"`
	Sites        []LiveSite        `json:"sites"`
	PHPVersions  []LivePHPVersion  `json:"php_versions"`
	Databases    []LiveDatabase    `json:"databases"`
	DNSZones     []LiveDNSZone     `json:"dns_zones"`
	Mailboxes    []LiveMailbox     `json:"mailboxes"`
	Certificates []LiveCertificate `json:"certificates"`
	Warnings     []string          `json:"warnings"`
	Diagnostics  map[string]any    `json:"diagnostics,omitempty"`
}

var (
	nginxServerNameRE = regexp.MustCompile(`(?m)(?:^|[;{}])\s*server_name\s+([^;]+);`)
	nginxRootRE       = regexp.MustCompile(`(?m)(?:^|[;{}])\s*root\s+([^;]+);`)
	nginxPHPRE        = regexp.MustCompile(`php([0-9]+\.[0-9]+)-fpm-([a-z][a-z0-9_-]{2,31})\.sock`)
)

// DiscoverInventory reads the actual host configuration. It is deliberately
// read-only: discovery never creates, edits, reloads, or deletes host state.
// A short cache is intentional: a single PCC render asks for accounts, sites,
// databases and related resources in rapid succession. Re-running SQL and
// Nginx discovery for every endpoint made the real panel look empty whenever
// one subsystem was slow. The cache keeps one authoritative snapshot for the
// request burst while refreshing frequently enough for an admin control panel.
func (a *Adapter) DiscoverInventory(ctx context.Context) HostInventory {
	a.inventoryMu.Lock()
	defer a.inventoryMu.Unlock()
	if !a.inventoryCachedAt.IsZero() && time.Since(a.inventoryCachedAt) < 8*time.Second {
		return a.inventoryCache
	}
	inv := a.discoverInventoryUncached(ctx)
	a.inventoryCache = inv
	a.inventoryCachedAt = time.Now()
	return inv
}

// InvalidateInventory forces the next live-host read to observe a mutation that
// Privora just committed. Mutating transactions call this before returning so
// the UI never has to wait for the normal short discovery cache to expire.
func (a *Adapter) InvalidateInventory() {
	a.inventoryMu.Lock()
	a.inventoryCachedAt = time.Time{}
	a.inventoryCache = HostInventory{}
	a.inventoryMu.Unlock()
}

func (a *Adapter) discoverInventoryUncached(ctx context.Context) HostInventory {
	inv := HostInventory{CollectedAt: time.Now().UTC(), Accounts: []LiveAccount{}, Sites: []LiveSite{}, PHPVersions: []LivePHPVersion{}, Databases: []LiveDatabase{}, DNSZones: []LiveDNSZone{}, Mailboxes: []LiveMailbox{}, Certificates: []LiveCertificate{}, Warnings: []string{}, Diagnostics: map[string]any{}}
	inv.Environment = a.discoverHostEnvironment()
	inv.Accounts = a.discoverAccounts(&inv)

	// Slow external probes run concurrently. A database authentication problem
	// must not prevent WHM from showing Nginx websites or Linux accounts.
	sitePart := HostInventory{Diagnostics: map[string]any{}}
	phpPart := HostInventory{Diagnostics: map[string]any{}}
	dbPart := HostInventory{Diagnostics: map[string]any{}}
	var sites []LiveSite
	var php []LivePHPVersion
	var dbs []LiveDatabase
	var wg sync.WaitGroup
	wg.Add(3)
	go func() { defer wg.Done(); sites = a.discoverNginxSites(ctx, inv.Accounts, &sitePart) }()
	go func() { defer wg.Done(); php = a.discoverPHPVersions(ctx, &phpPart) }()
	go func() { defer wg.Done(); dbs = a.discoverDatabases(ctx, inv.Accounts, &dbPart) }()

	// Pure filesystem scans are cheap and cannot block on service authentication.
	inv.DNSZones = a.discoverDNSZones(ctx, &inv)
	inv.Mailboxes = a.discoverMailboxes(&inv)
	wg.Wait()
	inv.Sites, inv.PHPVersions, inv.Databases = sites, php, dbs
	for _, part := range []*HostInventory{&sitePart, &phpPart, &dbPart} {
		inv.Warnings = append(inv.Warnings, part.Warnings...)
		for k, v := range part.Diagnostics {
			inv.Diagnostics[k] = v
		}
	}

	inv.Accounts = a.enrichAccountsFromSites(inv.Accounts, inv.Sites, &inv)
	inv.Certificates = a.discoverCertificates(inv.Sites, &inv)
	inv.Diagnostics["counts"] = inv.Summary()
	inv.Diagnostics["environment"] = inv.Environment
	inv.Diagnostics["account_home_base"] = a.cfg.AccountHomeBase
	inv.Diagnostics["nginx_sites_available"] = a.cfg.NginxSitesAvailable
	inv.Diagnostics["nginx_sites_enabled"] = a.cfg.NginxSitesEnabled
	return inv
}

func (a *Adapter) discoverHostEnvironment() HostEnvironment {
	env := HostEnvironment{ControlPanel: "none", WebServer: "unknown", AccountModel: "linux-home", HomeBase: a.cfg.AccountHomeBase, Markers: []string{}}
	panels := []struct {
		name   string
		marker string
		model  string
	}{
		{"cPanel/WHM", "/usr/local/cpanel", "cpanel"},
		{"Plesk", "/usr/local/psa", "plesk"},
		{"DirectAdmin", "/usr/local/directadmin", "directadmin"},
		{"HestiaCP", "/usr/local/hestia", "hestia"},
		{"CyberPanel", "/usr/local/CyberCP", "cyberpanel"},
		{"ISPConfig", "/usr/local/ispconfig", "ispconfig"},
		{"Virtualmin/Webmin", "/etc/webmin/virtual-server", "virtualmin"},
	}
	for _, p := range panels {
		if _, err := os.Stat(p.marker); err == nil {
			env.ControlPanel, env.AccountModel = p.name, p.model
			env.Markers = append(env.Markers, p.marker)
			break
		}
	}
	if _, ok := commandExists("nginx"); ok {
		env.WebServer = "nginx"
	} else if _, ok := commandExists("apache2"); ok {
		env.WebServer = "apache"
	} else if _, ok := commandExists("httpd"); ok {
		env.WebServer = "apache"
	} else if _, ok := commandExists("lswsctrl"); ok {
		env.WebServer = "litespeed"
	}
	return env
}

func (a *Adapter) discoverAccounts(inv *HostInventory) []LiveAccount {
	f, err := os.Open(a.cfg.PasswdPath)
	if err != nil {
		inv.Warnings = append(inv.Warnings, "accounts: "+err.Error())
		return nil
	}
	defer f.Close()
	suspended := readShadowExpiry(a.cfg.ShadowPath)
	out := []LiveAccount{}
	s := bufio.NewScanner(f)
	for s.Scan() {
		fields := strings.Split(s.Text(), ":")
		if len(fields) < 7 {
			continue
		}
		username := fields[0]
		if !validUser(username) {
			continue
		}
		uid, err1 := strconv.Atoi(fields[2])
		gid, err2 := strconv.Atoi(fields[3])
		if err1 != nil || err2 != nil {
			continue
		}
		home, shell := fields[5], fields[6]
		// Existing hosting providers do not all use Privora's /domains layout.
		// Treat normal human/service hosting identities under the configured home
		// base as discoverable accounts, while still marking Privora-layout users
		// as managed. System identities are excluded by UID and home location.
		if uid < 1000 {
			continue
		}
		expectedHome := filepath.Join(a.cfg.AccountHomeBase, username)
		if filepath.Clean(home) != filepath.Clean(expectedHome) {
			continue
		}
		domains := filepath.Join(home, "domains")
		managed := false
		source := "/etc/passwd + existing home"
		if st, err := os.Stat(domains); err == nil && st.IsDir() {
			managed = true
			source = "/etc/passwd + " + domains
		} else {
			for _, candidate := range []string{"public_html", "www", "htdocs", "web"} {
				if st, err := os.Stat(filepath.Join(home, candidate)); err == nil && st.IsDir() {
					source = "/etc/passwd + " + filepath.Join(home, candidate)
					break
				}
			}
		}
		status := "active"
		if suspended[username] {
			status = "suspended"
		}
		out = append(out, LiveAccount{Username: username, UID: uid, GID: gid, Home: home, Shell: shell, Status: status, Managed: managed, Source: source})
	}
	if err := s.Err(); err != nil {
		inv.Warnings = append(inv.Warnings, "accounts scan: "+err.Error())
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Username < out[j].Username })
	return out
}

func readShadowExpiry(path string) map[string]bool {
	out := map[string]bool{}
	f, err := os.Open(path)
	if err != nil {
		return out
	}
	defer f.Close()
	s := bufio.NewScanner(f)
	nowDays := time.Now().UTC().Unix() / 86400
	for s.Scan() {
		fields := strings.Split(s.Text(), ":")
		if len(fields) < 8 {
			continue
		}
		exp := strings.TrimSpace(fields[7])
		if exp == "" {
			continue
		}
		days, err := strconv.ParseInt(exp, 10, 64)
		if err == nil && days > 0 && days <= nowDays {
			out[fields[0]] = true
		}
	}
	return out
}

func accountSet(accounts []LiveAccount) map[string]bool {
	m := map[string]bool{}
	for _, a := range accounts {
		m[a.Username] = true
	}
	return m
}

type passwdIdentity struct {
	Username string
	UID      int
	GID      int
	Home     string
	Shell    string
}

func readPasswdIdentities(path string) (map[string]passwdIdentity, map[int]string) {
	byName := map[string]passwdIdentity{}
	byUID := map[int]string{}
	f, err := os.Open(path)
	if err != nil {
		return byName, byUID
	}
	defer f.Close()
	s := bufio.NewScanner(f)
	for s.Scan() {
		fields := strings.Split(s.Text(), ":")
		if len(fields) < 7 || !validUser(fields[0]) {
			continue
		}
		uid, err1 := strconv.Atoi(fields[2])
		gid, err2 := strconv.Atoi(fields[3])
		if err1 != nil || err2 != nil {
			continue
		}
		id := passwdIdentity{Username: fields[0], UID: uid, GID: gid, Home: fields[5], Shell: fields[6]}
		byName[id.Username] = id
		byUID[id.UID] = id.Username
	}
	return byName, byUID
}

func inferSiteOwner(root string, identities map[string]passwdIdentity, byUID map[int]string) string {
	cleanRoot := filepath.Clean(root)
	best := ""
	bestLen := 0
	for name, id := range identities {
		home := filepath.Clean(id.Home)
		if home == "." || home == "/" || home == "/nonexistent" || home == "/var/empty" {
			continue
		}
		if cleanRoot == home || strings.HasPrefix(cleanRoot, home+string(os.PathSeparator)) {
			if len(home) > bestLen {
				best, bestLen = name, len(home)
			}
		}
	}
	if best != "" {
		return best
	}
	if st, err := os.Stat(cleanRoot); err == nil {
		if sys, ok := st.Sys().(*syscall.Stat_t); ok {
			if name := byUID[int(sys.Uid)]; name != "" {
				return name
			}
		}
	}
	return ""
}

type nginxServerBlock struct {
	Source string
	Text   string
	Active bool
}

var nginxServerOpenRE = regexp.MustCompile(`^\s*server\s*\{`)

func nginxBlocksFromDump(text string) []nginxServerBlock {
	blocks := []nginxServerBlock{}
	currentSource := "nginx -T"
	inServer := false
	depth := 0
	var b strings.Builder
	s := bufio.NewScanner(strings.NewReader(text))
	for s.Scan() {
		line := s.Text()
		trim := strings.TrimSpace(line)
		if !inServer && strings.HasPrefix(trim, "# configuration file ") {
			name := strings.TrimPrefix(trim, "# configuration file ")
			if i := strings.LastIndex(name, ":"); i >= 0 {
				name = name[:i]
			}
			if strings.TrimSpace(name) != "" {
				currentSource = strings.TrimSpace(name)
			}
			continue
		}
		if !inServer {
			if !nginxServerOpenRE.MatchString(line) {
				continue
			}
			inServer = true
			depth = strings.Count(line, "{") - strings.Count(line, "}")
			b.Reset()
			b.WriteString(line)
			b.WriteByte('\n')
			if depth <= 0 {
				blocks = append(blocks, nginxServerBlock{Source: currentSource, Text: b.String(), Active: true})
				inServer = false
			}
			continue
		}
		b.WriteString(line)
		b.WriteByte('\n')
		depth += strings.Count(line, "{") - strings.Count(line, "}")
		if depth <= 0 {
			blocks = append(blocks, nginxServerBlock{Source: currentSource, Text: b.String(), Active: true})
			inServer = false
		}
	}
	return blocks
}

func siteFromBlock(block nginxServerBlock, identities map[string]passwdIdentity, byUID map[int]string, managedUsers map[string]bool) []LiveSite {
	serverMatches := nginxServerNameRE.FindAllStringSubmatch(block.Text, -1)
	if len(serverMatches) == 0 {
		return nil
	}
	root := ""
	if rm := nginxRootRE.FindStringSubmatch(block.Text); len(rm) >= 2 {
		root = strings.TrimSpace(strings.Trim(rm[1], `"'`))
	}
	username := ""
	if root != "" && !strings.Contains(root, "$") {
		username = inferSiteOwner(root, identities, byUID)
	}
	phpVersion := "unknown"
	if pm := nginxPHPRE.FindStringSubmatch(block.Text); len(pm) >= 3 {
		phpVersion = pm[1]
		if username == "" {
			username = pm[2]
		}
	}
	ssl := "off"
	if strings.Contains(block.Text, "listen 443") || strings.Contains(block.Text, "ssl_certificate ") {
		ssl = "configured"
	}
	managed := (managedUsers[username] && root != "" && strings.Contains(filepath.Clean(root), filepath.Join("home", username, "domains"))) || strings.HasPrefix(filepath.Base(strings.TrimSpace(block.Source)), "privora-")
	candidates := []string{}
	has := map[string]bool{}
	for _, sm := range serverMatches {
		if len(sm) < 2 {
			continue
		}
		for _, raw := range strings.Fields(sm[1]) {
			domain := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(raw), ";"))
			if strings.HasPrefix(domain, "$") || domain == "_" || strings.HasPrefix(domain, "~") {
				continue
			}
			if strings.HasPrefix(domain, "*.") {
				domain = strings.TrimPrefix(domain, "*.")
			}
			if !validDomain(domain) || has[domain] {
				continue
			}
			has[domain] = true
			candidates = append(candidates, domain)
		}
	}
	out := []LiveSite{}
	for _, domain := range candidates {
		// A normal Privora vhost advertises both the apex and its www alias.
		// The alias is not a second website and must not create a duplicate card.
		if strings.HasPrefix(domain, "www.") && has[strings.TrimPrefix(domain, "www.")] {
			continue
		}
		out = append(out, LiveSite{Domain: domain, Username: username, DocumentRoot: root, PHPVersion: phpVersion, Enabled: block.Active, SSL: ssl, NginxConfig: block.Source, Managed: managed, Source: "nginx-effective"})
	}
	return out
}

func mergeLiveSite(existing, candidate LiveSite) LiveSite {
	out := existing
	if out.Domain == "" {
		out.Domain = candidate.Domain
	}
	if out.Username == "" && candidate.Username != "" {
		out.Username = candidate.Username
	}
	if out.DocumentRoot == "" && candidate.DocumentRoot != "" {
		out.DocumentRoot = candidate.DocumentRoot
	}
	if (out.PHPVersion == "" || out.PHPVersion == "unknown") && candidate.PHPVersion != "" && candidate.PHPVersion != "unknown" {
		out.PHPVersion = candidate.PHPVersion
	}
	if candidate.SSL == "configured" {
		out.SSL = "configured"
	} else if out.SSL == "" {
		out.SSL = candidate.SSL
	}
	out.Enabled = out.Enabled || candidate.Enabled
	out.Managed = out.Managed || candidate.Managed
	if out.NginxConfig == "" {
		out.NginxConfig = candidate.NginxConfig
	}
	if candidate.Source == "nginx-effective" {
		out.Source = candidate.Source
	} else if out.Source == "" {
		out.Source = candidate.Source
	}
	return out
}

// InspectManagedSite reconciles a known domain against the effective Nginx
// configuration and conventional vhost files. Older/imported sites are not
// required to use Privora's current privora-<domain>.conf filename convention.
// A matching server_name in nginx -T is authoritative for an active site; the
// enabled directory is the fallback when nginx -T is temporarily unavailable.
func nginxDumpHasServerName(dump, domain string) bool {
	domain = strings.ToLower(strings.TrimSpace(domain))
	if !validDomain(domain) {
		return false
	}
	for _, sm := range nginxServerNameRE.FindAllStringSubmatch(dump, -1) {
		if len(sm) < 2 {
			continue
		}
		for _, raw := range strings.Fields(sm[1]) {
			candidate := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(raw), ";"))
			if candidate == domain || strings.TrimPrefix(candidate, "*.") == domain {
				return true
			}
		}
	}
	return false
}

func (a *Adapter) InspectManagedSite(domain string) (LiveSite, bool) {
	return a.InspectKnownSite(domain, "")
}

// InspectKnownSite adds a durable metadata fallback for older/imported sites.
// If an exact server_name cannot be parsed but the recorded document root is
// present in an active nginx -T server block, that is strong evidence that the
// website is live. This prevents a valid legacy/default-host layout from being
// mislabeled solely because it predates Privora's server_name conventions.
func (a *Adapter) InspectKnownSite(domain, expectedRoot string) (LiveSite, bool) {
	domain = strings.ToLower(strings.TrimSpace(domain))
	if !validDomain(domain) {
		return LiveSite{}, false
	}
	identities, byUID := readPasswdIdentities(a.cfg.PasswdPath)
	best := LiveSite{Domain: domain, Source: "domain-vhost-reconciled"}
	found := false
	mergeMatching := func(blocks []nginxServerBlock, active bool, sourceOverride string) {
		for _, block := range blocks {
			block.Active = active
			if sourceOverride != "" {
				block.Source = sourceOverride
			}
			for _, candidate := range siteFromBlock(block, identities, byUID, map[string]bool{}) {
				if !strings.EqualFold(candidate.Domain, domain) {
					continue
				}
				candidate.Enabled = active
				candidate.Managed = candidate.Managed || strings.HasPrefix(filepath.Base(strings.TrimSpace(block.Source)), "privora-")
				candidate.Source = "domain-vhost-reconciled"
				best = mergeLiveSite(best, candidate)
				found = true
			}
		}
	}

	// nginx -T is the strongest evidence because it is the configuration Nginx
	// actually loaded after include expansion. This also finds custom filenames,
	// imported vhosts and configs living outside sites-available.
	ctx, cancel := context.WithTimeout(context.Background(), a.cfg.CommandTimeout)
	defer cancel()
	if dump, err := a.run(ctx, "nginx", "-T"); err == nil {
		blocks := nginxBlocksFromDump(dump)
		mergeMatching(blocks, true, "")
		if found {
			best.Enabled = true
			return best, true
		}
		// Some imported/provider Nginx files use unusual server-block formatting
		// that can defeat the structured block splitter. nginx -T is still the
		// authoritative loaded configuration, so an exact server_name match is
		// sufficient to recover the live status instead of falsely showing missing.
		if nginxDumpHasServerName(dump, domain) {
			best.Enabled = true
			best.Source = "domain-vhost-effective-name"
			return best, true
		}

		root := filepath.Clean(strings.TrimSpace(expectedRoot))
		if root != "." && root != "" && filepath.IsAbs(root) {
			rootBest := LiveSite{Domain: domain, DocumentRoot: root, Source: "domain-vhost-root-reconciled", Enabled: true}
			rootFound := false
			for _, block := range blocks {
				block.Active = true
				for _, candidate := range siteFromBlock(block, identities, byUID, map[string]bool{}) {
					if filepath.Clean(strings.TrimSpace(candidate.DocumentRoot)) != root {
						continue
					}
					candidate.Domain = domain
					candidate.Enabled = true
					candidate.Source = "domain-vhost-root-reconciled"
					rootBest = mergeLiveSite(rootBest, candidate)
					rootFound = true
				}
			}
			if rootFound {
				rootBest.Domain = domain
				rootBest.Enabled = true
				rootBest.Source = "domain-vhost-root-reconciled"
				return rootBest, true
			}
		}
	}

	// Fallback to conventional directories if Nginx cannot be queried. Search by
	// server_name rather than filename so legacy/imported site names reconcile.
	scanDir := func(dir string, active bool) {
		entries, err := os.ReadDir(filepath.Clean(dir))
		if err != nil {
			return
		}
		for _, entry := range entries {
			if entry.IsDir() || strings.HasPrefix(entry.Name(), ".") {
				continue
			}
			path := filepath.Join(filepath.Clean(dir), entry.Name())
			b, err := os.ReadFile(path)
			if err != nil {
				continue
			}
			blocks := nginxBlocksFromDump("# configuration file " + path + ":\n" + string(b))
			mergeMatching(blocks, active, path)
		}
	}
	scanDir(a.cfg.NginxSitesEnabled, true)
	if found && best.Enabled {
		return best, true
	}
	scanDir(a.cfg.NginxSitesAvailable, false)
	return best, found
}

func (a *Adapter) discoverNginxSites(ctx context.Context, accounts []LiveAccount, inv *HostInventory) []LiveSite {
	if inv.Diagnostics == nil {
		inv.Diagnostics = map[string]any{}
	}
	availableDir := filepath.Clean(a.cfg.NginxSitesAvailable)
	enabledDir := filepath.Clean(a.cfg.NginxSitesEnabled)
	confDDir := filepath.Join(filepath.Dir(availableDir), "conf.d")
	inv.Diagnostics["nginx_scan_paths"] = []string{availableDir, enabledDir, confDDir}

	identities, byUID := readPasswdIdentities(a.cfg.PasswdPath)
	managedUsers := accountSet(accounts)
	out := []LiveSite{}
	seen := map[string]int{}

	// nginx -T is the authoritative source for active configuration because it
	// expands arbitrary include paths. This is more accurate than assuming every
	// host follows Debian's sites-available convention.
	if _, ok := commandExists("nginx"); ok {
		if dump, err := a.run(ctx, "nginx", "-T"); err == nil {
			blocks := nginxBlocksFromDump(dump)
			inv.Diagnostics["nginx_effective_config"] = true
			inv.Diagnostics["nginx_active_server_blocks"] = len(blocks)
			for _, block := range blocks {
				for _, site := range siteFromBlock(block, identities, byUID, managedUsers) {
					if idx, ok := seen[site.Domain]; ok {
						out[idx] = mergeLiveSite(out[idx], site)
						continue
					}
					seen[site.Domain] = len(out)
					out = append(out, site)
				}
			}
		} else {
			inv.Diagnostics["nginx_effective_config"] = false
			inv.Warnings = append(inv.Warnings, "nginx effective configuration: "+err.Error())
		}
	} else {
		inv.Diagnostics["nginx_effective_config"] = false
		inv.Warnings = append(inv.Warnings, "nginx executable not found")
	}

	// Also scan conventional files so disabled vhosts are visible and so
	// inventory still works if nginx -T is temporarily unavailable.
	type fileScan struct {
		pattern string
		active  bool
	}
	scans := []fileScan{{filepath.Join(availableDir, "*"), false}, {filepath.Join(enabledDir, "*"), true}, {filepath.Join(confDDir, "*.conf"), true}}
	for _, scan := range scans {
		files, _ := filepath.Glob(scan.pattern)
		for _, path := range files {
			st, err := os.Stat(path)
			if err != nil || !st.Mode().IsRegular() {
				continue
			}
			b, err := os.ReadFile(path)
			if err != nil {
				continue
			}
			active := scan.active
			if !active && strings.HasPrefix(filepath.Clean(path), availableDir+string(os.PathSeparator)) {
				candidate := filepath.Join(enabledDir, filepath.Base(path))
				if _, err := os.Stat(candidate); err == nil {
					active = true
				}
			}
			for _, block := range nginxBlocksFromDump("# configuration file " + path + ":\n" + string(b)) {
				block.Active = active
				for _, site := range siteFromBlock(block, identities, byUID, managedUsers) {
					site.Source = "nginx-file"
					if idx, ok := seen[site.Domain]; ok {
						out[idx] = mergeLiveSite(out[idx], site)
						continue
					}
					seen[site.Domain] = len(out)
					out = append(out, site)
				}
			}
		}
	}

	inv.Diagnostics["nginx_sites_discovered"] = len(out)
	if len(out) == 0 {
		inv.Warnings = append(inv.Warnings, "nginx inventory: no named website vhosts were discovered; the stock '_' default and the Privora :8443 control-plane vhost are intentionally not counted as hosted websites")
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Domain < out[j].Domain })
	return out
}

func (a *Adapter) enrichAccountsFromSites(accounts []LiveAccount, sites []LiveSite, inv *HostInventory) []LiveAccount {
	if inv.Diagnostics == nil {
		inv.Diagnostics = map[string]any{}
	}
	seen := map[string]bool{}
	for _, a := range accounts {
		seen[a.Username] = true
	}
	identities, _ := readPasswdIdentities(a.cfg.PasswdPath)
	for _, site := range sites {
		name := site.Username
		if name == "" || seen[name] {
			continue
		}
		id, ok := identities[name]
		if !ok || id.UID < 1000 {
			continue
		}
		accounts = append(accounts, LiveAccount{Username: name, UID: id.UID, GID: id.GID, Home: id.Home, Shell: id.Shell, Status: "active", Managed: false, Source: "nginx document-root owner"})
		seen[name] = true
	}
	sort.Slice(accounts, func(i, j int) bool { return accounts[i].Username < accounts[j].Username })
	inv.Diagnostics["hosting_accounts_discovered"] = len(accounts)
	return accounts
}

func (a *Adapter) discoverPHPVersions(ctx context.Context, inv *HostInventory) []LivePHPVersion {
	dirs, _ := filepath.Glob(filepath.Join(a.cfg.PHPFPMPoolDir, "*"))
	out := []LivePHPVersion{}
	for _, d := range dirs {
		version := filepath.Base(d)
		if !regexp.MustCompile(`^[0-9]+\.[0-9]+$`).MatchString(version) {
			continue
		}
		poolDir := filepath.Join(d, "fpm", "pool.d")
		if st, err := os.Stat(poolDir); err != nil || !st.IsDir() {
			continue
		}
		pools, _ := filepath.Glob(filepath.Join(poolDir, "*.conf"))
		service := "php" + version + "-fpm"
		status := "unknown"
		if _, ok := commandExists("systemctl"); ok {
			if outText, err := a.run(ctx, "systemctl", "is-active", service); err == nil {
				status = strings.TrimSpace(outText)
			} else {
				status = "inactive"
			}
		}
		out = append(out, LivePHPVersion{Version: version, Service: service, Status: status, Pools: len(pools)})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Version < out[j].Version })
	return out
}

func inferOwner(name string, accounts []LiveAccount) string {
	for _, a := range accounts {
		if name == a.Username || strings.HasPrefix(name, a.Username+"_") {
			return a.Username
		}
	}
	return ""
}

func (a *Adapter) discoverDatabases(ctx context.Context, accounts []LiveAccount, inv *HostInventory) []LiveDatabase {
	out := []LiveDatabase{}
	client := ""
	engine := ""
	if _, ok := commandExists("mariadb"); ok {
		client = "mariadb"
	} else if _, ok := commandExists("mysql"); ok {
		client = "mysql"
	}
	if client != "" {
		if ver, err := a.run(ctx, client, "--protocol=socket", "--batch", "--skip-column-names", "-e", "SELECT CONCAT(@@version,' ',@@version_comment)"); err == nil {
			if strings.Contains(strings.ToLower(ver), "mariadb") {
				engine = "mariadb"
			} else {
				engine = "mysql"
			}
		} else {
			inv.Warnings = append(inv.Warnings, "mysql-family detection: "+err.Error())
		}
	}
	if client != "" && engine != "" {
		q := "SELECT SCHEMA_NAME FROM INFORMATION_SCHEMA.SCHEMATA WHERE SCHEMA_NAME NOT IN ('information_schema','mysql','performance_schema','sys') ORDER BY SCHEMA_NAME"
		if text, err := a.run(ctx, client, "--protocol=socket", "--batch", "--skip-column-names", "-e", q); err == nil {
			for _, line := range strings.Split(text, "\n") {
				name := strings.TrimSpace(line)
				if name != "" {
					out = append(out, LiveDatabase{Name: name, Engine: engine, Owner: inferOwner(name, accounts), Source: engine + " system catalog"})
				}
			}
		} else {
			inv.Warnings = append(inv.Warnings, engine+" inventory: "+err.Error())
		}
	}
	if _, ok := commandExists("psql"); ok {
		if _, ok2 := commandExists("runuser"); ok2 {
			q := "SELECT datname FROM pg_database WHERE datistemplate = false AND datname <> 'postgres' ORDER BY datname"
			if text, err := a.run(ctx, "runuser", "-u", "postgres", "--", "psql", "--no-psqlrc", "-Atqc", q); err == nil {
				for _, line := range strings.Split(text, "\n") {
					name := strings.TrimSpace(line)
					if name != "" {
						out = append(out, LiveDatabase{Name: name, Engine: "postgresql", Owner: inferOwner(name, accounts), Source: "postgresql system catalog"})
					}
				}
			} else {
				inv.Warnings = append(inv.Warnings, "postgresql inventory: "+err.Error())
			}
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Engine == out[j].Engine {
			return out[i].Name < out[j].Name
		}
		return out[i].Engine < out[j].Engine
	})
	return out
}

var (
	bindZoneBlockRE = regexp.MustCompile(`(?ms)\bzone\s+"([^"]+)"\s*\{(.*?)\};`)
	bindZoneFileRE  = regexp.MustCompile(`(?m)\bfile\s+"([^"]+)"\s*;`)
	bindDirectoryRE = regexp.MustCompile(`(?m)\bdirectory\s+"([^"]+)"\s*;`)
)

func dnsInventoryDomain(v string) string {
	v = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(v)), ".")
	if !validDomain(v) || strings.HasSuffix(v, ".in-addr.arpa") || strings.HasSuffix(v, ".ip6.arpa") {
		return ""
	}
	return v
}

// effectiveBINDZones parses `named-checkconf -p`, which is the effective BIND
// configuration after includes have been expanded. This is intentionally the
// discovery source for legacy/imported zones: a zone does not have to live in
// Privora's private zone directory to be visible in DNS Zone Manager.
func effectiveBINDZones(configText, managedZoneDir string) []LiveDNSZone {
	baseDir := ""
	if m := bindDirectoryRE.FindStringSubmatch(configText); len(m) > 1 {
		baseDir = strings.TrimSpace(m[1])
	}
	managedClean := filepath.Clean(managedZoneDir)
	seen := map[string]bool{}
	out := []LiveDNSZone{}
	for _, m := range bindZoneBlockRE.FindAllStringSubmatch(configText, -1) {
		if len(m) < 3 {
			continue
		}
		domain := dnsInventoryDomain(m[1])
		if domain == "" || seen[domain] {
			continue
		}
		fm := bindZoneFileRE.FindStringSubmatch(m[2])
		if len(fm) < 2 {
			continue
		}
		zonePath := strings.TrimSpace(fm[1])
		if zonePath == "" {
			continue
		}
		if !filepath.IsAbs(zonePath) && baseDir != "" {
			zonePath = filepath.Join(baseDir, zonePath)
		}
		zonePath = filepath.Clean(zonePath)
		managed := managedZoneDir != "" && (zonePath == filepath.Join(managedClean, domain+".zone") || strings.HasPrefix(zonePath, managedClean+string(os.PathSeparator)))
		source := "bind effective config"
		if managed {
			source = "bind privora zone"
		}
		seen[domain] = true
		out = append(out, LiveDNSZone{Domain: domain, ZoneFile: zonePath, Managed: managed, Source: source})
	}
	return out
}

// DiscoverDNSInventory performs the narrow host discovery needed by DNS Zone
// Manager. It intentionally avoids database, PHP, mail and certificate probes so
// an unrelated subsystem cannot make authoritative DNS inventory disappear.
func (a *Adapter) DiscoverDNSInventory(ctx context.Context) HostInventory {
	inv := HostInventory{CollectedAt: time.Now().UTC(), Accounts: []LiveAccount{}, Sites: []LiveSite{}, DNSZones: []LiveDNSZone{}, Warnings: []string{}, Diagnostics: map[string]any{}}
	inv.Environment = a.discoverHostEnvironment()
	inv.Accounts = a.discoverAccounts(&inv)
	inv.Sites = a.discoverNginxSites(ctx, inv.Accounts, &inv)
	inv.Accounts = a.enrichAccountsFromSites(inv.Accounts, inv.Sites, &inv)
	inv.DNSZones = a.discoverDNSZones(ctx, &inv)
	inv.Diagnostics["dns_inventory_scope"] = "dns-only"
	return inv
}

func (a *Adapter) discoverDNSZones(ctx context.Context, inv *HostInventory) []LiveDNSZone {
	zoneDir := a.cfg.DNSZoneDir
	if zoneDir == "" {
		zoneDir = "/etc/bind/privora-zones"
	}
	byDomain := map[string]LiveDNSZone{}
	files, _ := filepath.Glob(filepath.Join(zoneDir, "*.zone"))
	for _, p := range files {
		domain := dnsInventoryDomain(strings.TrimSuffix(filepath.Base(p), ".zone"))
		if domain != "" {
			byDomain[domain] = LiveDNSZone{Domain: domain, ZoneFile: p, Managed: true, Source: "bind privora zone"}
		}
	}

	// Discover every zone BIND is actually configured to load, including zones
	// created before Privora and zones stored in distro/provider-specific paths.
	if _, ok := commandExists("named-checkconf"); ok {
		if dump, err := a.run(ctx, "named-checkconf", "-p"); err == nil {
			for _, z := range effectiveBINDZones(dump, zoneDir) {
				if cur, exists := byDomain[z.Domain]; exists && cur.Managed {
					continue
				}
				byDomain[z.Domain] = z
			}
			if inv.Diagnostics == nil {
				inv.Diagnostics = map[string]any{}
			}
			inv.Diagnostics["bind_effective_config"] = true
		} else {
			inv.Warnings = append(inv.Warnings, "bind inventory: named-checkconf -p failed: "+err.Error())
		}
	}

	// Last-resort loaded-zone discovery: if effective config parsing is degraded
	// (for example because a legacy include is malformed), BIND may still have a
	// root zone loaded from the last valid configuration. Ask rndc for hosted root
	// domains so DNS Zone Manager never calls a genuinely loaded zone "not configured".
	// Child hostnames are intentionally excluded because they belong to their
	// longest hosted parent zone rather than owning an authoritative zone.
	knownSites := map[string]bool{}
	for _, site := range inv.Sites {
		d := dnsInventoryDomain(site.Domain)
		if d != "" {
			knownSites[d] = true
		}
	}
	for domain := range knownSites {
		if _, exists := byDomain[domain]; exists {
			continue
		}
		isChild := false
		for parent := range knownSites {
			if parent != domain && strings.HasSuffix(domain, "."+parent) {
				isChild = true
				break
			}
		}
		if !isChild {
			for parent := range byDomain {
				if parent != domain && strings.HasSuffix(domain, "."+parent) {
					isChild = true
					break
				}
			}
		}
		if isChild {
			continue
		}
		if loaded, source := a.rndcZoneStatus(ctx, domain); loaded {
			byDomain[domain] = LiveDNSZone{Domain: domain, Managed: false, Source: "bind loaded zone (" + source + ")"}
			if inv.Diagnostics == nil {
				inv.Diagnostics = map[string]any{}
			}
			inv.Diagnostics["bind_rndc_fallback"] = true
		}
	}

	out := make([]LiveDNSZone, 0, len(byDomain))
	for _, z := range byDomain {
		out = append(out, z)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Domain < out[j].Domain })
	if inv.Diagnostics == nil {
		inv.Diagnostics = map[string]any{}
	}
	inv.Diagnostics["dns_zones_discovered"] = len(out)
	return out
}

func (a *Adapter) discoverMailboxes(inv *HostInventory) []LiveMailbox {
	stateDir := a.cfg.MailStateDir
	if stateDir == "" {
		stateDir = "/etc/privora-mail"
	}
	path := filepath.Join(stateDir, "virtual_mailboxes")
	f, err := os.Open(path)
	if err != nil {
		if !os.IsNotExist(err) {
			inv.Warnings = append(inv.Warnings, "mail inventory: "+err.Error())
		}
		return nil
	}
	defer f.Close()
	out := []LiveMailbox{}
	s := bufio.NewScanner(f)
	for s.Scan() {
		fields := strings.Fields(s.Text())
		if len(fields) < 1 {
			continue
		}
		addr := strings.ToLower(fields[0])
		parts := strings.Split(addr, "@")
		if len(parts) != 2 || !validDomain(parts[1]) {
			continue
		}
		maildir := ""
		if len(fields) > 1 {
			maildir = fields[1]
		}
		out = append(out, LiveMailbox{Address: addr, Domain: parts[1], Maildir: maildir, Source: "postfix virtual mailbox map"})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Address < out[j].Address })
	return out
}

var nginxSSLCertRE = regexp.MustCompile(`(?m)^\s*ssl_certificate\s+([^;]+);`)

func (a *Adapter) discoverCertificates(sites []LiveSite, inv *HostInventory) []LiveCertificate {
	out := []LiveCertificate{}
	seen := map[string]bool{}
	for _, site := range sites {
		if site.SSL == "off" || seen[site.Domain] || site.NginxConfig == "" {
			continue
		}
		b, err := os.ReadFile(site.NginxConfig)
		if err != nil {
			continue
		}
		m := nginxSSLCertRE.FindStringSubmatch(string(b))
		if len(m) < 2 {
			continue
		}
		certPath := strings.Trim(strings.TrimSpace(m[1]), `"'`)
		certBytes, err := os.ReadFile(certPath)
		if err != nil {
			inv.Warnings = append(inv.Warnings, "certificate "+site.Domain+": "+err.Error())
			continue
		}
		block, _ := pem.Decode(certBytes)
		if block == nil {
			inv.Warnings = append(inv.Warnings, "certificate "+site.Domain+": PEM decode failed")
			continue
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			inv.Warnings = append(inv.Warnings, "certificate "+site.Domain+": "+err.Error())
			continue
		}
		provider := "Imported"
		auto := false
		if strings.Contains(filepath.Clean(certPath), filepath.Clean("/etc/letsencrypt/")) {
			provider = "Let's Encrypt"
			auto = true
		}
		status := "valid"
		if time.Now().After(cert.NotAfter) {
			status = "expired"
		}
		out = append(out, LiveCertificate{Domain: site.Domain, Provider: provider, Status: status, ExpiresAt: cert.NotAfter.UTC(), AutoRenew: auto, CertPath: certPath, Source: "nginx certificate"})
		seen[site.Domain] = true
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Domain < out[j].Domain })
	return out
}

func (inv HostInventory) Summary() map[string]int {
	return map[string]int{"accounts": len(inv.Accounts), "sites": len(inv.Sites), "php_versions": len(inv.PHPVersions), "databases": len(inv.Databases), "dns_zones": len(inv.DNSZones), "mailboxes": len(inv.Mailboxes), "certificates": len(inv.Certificates), "warnings": len(inv.Warnings)}
}

func (inv HostInventory) String() string {
	return fmt.Sprintf("accounts=%d sites=%d php=%d databases=%d dns=%d mailboxes=%d", len(inv.Accounts), len(inv.Sites), len(inv.PHPVersions), len(inv.Databases), len(inv.DNSZones), len(inv.Mailboxes))
}
