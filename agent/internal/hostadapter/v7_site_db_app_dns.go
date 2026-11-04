package hostadapter

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
)

type SitePolicyInput struct {
	ForceHTTPS        bool
	HSTS              bool
	HSTSMaxAge        int
	RedirectTarget    string
	DirectoryIndex    string
	HotlinkProtection bool
}

func stripPrivoraPolicy(text string) string {
	re := regexp.MustCompile(`(?ms)\n?\s*# PRIVORA-SITE-POLICY-BEGIN.*?# PRIVORA-SITE-POLICY-END\s*\n?`)
	return re.ReplaceAllString(text, "\n")
}
func buildPolicyLines(p SitePolicyInput, tls bool) string {
	var b strings.Builder
	b.WriteString("    # PRIVORA-SITE-POLICY-BEGIN\n")
	if p.RedirectTarget != "" {
		b.WriteString("    return 302 " + p.RedirectTarget + "$request_uri;\n")
	} else if p.ForceHTTPS && !tls {
		b.WriteString("    return 301 https://$host$request_uri;\n")
	}
	if p.HSTS && tls {
		age := p.HSTSMaxAge
		if age <= 0 {
			age = 15552000
		}
		fmt.Fprintf(&b, "    add_header Strict-Transport-Security \"max-age=%d; includeSubDomains\" always;\n", age)
	}
	if p.DirectoryIndex != "" {
		b.WriteString("    index " + p.DirectoryIndex + ";\n")
	}
	if p.HotlinkProtection {
		b.WriteString("    location ~* \\.(?:jpg|jpeg|png|gif|webp|svg)$ { valid_referers none blocked server_names; if ($invalid_referer) { return 403; } try_files $uri =404; }\n")
	}
	b.WriteString("    # PRIVORA-SITE-POLICY-END\n")
	return b.String()
}
func injectPolicy(text string, p SitePolicyInput) (string, error) {
	text = stripPrivoraPolicy(text)
	lines := strings.Split(text, "\n")
	out := []string{}
	block := []string{}
	depth := 0
	inServer := false
	flush := func() {
		joined := strings.Join(block, "\n")
		tls := strings.Contains(joined, "listen 443") || strings.Contains(joined, "ssl_certificate")
		if len(block) > 0 {
			block = append(block[:1], append([]string{strings.TrimSuffix(buildPolicyLines(p, tls), "\n")}, block[1:]...)...)
		}
		out = append(out, block...)
		block = nil
		inServer = false
	}
	for _, line := range lines {
		trim := strings.TrimSpace(line)
		if !inServer && strings.HasPrefix(trim, "server") && strings.Contains(trim, "{") {
			inServer = true
			block = []string{line}
			depth = strings.Count(line, "{") - strings.Count(line, "}")
			if depth <= 0 {
				flush()
			}
			continue
		}
		if inServer {
			block = append(block, line)
			depth += strings.Count(line, "{") - strings.Count(line, "}")
			if depth <= 0 {
				flush()
			}
			continue
		}
		out = append(out, line)
	}
	if inServer {
		flush()
	}
	result := strings.Join(out, "\n")
	if !strings.Contains(result, "PRIVORA-SITE-POLICY-BEGIN") {
		return "", errors.New("no Nginx server block found")
	}
	return result, nil
}
func (a *Adapter) ApplySitePolicy(ctx context.Context, domain string, p SitePolicyInput) error {
	if !a.cfg.AllowMutations {
		return errors.New("host mutations disabled")
	}
	if err := a.requireCertified("nginx"); err != nil {
		return err
	}
	if !validDomain(domain) {
		return errors.New("invalid domain")
	}
	path := filepath.Join(a.cfg.NginxSitesAvailable, "privora-"+strings.ToLower(domain)+".conf")
	old, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	next, err := injectPolicy(string(old), p)
	if err != nil {
		return err
	}
	if err := AtomicWrite(path, []byte(next), 0644); err != nil {
		return err
	}
	if _, err := a.run(ctx, "nginx", "-t"); err != nil {
		_ = AtomicWrite(path, old, 0644)
		return err
	}
	if _, err := a.run(ctx, "systemctl", "reload", "nginx"); err != nil {
		_ = AtomicWrite(path, old, 0644)
		_, _ = a.run(context.Background(), "systemctl", "reload", "nginx")
		return err
	}
	return nil
}

type DatabaseActivityRow struct {
	ID       string `json:"id"`
	User     string `json:"user"`
	Database string `json:"database"`
	Host     string `json:"host"`
	Command  string `json:"command"`
	Seconds  int    `json:"seconds"`
	State    string `json:"state"`
	Query    string `json:"query"`
}

func (a *Adapter) DatabaseActivity(ctx context.Context, engine string) ([]DatabaseActivityRow, error) {
	if err := a.requireCertified(engine); err != nil {
		return nil, err
	}
	rows := []DatabaseActivityRow{}
	switch engine {
	case "mysql", "mariadb":
		out, err := a.runInput(ctx, "SHOW FULL PROCESSLIST;\n", engine, "--protocol=socket", "--batch", "--raw")
		if err != nil {
			return nil, err
		}
		for i, l := range strings.Split(strings.TrimSpace(out), "\n") {
			if i == 0 {
				continue
			}
			f := strings.Split(l, "\t")
			if len(f) < 8 {
				continue
			}
			sec, _ := strconv.Atoi(f[5])
			rows = append(rows, DatabaseActivityRow{ID: f[0], User: f[1], Host: f[2], Database: f[3], Command: f[4], Seconds: sec, State: f[6], Query: f[7]})
		}
	case "postgresql":
		sql := "SELECT pid,usename,COALESCE(datname,''),COALESCE(client_addr::text,''),state,EXTRACT(EPOCH FROM (now()-query_start))::int,COALESCE(query,'') FROM pg_stat_activity WHERE pid<>pg_backend_pid();\n"
		out, err := a.runInput(ctx, sql, "runuser", "-u", "postgres", "--", "psql", "--no-psqlrc", "--tuples-only", "--no-align", "--field-separator=\t", "--set=ON_ERROR_STOP=1")
		if err != nil {
			return nil, err
		}
		for _, l := range strings.Split(strings.TrimSpace(out), "\n") {
			f := strings.Split(l, "\t")
			if len(f) < 7 {
				continue
			}
			sec, _ := strconv.Atoi(f[5])
			rows = append(rows, DatabaseActivityRow{ID: f[0], User: f[1], Database: f[2], Host: f[3], Command: f[4], Seconds: sec, State: f[4], Query: f[6]})
		}
	default:
		return nil, errors.New("unsupported database engine")
	}
	return rows, nil
}
func (a *Adapter) KillDatabaseSession(ctx context.Context, engine, id string) error {
	if !a.cfg.AllowMutations {
		return errors.New("host mutations disabled")
	}
	if err := a.requireCertified(engine); err != nil {
		return err
	}
	if !regexp.MustCompile(`^[0-9]{1,12}$`).MatchString(id) {
		return errors.New("invalid session id")
	}
	switch engine {
	case "mysql", "mariadb":
		_, err := a.runInput(ctx, "KILL "+id+";\n", engine, "--protocol=socket", "--batch")
		return err
	case "postgresql":
		_, err := a.runInput(ctx, "SELECT pg_terminate_backend("+id+");\n", "runuser", "-u", "postgres", "--", "psql", "--no-psqlrc", "--set=ON_ERROR_STOP=1")
		return err
	}
	return errors.New("unsupported database engine")
}

type AppDiscovery struct {
	Domain  string   `json:"domain"`
	Owner   string   `json:"owner"`
	Root    string   `json:"root"`
	Kind    string   `json:"kind"`
	Version string   `json:"version,omitempty"`
	Tools   []string `json:"tools"`
	Status  string   `json:"status"`
}

func (a *Adapter) runAsUserV7(ctx context.Context, user, cmd string, args ...string) (string, error) {
	all := append([]string{"-u", user, "--", cmd}, args...)
	return a.run(ctx, "runuser", all...)
}
func (a *Adapter) DiscoverApplication(ctx context.Context, domain, owner, root string) (AppDiscovery, error) {
	if !validDomain(domain) || !validUser(owner) {
		return AppDiscovery{}, errors.New("invalid application target")
	}
	r := filepath.Clean(root)
	base := filepath.Clean(filepath.Join(a.cfg.AccountHomeBase, owner))
	if !filepath.IsAbs(r) || !strings.HasPrefix(r, base+string(os.PathSeparator)) {
		return AppDiscovery{}, errors.New("application root outside account")
	}
	v := AppDiscovery{Domain: domain, Owner: owner, Root: r, Kind: "static", Status: "detected", Tools: []string{"status"}}
	if _, err := os.Stat(filepath.Join(r, "wp-config.php")); err == nil {
		v.Kind = "wordpress"
		v.Tools = []string{"status", "core-version", "plugin-list", "checksum-verify", "cache-flush", "core-update", "plugin-update-all", "theme-update-all", "maintenance-on", "maintenance-off"}
		if _, ok := commandExists("wp"); ok {
			if out, err := a.runAsUserV7(ctx, owner, "wp", "--path="+r, "core", "version"); err == nil {
				v.Version = strings.TrimSpace(out)
			}
		}
	} else if _, err := os.Stat(filepath.Join(r, "artisan")); err == nil {
		v.Kind = "laravel"
		v.Tools = []string{"status", "migrate-status", "cache-clear", "config-clear", "route-clear", "view-clear", "optimize", "optimize-clear", "queue-restart", "storage-link", "maintenance-on", "maintenance-off", "migrate"}
	} else if _, err := os.Stat(filepath.Join(r, "package.json")); err == nil {
		v.Kind = "node"
	} else if _, err := os.Stat(filepath.Join(r, "requirements.txt")); err == nil {
		v.Kind = "python"
	}
	return v, nil
}
func (a *Adapter) RunApplicationAction(ctx context.Context, app AppDiscovery, action string) (string, error) {
	readOnly := map[string]bool{"status": true, "core-version": true, "plugin-list": true, "checksum-verify": true, "migrate-status": true}
	if !a.cfg.AllowMutations && !readOnly[action] {
		return "", errors.New("host mutations disabled")
	}
	switch app.Kind {
	case "wordpress":
		if _, ok := commandExists("wp"); !ok {
			return "", errors.New("wp-cli not installed")
		}
		args := []string{"--path=" + app.Root}
		switch action {
		case "status", "core-version":
			args = append(args, "core", "version")
		case "plugin-list":
			args = append(args, "plugin", "list", "--format=json")
		case "checksum-verify":
			args = append(args, "core", "verify-checksums")
		case "cache-flush":
			args = append(args, "cache", "flush")
		case "core-update":
			args = append(args, "core", "update")
		case "plugin-update-all":
			args = append(args, "plugin", "update", "--all")
		case "theme-update-all":
			args = append(args, "theme", "update", "--all")
		case "maintenance-on":
			args = append(args, "maintenance-mode", "activate")
		case "maintenance-off":
			args = append(args, "maintenance-mode", "deactivate")
		default:
			return "", errors.New("unsupported WordPress action")
		}
		return a.runAsUserV7(ctx, app.Owner, "wp", args...)
	case "laravel":
		php := "php"
		if _, ok := commandExists("php8.4"); ok {
			php = "php8.4"
		}
		artisan := filepath.Join(app.Root, "artisan")
		var args []string
		switch action {
		case "status":
			args = []string{artisan, "about", "--only=environment"}
		case "cache-clear":
			args = []string{artisan, "cache:clear"}
		case "config-clear":
			args = []string{artisan, "config:clear"}
		case "route-clear":
			args = []string{artisan, "route:clear"}
		case "view-clear":
			args = []string{artisan, "view:clear"}
		case "migrate-status":
			args = []string{artisan, "migrate:status", "--no-interaction"}
		case "optimize":
			args = []string{artisan, "optimize"}
		case "optimize-clear":
			args = []string{artisan, "optimize:clear"}
		case "queue-restart":
			args = []string{artisan, "queue:restart"}
		case "storage-link":
			args = []string{artisan, "storage:link"}
		case "maintenance-on":
			args = []string{artisan, "down", "--retry=60"}
		case "maintenance-off":
			args = []string{artisan, "up"}
		case "migrate":
			args = []string{artisan, "migrate", "--force", "--no-interaction"}
		default:
			return "", errors.New("unsupported Laravel action")
		}
		return a.runAsUserV7(ctx, app.Owner, php, args...)
	default:
		if action == "status" {
			return app.Kind + " application detected at " + app.Root, nil
		}
		return "", errors.New("no certified mutation for this application type")
	}
}

type DNSSECStatus struct {
	Domain        string   `json:"domain"`
	Enabled       bool     `json:"enabled"`
	InlineSigning bool     `json:"inline_signing"`
	DS            []string `json:"ds_records"`
	Detail        string   `json:"detail"`
}

func (a *Adapter) DNSSECStatus(ctx context.Context, domain string) (DNSSECStatus, error) {
	if err := a.requireCertified("authoritative-dns"); err != nil {
		return DNSSECStatus{}, err
	}
	if !validDomain(domain) {
		return DNSSECStatus{}, errors.New("invalid domain")
	}
	b, err := os.ReadFile(a.cfg.DNSIndexPath)
	if err != nil {
		return DNSSECStatus{}, err
	}
	low := strings.ToLower(string(b))
	needle := `zone "` + strings.ToLower(domain) + `"`
	i := strings.Index(low, needle)
	if i < 0 {
		return DNSSECStatus{}, errors.New("zone not found")
	}
	end := strings.Index(low[i:], "};")
	if end < 0 {
		return DNSSECStatus{}, errors.New("invalid zone stanza")
	}
	block := low[i : i+end+2]
	st := DNSSECStatus{Domain: domain, Enabled: strings.Contains(block, "dnssec-policy"), InlineSigning: strings.Contains(block, "inline-signing yes"), Detail: "BIND authoritative zone"}
	if _, ok := commandExists("dnssec-dsfromkey"); ok {
		for _, pat := range []string{filepath.Join("/var/cache/bind", "K"+domain+".+*.key"), filepath.Join("/etc/bind/keys", "K"+domain+".+*.key")} {
			files, _ := filepath.Glob(pat)
			for _, f := range files {
				out, err := a.run(ctx, "dnssec-dsfromkey", "-f", f, domain)
				if err == nil {
					for _, line := range strings.Split(strings.TrimSpace(out), "\n") {
						if strings.Contains(line, " IN DS ") {
							st.DS = append(st.DS, strings.TrimSpace(line))
						}
					}
				}
			}
		}
	}
	sort.Strings(st.DS)
	return st, nil
}
func (a *Adapter) SetDNSSEC(ctx context.Context, domain string, enabled bool) (DNSSECStatus, error) {
	if !a.cfg.AllowMutations {
		return DNSSECStatus{}, errors.New("host mutations disabled")
	}
	if err := a.requireCertified("authoritative-dns"); err != nil {
		return DNSSECStatus{}, err
	}
	if !validDomain(domain) {
		return DNSSECStatus{}, errors.New("invalid domain")
	}
	path := a.cfg.DNSIndexPath
	old, err := os.ReadFile(path)
	if err != nil {
		return DNSSECStatus{}, err
	}
	text := string(old)
	re := regexp.MustCompile(`(?s)zone\s+"` + regexp.QuoteMeta(strings.ToLower(domain)) + `"\s*\{.*?\};`)
	loc := re.FindStringIndex(strings.ToLower(text))
	if loc == nil {
		return DNSSECStatus{}, errors.New("zone not found")
	}
	block := text[loc[0]:loc[1]]
	block = regexp.MustCompile(`(?mi)^\s*dnssec-policy\s+[^;]+;\s*$`).ReplaceAllString(block, "")
	block = regexp.MustCompile(`(?mi)^\s*inline-signing\s+yes;\s*$`).ReplaceAllString(block, "")
	if enabled {
		block = strings.Replace(block, "{", "{ dnssec-policy default; inline-signing yes;", 1)
	}
	next := text[:loc[0]] + block + text[loc[1]:]
	if err := AtomicWrite(path, []byte(next), 0644); err != nil {
		return DNSSECStatus{}, err
	}
	if _, err := a.run(ctx, "named-checkconf"); err != nil {
		_ = AtomicWrite(path, old, 0644)
		return DNSSECStatus{}, err
	}
	if _, ok := commandExists("rndc"); ok {
		if _, err := a.run(ctx, "rndc", "reconfig"); err != nil {
			_ = AtomicWrite(path, old, 0644)
			_, _ = a.run(context.Background(), "rndc", "reconfig")
			return DNSSECStatus{}, err
		}
	}
	time.Sleep(100 * time.Millisecond)
	return a.DNSSECStatus(ctx, domain)
}
