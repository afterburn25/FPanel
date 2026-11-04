package hostadapter

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/mail"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

type ACMEProvisionResult struct {
	Domain    string    `json:"domain"`
	Fullchain string    `json:"fullchain"`
	Privkey   string    `json:"privkey"`
	ExpiresAt time.Time `json:"expires_at"`
	Provider  string    `json:"provider"`
}

func (a *Adapter) IssueLetsEncryptWebroot(ctx context.Context, domain, documentRoot, email string) (ACMEProvisionResult, error) {
	if !a.cfg.AllowMutations {
		return ACMEProvisionResult{}, errors.New("host mutations disabled")
	}
	if err := a.requireCertified("acme"); err != nil {
		return ACMEProvisionResult{}, err
	}
	domain = strings.ToLower(strings.TrimSpace(domain))
	if !validDomain(domain) {
		return ACMEProvisionResult{}, errors.New("invalid certificate domain")
	}
	root, err := filepath.Abs(documentRoot)
	if err != nil {
		return ACMEProvisionResult{}, err
	}
	info, err := os.Stat(root)
	if err != nil || !info.IsDir() {
		return ACMEProvisionResult{}, errors.New("certificate webroot must exist and be a directory")
	}
	if _, err := mail.ParseAddress(email); err != nil || !strings.Contains(email, "@") {
		return ACMEProvisionResult{}, errors.New("invalid ACME contact email")
	}
	if _, ok := commandExists("certbot"); !ok {
		return ACMEProvisionResult{}, errors.New("certbot not installed")
	}
	if _, ok := commandExists("openssl"); !ok {
		return ACMEProvisionResult{}, errors.New("openssl not installed")
	}
	if pre := a.PreflightLetsEncryptHTTP01(ctx, domain, root); !pre.Ready {
		return ACMEProvisionResult{}, fmt.Errorf("ACME HTTP-01 preflight blocked: %s", pre.Detail)
	}
	configDir := a.cfg.ACMEConfigDir
	if configDir == "" {
		configDir = "/etc/letsencrypt"
	}
	workDir := filepath.Join(filepath.Dir(configDir), "privora-acme-work")
	logsDir := filepath.Join(filepath.Dir(configDir), "privora-acme-logs")
	for _, p := range []string{configDir, workDir, logsDir} {
		if err := os.MkdirAll(p, 0700); err != nil {
			return ACMEProvisionResult{}, err
		}
	}
	if _, err := a.run(ctx, "certbot", "certonly", "--webroot", "-w", root, "-d", domain,
		"--cert-name", domain,
		"--non-interactive", "--agree-tos", "--email", email,
		"--config-dir", configDir, "--work-dir", workDir, "--logs-dir", logsDir,
		"--keep-until-expiring"); err != nil {
		detail := acmeFailureSummary(filepath.Join(logsDir, "letsencrypt.log"))
		if detail != "" {
			return ACMEProvisionResult{}, fmt.Errorf("ACME issuance failed: %w; Let's Encrypt detail: %s", err, detail)
		}
		return ACMEProvisionResult{}, fmt.Errorf("ACME issuance failed: %w", err)
	}
	fullchain, privkey, err := a.resolveLetsEncryptLineage(ctx, configDir, domain)
	if err != nil {
		return ACMEProvisionResult{}, err
	}
	out, err := a.run(ctx, "openssl", "x509", "-in", fullchain, "-noout", "-enddate")
	if err != nil {
		return ACMEProvisionResult{}, fmt.Errorf("certificate expiry verification failed: %w", err)
	}
	expires, err := parseOpenSSLEndDate(strings.TrimSpace(out))
	if err != nil {
		return ACMEProvisionResult{}, err
	}
	if !expires.After(time.Now().UTC().Add(24 * time.Hour)) {
		return ACMEProvisionResult{}, errors.New("issued certificate expires too soon")
	}
	return ACMEProvisionResult{Domain: domain, Fullchain: fullchain, Privkey: privkey, ExpiresAt: expires, Provider: "letsencrypt"}, nil
}

func (a *Adapter) resolveLetsEncryptLineage(ctx context.Context, configDir, domain string) (string, string, error) {
	liveRoot := filepath.Join(configDir, "live")
	exact := filepath.Join(liveRoot, domain)
	fullchain := filepath.Join(exact, "fullchain.pem")
	privkey := filepath.Join(exact, "privkey.pem")
	if regularOrSymlinkExists(fullchain) && regularOrSymlinkExists(privkey) {
		return fullchain, privkey, nil
	}

	entries, err := os.ReadDir(liveRoot)
	if err != nil {
		return "", "", errors.New("ACME client reported success but certificate files are missing")
	}
	type candidate struct {
		fullchain string
		privkey   string
		expires   time.Time
	}
	candidates := []candidate{}
	prefix := domain + "-"
	for _, entry := range entries {
		name := entry.Name()
		if name != domain && !strings.HasPrefix(name, prefix) {
			continue
		}
		dir := filepath.Join(liveRoot, name)
		fc := filepath.Join(dir, "fullchain.pem")
		pk := filepath.Join(dir, "privkey.pem")
		if !regularOrSymlinkExists(fc) || !regularOrSymlinkExists(pk) {
			continue
		}
		if _, err := a.run(ctx, "openssl", "x509", "-in", fc, "-noout", "-checkhost", domain); err != nil {
			continue
		}
		out, err := a.run(ctx, "openssl", "x509", "-in", fc, "-noout", "-enddate")
		if err != nil {
			continue
		}
		expires, err := parseOpenSSLEndDate(strings.TrimSpace(out))
		if err != nil {
			continue
		}
		candidates = append(candidates, candidate{fullchain: fc, privkey: pk, expires: expires})
	}
	if len(candidates) == 0 {
		return "", "", errors.New("ACME client reported success but certificate files are missing")
	}
	sort.Slice(candidates, func(i, j int) bool { return candidates[i].expires.After(candidates[j].expires) })
	return candidates[0].fullchain, candidates[0].privkey, nil
}

func regularOrSymlinkExists(path string) bool {
	st, err := os.Lstat(path)
	if err != nil {
		return false
	}
	return st.Mode().IsRegular() || st.Mode()&os.ModeSymlink != 0
}

func parseOpenSSLEndDate(v string) (time.Time, error) {
	const prefix = "notAfter="
	if !strings.HasPrefix(v, prefix) {
		return time.Time{}, errors.New("unexpected openssl enddate output")
	}
	raw := strings.TrimPrefix(v, prefix)
	t, err := time.Parse("Jan 2 15:04:05 2006 MST", raw)
	if err != nil {
		return time.Time{}, fmt.Errorf("invalid certificate expiry: %w", err)
	}
	return t.UTC(), nil
}

// ACMEPreflightResult is advisory. A site must never be rolled back solely
// because public DNS has not propagated yet.
type ACMEPreflightResult struct {
	Ready  bool     `json:"ready"`
	Status string   `json:"status"`
	IPs    []string `json:"ips,omitempty"`
	Detail string   `json:"detail,omitempty"`
}

func (a *Adapter) PreflightLetsEncryptDomain(ctx context.Context, domain string) ACMEPreflightResult {
	domain = strings.ToLower(strings.TrimSpace(domain))
	if !validDomain(domain) {
		return ACMEPreflightResult{Ready: false, Status: "invalid", Detail: "invalid certificate domain"}
	}
	resolver := net.DefaultResolver
	ctx, cancel := context.WithTimeout(ctx, 4*time.Second)
	defer cancel()
	ips, err := resolver.LookupHost(ctx, domain)
	if err != nil || len(ips) == 0 {
		detail := "DNS A/AAAA record is not publicly resolvable yet"
		if err != nil {
			detail = err.Error()
		}
		return ACMEPreflightResult{Ready: false, Status: "dns-pending", Detail: detail}
	}
	return ACMEPreflightResult{Ready: true, Status: "dns-resolved", IPs: ips}
}

func acmeProbeTransport(base http.RoundTripper) http.RoundTripper {
	if base == nil {
		base = http.DefaultTransport
	}
	transport, ok := base.(*http.Transport)
	if !ok {
		// Test/certification clients may provide a controlled RoundTripper. Preserve
		// it rather than silently replacing the injected transport.
		return base
	}
	cp := transport.Clone()
	cp.Proxy = nil
	if cp.TLSClientConfig == nil {
		cp.TLSClientConfig = &tls.Config{MinVersion: tls.VersionTLS12, InsecureSkipVerify: true}
	} else {
		tlsCfg := cp.TLSClientConfig.Clone()
		if tlsCfg.MinVersion < tls.VersionTLS12 {
			tlsCfg.MinVersion = tls.VersionTLS12
		}
		tlsCfg.InsecureSkipVerify = true
		cp.TLSClientConfig = tlsCfg
	}
	return cp
}

func acmeProbeClient(base *http.Client) *http.Client {
	if base != nil {
		cp := *base
		cp.Transport = acmeProbeTransport(cp.Transport)
		if cp.Timeout <= 0 || cp.Timeout > 10*time.Second {
			cp.Timeout = 8 * time.Second
		}
		return &cp
	}
	return &http.Client{Transport: acmeProbeTransport(nil), Timeout: 8 * time.Second}
}

func acmeProbeRequest(ctx context.Context, client *http.Client, url, host, body string) (int, string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return 0, "", err
	}
	if strings.TrimSpace(host) != "" {
		req.Host = host
	}
	resp, err := client.Do(req)
	if err != nil {
		return 0, "", err
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, 4096))
	if err != nil {
		return resp.StatusCode, "", err
	}
	return resp.StatusCode, strings.TrimSpace(string(data)), nil
}

func acmeTraversalACLTargets(root string) []string {
	clean := filepath.Clean(root)
	var targets []string
	switch {
	case strings.HasPrefix(clean, "/home/"):
		rel := strings.TrimPrefix(clean, "/home/")
		parts := strings.Split(rel, string(os.PathSeparator))
		if len(parts) == 0 || strings.TrimSpace(parts[0]) == "" {
			return nil
		}
		cur := filepath.Join("/home", parts[0])
		targets = append(targets, cur)
		for _, part := range parts[1:] {
			if strings.TrimSpace(part) == "" {
				continue
			}
			cur = filepath.Join(cur, part)
			targets = append(targets, cur)
		}
	case strings.HasPrefix(clean, "/etc/privora-mail/acme/"):
		targets = []string{"/etc/privora-mail", "/etc/privora-mail/acme", clean}
	}
	return targets
}

func (a *Adapter) ensureACMEWebrootTraversal(ctx context.Context, root string) error {
	targets := acmeTraversalACLTargets(root)
	if len(targets) == 0 {
		return nil
	}
	if _, ok := commandExists("setfacl"); !ok {
		return errors.New("setfacl is required for least-privilege Nginx ACME webroot traversal")
	}
	for _, target := range targets {
		info, err := os.Stat(target)
		if err != nil || !info.IsDir() {
			if err == nil {
				err = errors.New("not a directory")
			}
			return fmt.Errorf("ACME traversal path %s unavailable: %w", target, err)
		}
		if _, err := a.run(ctx, "setfacl", "-m", "u:www-data:--x", target); err != nil {
			return fmt.Errorf("grant Nginx execute-only traversal on %s: %w", target, err)
		}
	}
	return nil
}

func (a *Adapter) PreflightLetsEncryptHTTP01(ctx context.Context, domain, documentRoot string) ACMEPreflightResult {
	domain = strings.ToLower(strings.TrimSpace(domain))
	if !validDomain(domain) {
		return ACMEPreflightResult{Ready: false, Status: "http-blocked", Detail: "invalid certificate domain"}
	}
	root, err := filepath.Abs(documentRoot)
	if err != nil {
		return ACMEPreflightResult{Ready: false, Status: "http-blocked", Detail: err.Error()}
	}
	info, err := os.Stat(root)
	if err != nil || !info.IsDir() {
		return ACMEPreflightResult{Ready: false, Status: "http-blocked", Detail: "certificate webroot does not exist"}
	}
	if err := a.ensureACMEWebrootTraversal(ctx, root); err != nil {
		return ACMEPreflightResult{Ready: false, Status: "http-blocked", Detail: "cannot grant Nginx traversal to ACME webroot: " + err.Error()}
	}
	var random [12]byte
	if _, err := rand.Read(random[:]); err != nil {
		return ACMEPreflightResult{Ready: false, Status: "http-blocked", Detail: "could not create ACME preflight token"}
	}
	token := "privora-preflight-" + hex.EncodeToString(random[:])
	wellKnownDir := filepath.Join(root, ".well-known")
	challengeDir := filepath.Join(wellKnownDir, "acme-challenge")
	if err := os.MkdirAll(challengeDir, 0755); err != nil {
		return ACMEPreflightResult{Ready: false, Status: "http-blocked", Detail: "cannot create ACME challenge directory: " + err.Error()}
	}
	// The privileged agent intentionally runs with systemd UMask=0007. mkdir(0755)
	// and WriteFile(0644) are therefore created as 0750/0640 unless we normalize
	// the narrow public ACME path after creation. Nginx (www-data) must be able to
	// traverse .well-known/acme-challenge and read the temporary token.
	for _, dir := range []string{wellKnownDir, challengeDir} {
		if err := os.Chmod(dir, 0755); err != nil {
			return ACMEPreflightResult{Ready: false, Status: "http-blocked", Detail: "cannot normalize ACME challenge directory permissions: " + err.Error()}
		}
	}
	challengePath := filepath.Join(challengeDir, token)
	body := "privora-http01-" + hex.EncodeToString(random[:])
	if err := os.WriteFile(challengePath, []byte(body), 0644); err != nil {
		return ACMEPreflightResult{Ready: false, Status: "http-blocked", Detail: "cannot write ACME challenge file: " + err.Error()}
	}
	if err := os.Chmod(challengePath, 0644); err != nil {
		os.Remove(challengePath)
		return ACMEPreflightResult{Ready: false, Status: "http-blocked", Detail: "cannot normalize ACME challenge file permissions: " + err.Error()}
	}
	defer os.Remove(challengePath)

	client := acmeProbeClient(a.cfg.HTTPClient)
	probeCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	path := "/.well-known/acme-challenge/" + token
	localReady := false
	localDetail := ""
	for _, localURL := range []string{"http://127.0.0.1" + path, "http://[::1]" + path} {
		status, got, probeErr := acmeProbeRequest(probeCtx, client, localURL, domain, body)
		if probeErr == nil && status == http.StatusOK && got == body {
			localReady = true
			break
		}
		if probeErr != nil {
			localDetail = probeErr.Error()
		} else {
			localDetail = fmt.Sprintf("local HTTP challenge returned %d", status)
		}
	}
	status, got, publicErr := acmeProbeRequest(probeCtx, client, "http://"+domain+path, "", body)
	if publicErr == nil && status == http.StatusOK && got == body {
		return ACMEPreflightResult{Ready: true, Status: "http-ready", Detail: "local/public HTTP-01 path reaches intended webroot"}
	}
	if localReady {
		detail := "local HTTP-01 vhost/webroot is ready; public self-probe is advisory and the ACME provider will perform authoritative external validation"
		if publicErr != nil {
			detail += ": " + publicErr.Error()
		} else if status != http.StatusOK {
			detail += fmt.Sprintf(" (self-probe HTTP %d)", status)
		} else if got != body {
			detail += " (self-probe returned unexpected content)"
		}
		return ACMEPreflightResult{Ready: true, Status: "http-local-ready", Detail: detail}
	}
	if publicErr != nil {
		return ACMEPreflightResult{Ready: false, Status: "http-blocked", Detail: "public HTTP challenge request failed: " + publicErr.Error() + "; local vhost proof also failed: " + localDetail}
	}
	if status != http.StatusOK {
		hint := "verify the domain's port-80 vhost and ACME challenge exception"
		if status == http.StatusForbidden {
			hint = "Nginx denied /.well-known/acme-challenge; the ACME exception is missing or overridden"
		} else if status == http.StatusNotFound {
			hint = "the public domain is reaching a different vhost/document root or the ACME route is missing"
		}
		return ACMEPreflightResult{Ready: false, Status: "http-blocked", Detail: fmt.Sprintf("public HTTP challenge returned %d; %s; local vhost proof failed: %s", status, hint, localDetail)}
	}
	return ACMEPreflightResult{Ready: false, Status: "http-blocked", Detail: "public HTTP challenge returned unexpected content and local vhost proof failed"}
}

func acmeFailureSummary(path string) string {
	b, err := os.ReadFile(path)
	if err != nil || len(b) == 0 {
		return ""
	}
	if len(b) > 65536 {
		b = b[len(b)-65536:]
	}
	needles := []string{"detail:", "invalid response", "unauthorized", "timeout during connect", "connection refused", "dns problem", "nxdomain", "no valid ip addresses", "challenge failed"}
	lines := strings.Split(string(b), "\n")
	picked := make([]string, 0, 4)
	for i := len(lines) - 1; i >= 0 && len(picked) < 4; i-- {
		line := strings.TrimSpace(lines[i])
		if line == "" {
			continue
		}
		lower := strings.ToLower(line)
		match := false
		for _, needle := range needles {
			if strings.Contains(lower, needle) {
				match = true
				break
			}
		}
		if !match {
			continue
		}
		if len(line) > 500 {
			line = line[:500] + "…"
		}
		picked = append(picked, line)
	}
	for i, j := 0, len(picked)-1; i < j; i, j = i+1, j-1 {
		picked[i], picked[j] = picked[j], picked[i]
	}
	return strings.Join(picked, " | ")
}

func (a *Adapter) InstallLetsEncryptNginxTLS(ctx context.Context, domain, username, phpVersion, documentRoot string, cert ACMEProvisionResult) error {
	if !a.cfg.AllowMutations {
		return errors.New("host mutations disabled")
	}
	if err := a.requireCertified("nginx"); err != nil {
		return err
	}
	if !validDomain(domain) || !validUser(username) || !phpRE.MatchString(phpVersion) {
		return errors.New("invalid TLS site input")
	}
	if !strings.EqualFold(strings.TrimSpace(cert.Domain), strings.TrimSpace(domain)) {
		return errors.New("certificate domain does not match website")
	}
	cfg, err := RenderNginxSiteTLS(domain, username, phpVersion, documentRoot, cert.Fullchain, cert.Privkey)
	if err != nil {
		return err
	}
	nginxPath := filepath.Join(a.cfg.NginxSitesAvailable, "privora-"+strings.ToLower(domain)+".conf")
	old, had := readIfExists(nginxPath)
	if !had {
		return errors.New("Privora Nginx website configuration not found")
	}
	rollback := func() {
		restoreFile(nginxPath, old, true, 0644)
		_, _ = a.run(context.Background(), "nginx", "-t")
		_, _ = a.run(context.Background(), "systemctl", "reload", "nginx")
	}
	if err := AtomicWrite(nginxPath, []byte(cfg), 0644); err != nil {
		return err
	}
	if _, err := a.run(ctx, "nginx", "-t"); err != nil {
		rollback()
		return fmt.Errorf("Nginx TLS validation failed; rolled back: %w", err)
	}
	if _, err := a.run(ctx, "systemctl", "reload", "nginx"); err != nil {
		rollback()
		return fmt.Errorf("Nginx TLS reload failed; rolled back: %w", err)
	}
	return nil
}
