package hostadapter

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"net"
	"os"
	"os/user"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"
)

type MailDNSRecord struct {
	Type  string `json:"type"`
	Name  string `json:"name"`
	Value string `json:"value"`
	TTL   int    `json:"ttl"`
}
type MailClientService struct {
	ID                     string `json:"id"`
	Protocol               string `json:"protocol"`
	Direction              string `json:"direction"`
	Server                 string `json:"server"`
	Port                   int    `json:"port"`
	Security               string `json:"security"`
	Authentication         string `json:"authentication"`
	AuthenticationRequired bool   `json:"authentication_required"`
	UsernameFormat         string `json:"username_format"`
	Enabled                bool   `json:"enabled"`
	Listening              bool   `json:"listening"`
	Purpose                string `json:"purpose,omitempty"`
}

type MailClientConfiguration struct {
	Domain            string              `json:"domain"`
	MailHost          string              `json:"mail_host"`
	UsernameFormat    string              `json:"username_format"`
	PasswordFormat    string              `json:"password_format"`
	Configured        bool                `json:"configured"`
	TLSReady          bool                `json:"tls_ready"`
	PostfixActive     bool                `json:"postfix_active"`
	DovecotActive     bool                `json:"dovecot_active"`
	RspamdActive      bool                `json:"rspamd_active"`
	DKIMSelector      string              `json:"dkim_selector,omitempty"`
	DKIMRecordName    string              `json:"dkim_record_name,omitempty"`
	Services          []MailClientService `json:"services"`
	ConfigurationFrom []string            `json:"configuration_from"`
	CheckedAt         string              `json:"checked_at"`
}

type MailDomainReadiness struct {
	Domain    string `json:"domain"`
	MailHost  string `json:"mail_host"`
	TLSReady  bool   `json:"tls_ready"`
	DNSReady  bool   `json:"dns_ready"`
	DKIM      bool   `json:"dkim"`
	SPF       bool   `json:"spf"`
	DMARC     bool   `json:"dmarc_ready"`
	Status    string `json:"status"`
	CheckedAt string `json:"checked_at"`
}

type MailDomainProvisionResult struct {
	Domain      string          `json:"domain"`
	MailHost    string          `json:"mail_host"`
	Owner       string          `json:"owner"`
	DMARC       string          `json:"dmarc"`
	TLSReady    bool            `json:"tls_ready"`
	DNSReady    bool            `json:"dns_ready"`
	DKIM        bool            `json:"dkim"`
	SPF         bool            `json:"spf"`
	Status      string          `json:"status"`
	RequiredDNS []MailDNSRecord `json:"required_dns,omitempty"`
	Detail      string          `json:"detail,omitempty"`
}

func (a *Adapter) mailPaths() (state, root, dovecot, rspamd, dkimDir, tlsDir string) {
	state = a.cfg.MailStateDir
	if state == "" {
		state = "/etc/privora-mail"
	}
	root = a.cfg.MailRoot
	if root == "" {
		root = "/var/vmail"
	}
	dovecot = a.cfg.DovecotPrivoraConfig
	if dovecot == "" {
		dovecot = "/etc/dovecot/conf.d/99-privora-mail.conf"
	}
	rspamd = a.cfg.RspamdDKIMConfig
	if rspamd == "" {
		rspamd = "/etc/rspamd/local.d/dkim_signing.conf"
	}
	dkimDir = a.cfg.RspamdDKIMDir
	if dkimDir == "" {
		dkimDir = "/var/lib/rspamd/dkim"
	}
	tlsDir = a.cfg.MailTLSDir
	if tlsDir == "" {
		tlsDir = filepath.Join(state, "tls")
	}
	return
}

func (a *Adapter) EnsureMailFoundation(ctx context.Context) (int, int, error) {
	if !a.cfg.AllowMutations {
		return 0, 0, errors.New("host mutations disabled")
	}
	mailUser := a.cfg.MailUser
	if mailUser == "" {
		mailUser = "vmail"
	}
	u, err := user.Lookup(mailUser)
	if err != nil {
		if _, ok := commandExists("useradd"); !ok {
			return 0, 0, fmt.Errorf("mail storage user %s is missing and useradd is unavailable", mailUser)
		}
		_, err = a.run(ctx, "useradd", "--system", "--home-dir", a.defaultMailRoot(), "--create-home", "--shell", "/usr/sbin/nologin", mailUser)
		if err != nil {
			return 0, 0, fmt.Errorf("create mail storage identity: %w", err)
		}
		u, err = user.Lookup(mailUser)
		if err != nil {
			return 0, 0, fmt.Errorf("resolve created mail storage identity: %w", err)
		}
	}
	uid64, err := strconv.ParseInt(u.Uid, 10, 32)
	if err != nil {
		return 0, 0, err
	}
	gid64, err := strconv.ParseInt(u.Gid, 10, 32)
	if err != nil {
		return 0, 0, err
	}
	state, root, _, _, dkimDir, tlsDir := a.mailPaths()
	for _, p := range []string{state, root, tlsDir} {
		if err := os.MkdirAll(p, 0750); err != nil {
			return 0, 0, err
		}
	}
	if err := os.Chown(root, int(uid64), int(gid64)); err != nil {
		return 0, 0, err
	}
	if err := os.MkdirAll(dkimDir, 0750); err != nil {
		return 0, 0, err
	}
	if ru, err := user.Lookup("_rspamd"); err == nil {
		if ruid, e1 := strconv.Atoi(ru.Uid); e1 == nil {
			if rgid, e2 := strconv.Atoi(ru.Gid); e2 == nil {
				_ = os.Chown(dkimDir, ruid, rgid)
			}
		}
	}
	aliases := filepath.Join(state, "virtual_aliases")
	if _, err := os.Stat(aliases); errors.Is(err, os.ErrNotExist) {
		if err := AtomicWrite(aliases, []byte(""), 0640); err != nil {
			return 0, 0, err
		}
	}
	if err := migrateDovecotUsers(filepath.Join(state, "dovecot_users")); err != nil {
		return 0, 0, err
	}
	if err := a.secureMailAuthState(state); err != nil {
		return 0, 0, err
	}
	return int(uid64), int(gid64), nil
}

func migrateDovecotUsers(path string) error {
	b, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	changed := false
	lines := []string{}
	for _, line := range strings.Split(string(b), "\n") {
		trim := strings.TrimSpace(line)
		if trim == "" {
			continue
		}
		f := strings.Fields(trim)
		if len(f) >= 2 && !strings.Contains(f[0], ":") && strings.Contains(f[0], "@") {
			line = f[0] + ":" + strings.TrimSpace(strings.TrimPrefix(trim, f[0]))
			changed = true
		}
		lines = append(lines, line)
	}
	if !changed {
		return nil
	}
	return AtomicWrite(path, []byte(strings.Join(lines, "\n")+"\n"), 0640)
}
func (a *Adapter) defaultMailRoot() string {
	if a.cfg.MailRoot != "" {
		return a.cfg.MailRoot
	}
	return "/var/vmail"
}

func (a *Adapter) ConfigureMailDomain(ctx context.Context, domain, owner, dmarc string) (MailDomainProvisionResult, error) {
	result := MailDomainProvisionResult{Domain: strings.ToLower(strings.TrimSpace(domain)), Owner: strings.TrimSpace(owner), DMARC: strings.ToLower(strings.TrimSpace(dmarc))}
	if !a.cfg.AllowMutations {
		return result, errors.New("host mutations disabled")
	}
	for _, cap := range []string{"postfix", "dovecot", "rspamd"} {
		if err := a.requireCertified(cap); err != nil {
			return result, err
		}
	}
	if !validDomain(result.Domain) || !validUser(result.Owner) {
		return result, errors.New("invalid mail domain or owner")
	}
	if result.DMARC == "" {
		result.DMARC = "quarantine"
	}
	if result.DMARC != "none" && result.DMARC != "quarantine" && result.DMARC != "reject" {
		return result, errors.New("invalid DMARC policy")
	}
	result.MailHost = "mail." + result.Domain
	for _, cmd := range []string{"postconf", "postmap", "postfix", "doveconf", "systemctl"} {
		if _, ok := commandExists(cmd); !ok {
			return result, fmt.Errorf("%s not installed", cmd)
		}
	}
	uid, gid, err := a.EnsureMailFoundation(ctx)
	if err != nil {
		return result, err
	}
	state, root, dovecotCfg, rspamdCfg, dkimDir, tlsDir := a.mailPaths()
	_ = root

	pub, err := ensureDKIMKey(filepath.Join(dkimDir, result.Domain+".mail.key"))
	if err != nil {
		return result, err
	}
	if ru, e := user.Lookup("_rspamd"); e == nil {
		ruid, _ := strconv.Atoi(ru.Uid)
		rgid, _ := strconv.Atoi(ru.Gid)
		_ = os.Chown(filepath.Join(dkimDir, result.Domain+".mail.key"), ruid, rgid)
	}
	dkimTXT := "v=DKIM1; k=rsa; p=" + pub
	spfTXT := "v=spf1 mx a:" + result.MailHost + " ~all"
	dmarcTXT := "v=DMARC1; p=" + result.DMARC + "; adkim=s; aspf=s"
	v4, v6 := a.PrimaryHostAddresses()
	recs := []DNSRecord{}
	required := []MailDNSRecord{}
	add := func(t, n, v string) {
		required = append(required, MailDNSRecord{Type: t, Name: n, Value: v, TTL: 3600})
		recs = append(recs, DNSRecord{Type: t, Name: n, Value: v, TTL: 3600})
	}
	if v4 != "" {
		add("A", "mail", v4)
	}
	if v6 != "" {
		add("AAAA", "mail", v6)
	}
	add("MX", "@", "10 "+result.MailHost+".")
	add("TXT", "@", spfTXT)
	add("TXT", "mail._domainkey", dkimTXT)
	add("TXT", "_dmarc", dmarcTXT)
	result.RequiredDNS = required
	zonePath := filepath.Join(a.cfg.DNSZoneDir, result.Domain+".zone")
	if _, err := os.Stat(zonePath); err == nil {
		if _, err = a.UpsertBINDRecords(ctx, result.Domain, recs); err != nil {
			return result, fmt.Errorf("configure mail DNS: %w", err)
		}
	}
	result.DNSReady = mailDNSReady(result.MailHost, result.Domain, dkimTXT, spfTXT, dmarcTXT, v4, v6)

	if err := a.ensureMailChallengeVHost(ctx, result.Domain, result.MailHost); err != nil {
		return result, err
	}
	fullchain := filepath.Join(a.cfg.ACMEConfigDir, "live", result.MailHost, "fullchain.pem")
	privkey := filepath.Join(a.cfg.ACMEConfigDir, "live", result.MailHost, "privkey.pem")
	if a.cfg.ACMEConfigDir == "" {
		fullchain = filepath.Join("/etc/letsencrypt/live", result.MailHost, "fullchain.pem")
		privkey = filepath.Join("/etc/letsencrypt/live", result.MailHost, "privkey.pem")
	}
	if !regularOrSymlinkExists(fullchain) || !regularOrSymlinkExists(privkey) {
		acmeRoot := filepath.Join(state, "acme", result.Domain)
		_ = os.MkdirAll(filepath.Join(acmeRoot, ".well-known", "acme-challenge"), 0755)
		if a.certifiedFor("acme") {
			if cert, issueErr := a.IssueLetsEncryptWebroot(ctx, result.MailHost, acmeRoot, "hostmaster@"+result.Domain); issueErr == nil {
				fullchain, privkey = cert.Fullchain, cert.Privkey
			} else {
				result.Detail = "TLS certificate pending: " + issueErr.Error()
			}
		} else {
			result.Detail = "TLS certificate pending: ACME adapter is not certified"
		}
	}
	if regularOrSymlinkExists(fullchain) && regularOrSymlinkExists(privkey) {
		chainPath := filepath.Join(tlsDir, result.MailHost+".pem")
		keyBytes, e1 := os.ReadFile(privkey)
		certBytes, e2 := os.ReadFile(fullchain)
		if e1 != nil || e2 != nil {
			return result, errors.New("read mail TLS certificate material")
		}
		if err := AtomicWrite(chainPath, append(append(keyBytes, '\n'), certBytes...), 0600); err != nil {
			return result, err
		}
		if err := a.writeMailTLSSourcePaths(tlsDir, result.MailHost, fullchain, privkey); err != nil {
			return result, err
		}
		if err := a.renderMailServices(ctx, uid, gid, state, root, dovecotCfg, rspamdCfg, dkimDir, tlsDir); err != nil {
			return result, err
		}
		result.TLSReady = true
	}
	result.DKIM = publicTXTContains("mail._domainkey."+result.Domain, "v=DKIM1")
	result.SPF = publicTXTContains(result.Domain, "v=spf1")
	if result.TLSReady && result.DNSReady && result.DKIM && result.SPF {
		result.Status = "secure-active"
	} else if result.TLSReady {
		result.Status = "tls-ready-dns-auth-pending"
	} else {
		result.Status = "dns-or-tls-pending"
	}
	return result, nil
}

func (a *Adapter) IsManagedMailChallengeHost(mailHost string) bool {
	mailHost = strings.ToLower(strings.TrimSpace(mailHost))
	if !strings.HasPrefix(mailHost, "mail.") || !validDomain(mailHost) {
		return false
	}
	domain := strings.TrimPrefix(mailHost, "mail.")
	if !validDomain(domain) {
		return false
	}
	path := filepath.Join(a.cfg.NginxSitesAvailable, "privora-mail-"+domain+".conf")
	data, err := os.ReadFile(path)
	if err != nil {
		return false
	}
	state, _, _, _, _, _ := a.mailPaths()
	root := filepath.Join(state, "acme", domain)
	text := string(data)
	return strings.Contains(text, "server_name "+mailHost+";") && strings.Contains(text, "root "+root+";")
}

func (a *Adapter) InstallLetsEncryptMailTLS(ctx context.Context, mailHost string, cert ACMEProvisionResult) error {
	if !a.cfg.AllowMutations {
		return errors.New("host mutations disabled")
	}
	for _, cap := range []string{"postfix", "dovecot", "rspamd"} {
		if err := a.requireCertified(cap); err != nil {
			return err
		}
	}
	mailHost = strings.ToLower(strings.TrimSpace(mailHost))
	if !a.IsManagedMailChallengeHost(mailHost) {
		return errors.New("mail TLS target is not a Privora-managed mail challenge host")
	}
	if !strings.EqualFold(strings.TrimSpace(cert.Domain), mailHost) {
		return errors.New("certificate domain does not match mail host")
	}
	if !regularOrSymlinkExists(cert.Fullchain) || !regularOrSymlinkExists(cert.Privkey) {
		return errors.New("mail TLS certificate material is missing")
	}
	uid, gid, err := a.EnsureMailFoundation(ctx)
	if err != nil {
		return err
	}
	state, root, dovecotCfg, rspamdCfg, dkimDir, tlsDir := a.mailPaths()
	keyBytes, e1 := os.ReadFile(cert.Privkey)
	certBytes, e2 := os.ReadFile(cert.Fullchain)
	if e1 != nil || e2 != nil {
		return errors.New("read mail TLS certificate material")
	}
	chainPath := filepath.Join(tlsDir, mailHost+".pem")
	if err := AtomicWrite(chainPath, append(append(keyBytes, '\n'), certBytes...), 0600); err != nil {
		return err
	}
	if err := a.writeMailTLSSourcePaths(tlsDir, mailHost, cert.Fullchain, cert.Privkey); err != nil {
		return err
	}
	if err := a.renderMailServices(ctx, uid, gid, state, root, dovecotCfg, rspamdCfg, dkimDir, tlsDir); err != nil {
		return err
	}
	return nil
}

func (a *Adapter) InspectMailClientConfiguration(ctx context.Context, domain string) (MailClientConfiguration, error) {
	domain = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(domain)), ".")
	if !validDomain(domain) {
		return MailClientConfiguration{}, errors.New("invalid mail domain")
	}
	state, _, dovecotCfg, rspamdCfg, _, _ := a.mailPaths()
	host := "mail." + domain
	cfg := MailClientConfiguration{
		Domain: domain, MailHost: host,
		UsernameFormat:    "Full email address (user@" + domain + ")",
		PasswordFormat:    "Mailbox password",
		CheckedAt:         time.Now().UTC().Format(time.RFC3339),
		ConfigurationFrom: []string{"live Dovecot configuration", "live Postfix configuration", "live TCP listeners"},
	}

	doveText := ""
	if out, err := a.run(ctx, "doveconf", "-n"); err == nil {
		doveText = out
	} else if b, readErr := os.ReadFile(dovecotCfg); readErr == nil {
		doveText = string(b)
	}
	postfixMain := func(key string) string {
		out, err := a.run(ctx, "postconf", "-h", key)
		if err != nil {
			return ""
		}
		return strings.TrimSpace(out)
	}
	postfixMaster := func(args ...string) string {
		out, err := a.run(ctx, "postconf", args...)
		if err != nil {
			return ""
		}
		return strings.TrimSpace(out)
	}
	active := func(service string) bool {
		out, err := a.run(ctx, "systemctl", "is-active", service)
		return err == nil && strings.TrimSpace(out) == "active"
	}
	portListening := func(port int) bool {
		for _, addr := range []string{fmt.Sprintf("127.0.0.1:%d", port), fmt.Sprintf("[::1]:%d", port)} {
			c, err := net.DialTimeout("tcp", addr, 250*time.Millisecond)
			if err == nil {
				_ = c.Close()
				return true
			}
		}
		return false
	}
	blockPort := func(text, listener string, fallback int) (int, bool) {
		needle := "inet_listener " + listener + " "
		i := strings.Index(text, needle)
		if i < 0 {
			return fallback, false
		}
		tail := text[i:]
		if len(tail) > 320 {
			tail = tail[:320]
		}
		p := strings.Index(tail, "port =")
		if p < 0 {
			return fallback, true
		}
		v := strings.TrimSpace(tail[p+len("port ="):])
		digits := ""
		for _, r := range v {
			if r < '0' || r > '9' {
				break
			}
			digits += string(r)
		}
		if digits == "" {
			return fallback, true
		}
		n, err := strconv.Atoi(digits)
		if err != nil {
			return fallback, true
		}
		return n, n > 0
	}

	cfg.DovecotActive = active("dovecot")
	cfg.PostfixActive = active("postfix")
	cfg.RspamdActive = active("rspamd")

	imapPort, imapEnabled := blockPort(doveText, "imaps", 993)
	popPort, popEnabled := blockPort(doveText, "pop3s", 995)
	imapLegacyPort, imapLegacy := blockPort(doveText, "imap", 143)
	popLegacyPort, popLegacy := blockPort(doveText, "pop3", 110)
	_ = imapLegacyPort
	_ = popLegacyPort
	sslRequired := strings.Contains(doveText, "ssl = required") || strings.Contains(doveText, "ssl=yes") || strings.Contains(doveText, "ssl = yes")

	submissionEnabled := postfixMaster("-M", "submission/inet") != ""
	submissionsEnabled := postfixMaster("-M", "submissions/inet") != ""
	smtpEnabled := postfixMaster("-M", "smtp/inet") != ""
	saslMain := strings.EqualFold(postfixMain("smtpd_sasl_auth_enable"), "yes")
	subAuth := strings.Contains(strings.ToLower(postfixMaster("-P", "submission/inet/smtpd_sasl_auth_enable")), "yes") || saslMain
	subsAuth := strings.Contains(strings.ToLower(postfixMaster("-P", "submissions/inet/smtpd_sasl_auth_enable")), "yes") || saslMain
	subTLS := postfixMaster("-P", "submission/inet/smtpd_tls_security_level")
	subsWrapper := postfixMaster("-P", "submissions/inet/smtpd_tls_wrappermode")

	// Determine TLS readiness from the certificates the live mail daemons are
	// actually configured to present. This intentionally accepts wildcard SANs
	// such as *.example.com for mail.example.com. Fall back to ACME paths only
	// when daemon configuration cannot be read.
	postfixCert := strings.TrimSpace(postfixMain("smtpd_tls_cert_file"))
	postfixKey := strings.TrimSpace(postfixMain("smtpd_tls_key_file"))
	dovecotCert, _ := a.run(ctx, "doveconf", "-h", "ssl_cert")
	dovecotKey, _ := a.run(ctx, "doveconf", "-h", "ssl_key")
	dovecotCert = strings.TrimPrefix(strings.TrimSpace(dovecotCert), "<")
	dovecotKey = strings.TrimPrefix(strings.TrimSpace(dovecotKey), "<")
	postfixTLS := certificateCoversHost(postfixCert, host) && regularOrSymlinkExists(postfixKey)
	dovecotTLS := certificateCoversHost(dovecotCert, host) && regularOrSymlinkExists(dovecotKey)
	cfg.TLSReady = postfixTLS && dovecotTLS
	if !cfg.TLSReady {
		base := a.cfg.ACMEConfigDir
		if base == "" {
			base = "/etc/letsencrypt"
		}
		for _, certName := range []string{host, domain} {
			fullchain := filepath.Join(base, "live", certName, "fullchain.pem")
			privkey := filepath.Join(base, "live", certName, "privkey.pem")
			if certificateCoversHost(fullchain, host) && regularOrSymlinkExists(privkey) {
				cfg.TLSReady = true
				break
			}
		}
	}
	if b, err := os.ReadFile(filepath.Join(state, "postfix_sni")); err == nil && strings.Contains(strings.ToLower(string(b)), strings.ToLower(host)+" ") {
		cfg.Configured = true
	}
	if strings.Contains(strings.ToLower(doveText), "local_name "+strings.ToLower(host)) {
		cfg.Configured = true
	}

	selector := "mail"
	if b, err := os.ReadFile(rspamdCfg); err == nil {
		for _, line := range strings.Split(string(b), "\n") {
			line = strings.TrimSpace(line)
			if strings.HasPrefix(line, "selector =") {
				v := strings.Trim(strings.TrimSpace(strings.TrimPrefix(line, "selector =")), `"; `)
				if v != "" {
					selector = v
				}
			}
		}
	}
	cfg.DKIMSelector = selector
	cfg.DKIMRecordName = selector + "._domainkey." + domain

	cfg.Services = []MailClientService{
		{ID: "imap", Protocol: "IMAP", Direction: "incoming", Server: host, Port: imapPort, Security: func() string {
			if sslRequired {
				return "SSL/TLS"
			}
			return "TLS"
		}(), Authentication: "Password", AuthenticationRequired: true, UsernameFormat: cfg.UsernameFormat, Enabled: imapEnabled, Listening: imapEnabled && portListening(imapPort), Purpose: "Recommended incoming mail"},
		{ID: "pop3", Protocol: "POP3", Direction: "incoming", Server: host, Port: popPort, Security: "SSL/TLS", Authentication: "Password", AuthenticationRequired: true, UsernameFormat: cfg.UsernameFormat, Enabled: popEnabled, Listening: popEnabled && portListening(popPort), Purpose: "Optional download-style incoming mail"},
		{ID: "smtp-465", Protocol: "SMTP", Direction: "outgoing", Server: host, Port: 465, Security: func() string {
			if strings.Contains(strings.ToLower(subsWrapper), "yes") {
				return "SSL/TLS"
			}
			return "TLS"
		}(), Authentication: "Password", AuthenticationRequired: subsAuth, UsernameFormat: cfg.UsernameFormat, Enabled: submissionsEnabled, Listening: submissionsEnabled && portListening(465), Purpose: "Authenticated outgoing mail"},
		{ID: "smtp-587", Protocol: "SMTP", Direction: "outgoing", Server: host, Port: 587, Security: func() string {
			if strings.Contains(strings.ToLower(subTLS), "encrypt") {
				return "STARTTLS"
			}
			return "STARTTLS/TLS"
		}(), Authentication: "Password", AuthenticationRequired: subAuth, UsernameFormat: cfg.UsernameFormat, Enabled: submissionEnabled, Listening: submissionEnabled && portListening(587), Purpose: "Authenticated outgoing mail"},
		{ID: "smtp-25", Protocol: "SMTP", Direction: "server", Server: host, Port: 25, Security: "STARTTLS when available", Authentication: "Server-to-server", AuthenticationRequired: false, UsernameFormat: "Not used for normal mail-client setup", Enabled: smtpEnabled, Listening: smtpEnabled && portListening(25), Purpose: "Mail-server delivery; use 465 or 587 for email clients"},
	}
	if imapLegacy || popLegacy {
		cfg.ConfigurationFrom = append(cfg.ConfigurationFrom, "legacy plaintext incoming listener detected")
	}
	return cfg, nil
}

func ensureDKIMKey(path string) (string, error) {
	if b, err := os.ReadFile(path); err == nil {
		if block, _ := pem.Decode(b); block != nil {
			if k, e := x509.ParsePKCS1PrivateKey(block.Bytes); e == nil {
				der, _ := x509.MarshalPKIXPublicKey(&k.PublicKey)
				return base64.StdEncoding.EncodeToString(der), nil
			}
		}
	}
	k, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return "", err
	}
	b := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(k)})
	if err := os.MkdirAll(filepath.Dir(path), 0750); err != nil {
		return "", err
	}
	if err := AtomicWrite(path, b, 0640); err != nil {
		return "", err
	}
	der, err := x509.MarshalPKIXPublicKey(&k.PublicKey)
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(der), nil
}

func certificateCoversHost(path, host string) bool {
	path = strings.TrimSpace(strings.TrimPrefix(path, "<"))
	if path == "" || !regularOrSymlinkExists(path) {
		return false
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return false
	}
	block, _ := pem.Decode(b)
	if block == nil || block.Type != "CERTIFICATE" {
		return false
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return false
	}
	return cert.VerifyHostname(host) == nil && time.Now().Before(cert.NotAfter)
}

func (a *Adapter) InspectMailDomainReadiness(ctx context.Context, domain string) (MailDomainReadiness, error) {
	domain = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(domain)), ".")
	if !validDomain(domain) {
		return MailDomainReadiness{}, errors.New("invalid mail domain")
	}
	cfg, err := a.InspectMailClientConfiguration(ctx, domain)
	if err != nil {
		return MailDomainReadiness{}, err
	}
	selector := strings.TrimSpace(cfg.DKIMSelector)
	if selector == "" {
		selector = "mail"
	}
	host := "mail." + domain
	dkim := publicTXTContainsContext(ctx, selector+"._domainkey."+domain, "v=DKIM1")
	spf := publicTXTContainsContext(ctx, domain, "v=spf1")
	dmarc := publicTXTContainsContext(ctx, "_dmarc."+domain, "v=DMARC1")
	ips, _ := net.DefaultResolver.LookupHost(ctx, host)
	ipok := len(ips) > 0
	mxs, _ := net.DefaultResolver.LookupMX(ctx, domain)
	mxok := false
	for _, mx := range mxs {
		if strings.EqualFold(strings.TrimSuffix(mx.Host, "."), host) {
			mxok = true
			break
		}
	}
	dnsReady := ipok && mxok
	status := "dns-or-tls-pending"
	if cfg.TLSReady && dnsReady && dkim && spf {
		status = "secure-active"
	} else if cfg.TLSReady {
		status = "tls-ready-dns-auth-pending"
	}
	return MailDomainReadiness{Domain: domain, MailHost: host, TLSReady: cfg.TLSReady, DNSReady: dnsReady, DKIM: dkim, SPF: spf, DMARC: dmarc, Status: status, CheckedAt: time.Now().UTC().Format(time.RFC3339)}, nil
}

func (a *Adapter) RemoveMailDomainAuthentication(ctx context.Context, domain string) error {
	if !a.cfg.AllowMutations {
		return errors.New("host mutations disabled")
	}
	domain = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(domain)), ".")
	if !validDomain(domain) {
		return errors.New("invalid mail domain")
	}
	zonePath := filepath.Join(a.cfg.DNSZoneDir, domain+".zone")
	if _, err := os.Stat(zonePath); err == nil {
		zone, err := a.ReadBINDZone(domain)
		if err != nil {
			return err
		}
		primary, secondary := "", ""
		kept := make([]DNSRecord, 0, len(zone.Records))
		for _, r := range zone.Records {
			name := strings.TrimSuffix(strings.ToLower(strings.TrimSpace(r.Name)), ".")
			if r.Type == "NS" && (name == "@" || name == domain) {
				if primary == "" {
					primary = strings.TrimSuffix(r.Value, ".")
				} else if secondary == "" {
					secondary = strings.TrimSuffix(r.Value, ".")
				}
				continue
			}
			if r.Type == "TXT" {
				v := strings.ToLower(strings.TrimSpace(r.Value))
				if (name == "@" || name == domain) && strings.HasPrefix(v, "v=spf1") {
					continue
				}
				if name == "_dmarc" && strings.HasPrefix(v, "v=dmarc1") {
					continue
				}
				if name == "mail._domainkey" && strings.HasPrefix(v, "v=dkim1") {
					continue
				}
			}
			kept = append(kept, r)
		}
		if primary == "" || secondary == "" {
			return errors.New("managed zone does not contain a complete authoritative NS pair")
		}
		if _, err := a.ProvisionBINDZoneWithNameservers(ctx, domain, primary, secondary, kept); err != nil {
			return fmt.Errorf("remove mail authentication DNS: %w", err)
		}
	}
	_, _, _, _, dkimDir, _ := a.mailPaths()
	key := filepath.Join(dkimDir, domain+".mail.key")
	if err := os.Remove(key); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("remove DKIM private key: %w", err)
	}
	return nil
}

func mailDNSReady(host, domain, dkim, spf, dmarc, v4, v6 string) bool {
	ips, _ := net.LookupHost(host)
	ipok := false
	for _, ip := range ips {
		if ip == v4 || ip == v6 {
			ipok = true
		}
	}
	mxs, _ := net.LookupMX(domain)
	mxok := false
	for _, m := range mxs {
		if strings.EqualFold(strings.TrimSuffix(m.Host, "."), host) {
			mxok = true
		}
	}
	return ipok && mxok && publicTXTContains(domain, "v=spf1") && publicTXTContains("mail._domainkey."+domain, "v=DKIM1") && publicTXTContains("_dmarc."+domain, "v=DMARC1")
}
func publicTXTContainsContext(ctx context.Context, name, needle string) bool {
	xs, _ := net.DefaultResolver.LookupTXT(ctx, name)
	for _, x := range xs {
		if strings.Contains(strings.ToLower(x), strings.ToLower(needle)) {
			return true
		}
	}
	return false
}
func publicTXTContains(name, needle string) bool {
	xs, _ := net.LookupTXT(name)
	for _, x := range xs {
		if strings.Contains(strings.ToLower(x), strings.ToLower(needle)) {
			return true
		}
	}
	return false
}

func (a *Adapter) ensureMailChallengeVHost(ctx context.Context, domain, host string) error {
	state, _, _, _, _, _ := a.mailPaths()
	root := filepath.Join(state, "acme", domain)
	if err := os.MkdirAll(filepath.Join(root, ".well-known", "acme-challenge"), 0755); err != nil {
		return err
	}
	cfg := fmt.Sprintf("server {\n listen 80;\n listen [::]:80;\n server_name %s;\n location ^~ /.well-known/acme-challenge/ { root %s; try_files $uri =404; }\n location / { return 404; }\n}\n", host, root)
	path := filepath.Join(a.cfg.NginxSitesAvailable, "privora-mail-"+domain+".conf")
	if err := AtomicWrite(path, []byte(cfg), 0644); err != nil {
		return err
	}
	link := filepath.Join(a.cfg.NginxSitesEnabled, filepath.Base(path))
	_ = os.Remove(link)
	if err := os.Symlink(path, link); err != nil && !os.IsExist(err) {
		return err
	}
	if _, err := a.run(ctx, "nginx", "-t"); err != nil {
		return fmt.Errorf("validate mail challenge vhost: %w", err)
	}
	_, err := a.run(ctx, "systemctl", "reload", "nginx")
	return err
}

func (a *Adapter) writeMailTLSSourcePaths(tlsDir, host, fullchain, privkey string) error {
	host = strings.ToLower(strings.TrimSpace(host))
	fullchain = filepath.Clean(strings.TrimSpace(fullchain))
	privkey = filepath.Clean(strings.TrimSpace(privkey))
	if !validDomain(host) || !filepath.IsAbs(fullchain) || !filepath.IsAbs(privkey) {
		return errors.New("invalid mail TLS source path")
	}
	if !regularOrSymlinkExists(fullchain) || !regularOrSymlinkExists(privkey) {
		return errors.New("mail TLS source path does not exist")
	}
	if err := AtomicWrite(filepath.Join(tlsDir, host+".fullchain.path"), []byte(fullchain+"\n"), 0600); err != nil {
		return err
	}
	if err := AtomicWrite(filepath.Join(tlsDir, host+".privkey.path"), []byte(privkey+"\n"), 0600); err != nil {
		return err
	}
	return nil
}

func (a *Adapter) mailTLSSourcePaths(tlsDir, host string) (string, string) {
	live := filepath.Join(a.cfg.ACMEConfigDir, "live", host)
	if a.cfg.ACMEConfigDir == "" {
		live = filepath.Join("/etc/letsencrypt/live", host)
	}
	fullchain := filepath.Join(live, "fullchain.pem")
	privkey := filepath.Join(live, "privkey.pem")
	readPath := func(name, fallback string) string {
		b, err := os.ReadFile(filepath.Join(tlsDir, name))
		if err != nil {
			return fallback
		}
		p := filepath.Clean(strings.TrimSpace(string(b)))
		if !filepath.IsAbs(p) || !regularOrSymlinkExists(p) {
			return fallback
		}
		return p
	}
	return readPath(host+".fullchain.path", fullchain), readPath(host+".privkey.path", privkey)
}

func renderPrivoraDovecotMailConfig(root string, uid int, localNames string) string {
	return fmt.Sprintf(`protocols = imap pop3 lmtp
disable_plaintext_auth = yes
auth_mechanisms = plain login
ssl = required
ssl_min_protocol = TLSv1.2
service lmtp {
  unix_listener /var/spool/postfix/private/dovecot-lmtp {
    mode = 0600
    user = postfix
    group = postfix
  }
}
protocol lmtp {
  mail_plugins = $mail_plugins sieve
}
plugin {
  sieve = file:~/sieve;active=~/.dovecot.sieve
}
service imap-login {
  inet_listener imap {
    port = 0
  }
  inet_listener imaps {
    port = 993
    ssl = yes
  }
}
service pop3-login {
  inet_listener pop3 {
    port = 0
  }
  inet_listener pop3s {
    port = 995
    ssl = yes
  }
}
mail_home = %s/%%d/%%n
mail_location = maildir:~/Maildir
first_valid_uid = %d
last_valid_uid = %d
%s`, root, uid, uid, localNames)
}

func (a *Adapter) renderMailServices(ctx context.Context, uid, gid int, state, root, dovecotCfg, rspamdCfg, dkimDir, tlsDir string) error {
	chains, _ := filepath.Glob(filepath.Join(tlsDir, "mail.*.pem"))
	sort.Strings(chains)
	if len(chains) == 0 {
		return errors.New("no mail TLS chain available")
	}
	defaultChain := chains[0]
	// The combined chain begins with the private key, which Postfix supports. Dovecot uses LE source paths per SNI name.
	var localNames strings.Builder
	for _, chain := range chains {
		host := strings.TrimSuffix(filepath.Base(chain), ".pem")
		fullchain, privkey := a.mailTLSSourcePaths(tlsDir, host)
		fmt.Fprintf(&localNames, "local_name %s {\n  ssl_cert = <%s\n  ssl_key = <%s\n}\n", host, fullchain, privkey)
	}
	dovecot := renderPrivoraDovecotMailConfig(root, uid, localNames.String())
	if err := os.MkdirAll(filepath.Dir(dovecotCfg), 0755); err != nil {
		return err
	}
	if err := AtomicWrite(dovecotCfg, []byte(dovecot), 0644); err != nil {
		return err
	}
	dovecotAuthRollback, err := a.ensurePrivoraDovecotAuthConfig(ctx)
	if err != nil {
		return err
	}
	authCommitted := false
	defer func() {
		if !authCommitted {
			dovecotAuthRollback()
		}
	}()
	rspamd := fmt.Sprintf("enabled = true;\npath = \"%s/$domain.$selector.key\";\nselector = \"mail\";\nsign_authenticated = true;\nsign_local = true;\nuse_domain = \"header\";\ncheck_pubkey = true;\nallow_pubkey_mismatch = false;\n", dkimDir)
	if err := os.MkdirAll(filepath.Dir(rspamdCfg), 0755); err != nil {
		return err
	}
	if err := AtomicWrite(rspamdCfg, []byte(rspamd), 0644); err != nil {
		return err
	}
	// Current keys are domain.mail.key matching selector mail.
	aliases := filepath.Join(state, "virtual_aliases")
	domains := filepath.Join(state, "virtual_domains")
	boxes := filepath.Join(state, "virtual_mailboxes")
	sni := filepath.Join(state, "postfix_sni")
	var snib strings.Builder
	for _, chain := range chains {
		host := strings.TrimSuffix(filepath.Base(chain), ".pem")
		fmt.Fprintf(&snib, "%s %s\n", host, chain)
	}
	if err := AtomicWrite(sni, []byte(snib.String()), 0640); err != nil {
		return err
	}
	for _, p := range []string{domains, boxes, aliases} {
		if _, err := os.Stat(p); errors.Is(err, os.ErrNotExist) {
			if err := AtomicWrite(p, []byte(""), 0640); err != nil {
				return err
			}
		}
		if _, err := a.run(ctx, "postmap", p); err != nil {
			return err
		}
	}
	if _, err := a.run(ctx, "postmap", "-F", "hash:"+sni); err != nil {
		return fmt.Errorf("compile Postfix TLS SNI map: %w", err)
	}
	params := map[string]string{
		"virtual_mailbox_domains": "hash:" + domains, "virtual_mailbox_maps": "hash:" + boxes, "virtual_alias_maps": "hash:" + aliases,
		"virtual_mailbox_base": root, "virtual_uid_maps": fmt.Sprintf("static:%d", uid), "virtual_gid_maps": fmt.Sprintf("static:%d", gid), "virtual_transport": "lmtp:unix:private/dovecot-lmtp",
		"smtpd_sasl_type": "dovecot", "smtpd_sasl_path": "private/auth", "smtpd_sasl_auth_enable": "yes", "smtpd_relay_restrictions": "permit_mynetworks, permit_sasl_authenticated, reject_unauth_destination",
		"smtpd_tls_security_level": "may", "smtp_tls_security_level": "may", "smtpd_tls_chain_files": defaultChain, "tls_server_sni_maps": "hash:" + sni,
		"smtpd_milters": "inet:127.0.0.1:11332", "non_smtpd_milters": "inet:127.0.0.1:11332", "milter_default_action": "accept", "milter_protocol": "6",
	}
	keys := make([]string, 0, len(params))
	for k := range params {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		if _, err := a.run(ctx, "postconf", "-e", k+" = "+params[k]); err != nil {
			return err
		}
	}
	// Submission services: encrypted authenticated clients only.
	masters := [][]string{{"-M", "submission/inet=submission inet n - y - - smtpd"}, {"-P", "submission/inet/syslog_name=postfix/submission"}, {"-P", "submission/inet/smtpd_tls_security_level=encrypt"}, {"-P", "submission/inet/smtpd_sasl_auth_enable=yes"}, {"-P", "submission/inet/smtpd_client_restrictions=permit_sasl_authenticated,reject"}, {"-M", "submissions/inet=submissions inet n - y - - smtpd"}, {"-P", "submissions/inet/syslog_name=postfix/submissions"}, {"-P", "submissions/inet/smtpd_tls_wrappermode=yes"}, {"-P", "submissions/inet/smtpd_tls_security_level=encrypt"}, {"-P", "submissions/inet/smtpd_sasl_auth_enable=yes"}, {"-P", "submissions/inet/smtpd_client_restrictions=permit_sasl_authenticated,reject"}}
	for _, args := range masters {
		if _, err := a.run(ctx, "postconf", args...); err != nil {
			return err
		}
	}
	if _, err := a.run(ctx, "doveconf", "-n"); err != nil {
		return fmt.Errorf("validate Dovecot mail configuration: %w", err)
	}
	if err := a.validatePostfixCheck(ctx); err != nil {
		return fmt.Errorf("validate Postfix mail configuration: %w", err)
	}
	for _, svc := range []string{"rspamd", "dovecot", "postfix"} {
		if _, err := a.run(ctx, "systemctl", "restart", svc); err != nil {
			return fmt.Errorf("restart %s: %w", svc, err)
		}
	}
	stateUsers := filepath.Join(state, "dovecot_users")
	if known := firstPrivoraMailbox(stateUsers); known != "" {
		if _, err := a.run(ctx, "doveadm", "user", known); err != nil {
			return fmt.Errorf("Dovecot cannot resolve managed mailbox %s after mail service render", known)
		}
	}
	authCommitted = true
	return nil
}

func (a *Adapter) ProvisionMailAlias(ctx context.Context, address, destination string) error {
	if !a.cfg.AllowMutations {
		return errors.New("host mutations disabled")
	}
	if err := a.requireCertified("postfix"); err != nil {
		return err
	}
	address = strings.ToLower(strings.TrimSpace(address))
	destination = strings.ToLower(strings.TrimSpace(destination))
	if !validEmailAddress(address) || !validEmailAddress(destination) {
		return errors.New("invalid mail forwarder")
	}
	if _, _, err := a.EnsureMailFoundation(ctx); err != nil {
		return err
	}
	state, _, _, _, _, _ := a.mailPaths()
	path := filepath.Join(state, "virtual_aliases")
	old, had := readIfExists(path)
	next := upsertMapLine(string(old), address, destination)
	if err := AtomicWrite(path, []byte(next), 0640); err != nil {
		return err
	}
	rollback := func() {
		restoreFile(path, old, had, 0640)
		if had {
			_, _ = a.run(ctx, "postmap", path)
		}
	}
	if _, err := a.run(ctx, "postmap", path); err != nil {
		rollback()
		return err
	}
	if _, err := a.run(ctx, "systemctl", "reload", "postfix"); err != nil {
		rollback()
		return err
	}
	return nil
}
func (a *Adapter) UpdateMailAlias(ctx context.Context, address, destination string) error {
	if !a.cfg.AllowMutations {
		return errors.New("host mutations disabled")
	}
	if err := a.requireCertified("postfix"); err != nil {
		return err
	}
	address = strings.ToLower(strings.TrimSpace(address))
	destination = strings.ToLower(strings.TrimSpace(destination))
	if !validEmailAddress(address) || !validEmailAddress(destination) {
		return errors.New("invalid mail forwarder")
	}
	state, _, _, _, _, _ := a.mailPaths()
	path := filepath.Join(state, "virtual_aliases")
	old, had := readIfExists(path)
	if !had || !mapContainsKey(string(old), address) {
		return errors.New("mail forwarder is not present in the Privora-managed alias map")
	}
	next := upsertMapLine(string(old), address, destination)
	if err := AtomicWrite(path, []byte(next), 0640); err != nil {
		return err
	}
	rollback := func() {
		restoreFile(path, old, had, 0640)
		_, _ = a.run(ctx, "postmap", path)
		_, _ = a.run(ctx, "systemctl", "reload", "postfix")
	}
	if _, err := a.run(ctx, "postmap", path); err != nil {
		rollback()
		return err
	}
	if _, err := a.run(ctx, "systemctl", "reload", "postfix"); err != nil {
		rollback()
		return err
	}
	return nil
}

func (a *Adapter) DeleteMailAlias(ctx context.Context, address string) error {
	if !a.cfg.AllowMutations {
		return errors.New("host mutations disabled")
	}
	if err := a.requireCertified("postfix"); err != nil {
		return err
	}
	address = strings.ToLower(strings.TrimSpace(address))
	if !validEmailAddress(address) {
		return errors.New("invalid mail forwarder address")
	}
	state, _, _, _, _, _ := a.mailPaths()
	path := filepath.Join(state, "virtual_aliases")
	old, had := readIfExists(path)
	if !had || !mapContainsKey(string(old), address) {
		return errors.New("mail forwarder is not present in the Privora-managed alias map")
	}
	next := removeMapLine(string(old), address)
	if err := AtomicWrite(path, []byte(next), 0640); err != nil {
		return err
	}
	rollback := func() {
		restoreFile(path, old, had, 0640)
		_, _ = a.run(ctx, "postmap", path)
		_, _ = a.run(ctx, "systemctl", "reload", "postfix")
	}
	if _, err := a.run(ctx, "postmap", path); err != nil {
		rollback()
		return err
	}
	if _, err := a.run(ctx, "systemctl", "reload", "postfix"); err != nil {
		rollback()
		return err
	}
	return nil
}

func validEmailAddress(v string) bool {
	parts := strings.Split(v, "@")
	return len(parts) == 2 && mailLocalRE.MatchString(parts[0]) && validDomain(parts[1])
}
