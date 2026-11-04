package hostadapter

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestMigrateDovecotUsersLegacyWhitespaceToPasswdFile(t *testing.T) {
	p := filepath.Join(t.TempDir(), "dovecot_users")
	legacy := "hello@example.com {SHA512-CRYPT}$6$abc:1001:1001::/var/vmail/example.com/hello::userdb_mail=maildir:/var/vmail/example.com/hello/Maildir\n"
	if err := os.WriteFile(p, []byte(legacy), 0640); err != nil {
		t.Fatal(err)
	}
	if err := migrateDovecotUsers(p); err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(p)
	got := string(b)
	if !strings.HasPrefix(got, "hello@example.com:{SHA512-CRYPT}$6$abc:") {
		t.Fatalf("legacy entry was not converted to passwd-file syntax: %q", got)
	}
	if err := migrateDovecotUsers(p); err != nil {
		t.Fatal(err)
	}
	b2, _ := os.ReadFile(p)
	if string(b2) != got {
		t.Fatal("migration is not idempotent")
	}
}

func TestDKIMKeyIsStableAndPublishesPublicKey(t *testing.T) {
	p := filepath.Join(t.TempDir(), "example.test.mail.key")
	a, err := ensureDKIMKey(p)
	if err != nil {
		t.Fatal(err)
	}
	b, err := ensureDKIMKey(p)
	if err != nil {
		t.Fatal(err)
	}
	if a == "" || a != b {
		t.Fatalf("DKIM public key not stable: %q %q", a, b)
	}
}

func TestInspectMailClientConfigurationReadsEffectiveServerSettings(t *testing.T) {
	bin := t.TempDir()
	dove := `protocols = imap pop3 lmtp
ssl = required
service imap-login {
  inet_listener imap { port = 0 }
  inet_listener imaps { port = 993 ssl = yes }
}
service pop3-login {
  inet_listener pop3 { port = 0 }
  inet_listener pop3s { port = 995 ssl = yes }
}
local_name mail.example.test { ssl_cert = </cert; ssl_key = </key; }
`
	writeExecutable(t, bin, "doveconf", "cat <<'EOF'\n"+dove+"EOF")
	writeExecutable(t, bin, "systemctl", `if [ "$1" = "is-active" ]; then echo active; exit 0; fi; exit 1`)
	writeExecutable(t, bin, "postconf", `
if [ "$1" = "-h" ] && [ "$2" = "smtpd_sasl_auth_enable" ]; then echo yes; exit 0; fi
if [ "$1" = "-M" ]; then
  case "$2" in
    submission/inet) echo 'submission inet n - y - - smtpd'; exit 0;;
    submissions/inet) echo 'submissions inet n - y - - smtpd'; exit 0;;
    smtp/inet) echo 'smtp inet n - y - - smtpd'; exit 0;;
  esac
fi
if [ "$1" = "-P" ]; then
  case "$2" in
    submission/inet/smtpd_sasl_auth_enable) echo 'submission/inet/smtpd_sasl_auth_enable=yes'; exit 0;;
    submission/inet/smtpd_tls_security_level) echo 'submission/inet/smtpd_tls_security_level=encrypt'; exit 0;;
    submissions/inet/smtpd_sasl_auth_enable) echo 'submissions/inet/smtpd_sasl_auth_enable=yes'; exit 0;;
    submissions/inet/smtpd_tls_wrappermode) echo 'submissions/inet/smtpd_tls_wrappermode=yes'; exit 0;;
  esac
fi
exit 1`)
	t.Setenv("PATH", bin+":"+os.Getenv("PATH"))
	root := t.TempDir()
	state := filepath.Join(root, "mail")
	acme := filepath.Join(root, "acme")
	rspamd := filepath.Join(root, "dkim.conf")
	if err := os.MkdirAll(state, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(state, "postfix_sni"), []byte("mail.example.test /cert.pem\n"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(rspamd, []byte("selector = \"mail\";\n"), 0644); err != nil {
		t.Fatal(err)
	}
	live := filepath.Join(acme, "live", "mail.example.test")
	if err := os.MkdirAll(live, 0755); err != nil {
		t.Fatal(err)
	}
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "example.test"}, DNSNames: []string{"*.example.test", "example.test"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	if err := os.WriteFile(filepath.Join(live, "fullchain.pem"), certPEM, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(live, "privkey.pem"), keyPEM, 0600); err != nil {
		t.Fatal(err)
	}
	a := New(Config{MailStateDir: state, ACMEConfigDir: acme, RspamdDKIMConfig: rspamd})
	cfg, err := a.InspectMailClientConfiguration(context.Background(), "example.test")
	if err != nil {
		t.Fatal(err)
	}
	if !cfg.Configured || !cfg.TLSReady || !cfg.PostfixActive || !cfg.DovecotActive {
		t.Fatalf("unexpected status: %+v", cfg)
	}
	want := map[string]int{"imap": 993, "pop3": 995, "smtp-465": 465, "smtp-587": 587, "smtp-25": 25}
	for _, svc := range cfg.Services {
		if want[svc.ID] != svc.Port || !svc.Enabled {
			t.Fatalf("unexpected service: %+v", svc)
		}
		delete(want, svc.ID)
	}
	if len(want) != 0 {
		t.Fatalf("missing services: %+v", want)
	}
	if cfg.DKIMSelector != "mail" || cfg.DKIMRecordName != "mail._domainkey.example.test" {
		t.Fatalf("unexpected DKIM metadata: %+v", cfg)
	}
}

func TestRemoveMailDomainAuthenticationPreservesMailRoutingAndUnrelatedDNS(t *testing.T) {
	bin := t.TempDir()
	for name, body := range map[string]string{"named-checkzone": "exit 0", "systemctl": "exit 0"} {
		if err := os.WriteFile(filepath.Join(bin, name), []byte("#!/bin/sh\n"+body+"\n"), 0755); err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv("PATH", bin+":"+os.Getenv("PATH"))
	root := t.TempDir()
	zoneDir := filepath.Join(root, "zones")
	dkimDir := filepath.Join(root, "dkim")
	a := New(Config{AllowMutations: true, CertificationMode: true, DNSZoneDir: zoneDir, DNSIndexPath: filepath.Join(root, "zones.conf"), DNSService: "bind9", RspamdDKIMDir: dkimDir})
	longKey := "v=DKIM1; k=rsa; p=" + strings.Repeat("A", 420)
	records := []DNSRecord{
		{Type: "A", Name: "mail", Value: "192.0.2.10", TTL: 3600},
		{Type: "MX", Name: "@", Value: "10 mail.example.test.", TTL: 3600},
		{Type: "TXT", Name: "@", Value: "v=spf1 mx a:mail.example.test ~all", TTL: 3600},
		{Type: "TXT", Name: "mail._domainkey", Value: longKey, TTL: 3600},
		{Type: "TXT", Name: "_dmarc", Value: "v=DMARC1; p=quarantine", TTL: 3600},
		{Type: "TXT", Name: "@", Value: "google-site-verification=keep-me", TTL: 3600},
	}
	if _, err := a.ProvisionBINDZoneWithNameservers(context.Background(), "example.test", "ns1.example.test", "ns2.example.test", records); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(dkimDir, 0750); err != nil {
		t.Fatal(err)
	}
	key := filepath.Join(dkimDir, "example.test.mail.key")
	if err := os.WriteFile(key, []byte("private"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := a.RemoveMailDomainAuthentication(context.Background(), "example.test"); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(key); !os.IsNotExist(err) {
		t.Fatalf("DKIM private key still exists: %v", err)
	}
	zone, err := a.ReadBINDZone("example.test")
	if err != nil {
		t.Fatal(err)
	}
	seenA, seenMX, seenUnrelated := false, false, false
	for _, r := range zone.Records {
		v := strings.ToLower(r.Value)
		if r.Type == "TXT" && (strings.HasPrefix(v, "v=spf1") || strings.HasPrefix(v, "v=dkim1") || strings.HasPrefix(v, "v=dmarc1")) {
			t.Fatalf("authentication TXT survived: %+v", r)
		}
		if r.Type == "A" && r.Name == "mail" {
			seenA = true
		}
		if r.Type == "MX" && r.Name == "@" {
			seenMX = true
		}
		if r.Type == "TXT" && strings.Contains(r.Value, "google-site-verification=keep-me") {
			seenUnrelated = true
		}
	}
	if !seenA || !seenMX || !seenUnrelated {
		t.Fatalf("routing/unrelated DNS was not preserved: A=%v MX=%v unrelated=%v", seenA, seenMX, seenUnrelated)
	}
}

func TestCertificateCoversWildcardMailHost(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "example.test"}, DNSNames: []string{"*.example.test", "example.test"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(t.TempDir(), "fullchain.pem")
	if err := os.WriteFile(p, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0644); err != nil {
		t.Fatal(err)
	}
	if !certificateCoversHost(p, "mail.example.test") {
		t.Fatal("wildcard certificate was not accepted for mail.example.test")
	}
	if certificateCoversHost(p, "mail.other.test") {
		t.Fatal("wildcard certificate incorrectly covered unrelated host")
	}
}

func TestManagedMailChallengeHostDetection(t *testing.T) {
	tmp := t.TempDir()
	available := filepath.Join(tmp, "sites-available")
	state := filepath.Join(tmp, "mail-state")
	if err := os.MkdirAll(available, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(state, "acme", "example.test"), 0755); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(available, "privora-mail-example.test.conf")
	cfg := "server {\n listen 80;\n server_name mail.example.test;\n location ^~ /.well-known/acme-challenge/ { root " + filepath.Join(state, "acme", "example.test") + "; try_files $uri =404; }\n}\n"
	if err := os.WriteFile(path, []byte(cfg), 0644); err != nil {
		t.Fatal(err)
	}
	a := New(Config{NginxSitesAvailable: available, MailStateDir: state})
	if !a.IsManagedMailChallengeHost("mail.example.test") {
		t.Fatal("expected managed mail challenge host")
	}
	if a.IsManagedMailChallengeHost("www.example.test") {
		t.Fatal("normal website must not be classified as managed mail host")
	}
}

func TestMailTLSSourcePathsPreserveResolvedLineage(t *testing.T) {
	tmp := t.TempDir()
	tlsDir := filepath.Join(tmp, "tls")
	if err := os.MkdirAll(tlsDir, 0700); err != nil {
		t.Fatal(err)
	}
	live := filepath.Join(tmp, "letsencrypt", "live", "mail.example.test-0001")
	if err := os.MkdirAll(live, 0755); err != nil {
		t.Fatal(err)
	}
	fullchain := filepath.Join(live, "fullchain.pem")
	privkey := filepath.Join(live, "privkey.pem")
	if err := os.WriteFile(fullchain, []byte("cert"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(privkey, []byte("key"), 0600); err != nil {
		t.Fatal(err)
	}
	a := New(Config{ACMEConfigDir: filepath.Join(tmp, "letsencrypt")})
	if err := a.writeMailTLSSourcePaths(tlsDir, "mail.example.test", fullchain, privkey); err != nil {
		t.Fatal(err)
	}
	gotCert, gotKey := a.mailTLSSourcePaths(tlsDir, "mail.example.test")
	if gotCert != fullchain || gotKey != privkey {
		t.Fatalf("resolved lineage was not preserved: cert=%q key=%q", gotCert, gotKey)
	}
}

func TestRenderPrivoraDovecotMailConfigUsesCanonicalMultilineBlocks(t *testing.T) {
	localNames := "local_name mail.example.test {\n  ssl_cert = </etc/letsencrypt/live/mail.example.test/fullchain.pem\n  ssl_key = </etc/letsencrypt/live/mail.example.test/privkey.pem\n}\n"
	got := renderPrivoraDovecotMailConfig("/var/vmail", 997, localNames)
	for _, bad := range []string{
		"service lmtp { unix_listener",
		"protocol lmtp { mail_plugins",
		"plugin { sieve",
		"service imap-login { inet_listener",
		"service pop3-login { inet_listener",
		"local_name mail.example.test { ssl_cert",
	} {
		if strings.Contains(got, bad) {
			t.Fatalf("Dovecot renderer emitted unsupported inline block %q:\n%s", bad, got)
		}
	}
	for _, want := range []string{
		"service lmtp {\n",
		"  unix_listener /var/spool/postfix/private/dovecot-lmtp {\n",
		"service imap-login {\n",
		"  inet_listener imaps {\n",
		"service pop3-login {\n",
		"local_name mail.example.test {\n",
	} {
		if !strings.Contains(got, want) {
			t.Fatalf("Dovecot renderer missing %q:\n%s", want, got)
		}
	}
}
