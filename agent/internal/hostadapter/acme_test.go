package hostadapter

import (
	"context"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"testing"
	"time"
)

type acmeRoundTripFunc func(*http.Request) (*http.Response, error)

func (f acmeRoundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestACMEWebrootWithControlledClients(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("unix helper test")
	}
	tmp := t.TempDir()
	bin := filepath.Join(tmp, "bin")
	if err := os.MkdirAll(bin, 0755); err != nil {
		t.Fatal(err)
	}
	certbot := `#!/bin/sh
set -eu
cfg=""
domain=""
while [ "$#" -gt 0 ]; do
  case "$1" in
    --config-dir) cfg="$2"; shift 2 ;;
    -d) domain="$2"; shift 2 ;;
    *) shift ;;
  esac
done
mkdir -p "$cfg/live/$domain"
printf 'fake cert\n' > "$cfg/live/$domain/fullchain.pem"
printf 'fake key\n' > "$cfg/live/$domain/privkey.pem"
`
	openssl := `#!/bin/sh
printf 'notAfter=Dec 31 23:59:59 2099 GMT\n'
`
	if err := os.WriteFile(filepath.Join(bin, "certbot"), []byte(certbot), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(bin, "openssl"), []byte(openssl), 0755); err != nil {
		t.Fatal(err)
	}
	old := os.Getenv("PATH")
	t.Setenv("PATH", bin+":"+old)
	root := filepath.Join(tmp, "web")
	if err := os.MkdirAll(root, 0755); err != nil {
		t.Fatal(err)
	}
	client := &http.Client{Transport: acmeRoundTripFunc(func(req *http.Request) (*http.Response, error) {
		path := filepath.Join(root, filepath.FromSlash(strings.TrimPrefix(req.URL.Path, "/")))
		b, err := os.ReadFile(path)
		if err != nil {
			return &http.Response{StatusCode: http.StatusNotFound, Status: "404 Not Found", Body: io.NopCloser(strings.NewReader("missing")), Header: make(http.Header), Request: req}, nil
		}
		return &http.Response{StatusCode: http.StatusOK, Status: "200 OK", Body: io.NopCloser(strings.NewReader(string(b))), Header: make(http.Header), Request: req}, nil
	})}
	a := New(Config{AllowMutations: true, CertificationMode: true, ACMEConfigDir: filepath.Join(tmp, "letsencrypt"), HTTPClient: client})
	got, err := a.IssueLetsEncryptWebroot(context.Background(), "example.test", root, "hostmaster@example.test")
	if err != nil {
		t.Fatal(err)
	}
	if got.Domain != "example.test" || got.Provider != "letsencrypt" || got.ExpiresAt.Year() != 2099 {
		t.Fatalf("unexpected result: %+v", got)
	}
}

func TestACMEProductionProbeBypassesEnvironmentProxy(t *testing.T) {
	client := acmeProbeClient(nil)
	transport, ok := client.Transport.(*http.Transport)
	if !ok {
		t.Fatalf("unexpected production ACME transport: %T", client.Transport)
	}
	if transport.Proxy != nil {
		t.Fatal("production ACME self-probe must bypass environment proxies")
	}
}

func TestACMEInjectedHTTPTransportAlsoBypassesProxy(t *testing.T) {
	baseTransport := http.DefaultTransport.(*http.Transport).Clone()
	baseTransport.Proxy = http.ProxyFromEnvironment
	base := &http.Client{Transport: baseTransport, Timeout: 30 * time.Second}
	client := acmeProbeClient(base)
	transport, ok := client.Transport.(*http.Transport)
	if !ok {
		t.Fatalf("unexpected injected ACME transport: %T", client.Transport)
	}
	if transport.Proxy != nil {
		t.Fatal("injected production-style ACME transport must bypass proxies")
	}
	if baseTransport.Proxy == nil {
		t.Fatal("ACME probe transport mutation leaked back into caller transport")
	}
	if client.Timeout != 8*time.Second {
		t.Fatalf("unexpected probe timeout: %s", client.Timeout)
	}
}

func TestACMETraversalACLTargetsAreLeastPrivilegeAndScoped(t *testing.T) {
	got := acmeTraversalACLTargets("/home/exampleweb/domains/example.test/public")
	want := []string{
		"/home/exampleweb",
		"/home/exampleweb/domains",
		"/home/exampleweb/domains/example.test",
		"/home/exampleweb/domains/example.test/public",
	}
	if len(got) != len(want) {
		t.Fatalf("home traversal target count=%d want=%d: %#v", len(got), len(want), got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("home traversal target[%d]=%q want=%q", i, got[i], want[i])
		}
	}

	got = acmeTraversalACLTargets("/etc/privora-mail/acme/privategather.com")
	want = []string{
		"/etc/privora-mail",
		"/etc/privora-mail/acme",
		"/etc/privora-mail/acme/privategather.com",
	}
	if len(got) != len(want) {
		t.Fatalf("mail traversal target count=%d want=%d: %#v", len(got), len(want), got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("mail traversal target[%d]=%q want=%q", i, got[i], want[i])
		}
	}

	if got := acmeTraversalACLTargets("/var/www/example"); len(got) != 0 {
		t.Fatalf("unmanaged root must not receive ACL mutation targets: %#v", got)
	}
}

func TestACMEHTTP01PreflightAcceptsLocalProofWhenPublicSelfProbe404(t *testing.T) {
	root := t.TempDir()
	client := &http.Client{Transport: acmeRoundTripFunc(func(req *http.Request) (*http.Response, error) {
		if req.URL.Hostname() == "example.test" {
			return &http.Response{StatusCode: http.StatusNotFound, Status: "404 Not Found", Body: io.NopCloser(strings.NewReader("public-self-probe-miss")), Header: make(http.Header), Request: req}, nil
		}
		path := filepath.Join(root, filepath.FromSlash(strings.TrimPrefix(req.URL.Path, "/")))
		b, err := os.ReadFile(path)
		if err != nil {
			return &http.Response{StatusCode: http.StatusNotFound, Status: "404 Not Found", Body: io.NopCloser(strings.NewReader("missing")), Header: make(http.Header), Request: req}, nil
		}
		return &http.Response{StatusCode: http.StatusOK, Status: "200 OK", Body: io.NopCloser(strings.NewReader(string(b))), Header: make(http.Header), Request: req}, nil
	})}
	a := New(Config{HTTPClient: client})
	got := a.PreflightLetsEncryptHTTP01(context.Background(), "example.test", root)
	if !got.Ready || got.Status != "http-local-ready" {
		t.Fatalf("public self-probe must be advisory when local vhost proof succeeds: %+v", got)
	}
	if !strings.Contains(got.Detail, "self-probe HTTP 404") {
		t.Fatalf("advisory public failure detail missing: %+v", got)
	}
}

func TestACMEHTTP01PreflightReportsBlockedRoute(t *testing.T) {
	root := t.TempDir()
	client := &http.Client{Transport: acmeRoundTripFunc(func(req *http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: http.StatusForbidden, Status: "403 Forbidden", Body: io.NopCloser(strings.NewReader("denied")), Header: make(http.Header), Request: req}, nil
	})}
	a := New(Config{HTTPClient: client})
	got := a.PreflightLetsEncryptHTTP01(context.Background(), "example.test", root)
	if got.Ready || got.Status != "http-blocked" || !strings.Contains(got.Detail, "Nginx denied") {
		t.Fatalf("unexpected blocked preflight result: %+v", got)
	}
}

func TestACMEHTTP01PreflightNormalizesPermissionsUnderAgentUmask(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("unix permission semantics")
	}
	root := t.TempDir()
	oldUmask := syscall.Umask(0007)
	defer syscall.Umask(oldUmask)

	client := &http.Client{Transport: acmeRoundTripFunc(func(req *http.Request) (*http.Response, error) {
		wellKnown := filepath.Join(root, ".well-known")
		challenge := filepath.Join(wellKnown, "acme-challenge")
		for _, item := range []struct {
			path string
			want os.FileMode
		}{
			{wellKnown, 0755},
			{challenge, 0755},
		} {
			st, err := os.Stat(item.path)
			if err != nil {
				t.Fatalf("stat %s: %v", item.path, err)
			}
			if got := st.Mode().Perm(); got != item.want {
				t.Fatalf("%s mode=%#o want=%#o", item.path, got, item.want)
			}
		}
		challengePath := filepath.Join(root, filepath.FromSlash(strings.TrimPrefix(req.URL.Path, "/")))
		st, err := os.Stat(challengePath)
		if err != nil {
			t.Fatalf("stat challenge token: %v", err)
		}
		if got := st.Mode().Perm(); got != 0644 {
			t.Fatalf("challenge token mode=%#o want=0644", got)
		}
		body, err := os.ReadFile(challengePath)
		if err != nil {
			t.Fatalf("read challenge token: %v", err)
		}
		return &http.Response{StatusCode: http.StatusOK, Status: "200 OK", Body: io.NopCloser(strings.NewReader(string(body))), Header: make(http.Header), Request: req}, nil
	})}

	a := New(Config{HTTPClient: client})
	got := a.PreflightLetsEncryptHTTP01(context.Background(), "example.test", root)
	if !got.Ready {
		t.Fatalf("expected ready preflight under agent umask: %+v", got)
	}
}

func TestACMEFailureSummarySurfacesValidationDetail(t *testing.T) {
	path := filepath.Join(t.TempDir(), "letsencrypt.log")
	log := "noise\nDetail: 203.0.113.10: Invalid response from http://example.test/.well-known/acme-challenge/token: 403\nChallenge failed for domain example.test\n"
	if err := os.WriteFile(path, []byte(log), 0600); err != nil {
		t.Fatal(err)
	}
	got := acmeFailureSummary(path)
	if !strings.Contains(got, "Invalid response") || !strings.Contains(got, "Challenge failed") {
		t.Fatalf("validation detail missing: %q", got)
	}
}

func TestACMERejectsUnsafeInputs(t *testing.T) {
	a := New(Config{AllowMutations: true, CertificationMode: true})
	if _, err := a.IssueLetsEncryptWebroot(context.Background(), "bad;domain.test", t.TempDir(), "a@example.test"); err == nil {
		t.Fatal("expected invalid domain rejection")
	}
	if _, err := a.IssueLetsEncryptWebroot(context.Background(), "example.test", t.TempDir(), "not-email"); err == nil {
		t.Fatal("expected invalid email rejection")
	}
}

func TestRenderNginxSiteAllowsACMEBeforeDotfileDeny(t *testing.T) {
	cfg, err := RenderNginxSite("example.test", "exampleweb", "8.4", "/home/exampleweb/domains/example.test/public")
	if err != nil {
		t.Fatal(err)
	}
	acme := strings.Index(cfg, "location ^~ /.well-known/acme-challenge/")
	deny := strings.Index(cfg, "location ~ /\\. { deny all; }")
	if acme < 0 || deny < 0 || acme > deny {
		t.Fatalf("HTTP vhost must allow ACME challenge before dotfile deny: %s", cfg)
	}
}

func TestRenderNginxSiteTLS(t *testing.T) {
	cfg, err := RenderNginxSiteTLS("example.test", "exampleweb", "8.4", "/home/exampleweb/domains/example.test/public", "/etc/letsencrypt/live/example.test/fullchain.pem", "/etc/letsencrypt/live/example.test/privkey.pem")
	if err != nil {
		t.Fatal(err)
	}
	for _, needle := range []string{"listen 443 ssl http2;", "return 301 https://$host$request_uri;", "ssl_certificate /etc/letsencrypt/live/example.test/fullchain.pem;", "location ^~ /.well-known/acme-challenge/"} {
		if !strings.Contains(cfg, needle) {
			t.Fatalf("TLS config missing %q: %s", needle, cfg)
		}
	}
	if _, err := RenderNginxSiteTLS("example.test", "exampleweb", "8.4", "/home/exampleweb/domains/example.test/public", "/tmp/fullchain.pem", "/etc/letsencrypt/live/example.test/privkey.pem"); err == nil {
		t.Fatal("expected certificate path outside letsencrypt to be rejected")
	}
}

func TestACMEWebrootResolvesSuffixedCertbotLineage(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("unix helper test")
	}
	tmp := t.TempDir()
	bin := filepath.Join(tmp, "bin")
	if err := os.MkdirAll(bin, 0755); err != nil {
		t.Fatal(err)
	}
	certbot := `#!/bin/sh
set -eu
cfg=""
domain=""
while [ "$#" -gt 0 ]; do
  case "$1" in
    --config-dir) cfg="$2"; shift 2 ;;
    -d) domain="$2"; shift 2 ;;
    *) shift ;;
  esac
done
mkdir -p "$cfg/live/$domain-0001"
printf 'fake cert\n' > "$cfg/live/$domain-0001/fullchain.pem"
printf 'fake key\n' > "$cfg/live/$domain-0001/privkey.pem"
`
	openssl := `#!/bin/sh
case " $* " in
  *" -checkhost "*) exit 0 ;;
  *) printf 'notAfter=Dec 31 23:59:59 2099 GMT\n' ;;
esac
`
	if err := os.WriteFile(filepath.Join(bin, "certbot"), []byte(certbot), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(bin, "openssl"), []byte(openssl), 0755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", bin+":"+os.Getenv("PATH"))
	root := filepath.Join(tmp, "web")
	if err := os.MkdirAll(root, 0755); err != nil {
		t.Fatal(err)
	}
	client := &http.Client{Transport: acmeRoundTripFunc(func(req *http.Request) (*http.Response, error) {
		path := filepath.Join(root, filepath.FromSlash(strings.TrimPrefix(req.URL.Path, "/")))
		b, err := os.ReadFile(path)
		if err != nil {
			return &http.Response{StatusCode: http.StatusNotFound, Status: "404 Not Found", Body: io.NopCloser(strings.NewReader("missing")), Header: make(http.Header), Request: req}, nil
		}
		return &http.Response{StatusCode: http.StatusOK, Status: "200 OK", Body: io.NopCloser(strings.NewReader(string(b))), Header: make(http.Header), Request: req}, nil
	})}
	cfg := filepath.Join(tmp, "letsencrypt")
	a := New(Config{AllowMutations: true, CertificationMode: true, ACMEConfigDir: cfg, HTTPClient: client})
	got, err := a.IssueLetsEncryptWebroot(context.Background(), "mail.example.test", root, "hostmaster@example.test")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(got.Fullchain, "mail.example.test-0001/fullchain.pem") || !strings.Contains(got.Privkey, "mail.example.test-0001/privkey.pem") {
		t.Fatalf("suffixed lineage was not resolved: %+v", got)
	}
}
