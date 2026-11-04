package api

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"privora.local/panel/agent/internal/audit"
	"privora.local/panel/agent/internal/config"
	"privora.local/panel/agent/internal/hostadapter"
	"privora.local/panel/agent/internal/hosting"
	"privora.local/panel/agent/internal/resources"
	"privora.local/panel/agent/internal/runner"
)

const testToken = "test-agent-token"

func newTestServer(t *testing.T) *Server {
	t.Helper()
	dir := t.TempDir()
	cfg := config.Config{Mock: true, AgentToken: testToken, AuditPath: dir + "/audit.jsonl", StatePath: dir + "/state.json", MockRoot: dir + "/root", AllowedServices: map[string]bool{"nginx": true}}
	return New(cfg, runner.NewMockRunner(), audit.New(cfg.AuditPath))
}
func req(method, path, body string) *http.Request {
	r := httptest.NewRequest(method, path, strings.NewReader(body))
	ts := time.Now().UTC().Format(time.RFC3339)
	nonce := fmt.Sprintf("nonce-%d", time.Now().UnixNano())
	mac := hmac.New(sha256.New, []byte(testToken))
	_, _ = mac.Write(signaturePayload(method, path, ts, nonce, []byte(body)))
	r.Header.Set("X-Privora-Timestamp", ts)
	r.Header.Set("X-Privora-Nonce", nonce)
	r.Header.Set("X-Privora-Signature", hex.EncodeToString(mac.Sum(nil)))
	r.Header.Set("X-Privora-Actor", "admin:test")
	r.Header.Set("X-Privora-Request-ID", "req-test")
	if body != "" {
		r.Header.Set("Content-Type", "application/json")
	}
	return r
}
func TestRequiresAgentAuthentication(t *testing.T) {
	s := newTestServer(t)
	r := httptest.NewRequest(http.MethodGet, "/v1/health", nil)
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, r)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("wanted 401, got %d", w.Code)
	}
}
func TestHealth(t *testing.T) {
	s := newTestServer(t)
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, req(http.MethodGet, "/v1/health", ""))
	if w.Code != 200 || !strings.Contains(w.Body.String(), `"ok":true`) {
		t.Fatalf("unexpected response: %d %s", w.Code, w.Body.String())
	}
}
func TestRejectsUnknownService(t *testing.T) {
	s := newTestServer(t)
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, req(http.MethodPost, "/v1/services/not-real/restart", ""))
	if w.Code != 403 {
		t.Fatalf("wanted 403, got %d", w.Code)
	}
}
func TestRestartAllowListedService(t *testing.T) {
	dir := t.TempDir()
	cfg := config.Config{Mock: true, AgentToken: testToken, AuditPath: dir + "/audit.jsonl", StatePath: dir + "/state.json", MockRoot: dir + "/root", AllowedServices: map[string]bool{"nginx": true}}
	s := New(cfg, runner.NewMockRunner(), audit.New(cfg.AuditPath))
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, req(http.MethodPost, "/v1/services/nginx/restart", ""))
	if w.Code != 200 {
		t.Fatalf("wanted 200, got %d: %s", w.Code, w.Body.String())
	}
	data, err := os.ReadFile(cfg.AuditPath)
	if err != nil || !strings.Contains(string(data), `"operation":"service.restart"`) || !strings.Contains(string(data), `"actor":"admin:test"`) {
		t.Fatalf("audit missing: %v %s", err, data)
	}
}
func TestHostingAccountAndSitePHP(t *testing.T) {
	s := newTestServer(t)
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, req(http.MethodPost, "/v1/hosting/accounts", `{"username":"acmeweb","primary_domain":"acme.test","package":"Business"}`))
	if w.Code != 201 {
		t.Fatalf("account create failed: %d %s", w.Code, w.Body.String())
	}
	w = httptest.NewRecorder()
	s.Handler().ServeHTTP(w, req(http.MethodPost, "/v1/sites", `{"domain":"www.acme.test","username":"acmeweb","php_version":"8.4"}`))
	if w.Code != 201 || !strings.Contains(w.Body.String(), `"ssl":{"domain":"www.acme.test"`) || !strings.Contains(w.Body.String(), `"status":"valid"`) {
		t.Fatalf("site create/automatic SSL failed: %d %s", w.Code, w.Body.String())
	}
	w = httptest.NewRecorder()
	s.Handler().ServeHTTP(w, req(http.MethodPost, "/v1/sites/www.acme.test/php", `{"version":"8.5"}`))
	if w.Code != 200 || !strings.Contains(w.Body.String(), `"php_version":"8.5"`) {
		t.Fatalf("php switch failed: %d %s", w.Code, w.Body.String())
	}
}
func TestSubdomainCreateUsesParentSiteAndParentDNSZone(t *testing.T) {
	s := newTestServer(t)
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, req(http.MethodPost, "/v1/hosting/accounts", `{"username":"subacct","primary_domain":"example.test","package":"Business"}`))
	if w.Code != 201 {
		t.Fatalf("account create failed: %d %s", w.Code, w.Body.String())
	}
	w = httptest.NewRecorder()
	s.Handler().ServeHTTP(w, req(http.MethodPost, "/v1/sites", `{"domain":"example.test","username":"subacct","php_version":"8.4"}`))
	if w.Code != 201 {
		t.Fatalf("parent site create failed: %d %s", w.Code, w.Body.String())
	}
	w = httptest.NewRecorder()
	s.Handler().ServeHTTP(w, req(http.MethodPost, "/v1/subdomains", `{"parent_domain":"example.test","label":"blog","username":"subacct","php_version":"8.4"}`))
	if w.Code != 201 || !strings.Contains(w.Body.String(), `"domain":"blog.example.test"`) || !strings.Contains(w.Body.String(), `"kind":"subdomain"`) || !strings.Contains(w.Body.String(), `"parent_domain":"example.test"`) || !strings.Contains(w.Body.String(), `"status":"valid"`) {
		t.Fatalf("subdomain create failed: %d %s", w.Code, w.Body.String())
	}
	if s.resources.HasDNSZone("blog.example.test") {
		t.Fatal("subdomain creation must not create an independent DNS zone")
	}
	foundA := false
	for _, zone := range s.resources.ListDNSZones() {
		if zone.Domain != "example.test" {
			continue
		}
		for _, rec := range zone.Records {
			if rec.Type == "A" && rec.Name == "blog" {
				foundA = true
			}
		}
	}
	if !foundA {
		t.Fatal("expected blog A record in parent DNS zone")
	}
	w = httptest.NewRecorder()
	s.Handler().ServeHTTP(w, req(http.MethodDelete, "/v1/sites/blog.example.test", `{"delete_dns":true,"delete_files":false}`))
	if w.Code != 200 {
		t.Fatalf("subdomain delete failed: %d %s", w.Code, w.Body.String())
	}
	if !s.resources.HasDNSZone("example.test") {
		t.Fatal("deleting a subdomain must preserve the parent DNS zone")
	}
	for _, zone := range s.resources.ListDNSZones() {
		if zone.Domain != "example.test" {
			continue
		}
		for _, rec := range zone.Records {
			if rec.Name == "blog" && (rec.Type == "A" || rec.Type == "AAAA") {
				t.Fatalf("subdomain DNS record was not removed: %+v", rec)
			}
		}
	}
}

func TestGenericSiteCreateUsesExistingParentDNSZoneForChildHostname(t *testing.T) {
	s := newTestServer(t)
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, req(http.MethodPost, "/v1/hosting/accounts", `{"username":"childacct","primary_domain":"example.test","package":"Business"}`))
	if w.Code != 201 {
		t.Fatalf("account create failed: %d %s", w.Code, w.Body.String())
	}
	w = httptest.NewRecorder()
	s.Handler().ServeHTTP(w, req(http.MethodPost, "/v1/sites", `{"domain":"example.test","username":"childacct","php_version":"8.4"}`))
	if w.Code != 201 {
		t.Fatalf("parent site create failed: %d %s", w.Code, w.Body.String())
	}
	w = httptest.NewRecorder()
	s.Handler().ServeHTTP(w, req(http.MethodPost, "/v1/sites", `{"domain":"demo.example.test","username":"childacct","php_version":"8.4"}`))
	if w.Code != 201 || !strings.Contains(w.Body.String(), `"kind":"subdomain"`) || !strings.Contains(w.Body.String(), `"parent_domain":"example.test"`) || !strings.Contains(w.Body.String(), `"status":"managed-parent-zone"`) {
		t.Fatalf("generic child-site DNS routing failed: %d %s", w.Code, w.Body.String())
	}
	if s.resources.HasDNSZone("demo.example.test") {
		t.Fatal("generic child hostname must not create an independent DNS zone")
	}
	foundA := false
	for _, zone := range s.resources.ListDNSZones() {
		if zone.Domain != "example.test" {
			continue
		}
		for _, rec := range zone.Records {
			if rec.Type == "A" && rec.Name == "demo" {
				foundA = true
			}
		}
	}
	if !foundA {
		t.Fatal("expected demo A record in existing parent zone")
	}
}

func TestRepairHostedDNSCreatesMissingRootZoneAndRepairsChildClassification(t *testing.T) {
	s := newTestServer(t)
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, req(http.MethodPost, "/v1/hosting/accounts", `{"username":"repairacct","primary_domain":"repair.test","package":"Business"}`))
	if w.Code != 201 {
		t.Fatalf("account create failed: %d %s", w.Code, w.Body.String())
	}
	root, err := s.hosting.CreateSite(hosting.Site{Domain: "repair.test", Username: "repairacct", PHPVersion: "8.4"})
	if err != nil {
		t.Fatal(err)
	}
	_ = root
	child, err := s.hosting.CreateSite(hosting.Site{Domain: "demo.repair.test", Username: "repairacct", PHPVersion: "8.4"})
	if err != nil {
		t.Fatal(err)
	}
	_ = child
	if s.resources.HasDNSZone("repair.test") {
		t.Fatal("test setup unexpectedly has root DNS zone")
	}
	w = httptest.NewRecorder()
	s.Handler().ServeHTTP(w, req(http.MethodPost, "/v1/dns/repair-hosted", `{}`))
	if w.Code != 200 || !strings.Contains(w.Body.String(), `"repaired":2`) {
		t.Fatalf("hosted DNS repair failed: %d %s", w.Code, w.Body.String())
	}
	if !s.resources.HasDNSZone("repair.test") {
		t.Fatal("repair did not create missing root DNS zone")
	}
	if s.resources.HasDNSZone("demo.repair.test") {
		t.Fatal("repair must not create independent child DNS zone")
	}
	got, ok := s.hosting.GetSite("demo.repair.test")
	if !ok || got.Kind != "subdomain" || got.ParentDomain != "repair.test" {
		t.Fatalf("repair did not fix child classification: %+v", got)
	}
}

func TestConfiguredInBailiwickNameserverGlueIsAddedToNewRootZone(t *testing.T) {
	ns := resources.NameserverConfig{BaseDomain: "privoralabs.com", Primary: "ns1.privoralabs.com", Secondary: "ns2.privoralabs.com"}
	hostRows, stateRows := standardSiteDNSRecords("privoralabs.com", "203.0.113.25", "", false)
	hostRows, stateRows = ensureConfiguredNameserverGlue("privoralabs.com", "203.0.113.25", "", ns, hostRows, stateRows)
	seen := map[string]bool{}
	for _, rec := range hostRows {
		seen[strings.ToLower(rec.Name)+"|"+strings.ToUpper(rec.Type)+"|"+rec.Value] = true
	}
	for _, want := range []string{"ns1|A|203.0.113.25", "ns2|A|203.0.113.25"} {
		if !seen[want] {
			t.Fatalf("missing in-bailiwick glue %s; rows=%+v", want, hostRows)
		}
	}
	if len(stateRows) != len(hostRows) {
		t.Fatalf("state/host record mismatch: %d != %d", len(stateRows), len(hostRows))
	}
}

func TestConfiguredExternalNameserversDoNotInjectForeignGlue(t *testing.T) {
	ns := resources.NameserverConfig{BaseDomain: "hosting.example", Primary: "ns1.hosting.example", Secondary: "ns2.hosting.example"}
	hostRows, _ := standardSiteDNSRecords("customer.test", "203.0.113.25", "", false)
	hostRows, _ = ensureConfiguredNameserverGlue("customer.test", "203.0.113.25", "", ns, hostRows, nil)
	for _, rec := range hostRows {
		if strings.HasPrefix(strings.ToLower(rec.Name), "ns1") || strings.HasPrefix(strings.ToLower(rec.Name), "ns2") {
			t.Fatalf("foreign nameserver glue leaked into customer zone: %+v", rec)
		}
	}
}

func TestLongestHostedParentUsesExistingZone(t *testing.T) {
	roots := map[string]bool{"privategather.com": true, "privoralabs.org": true}
	if got := longestHostedParent("demo.privategather.com", roots); got != "privategather.com" {
		t.Fatalf("parent=%q", got)
	}
	if got := longestHostedParent("downloads.privoralabs.org", roots); got != "privoralabs.org" {
		t.Fatalf("parent=%q", got)
	}
	if got := longestHostedParent("privoralabs.com", roots); got != "" {
		t.Fatalf("unexpected parent=%q", got)
	}
}

func TestNormalizeSubdomainPrefixAcceptsOneLabelOnly(t *testing.T) {
	if got, err := normalizeSubdomainPrefix("Blog"); err != nil || got != "blog" {
		t.Fatalf("single-label subdomain normalization failed: got=%q err=%v", got, err)
	}
	for _, bad := range []string{"shop.eu", "blog.example.test", "-blog", "blog-"} {
		if _, err := normalizeSubdomainPrefix(bad); err == nil {
			t.Fatalf("expected invalid single-label subdomain %q to be rejected", bad)
		}
	}
}

func TestSubdomainCreateRejectsDifferentParentOwner(t *testing.T) {
	s := newTestServer(t)
	for _, body := range []string{
		`{"username":"ownerone","primary_domain":"one.test","package":"Starter"}`,
		`{"username":"ownertwo","primary_domain":"two.test","package":"Starter"}`,
	} {
		w := httptest.NewRecorder()
		s.Handler().ServeHTTP(w, req(http.MethodPost, "/v1/hosting/accounts", body))
		if w.Code != 201 {
			t.Fatalf("account setup failed: %d %s", w.Code, w.Body.String())
		}
	}
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, req(http.MethodPost, "/v1/sites", `{"domain":"one.test","username":"ownerone","php_version":"8.4"}`))
	if w.Code != 201 {
		t.Fatalf("parent setup failed: %d %s", w.Code, w.Body.String())
	}
	w = httptest.NewRecorder()
	s.Handler().ServeHTTP(w, req(http.MethodPost, "/v1/subdomains", `{"parent_domain":"one.test","label":"blog","username":"ownertwo","php_version":"8.4"}`))
	if w.Code != 409 || !strings.Contains(w.Body.String(), "same hosting owner") {
		t.Fatalf("wanted owner mismatch rejection, got %d %s", w.Code, w.Body.String())
	}
}

func TestRejectsTraversalLikeDomain(t *testing.T) {
	s := newTestServer(t)
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, req(http.MethodPost, "/v1/hosting/accounts", `{"username":"safeusr","primary_domain":"safe.test","package":"Starter"}`))
	if w.Code != 201 {
		t.Fatalf("setup failed: %d %s", w.Code, w.Body.String())
	}
	w = httptest.NewRecorder()
	s.Handler().ServeHTTP(w, req(http.MethodPost, "/v1/sites", `{"domain":"../../etc/passwd","username":"safeusr","php_version":"8.4"}`))
	if w.Code != 400 {
		t.Fatalf("wanted 400, got %d: %s", w.Code, w.Body.String())
	}
}

func TestProductionClassResourceModels(t *testing.T) {
	s := newTestServer(t)
	cases := []struct{ path, body, needle string }{
		{"/v1/databases", `{"name":"acme_app","engine":"mariadb","owner":"acmeweb"}`, `"status":"ready"`},
		{"/v1/dns/zones", `{"domain":"acme.test","dnssec":true}`, `"domain":"acme.test"`},
		{"/v1/ssl/issue", `{"domain":"www.acme.test"}`, `"status":"valid"`},
		{"/v1/backups", `{"scope":"site","resource":"www.acme.test","destination":"local"}`, `"status":"verified"`},
		{"/v1/mailboxes", `{"address":"admin@acme.test","quota_mb":2048,"password":"A-Strong-Test-Password-2026!"}`, `"status":"active"`},
		{"/v1/resellers", `{"name":"partner1","company":"Acme Hosting","max_accounts":50}`, `"status":"active"`},
	}
	for _, tc := range cases {
		w := httptest.NewRecorder()
		s.Handler().ServeHTTP(w, req(http.MethodPost, tc.path, tc.body))
		if w.Code != 201 || !strings.Contains(w.Body.String(), tc.needle) {
			t.Fatalf("%s failed: %d %s", tc.path, w.Code, w.Body.String())
		}
	}
}

func TestDatabaseCredentialLifecycleIsOneTimeAndManageable(t *testing.T) {
	s := newTestServer(t)
	chosen := "Strong-Database-Pass-2026!"
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, req(http.MethodPost, "/v1/databases", `{"name":"portal_db","user":"portal_user","engine":"mariadb","owner":"portalweb","password":"`+chosen+`"}`))
	if w.Code != http.StatusCreated || !strings.Contains(w.Body.String(), `"user":"portal_user"`) || !strings.Contains(w.Body.String(), `"password":"`+chosen+`"`) || !strings.Contains(w.Body.String(), `"secret_once":true`) {
		t.Fatalf("database create credentials missing: %d %s", w.Code, w.Body.String())
	}
	w = httptest.NewRecorder()
	s.Handler().ServeHTTP(w, req(http.MethodGet, "/v1/databases", ""))
	if w.Code != http.StatusOK || strings.Contains(w.Body.String(), chosen) {
		t.Fatalf("plaintext database password leaked into inventory: %d %s", w.Code, w.Body.String())
	}

	w = httptest.NewRecorder()
	s.Handler().ServeHTTP(w, req(http.MethodPost, "/v1/databases/portal_db/user", `{"user":"portal_login","password":"Replacement-Pass-2026!"}`))
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), `"user":"portal_login"`) || !strings.Contains(w.Body.String(), `"password":"Replacement-Pass-2026!"`) {
		t.Fatalf("database user edit failed: %d %s", w.Code, w.Body.String())
	}

	w = httptest.NewRecorder()
	s.Handler().ServeHTTP(w, req(http.MethodPost, "/v1/databases/portal_db/password", `{}`))
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), `"generated":true`) || !strings.Contains(w.Body.String(), `"secret_once":true`) {
		t.Fatalf("database password reset failed: %d %s", w.Code, w.Body.String())
	}

	w = httptest.NewRecorder()
	s.Handler().ServeHTTP(w, req(http.MethodDelete, "/v1/databases/portal_db?confirm=wrong", ""))
	if w.Code != http.StatusBadRequest {
		t.Fatalf("database delete accepted wrong confirmation: %d %s", w.Code, w.Body.String())
	}
	w = httptest.NewRecorder()
	s.Handler().ServeHTTP(w, req(http.MethodDelete, "/v1/databases/portal_db?confirm=portal_db", ""))
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), `"ok":true`) {
		t.Fatalf("database delete failed: %d %s", w.Code, w.Body.String())
	}
}

func TestFuturePlatformSimulationIsExplicit(t *testing.T) {
	s := newTestServer(t)
	cases := []struct{ path, body, needle string }{
		{"/v1/fleet/nodes", `{"name":"web01","role":"web","region":"us-central","endpoint":"https://node.invalid"}`, `"simulation":true`},
		{"/v1/cloud/instances", `{"provider":"mock","region":"us-central","size":"small","image":"ubuntu-lts"}`, `"simulation":true`},
		{"/v1/fabric/workloads", `{"name":"frontend","type":"web","region":"us-central","desired_replicas":2}`, `"simulation":true`},
	}
	for _, tc := range cases {
		w := httptest.NewRecorder()
		s.Handler().ServeHTTP(w, req(http.MethodPost, tc.path, tc.body))
		if w.Code != 201 || !strings.Contains(w.Body.String(), tc.needle) {
			t.Fatalf("%s failed: %d %s", tc.path, w.Code, w.Body.String())
		}
	}
}

func TestAutomationProvisionSimulation(t *testing.T) {
	s := newTestServer(t)
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, req(http.MethodPost, "/v1/automation/provision", `{"customer":"buyer@example.test","username":"buyerweb","domain":"buyer.test","package":"Starter","php_version":"8.4"}`))
	if w.Code != 201 || !strings.Contains(w.Body.String(), `"simulation":true`) || !strings.Contains(w.Body.String(), `"status":"simulated-complete"`) {
		t.Fatalf("automation failed: %d %s", w.Code, w.Body.String())
	}
}

func TestSafeMockFileManager(t *testing.T) {
	s := newTestServer(t)
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, req(http.MethodPost, "/v1/hosting/accounts", `{"username":"filesusr","primary_domain":"files.test","package":"Starter"}`))
	if w.Code != 201 {
		t.Fatalf("account failed: %s", w.Body.String())
	}
	w = httptest.NewRecorder()
	s.Handler().ServeHTTP(w, req(http.MethodPost, "/v1/files/filesusr/write", `{"path":"notes/readme.txt","content":"hello Privora"}`))
	if w.Code != 201 {
		t.Fatalf("file write failed: %d %s", w.Code, w.Body.String())
	}
	w = httptest.NewRecorder()
	s.Handler().ServeHTTP(w, req(http.MethodGet, "/v1/files/filesusr?path=notes", ""))
	if w.Code != 200 || !strings.Contains(w.Body.String(), `"readme.txt"`) {
		t.Fatalf("file list failed: %d %s", w.Code, w.Body.String())
	}
	w = httptest.NewRecorder()
	s.Handler().ServeHTTP(w, req(http.MethodPost, "/v1/files/filesusr/write", `{"path":"../../escape","content":"no"}`))
	if w.Code != 400 {
		t.Fatalf("traversal should fail: %d %s", w.Code, w.Body.String())
	}
}

func TestSFTPFirewallAndApplicationModels(t *testing.T) {
	s := newTestServer(t)
	cases := []struct{ path, body, needle string }{
		{"/v1/sftp", `{"username":"deploy1","owner":"acmeweb","root":"/home/acmeweb","auth":"ssh-key"}`, `"status":"active"`},
		{"/v1/firewall/rules", `{"direction":"inbound","protocol":"tcp","port":443,"source":"0.0.0.0/0","action":"allow"}`, `"simulation":true`},
		{"/v1/applications", `{"type":"laravel","domain":"app.acme.test","owner":"acmeweb","runtime":"php8.4"}`, `"simulation":true`},
	}
	for _, tc := range cases {
		w := httptest.NewRecorder()
		s.Handler().ServeHTTP(w, req(http.MethodPost, tc.path, tc.body))
		if w.Code != 201 || !strings.Contains(w.Body.String(), tc.needle) {
			t.Fatalf("%s failed: %d %s", tc.path, w.Code, w.Body.String())
		}
	}
}

func TestLiveProductionAccountProvision(t *testing.T) {
	if os.Getenv("PRIVORA_LIVE_HOST_TEST") != "1" {
		t.Skip("set PRIVORA_LIVE_HOST_TEST=1 for destructive sandbox certification")
	}
	if os.Geteuid() != 0 {
		t.Skip("requires root sandbox")
	}
	mid, err := os.ReadFile("/etc/machine-id")
	if err != nil {
		t.Fatal(err)
	}
	h := sha256.Sum256([]byte(strings.TrimSpace(string(mid))))
	dir := t.TempDir()
	cert := dir + "/host-cert.json"
	evidence := fmt.Sprintf(`{"profile":"privora-panel-host-adapter-certification-v1","status":"PASS","machine_id_sha256":"%s","certified_adapters":["linux-users","nginx"]}`, hex.EncodeToString(h[:]))
	if err := os.WriteFile(cert, []byte(evidence), 0600); err != nil {
		t.Fatal(err)
	}
	username := fmt.Sprintf("pvapi%d", time.Now().UnixNano()%1000000)
	cleanup := func() { _ = exec.Command("userdel", "--remove", username).Run() }
	cleanup()
	defer cleanup()
	cfg := config.Config{Mock: false, HostMutations: true, HostCertificationPath: cert, AgentToken: testToken, AuditPath: dir + "/audit.jsonl", StatePath: dir + "/state.json", MockRoot: dir + "/root", AllowedServices: map[string]bool{"nginx": true}}
	s := New(cfg, runner.NewMockRunner(), audit.New(cfg.AuditPath))
	w := httptest.NewRecorder()
	body := fmt.Sprintf(`{"username":"%s","primary_domain":"live.test","package":"Starter"}`, username)
	s.Handler().ServeHTTP(w, req(http.MethodPost, "/v1/hosting/accounts", body))
	if w.Code != 201 {
		t.Fatalf("real API account provision failed: %d %s", w.Code, w.Body.String())
	}
	if out, err := exec.Command("id", username).CombinedOutput(); err != nil {
		t.Fatalf("OS user missing: %v %s", err, out)
	}
	w = httptest.NewRecorder()
	s.Handler().ServeHTTP(w, req(http.MethodPost, "/v1/hosting/accounts/"+username+"/suspend", "{}"))
	if w.Code != 200 || !strings.Contains(w.Body.String(), `"status":"suspended"`) {
		t.Fatalf("real API suspend failed: %d %s", w.Code, w.Body.String())
	}
	w = httptest.NewRecorder()
	s.Handler().ServeHTTP(w, req(http.MethodPost, "/v1/hosting/accounts/"+username+"/unsuspend", "{}"))
	if w.Code != 200 || !strings.Contains(w.Body.String(), `"status":"active"`) {
		t.Fatalf("real API unsuspend failed: %d %s", w.Code, w.Body.String())
	}
}

func TestLiveProductionAccountBackup(t *testing.T) {
	if os.Getenv("PRIVORA_LIVE_HOST_TEST") != "1" {
		t.Skip("set PRIVORA_LIVE_HOST_TEST=1 for destructive sandbox certification")
	}
	if os.Geteuid() != 0 {
		t.Skip("requires root sandbox")
	}
	mid, err := os.ReadFile("/etc/machine-id")
	if err != nil {
		t.Fatal(err)
	}
	h := sha256.Sum256([]byte(strings.TrimSpace(string(mid))))
	dir := t.TempDir()
	cert := dir + "/host-cert.json"
	evidence := fmt.Sprintf(`{"profile":"privora-panel-host-adapter-certification-v1","status":"PASS","machine_id_sha256":"%s","certified_adapters":["linux-users","nginx","local-backup"]}`, hex.EncodeToString(h[:]))
	if err := os.WriteFile(cert, []byte(evidence), 0600); err != nil {
		t.Fatal(err)
	}
	username := fmt.Sprintf("pvbkp%d", time.Now().UnixNano()%1000000)
	cleanup := func() { _ = exec.Command("userdel", "--remove", username).Run() }
	cleanup()
	defer cleanup()
	cfg := config.Config{Mock: false, HostMutations: true, HostCertificationPath: cert, BackupRoot: dir + "/backups", AgentToken: testToken, AuditPath: dir + "/audit.jsonl", StatePath: dir + "/state.json", AllowedServices: map[string]bool{"nginx": true}}
	s := New(cfg, runner.NewMockRunner(), audit.New(cfg.AuditPath))
	w := httptest.NewRecorder()
	body := fmt.Sprintf(`{"username":"%s","primary_domain":"backup.test","package":"Starter"}`, username)
	s.Handler().ServeHTTP(w, req(http.MethodPost, "/v1/hosting/accounts", body))
	if w.Code != 201 {
		t.Fatalf("account=%d %s", w.Code, w.Body.String())
	}
	if err := os.WriteFile("/home/"+username+"/backup-proof.txt", []byte("privora-real-backup"), 0640); err != nil {
		t.Fatal(err)
	}
	w = httptest.NewRecorder()
	b := fmt.Sprintf(`{"scope":"account","resource":"%s","destination":"local"}`, username)
	s.Handler().ServeHTTP(w, req(http.MethodPost, "/v1/backups", b))
	if w.Code != 201 || !strings.Contains(w.Body.String(), "verified-real-local") {
		t.Fatalf("backup=%d %s", w.Code, w.Body.String())
	}
	matches, err := filepath.Glob(dir + "/backups/*.tar.zst")
	if err != nil || len(matches) != 1 {
		t.Fatalf("backup artifact missing: %v %v", err, matches)
	}
}

func TestLiveProductionAccountFiles(t *testing.T) {
	if os.Getenv("PRIVORA_LIVE_HOST_TEST") != "1" {
		t.Skip("set PRIVORA_LIVE_HOST_TEST=1 for destructive sandbox certification")
	}
	if os.Geteuid() != 0 {
		t.Skip("requires root sandbox")
	}
	mid, err := os.ReadFile("/etc/machine-id")
	if err != nil {
		t.Fatal(err)
	}
	h := sha256.Sum256([]byte(strings.TrimSpace(string(mid))))
	dir := t.TempDir()
	cert := dir + "/host-cert.json"
	evidence := fmt.Sprintf(`{"profile":"privora-panel-host-adapter-certification-v1","status":"PASS","machine_id_sha256":"%s","certified_adapters":["linux-users","nginx"]}`, hex.EncodeToString(h[:]))
	if err := os.WriteFile(cert, []byte(evidence), 0600); err != nil {
		t.Fatal(err)
	}
	username := fmt.Sprintf("pvfile%d", time.Now().UnixNano()%1000000)
	cleanup := func() { _ = exec.Command("userdel", "--remove", username).Run() }
	cleanup()
	defer cleanup()
	cfg := config.Config{Mock: false, HostMutations: true, HostCertificationPath: cert, AgentToken: testToken, AuditPath: dir + "/audit.jsonl", StatePath: dir + "/state.json", AllowedServices: map[string]bool{"nginx": true}}
	s := New(cfg, runner.NewMockRunner(), audit.New(cfg.AuditPath))
	w := httptest.NewRecorder()
	body := fmt.Sprintf(`{"username":"%s","primary_domain":"files.test","package":"Starter"}`, username)
	s.Handler().ServeHTTP(w, req(http.MethodPost, "/v1/hosting/accounts", body))
	if w.Code != 201 {
		t.Fatalf("account=%d %s", w.Code, w.Body.String())
	}
	w = httptest.NewRecorder()
	s.Handler().ServeHTTP(w, req(http.MethodPost, "/v1/files/"+username+"/write", `{"path":"domains/files.test/public/index.html","content":"privora-live-file"}`))
	if w.Code != 201 {
		t.Fatalf("write=%d %s", w.Code, w.Body.String())
	}
	w = httptest.NewRecorder()
	s.Handler().ServeHTTP(w, req(http.MethodGet, "/v1/files/"+username+"?path=domains/files.test/public", ""))
	if w.Code != 200 || !strings.Contains(w.Body.String(), "index.html") {
		t.Fatalf("list=%d %s", w.Code, w.Body.String())
	}
	outside := t.TempDir()
	if err := os.Symlink(outside, "/home/"+username+"/domains/escape"); err != nil {
		t.Fatal(err)
	}
	w = httptest.NewRecorder()
	s.Handler().ServeHTTP(w, req(http.MethodPost, "/v1/files/"+username+"/write", `{"path":"domains/escape/pwned","content":"x"}`))
	if w.Code == 201 {
		t.Fatalf("symlink escape unexpectedly succeeded: %s", w.Body.String())
	}
	if _, err := os.Stat(filepath.Join(outside, "pwned")); !os.IsNotExist(err) {
		t.Fatal("outside file created through symlink")
	}
}

func TestCreateSiteAutoSelectsSingleDetectedOwnerInMock(t *testing.T) {
	s := newTestServer(t)
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, req(http.MethodPost, "/v1/hosting/accounts", `{"username":"singleusr","primary_domain":"single.test","package":"Business"}`))
	if w.Code != 201 {
		t.Fatalf("account create failed: %d %s", w.Code, w.Body.String())
	}
	w = httptest.NewRecorder()
	s.Handler().ServeHTTP(w, req(http.MethodPost, "/v1/sites", `{"domain":"www.single.test","username":"","php_version":"8.4"}`))
	if w.Code != 201 || !strings.Contains(w.Body.String(), `"username":"singleusr"`) {
		t.Fatalf("auto owner site create failed: %d %s", w.Code, w.Body.String())
	}
}

func TestAutomaticSiteUsername(t *testing.T) {
	if got := automaticSiteUsername("Example-Shop.test"); got != "exampleshopweb" {
		t.Fatalf("got %q", got)
	}
}

func TestDuplicateSiteRejectedAndDeletePreservesFilesByDefault(t *testing.T) {
	s := newTestServer(t)
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, req(http.MethodPost, "/v1/hosting/accounts", `{"username":"dupeweb","primary_domain":"dupe.test","package":"Starter"}`))
	if w.Code != 201 {
		t.Fatalf("account create failed: %d %s", w.Code, w.Body.String())
	}
	w = httptest.NewRecorder()
	s.Handler().ServeHTTP(w, req(http.MethodPost, "/v1/sites", `{"domain":"dupe.test","username":"dupeweb","php_version":"8.4"}`))
	if w.Code != 201 {
		t.Fatalf("site create failed: %d %s", w.Code, w.Body.String())
	}
	index := filepath.Join(s.cfg.MockRoot, "home", "dupeweb", "domains", "dupe.test", "public", "index.html")
	before, err := os.ReadFile(index)
	if err != nil {
		t.Fatal(err)
	}
	w = httptest.NewRecorder()
	s.Handler().ServeHTTP(w, req(http.MethodPost, "/v1/sites", `{"domain":"dupe.test","username":"dupeweb","php_version":"8.4"}`))
	if w.Code != http.StatusConflict || !strings.Contains(w.Body.String(), `"duplicate":true`) {
		t.Fatalf("duplicate was not rejected atomically: %d %s", w.Code, w.Body.String())
	}
	after, err := os.ReadFile(index)
	if err != nil {
		t.Fatal(err)
	}
	if string(after) != string(before) {
		t.Fatal("duplicate create mutated existing website content")
	}
	w = httptest.NewRecorder()
	s.Handler().ServeHTTP(w, req(http.MethodDelete, "/v1/sites/dupe.test", `{"delete_files":false,"delete_dns":true}`))
	if w.Code != 200 {
		t.Fatalf("delete failed: %d %s", w.Code, w.Body.String())
	}
	if _, err := os.Stat(index); err != nil {
		t.Fatalf("default website delete removed files: %v", err)
	}
	w = httptest.NewRecorder()
	s.Handler().ServeHTTP(w, req(http.MethodGet, "/v1/sites", ""))
	if w.Code != 200 || strings.Contains(w.Body.String(), `"domain":"dupe.test"`) {
		t.Fatalf("deleted website remains registered: %d %s", w.Code, w.Body.String())
	}
}

func TestDNSZoneRecordCRUD(t *testing.T) {
	s := newTestServer(t)
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, req(http.MethodPost, "/v1/dns/zones", `{"domain":"records.test","dnssec":false}`))
	if w.Code != 201 {
		t.Fatalf("zone create failed: %d %s", w.Code, w.Body.String())
	}
	w = httptest.NewRecorder()
	s.Handler().ServeHTTP(w, req(http.MethodPost, "/v1/dns/zones/records.test/records", `{"type":"A","name":"app","value":"203.0.113.25","ttl":300}`))
	if w.Code != 200 || !strings.Contains(w.Body.String(), `"name":"app"`) {
		t.Fatalf("record upsert failed: %d %s", w.Code, w.Body.String())
	}
	w = httptest.NewRecorder()
	s.Handler().ServeHTTP(w, req(http.MethodGet, "/v1/dns/zones/records.test", ""))
	if w.Code != 200 || !strings.Contains(w.Body.String(), `"value":"203.0.113.25"`) {
		t.Fatalf("zone detail missing record: %d %s", w.Code, w.Body.String())
	}
	w = httptest.NewRecorder()
	s.Handler().ServeHTTP(w, req(http.MethodDelete, "/v1/dns/zones/records.test/records", `{"type":"A","name":"app","value":"203.0.113.25","ttl":300}`))
	if w.Code != 200 || strings.Contains(w.Body.String(), `"name":"app"`) {
		t.Fatalf("record delete failed: %d %s", w.Code, w.Body.String())
	}
	w = httptest.NewRecorder()
	s.Handler().ServeHTTP(w, req(http.MethodDelete, "/v1/dns/zones/records.test", ""))
	if w.Code != 200 {
		t.Fatalf("zone delete failed: %d %s", w.Code, w.Body.String())
	}
}

func TestMergeWebsiteInventoryKeepsRecordedAndPrimaryDomainsVisible(t *testing.T) {
	live := []hostadapter.LiveSite{{Domain: "live.test", Username: "acctone", PHPVersion: "8.4", SSL: "configured", Enabled: true}}
	recorded := []hosting.Site{{Domain: "recorded.test", Username: "accttwo", PHPVersion: "8.3", SSL: "configured", DNS: "managed", Status: "active"}}
	accounts := []hosting.Account{{Username: "acctone", PrimaryDomain: "live.test"}, {Username: "accttwo", PrimaryDomain: "recorded.test"}, {Username: "acctthree", PrimaryDomain: "primary-only.test"}}
	got := mergeWebsiteInventory(live, recorded, accounts, map[string]bool{"live.test": true})
	byDomain := map[string]hosting.Site{}
	for _, site := range got {
		byDomain[site.Domain] = site
	}
	if byDomain["live.test"].Status != "active" {
		t.Fatalf("live website status = %q", byDomain["live.test"].Status)
	}
	if byDomain["recorded.test"].Status != "missing" {
		t.Fatalf("recorded website should remain visible as missing: %#v", byDomain["recorded.test"])
	}
	if byDomain["primary-only.test"].Status != "missing" || byDomain["primary-only.test"].Username != "acctthree" {
		t.Fatalf("primary domain fallback missing: %#v", byDomain["primary-only.test"])
	}
}

func TestRunPackageProbeHardDeadlineKillsProcessGroup(t *testing.T) {
	dir := t.TempDir()
	script := filepath.Join(dir, "stubborn-apt")
	body := "#!/bin/sh\n(sleep 30) &\nwait\n"
	if err := os.WriteFile(script, []byte(body), 0755); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 250*time.Millisecond)
	defer cancel()
	started := time.Now()
	_, err := runPackageProbe(ctx, script)
	elapsed := time.Since(started)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("wanted deadline exceeded, got %v", err)
	}
	if elapsed > 2*time.Second {
		t.Fatalf("hard deadline leaked descendant process pipes: %s", elapsed)
	}
}
