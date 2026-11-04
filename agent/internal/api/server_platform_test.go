package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func call(t *testing.T, s *Server, method, path, body string, want int, needles ...string) string {
	t.Helper()
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, req(method, path, body))
	if w.Code != want {
		t.Fatalf("%s %s wanted %d got %d: %s", method, path, want, w.Code, w.Body.String())
	}
	for _, n := range needles {
		if !strings.Contains(w.Body.String(), n) {
			t.Fatalf("%s missing %q: %s", path, n, w.Body.String())
		}
	}
	return w.Body.String()
}

func Test019To039OperationsTrain(t *testing.T) {
	s := newTestServer(t)
	cron := call(t, s, http.MethodPost, "/v1/tasks/cron", `{"owner":"acmeweb","schedule":"*/5 * * * *","command":"php artisan schedule:run"}`, 201, `"status":"scheduled"`)
	var c struct {
		CronJob struct {
			ID string `json:"id"`
		} `json:"cron_job"`
	}
	if err := json.Unmarshal([]byte(cron), &c); err != nil || c.CronJob.ID == "" {
		t.Fatalf("bad cron: %v %s", err, cron)
	}
	call(t, s, http.MethodPost, "/v1/tasks/cron/"+c.CronJob.ID+"/run", "", 200, `"simulated-success"`)
	call(t, s, http.MethodPost, "/v1/deployments", `{"kind":"laravel","domain":"app.acme.test","owner":"acmeweb","runtime":"php8.4","repository":"https://github.com/example/app.git","branch":"main"}`, 201, `"composer-install"`, `"simulation":true`)
	call(t, s, http.MethodGet, "/v1/apps/catalog", "", 200, `"slug":"wordpress"`, `"slug":"joomla"`, `"slug":"drupal"`, `"slug":"prestashop"`, `"slug":"nextcloud"`)
	call(t, s, http.MethodPost, "/v1/apps/installer/install", `{"template":"wordpress","domain":"app.acme.test","owner":"acmeweb","path":"blog"}`, 201, `"install-plan-ready-adapter-gated"`, `"provision-database-and-user"`, `"host_mutation":false`)
	call(t, s, http.MethodPost, "/v1/apps/installer/install", `{"template":"joomla","domain":"app.acme.test","owner":"acmeweb","path":"../../etc"}`, 400, `"invalid application install request"`)
	call(t, s, http.MethodPost, "/v1/mail/domains", `{"domain":"acme.test","owner":"acmeweb","dmarc":"reject","outbound_limit_per_hour":200}`, 201, `"dkim":true`, `"spf":true`)
	call(t, s, http.MethodPost, "/v1/mail/aliases", `{"address":"sales@acme.test","destination":"admin@acme.test","owner":"acmeweb"}`, 201, `"simulated-active"`)
	call(t, s, http.MethodPost, "/v1/mail/reputation/check", `{"target":"acme.test"}`, 201, `"score":92`)
	call(t, s, http.MethodPost, "/v1/security/bans", `{"service":"ssh","source":"203.0.113.20","reason":"brute force"}`, 201, `"simulated-blocked"`)
	call(t, s, http.MethodPost, "/v1/security/malware", `{"scope":"site","target":"app.acme.test"}`, 201, `"simulated-clean"`)
	call(t, s, http.MethodPost, "/v1/security/integrity", `{"scope":"site","target":"app.acme.test"}`, 201, `"simulated-pass"`)
	call(t, s, http.MethodPost, "/v1/security/ssh", `{"port":2222,"root_login":false,"password_auth":false,"allowed_cidrs":["203.0.113.0/24"]}`, 200, `"key_only":true`, `"host_mutation":false`)
	call(t, s, http.MethodPost, "/v1/monitoring/metrics", `{"cpu_percent":25.5,"memory_percent":42.1,"disk_percent":61.0,"load_1":0.8,"mail_queue":2,"php_busy_workers":4}`, 201, `"cpu_percent":25.5`)
	call(t, s, http.MethodPost, "/v1/monitoring/alerts", `{"name":"High CPU","metric":"cpu","operator":">=","threshold":90,"window_minutes":5,"severity":"critical"}`, 201, `"enabled":true`)
	call(t, s, http.MethodGet, "/v1/security/posture", "", 200, `"score":100`)
}

func Test040To069AdminAndMigrationTrain(t *testing.T) {
	s := newTestServer(t)
	call(t, s, http.MethodPost, "/v1/system/update-policy", `{"channel":"stable","security_auto":true,"package_auto":true,"major_versions_manual":true,"reboot_window":"Sun 03:00"}`, 200, `"security_auto":true`, `"package_auto":true`)
	call(t, s, http.MethodGet, "/v1/system/update-center", "", 200, `"signed_release_required":true`, `"automatic_timer":"privora-maintenance.timer"`, `"rollback_helper":"/usr/local/sbin/privora-update-rollback"`)
	call(t, s, http.MethodPost, "/v1/system/update-run", `{"mode":"security","channel":"stable","release_url":""}`, 202, `"status":"accepted"`, `"simulation":true`, `"apply-security-library-updates"`)
	call(t, s, http.MethodPost, "/v1/system/update-upload/prepare", `{"upload_path":"/mock/inbox/release.zip","original_name":"privora-panel-5.0.1.zip"}`, 201, `"root_reauth_required":true`, `"version":"5.0.0-dev.7.0"`)
	call(t, s, http.MethodPost, "/v1/system/update-upload/start", `{"upload_id":"20260820T000000Z-deadbeefdeadbeef","root_password":"correct horse battery staple"}`, 202, `"root_reauthorized":true`, `"mode":"uploaded"`)
	call(t, s, http.MethodGet, "/v1/system/update-transactions/20260820T000000Z-deadbeefdeadbeef", "", 200, `"status":"running"`, `"phase":"health"`)
	call(t, s, http.MethodPost, "/v1/resources/limits", `{"owner":"acmeweb","cpu_percent":200,"memory_mb":2048,"pids":256,"io_weight":200,"disk_gb":50,"bandwidth_gb":500}`, 200, `"owner":"acmeweb"`, `"host_adapter":false`)
	call(t, s, http.MethodGet, "/v1/system/processes", "", 200, `"php-fpm: pool acmeweb"`)
	call(t, s, http.MethodGet, "/v1/system/storage", "", 200, `"/srv/backups"`)
	call(t, s, http.MethodGet, "/v1/system/network", "", 200, `"eth0"`)
	call(t, s, http.MethodPost, "/v1/reseller/brands", `{"reseller":"partner1","company":"Partner Hosting","accent":"#3366AA","nameservers":["ns1.partner.test","ns2.partner.test"]}`, 200, `"Partner Hosting"`)
	call(t, s, http.MethodPost, "/v1/delegates", `{"owner":"acmeweb","username":"dev@example.test","role":"developer","permissions":["sites.read","git.deploy"]}`, 201, `"status":"active"`)
	call(t, s, http.MethodPost, "/v1/migrations", `{"source":"cpanel-source.example.test","source_type":"cpanel","account":"acmeweb","destination":"privora-local"}`, 201, `"delta-sync"`, `"simulation":true`)
	call(t, s, http.MethodPost, "/v1/clusters", `{"kind":"dns","name":"authoritative-dns","nodes":["dns01","dns02"],"mode":"active-active"}`, 201, `"simulation-contract"`)
	call(t, s, http.MethodPost, "/v1/load-balancers", `{"name":"edge-us","region":"us-central","backends":["web01","web02"],"algorithm":"least-connections"}`, 201, `"simulation-contract"`)
	call(t, s, http.MethodPost, "/v1/provision/profiles", `{"name":"Ubuntu Web","os":"ubuntu-lts","role":"web","packages":["nginx","php8.4-fpm"],"hardening":"balanced"}`, 201, `"ubuntu-lts"`)
	key := call(t, s, http.MethodPost, "/v1/api-keys", `{"name":"automation","scopes":["sites.read","sites.write"]}`, 201, `"secret_once"`)
	if strings.Contains(key, `"prefix":""`) {
		t.Fatal("missing api key prefix")
	}
	call(t, s, http.MethodPost, "/v1/webhooks", `{"url":"https://hooks.example.test/privora","events":["site.created","backup.failed"]}`, 201, `"active-contract"`)
}

func TestAPIKeyVerification(t *testing.T) {
	s := newTestServer(t)
	created := call(t, s, http.MethodPost, "/v1/api-keys", `{"name":"external-client","scopes":["health.read","accounts.read"]}`, 201, `"secret_once"`)
	var payload struct {
		Secret string `json:"secret_once"`
		APIKey struct {
			Prefix string `json:"prefix"`
		} `json:"api_key"`
	}
	if err := json.Unmarshal([]byte(created), &payload); err != nil || payload.Secret == "" || payload.APIKey.Prefix == "" {
		t.Fatalf("bad api key create: %v %s", err, created)
	}
	call(t, s, http.MethodPost, "/v1/api-keys/verify", `{"token":"`+payload.Secret+`"}`, 200, `"valid":true`, `"accounts.read"`)
	call(t, s, http.MethodPost, "/v1/api-keys/verify", `{"token":"prv_bad_bad"}`, 401, `"valid":false`)
}

func Test070To099HardeningAndReleaseTrain(t *testing.T) {
	s := newTestServer(t)
	call(t, s, http.MethodPost, "/v1/plugins", `{"name":"Example Backup Adapter","version":"1.0.0","type":"backup"}`, 201, `"registered-contract"`)
	call(t, s, http.MethodPost, "/v1/billing/invoices", `{"customer":"buyer@example.test","amount_cents":2499,"currency":"USD"}`, 201, `"draft-simulation"`)
	call(t, s, http.MethodPost, "/v1/notifications", `{"channel":"email","recipient":"ops@example.test","subject":"Backup complete"}`, 201, `"queued-simulation"`)
	call(t, s, http.MethodPost, "/v1/diagnostics", `{"scope":"server"}`, 201, `healthy capacity`)
	call(t, s, http.MethodPost, "/v1/repairs", `{"resource":"nginx","action":"reload"}`, 201, `"capture-before-state"`)
	digest := strings.Repeat("a", 64)
	call(t, s, http.MethodPost, "/v1/config/revisions", `{"resource":"nginx","digest":"`+digest+`"}`, 201, `"sealed"`)
	call(t, s, http.MethodPost, "/v1/secrets", `{"name":"backup-s3","type":"backup"}`, 201, `"reference-only-no-secret-material"`)
	call(t, s, http.MethodPost, "/v1/releases", `{"version":"5.0.0-dev","channel":"developer","digest":"`+digest+`","signature":"development-signature-record"}`, 201, `not-cryptographically-verified`)
	call(t, s, http.MethodPost, "/v1/exports", `{"account":"acmeweb","encrypted":true}`, 201, `"privora-account-v1"`)
	call(t, s, http.MethodPost, "/v1/performance/recommendations", `{"resource":"php-fpm:acmeweb","current":"pm.max_children=10","suggested":"pm.max_children=18","impact":"more peak concurrency"}`, 201, `"advisory"`)
	call(t, s, http.MethodPost, "/v1/staging", `{"production_domain":"www.acme.test","staging_domain":"staging.acme.test","owner":"acmeweb"}`, 201, `"simulated-clone-ready"`)
	call(t, s, http.MethodPost, "/v1/isolation", `{"owner":"acmeweb","namespaces":true,"cgroups":true,"private_tmp":true,"no_new_privileges":true}`, 200, `host-adapter-gated`)
	call(t, s, http.MethodPost, "/v1/certification", `{"name":"single-server-production","status":"blocked","evidence":["go-tests-pass"],"blockers":["real-mail-backend"]}`, 201, `"real-mail-backend"`)
	call(t, s, http.MethodGet, "/v1/horizons", "", 200, `"major":1`, `"major":5`, `"durable-placement-safety-core-certified"`)
}

func TestExpandedCustomerControlRecords(t *testing.T) {
	s := newTestServer(t)
	call(t, s, http.MethodPost, "/v1/account-controls", `{"owner":"acmeweb","kind":"redirect","domain":"www.acme.test","name":"/old","value":"/new"}`, 201, `"policy-recorded-host-adapter-gated"`)
	call(t, s, http.MethodPost, "/v1/account-controls", `{"owner":"acmeweb","kind":"ssh_key","name":"laptop","value":"ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIBogusButValidatedAsShape user@example"}`, 201, `"ssh_key"`)
	call(t, s, http.MethodPost, "/v1/account-controls", `{"owner":"acmeweb","kind":"ip_block","name":"203.0.113.0/24","value":"blocked"}`, 201, `"ip_block"`)
	call(t, s, http.MethodPost, "/v1/account-controls", `{"owner":"acmeweb","kind":"php_setting","domain":"www.acme.test","name":"memory_limit","value":"512M"}`, 201, `"memory_limit"`)
	call(t, s, http.MethodPost, "/v1/account-controls", `{"owner":"acmeweb","kind":"redirect","domain":"www.acme.test","name":"/../../etc","value":"/new"}`, 400, `"invalid redirect source path"`)
}

func TestTypedHostPlansAreGated(t *testing.T) {
	s := newTestServer(t)
	call(t, s, http.MethodPost, "/v1/host/plans", `{"kind":"site-config","username":"acmeweb","domain":"www.acme.test","php_version":"8.4"}`, 200, `"executable":false`, `"nginx-config-test"`, `"host_mutation":false`)
	call(t, s, http.MethodPost, "/v1/host/plans", `{"kind":"site-config","username":"acmeweb","domain":"../../etc/passwd","php_version":"8.4"}`, 400, `"invalid domain"`)
}

func TestSignedAgentRequestReplayIsRejected(t *testing.T) {
	s := newTestServer(t)
	r := req(http.MethodGet, "/v1/health", "")
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, r)
	if w.Code != 200 {
		t.Fatalf("first request failed: %d %s", w.Code, w.Body.String())
	}
	r2 := httptest.NewRequest(http.MethodGet, "/v1/health", nil)
	for _, h := range []string{"X-Privora-Timestamp", "X-Privora-Nonce", "X-Privora-Signature", "X-Privora-Actor", "X-Privora-Request-ID"} {
		r2.Header.Set(h, r.Header.Get(h))
	}
	w = httptest.NewRecorder()
	s.Handler().ServeHTTP(w, r2)
	if w.Code != 409 {
		t.Fatalf("replay wanted 409 got %d %s", w.Code, w.Body.String())
	}
}

func TestAuditChainEndpoint(t *testing.T) {
	s := newTestServer(t)
	call(t, s, http.MethodPost, "/v1/services/nginx/restart", "", 200, `"ok":true`)
	call(t, s, http.MethodGet, "/v1/audit/verify", "", 200, `"ok":true`, `"records":1`)
}

func TestBillingLedgerIsBalancedDurableAndVerifiable(t *testing.T) {
	s := newTestServer(t)
	body := `{"idempotency_key":"invoice-ledger-1001","currency":"USD","lines":[{"account":"cash","amount_minor":2500},{"account":"accounts-receivable","amount_minor":-2500}]}`
	call(t, s, http.MethodPost, "/v1/billing/ledger", body, 201, `"double_entry"`)
	call(t, s, http.MethodGet, "/v1/billing/ledger/verify", "", 200, `"valid":true`)
	call(t, s, http.MethodPost, "/v1/billing/ledger", `{"idempotency_key":"invoice-ledger-bad","currency":"USD","lines":[{"account":"cash","amount_minor":2500},{"account":"revenue","amount_minor":-2499}]}`, 400, "not balanced")
}
