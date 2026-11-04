package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"privora.local/panel/agent/internal/resources"
)

func v7Call(t *testing.T, s *Server, method, path, body string, want int) map[string]any {
	t.Helper()
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, req(method, path, body))
	if w.Code != want {
		t.Fatalf("%s %s: wanted %d, got %d: %s", method, path, want, w.Code, w.Body.String())
	}
	var out map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil {
		t.Fatalf("%s %s: invalid JSON: %v: %s", method, path, err, w.Body.String())
	}
	return out
}

func v7ID(t *testing.T, body map[string]any, key string) string {
	t.Helper()
	obj, ok := body[key].(map[string]any)
	if !ok {
		t.Fatalf("missing %s object in %#v", key, body)
	}
	id, _ := obj["id"].(string)
	if id == "" {
		t.Fatalf("missing %s.id in %#v", key, body)
	}
	return id
}

func TestV7OperationalTrainMockContracts(t *testing.T) {
	s := newTestServer(t)

	// 6.91 — mail operations and mailbox filter lifecycle.
	q := v7Call(t, s, http.MethodGet, "/v1/mail/queue", "", 200)
	if _, ok := q["queue"]; !ok {
		t.Fatal("mail queue contract missing queue")
	}
	mf := v7Call(t, s, http.MethodPost, "/v1/mail/filters", `{"owner":"acmeweb","address":"admin@example.com","name":"Move invoices","field":"subject","operator":"contains","value":"invoice","action":"fileinto","destination":"Invoices"}`, 201)
	filterID := v7ID(t, mf, "filter")
	v7Call(t, s, http.MethodDelete, "/v1/mail/filters/"+filterID, "", 200)

	// 6.92 — local scheduled backups are executable; remote transports fail closed.
	bp := v7Call(t, s, http.MethodPost, "/v1/backup/policies", `{"owner":"acmeweb","scope":"account","resource":"acmeweb","destination":"local","schedule":"daily","retention":14,"verify":true}`, 201)
	policyID := v7ID(t, bp, "policy")
	v7Call(t, s, http.MethodPost, "/v1/backup/policies/"+policyID+"/run", `{}`, 200)
	v7Call(t, s, http.MethodPost, "/v1/backup/policies", `{"owner":"acmeweb","scope":"account","resource":"acmeweb","destination":"s3-compatible","schedule":"daily","retention":14}`, 400)
	v7Call(t, s, http.MethodPost, "/v1/backup/policies", `{"owner":"acmeweb","scope":"database","resource":"acme_db","destination":"local","schedule":"daily","retention":14}`, 400)

	// 6.93 — scoped token create/rotate/revoke lifecycle.
	key := v7Call(t, s, http.MethodPost, "/v1/api-keys", `{"name":"automation","owner":"acmeweb","scopes":["sites.read","dns.read"],"allowed_cidrs":["127.0.0.1/32"]}`, 201)
	keyID := v7ID(t, key, "api_key")
	if sec, _ := key["secret_once"].(string); !strings.HasPrefix(sec, "prv_") {
		t.Fatal("API key secret_once missing")
	}
	rot := v7Call(t, s, http.MethodPost, "/v1/api-keys/"+keyID+"/rotate", `{}`, 200)
	if sec, _ := rot["secret_once"].(string); !strings.HasPrefix(sec, "prv_") {
		t.Fatal("rotated secret_once missing")
	}
	v7Call(t, s, http.MethodDelete, "/v1/api-keys/"+keyID, "", 200)

	// 6.94 — live monitoring contract and alert-rule lifecycle.
	live := v7Call(t, s, http.MethodGet, "/v1/monitoring/live", "", 200)
	if _, ok := live["live"]; !ok {
		t.Fatal("monitoring contract missing live")
	}
	ar := v7Call(t, s, http.MethodPost, "/v1/monitoring/alerts", `{"name":"Disk pressure","metric":"disk","operator":">=","threshold":85,"window_minutes":5,"severity":"warning"}`, 201)
	alertID := v7ID(t, ar, "alert_rule")
	v7Call(t, s, http.MethodDelete, "/v1/monitoring/alerts/"+alertID, "", 200)

	// 6.95 — Security Advisor truthfully reports simulation and supported fix path.
	sec := v7Call(t, s, http.MethodGet, "/v1/security/advisor", "", 200)
	if sec["simulation"] != true {
		t.Fatal("mock Security Advisor must identify simulation")
	}
	v7Call(t, s, http.MethodPost, "/v1/security/advisor/fix", `{"fix":"panel-permissions"}`, 200)

	// 6.96 — advanced site policy persists independently of host mutation in mock mode.
	sp := v7Call(t, s, http.MethodPost, "/v1/sites/example.com/policy", `{"owner":"acmeweb","force_https":true,"hsts":true,"hsts_max_age":15552000,"directory_index":"index.php index.html","hotlink_protection":true}`, 200)
	policy, _ := sp["policy"].(map[string]any)
	if policy["domain"] != "example.com" {
		t.Fatalf("unexpected site policy: %#v", policy)
	}
}

func TestV7OperationalTrainMockContractsPart2(t *testing.T) {
	s := newTestServer(t)

	// 6.96 site policy response should carry the selected domain.
	sp := v7Call(t, s, http.MethodPost, "/v1/sites/example.com/policy", `{"owner":"acmeweb","force_https":true,"hsts":true,"hsts_max_age":15552000,"directory_index":"index.php index.html","hotlink_protection":true}`, 200)
	policy, _ := sp["policy"].(map[string]any)
	if policy["domain"] != "example.com" {
		t.Fatalf("unexpected site policy: %#v", policy)
	}

	// 6.97 — database activity is a truthful empty simulation rather than phantom sessions.
	db := v7Call(t, s, http.MethodGet, "/v1/databases/activity?engine=mariadb", "", 200)
	if db["simulation"] != true {
		t.Fatal("mock DB activity must identify simulation")
	}

	// 6.98 — application discovery is truthful in an empty mock host.
	apps := v7Call(t, s, http.MethodGet, "/v1/apps/discover", "", 200)
	if apps["simulation"] != true {
		t.Fatal("mock app discovery must identify simulation")
	}

	// 6.99 — DNSSEC status and DNS-template persistence.
	dnssec := v7Call(t, s, http.MethodGet, "/v1/dns/zones/example.com/dnssec", "", 200)
	if dnssec["simulation"] != true {
		t.Fatal("mock DNSSEC must identify simulation")
	}
	tpl := v7Call(t, s, http.MethodPost, "/v1/dns/templates", `{"name":"Web defaults","records":[{"type":"A","name":"@","value":"203.0.113.10","ttl":300},{"type":"CNAME","name":"www","value":"example.com.","ttl":300}]}`, 201)
	templateID := v7ID(t, tpl, "template")
	if _, err := s.resources.CreateDNSZone(resources.DNSZone{Domain: "example.com"}); err != nil {
		t.Fatalf("seed DNS zone: %v", err)
	}
	v7Call(t, s, http.MethodPost, "/v1/dns/templates/"+templateID+"/apply", `{"domain":"example.com"}`, 200)
	v7Call(t, s, http.MethodDelete, "/v1/dns/templates/"+templateID, "", 200)

	// 7.0 — readiness always returns an auditable run with bounded score.
	ready := v7Call(t, s, http.MethodGet, "/v1/readiness", "", 200)
	run, ok := ready["readiness"].(map[string]any)
	if !ok || run["id"] == "" {
		t.Fatalf("readiness run missing: %#v", ready)
	}
	if score, ok := run["score"].(float64); !ok || score < 0 || score > 100 {
		t.Fatalf("invalid readiness score: %#v", run["score"])
	}
	all := v7Call(t, s, http.MethodPost, "/v1/readiness/repair", `{"action":"repair-all"}`, 200)
	if _, ok := all["results"]; !ok {
		t.Fatalf("repair-all result missing: %#v", all)
	}
}
