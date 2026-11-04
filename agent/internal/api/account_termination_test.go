package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func terminationPlanForTest(t *testing.T, s *Server, user string) AccountTerminationPlan {
	t.Helper()
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, req(http.MethodGet, "/v1/hosting/accounts/"+user+"/termination-plan", ""))
	if w.Code != http.StatusOK {
		t.Fatalf("termination plan failed: %d %s", w.Code, w.Body.String())
	}
	var out struct {
		Plan AccountTerminationPlan `json:"plan"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	return out.Plan
}

func TestAccountTerminationRequiresFreshReadyPlan(t *testing.T) {
	s := newTestServer(t)
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, req(http.MethodPost, "/v1/hosting/accounts", `{"username":"termacct","primary_domain":"term.test","package":"Business"}`))
	if w.Code != 201 {
		t.Fatalf("create: %d %s", w.Code, w.Body.String())
	}

	plan := terminationPlanForTest(t, s, "termacct")
	if plan.Ready || !strings.Contains(strings.Join(plan.Blockers, " "), "suspended") {
		t.Fatalf("active account unexpectedly ready: %+v", plan)
	}

	w = httptest.NewRecorder()
	s.Handler().ServeHTTP(w, req(http.MethodPost, "/v1/hosting/accounts/termacct/suspend", ""))
	if w.Code != 200 {
		t.Fatalf("suspend: %d %s", w.Code, w.Body.String())
	}
	plan = terminationPlanForTest(t, s, "termacct")
	if !plan.Ready || len(plan.Fingerprint) != 64 {
		t.Fatalf("suspended clean account should be ready: %+v", plan)
	}

	w = httptest.NewRecorder()
	s.Handler().ServeHTTP(w, req(http.MethodDelete, "/v1/hosting/accounts/termacct", `{"delete_dns":true}`))
	if w.Code != http.StatusConflict || !strings.Contains(w.Body.String(), "run preflight again") {
		t.Fatalf("delete without fingerprint should fail closed: %d %s", w.Code, w.Body.String())
	}

	body, _ := json.Marshal(map[string]any{"delete_dns": true, "plan_fingerprint": plan.Fingerprint})
	w = httptest.NewRecorder()
	s.Handler().ServeHTTP(w, req(http.MethodDelete, "/v1/hosting/accounts/termacct", string(body)))
	if w.Code != 200 {
		t.Fatalf("confirmed termination: %d %s", w.Code, w.Body.String())
	}
}

func TestAccountTerminationCleansManagedDatabase(t *testing.T) {
	s := newTestServer(t)
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, req(http.MethodPost, "/v1/hosting/accounts", `{"username":"dbterm","primary_domain":"dbterm.test","package":"Business"}`))
	if w.Code != 201 {
		t.Fatalf("create: %d %s", w.Code, w.Body.String())
	}
	w = httptest.NewRecorder()
	s.Handler().ServeHTTP(w, req(http.MethodPost, "/v1/databases", `{"name":"dbterm_app","user":"dbterm_user","engine":"mariadb","owner":"dbterm"}`))
	if w.Code != 201 {
		t.Fatalf("database create: %d %s", w.Code, w.Body.String())
	}
	w = httptest.NewRecorder()
	s.Handler().ServeHTTP(w, req(http.MethodPost, "/v1/hosting/accounts/dbterm/suspend", ""))
	if w.Code != 200 {
		t.Fatalf("suspend: %d %s", w.Code, w.Body.String())
	}

	plan := terminationPlanForTest(t, s, "dbterm")
	if !plan.Ready || len(plan.ManagedDatabases) != 1 || len(plan.UnmanagedDatabases) != 0 {
		t.Fatalf("managed database should be an executable cleanup action: %+v", plan)
	}
	body, _ := json.Marshal(map[string]any{"delete_dns": true, "plan_fingerprint": plan.Fingerprint})
	w = httptest.NewRecorder()
	s.Handler().ServeHTTP(w, req(http.MethodDelete, "/v1/hosting/accounts/dbterm", string(body)))
	if w.Code != 200 {
		t.Fatalf("managed-database termination: %d %s", w.Code, w.Body.String())
	}
	if _, ok := s.resources.DatabaseByName("dbterm_app"); ok {
		t.Fatal("managed database metadata survived account termination")
	}
}
