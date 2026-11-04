package hostadapter

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestRegistrarGlueAdapterSyncAndDelete(t *testing.T) {
	seen := map[string]int{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer secret" {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		seen[r.URL.Path]++
		var in RegistrarGlueRequest
		_ = json.NewDecoder(r.Body).Decode(&in)
		if in.BaseDomain != "host.test" || in.Primary != "ns1.host.test" {
			http.Error(w, "bad payload", http.StatusBadRequest)
			return
		}
		_ = json.NewEncoder(w).Encode(RegistrarGlueResult{Connected: true, Provider: "test", Status: "synced"})
	}))
	defer srv.Close()
	a := New(Config{RegistrarProvider: "test", RegistrarAdapterURL: srv.URL, RegistrarToken: "secret", HTTPClient: srv.Client()})
	req := RegistrarGlueRequest{BaseDomain: "host.test", Primary: "ns1.host.test", Secondary: "ns2.host.test", IPv4: "192.0.2.10", Nameservers: []string{"ns1.host.test", "ns2.host.test"}}
	if out, err := a.SyncRegistrarGlue(context.Background(), req); err != nil || !out.Connected || out.Status != "synced" {
		t.Fatalf("sync failed: %+v %v", out, err)
	}
	if out, err := a.DeleteRegistrarGlue(context.Background(), req); err != nil || !out.Connected {
		t.Fatalf("delete failed: %+v %v", out, err)
	}
	if seen["/v1/glue/sync"] != 1 || seen["/v1/glue/delete"] != 1 {
		t.Fatalf("unexpected adapter calls: %+v", seen)
	}
}
