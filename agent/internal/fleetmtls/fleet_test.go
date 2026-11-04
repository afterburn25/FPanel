package fleetmtls

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"
)

func TestMTLSAndReplay(t *testing.T) {
	ca, err := NewCA("privora-ca")
	if err != nil {
		t.Fatal(err)
	}
	srvCert, _, err := ca.Issue("fleet-server", true)
	if err != nil {
		t.Fatal(err)
	}
	cliCert, _, err := ca.Issue("node-chi-01", false)
	if err != nil {
		t.Fatal(err)
	}
	srvTLS, cliTLS, err := TLSConfigs(ca.PEM, srvCert, cliCert)
	if err != nil {
		t.Fatal(err)
	}
	ts := httptest.NewUnstartedServer(Handler("node-chi-01", NewReplayGuard(time.Minute)))
	ts.TLS = srvTLS
	ts.StartTLS()
	defer ts.Close()
	client := ts.Client()
	client.Transport.(*http.Transport).TLSClientConfig = cliTLS
	c := Command{NodeID: "node-chi-01", Operation: "probe", Resource: "system", RequestID: "req-1", Nonce: "nonce-1", IssuedAt: time.Now().UTC()}
	b, _ := json.Marshal(c)
	resp, err := client.Post(ts.URL, "application/json", bytes.NewReader(b))
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != 200 {
		t.Fatalf("first=%d", resp.StatusCode)
	}
	resp.Body.Close()
	resp, err = client.Post(ts.URL, "application/json", bytes.NewReader(b))
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != 409 {
		t.Fatalf("replay=%d", resp.StatusCode)
	}
	resp.Body.Close()
}

func TestPersistentReplayGuardSurvivesRestart(t *testing.T) {
	p := filepath.Join(t.TempDir(), "replay.json")
	issued := time.Now().UTC()
	g1 := NewFileReplayGuard(p, time.Minute)
	if err := g1.Accept("persisted-nonce", issued); err != nil {
		t.Fatal(err)
	}
	g2 := NewFileReplayGuard(p, time.Minute)
	if err := g2.Accept("persisted-nonce", issued); err == nil {
		t.Fatal("replay accepted after guard restart")
	}
}

func TestHandlerExecutesTypedCommand(t *testing.T) {
	ca, err := NewCA("privora-test-ca")
	if err != nil {
		t.Fatal(err)
	}
	serverCert, _, err := ca.Issue("fleet-server", true)
	if err != nil {
		t.Fatal(err)
	}
	clientCert, _, err := ca.Issue("node-a", false)
	if err != nil {
		t.Fatal(err)
	}
	srvTLS, cliTLS, err := TLSConfigs(ca.PEM, serverCert, clientCert)
	if err != nil {
		t.Fatal(err)
	}
	called := false
	h := HandlerWithExecutor("node-a", NewReplayGuard(time.Minute), ExecutorFunc(func(_ context.Context, c Command) (string, error) {
		called = true
		if c.Operation != "probe" {
			t.Fatal("wrong op")
		}
		return "probe-ok", nil
	}))
	ts := httptest.NewUnstartedServer(h)
	ts.TLS = srvTLS
	ts.StartTLS()
	defer ts.Close()
	client := &http.Client{Transport: &http.Transport{TLSClientConfig: cliTLS}}
	cmd := Command{NodeID: "node-a", Operation: "probe", Resource: "system", RequestID: "typed-1", Nonce: "typed-nonce", IssuedAt: time.Now().UTC()}
	b, _ := json.Marshal(cmd)
	resp, err := client.Post(ts.URL, "application/json", bytes.NewReader(b))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("status %d", resp.StatusCode)
	}
	if !called {
		t.Fatal("executor not called")
	}
}
