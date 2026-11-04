package orderflow

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestIdempotentSuccessAndCompensation(t *testing.T) {
	e := New()
	count := 0
	steps := []Step{{Name: "account", Run: func(context.Context) error { count++; return nil }, Compensate: func(context.Context) error { count--; return nil }}, {Name: "site", Run: func(context.Context) error { count++; return nil }}}
	a, err := e.Run(context.Background(), "order-1001", steps)
	if err != nil || a.Status != "succeeded" {
		t.Fatalf("%+v %v", a, err)
	}
	_, err = e.Run(context.Background(), "order-1001", steps)
	if err != nil || count != 2 {
		t.Fatal("idempotency reran steps")
	}
	f := New()
	c := 0
	bad := []Step{{Name: "account", Run: func(context.Context) error { c++; return nil }, Compensate: func(context.Context) error { c--; return nil }}, {Name: "dns", Run: func(context.Context) error { return errors.New("dns failed") }}}
	r, err := f.Run(context.Background(), "order-2002", bad)
	if err == nil || r.Status != "failed" || c != 0 || len(r.Compensated) != 1 {
		t.Fatalf("%+v %v count=%d", r, err, c)
	}
}

func TestPersistentIdempotencySurvivesRestart(t *testing.T) {
	p := filepath.Join(t.TempDir(), "orders.jsonl")
	runs := 0
	e, err := NewPersistent(p)
	if err != nil {
		t.Fatal(err)
	}
	steps := []Step{{Name: "provision", Run: func(context.Context) error { runs++; return nil }}}
	if _, err := e.Run(context.Background(), "order-persist-1", steps); err != nil {
		t.Fatal(err)
	}
	e2, err := NewPersistent(p)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := e2.Run(context.Background(), "order-persist-1", steps); err != nil {
		t.Fatal(err)
	}
	if runs != 1 {
		t.Fatalf("side effect reran after restart: %d", runs)
	}
}

func TestPersistentIncompleteOrderFailsClosed(t *testing.T) {
	p := filepath.Join(t.TempDir(), "orders.jsonl")
	seed := Result{Key: "order-incomplete", Status: "running", StartedAt: time.Now().UTC()}
	b, _ := json.Marshal(seed)
	if err := os.WriteFile(p, append(b, '\n'), 0600); err != nil {
		t.Fatal(err)
	}
	e, err := NewPersistent(p)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := e.Run(context.Background(), "order-incomplete", []Step{{Name: "x", Run: func(context.Context) error { return nil }}}); err == nil {
		t.Fatal("incomplete order was re-executed")
	}
}
