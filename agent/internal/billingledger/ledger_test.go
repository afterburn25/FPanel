package billingledger

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestBalancedIdempotentLedgerSurvivesRestart(t *testing.T) {
	path := filepath.Join(t.TempDir(), "ledger.jsonl")
	l, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	tx := Transaction{IdempotencyKey: "invoice-1001-payment", Currency: "usd", Lines: []Line{{Account: "cash", AmountMinor: 2500}, {Account: "accounts-receivable", AmountMinor: -2500}}}
	a, err := l.Post(tx)
	if err != nil {
		t.Fatal(err)
	}
	l2, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	b, err := l2.Post(tx)
	if err != nil {
		t.Fatal(err)
	}
	if a.ID != b.ID || a.Hash != b.Hash {
		t.Fatal("idempotent transaction changed after restart")
	}
	if err := l2.Verify(); err != nil {
		t.Fatal(err)
	}
}

func TestUnbalancedLedgerRejected(t *testing.T) {
	l, _ := Open("")
	_, err := l.Post(Transaction{IdempotencyKey: "invoice-bad-1", Currency: "USD", Lines: []Line{{Account: "cash", AmountMinor: 100}, {Account: "revenue", AmountMinor: -99}}})
	if err == nil {
		t.Fatal("unbalanced transaction accepted")
	}
}

func TestLedgerTamperDetected(t *testing.T) {
	path := filepath.Join(t.TempDir(), "ledger.jsonl")
	l, _ := Open(path)
	_, err := l.Post(Transaction{IdempotencyKey: "invoice-2001-payment", Currency: "USD", Lines: []Line{{Account: "cash", AmountMinor: 500}, {Account: "revenue", AmountMinor: -500}}})
	if err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	tampered := strings.Replace(string(b), `"amount_minor":500`, `"amount_minor":501`, 1)
	if err := os.WriteFile(path, []byte(tampered), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(path); err == nil {
		t.Fatal("tampered ledger accepted")
	}
}
