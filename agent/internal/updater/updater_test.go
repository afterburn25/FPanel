package updater

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"
)

func TestVerifySignedManifest(t *testing.T) {
	k, _ := rsa.GenerateKey(rand.Reader, 2048)
	bundle := []byte("bundle")
	sum := sha256.Sum256(bundle)
	m := Manifest{Version: "5.0.0-dev.6", Channel: "developer", BundleSHA256: hex.EncodeToString(sum[:]), CreatedAt: "2026-08-18T22:00:00Z"}
	raw, _ := json.Marshal(m)
	d := sha256.Sum256(raw)
	sig, _ := rsa.SignPKCS1v15(rand.Reader, k, crypto.SHA256, d[:])
	der, _ := x509.MarshalPKIXPublicKey(&k.PublicKey)
	pub := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})
	if _, e := VerifySignedManifest(raw, sig, bundle, pub); e != nil {
		t.Fatal(e)
	}
	if _, e := VerifySignedManifest(raw, sig, []byte("bad"), pub); e == nil {
		t.Fatal("tamper accepted")
	}
}
func TestPlanJournal(t *testing.T) {
	p := BuildPlan("5.0.0-dev.6", "stable", true, false)
	if len(p.Steps) < 10 || len(p.Rollback) < 4 {
		t.Fatal("incomplete plan")
	}
	root := t.TempDir()
	path := filepath.Join(root, "20260102T000000Z-2", "journal.json")
	if e := WriteJournal(path, Journal{ID: "2", Phase: "health", Status: "pass", NewVersion: "5.0.0-dev.6"}); e != nil {
		t.Fatal(e)
	}
	j, e := LatestJournal(root)
	if e != nil || j.Status != "pass" {
		t.Fatalf("%#v %v", j, e)
	}
}

func TestEnvJournalProgressTiming(t *testing.T) {
	root := t.TempDir()
	id := "20260820T041500Z-deadbeefdeadbeef"
	dir := filepath.Join(root, id)
	if err := os.MkdirAll(dir, 0750); err != nil {
		t.Fatal(err)
	}
	body := "started_at=2026-08-20T04:15:00Z\nphase=backup\nstatus=running\nphase_started_at=2026-08-20T04:15:08Z\noperation=Creating\\ pre-update\\ snapshot\nactivity_at=2026-08-20T04:15:08Z\n"
	if err := os.WriteFile(filepath.Join(dir, "journal.env"), []byte(body), 0600); err != nil {
		t.Fatal(err)
	}
	j, err := TransactionJournal(root, id)
	if err != nil {
		t.Fatal(err)
	}
	if j.Phase != "backup" || j.Operation != "Creating pre-update snapshot" {
		t.Fatalf("unexpected journal %#v", j)
	}
	if j.StartedAt.IsZero() || j.PhaseStartedAt.IsZero() || j.ActivityAt.IsZero() {
		t.Fatalf("progress timing was not parsed %#v", j)
	}
}

func TestEnvJournalPreservesFailureAcrossRollback(t *testing.T) {
	root := t.TempDir()
	id := "20260820T102900Z-feedfacefeedface"
	dir := filepath.Join(root, id)
	if err := os.MkdirAll(dir, 0750); err != nil {
		t.Fatal(err)
	}
	body := "phase=health\nstatus=failed\nfailed_phase=health\nfailed_operation=Health:\\ probing\\ panel\\ HTTPS\\ endpoint\nfailed_command=curl\nfailed_rc=22\nfailed_error=phase=health\\ rc=22\nerror=phase=health\\ rc=22\nphase=rollback\nstatus=rolled-back\nresult=rolled-back\n"
	if err := os.WriteFile(filepath.Join(dir, "journal.env"), []byte(body), 0600); err != nil {
		t.Fatal(err)
	}
	j, err := TransactionJournal(root, id)
	if err != nil {
		t.Fatal(err)
	}
	if j.Status != "rolled-back" || j.Phase != "rollback" || j.FailedPhase != "health" || j.FailedRC != "22" || j.FailedOperation != "Health: probing panel HTTPS endpoint" {
		t.Fatalf("failure provenance lost: %#v", j)
	}
}
