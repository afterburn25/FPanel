package secretvault

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestEncryptedVaultSurvivesRestartAndRotatesVersion(t *testing.T) {
	path := filepath.Join(t.TempDir(), "vault.json")
	key := bytes.Repeat([]byte{0x42}, 32)
	v, err := Open(path, key)
	if err != nil {
		t.Fatal(err)
	}
	ver, err := v.Put("cloud/provider/token", []byte("super-secret-token"))
	if err != nil || ver != 1 {
		t.Fatalf("%d %v", ver, err)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), "super-secret-token") {
		t.Fatal("plaintext secret persisted")
	}
	v2, err := Open(path, key)
	if err != nil {
		t.Fatal(err)
	}
	got, ver, err := v2.Get("cloud/provider/token")
	if err != nil || string(got) != "super-secret-token" || ver != 1 {
		t.Fatalf("got=%q ver=%d err=%v", got, ver, err)
	}
	ver, err = v2.Put("cloud/provider/token", []byte("rotated-token"))
	if err != nil || ver != 2 {
		t.Fatalf("rotate=%d %v", ver, err)
	}
	got, ver, err = v2.Get("cloud/provider/token")
	if err != nil || string(got) != "rotated-token" || ver != 2 {
		t.Fatalf("got=%q ver=%d err=%v", got, ver, err)
	}
}

func TestWrongVaultKeyCannotDecrypt(t *testing.T) {
	path := filepath.Join(t.TempDir(), "vault.json")
	key := bytes.Repeat([]byte{1}, 32)
	v, _ := Open(path, key)
	if _, err := v.Put("billing/gateway/key", []byte("value")); err != nil {
		t.Fatal(err)
	}
	wrong := bytes.Repeat([]byte{2}, 32)
	v2, err := Open(path, wrong)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := v2.Get("billing/gateway/key"); err == nil {
		t.Fatal("wrong key decrypted vault")
	}
}
