package hostadapter

import (
	"os"
	"os/user"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestAccountFileManagerLifecycle(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("linux file manager test")
	}
	u, err := user.Current()
	if err != nil || !validUser(u.Username) {
		t.Skip("current user unavailable for hosting test")
	}
	base := filepath.Join(t.TempDir(), "home")
	home := filepath.Join(base, u.Username)
	if err := os.MkdirAll(home, 0750); err != nil {
		t.Fatal(err)
	}
	a := New(Config{AllowMutations: true, CertificationMode: true, AccountHomeBase: base})
	if _, err := a.CreateAccountDirectory(u.Username, "domains/example.test/public"); err != nil {
		t.Fatal(err)
	}
	if _, err := a.WriteAccountBytes(u.Username, "domains/example.test/public/index.txt", []byte("hello")); err != nil {
		t.Fatal(err)
	}
	got, err := a.ReadAccountFile(u.Username, "domains/example.test/public/index.txt", 1024)
	if err != nil || string(got.Content) != "hello" {
		t.Fatalf("read: %+v %v", got, err)
	}
	if err := a.CopyAccountPath(u.Username, "domains/example.test/public/index.txt", "domains/example.test/public/copy.txt"); err != nil {
		t.Fatal(err)
	}
	if err := a.RenameAccountPath(u.Username, "domains/example.test/public/copy.txt", "domains/example.test/public/moved.txt"); err != nil {
		t.Fatal(err)
	}
	if err := a.ChmodAccountPath(u.Username, "domains/example.test/public/moved.txt", 0600); err != nil {
		t.Fatal(err)
	}
	rows, err := a.SearchAccountFiles(u.Username, "moved", 50)
	if err != nil || len(rows) != 1 {
		t.Fatalf("search: %+v %v", rows, err)
	}
	if _, err := a.CreateAccountZip(u.Username, "domains/example.test/public", "archives/site.zip"); err != nil {
		t.Fatal(err)
	}
	if err := a.ExtractAccountZip(u.Username, "archives/site.zip", "restored"); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(filepath.Join(home, "restored", "public", "index.txt"))
	if err != nil || string(b) != "hello" {
		t.Fatalf("extract: %q %v", b, err)
	}
	if err := a.DeleteAccountPath(u.Username, "domains/example.test/public/moved.txt"); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(home, "domains/example.test/public/moved.txt")); !os.IsNotExist(err) {
		t.Fatal("delete did not remove file")
	}
}

func TestAccountFileManagerRejectsSymlinkParent(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("linux file manager test")
	}
	u, err := user.Current()
	if err != nil || !validUser(u.Username) {
		t.Skip("current user unavailable")
	}
	base := filepath.Join(t.TempDir(), "home")
	home := filepath.Join(base, u.Username)
	if err := os.MkdirAll(home, 0750); err != nil {
		t.Fatal(err)
	}
	outside := t.TempDir()
	if err := os.Symlink(outside, filepath.Join(home, "escape")); err != nil {
		t.Fatal(err)
	}
	a := New(Config{AllowMutations: true, CertificationMode: true, AccountHomeBase: base})
	_, err = a.WriteAccountBytes(u.Username, "escape/pwned", []byte("x"))
	if err == nil || !(strings.Contains(strings.ToLower(err.Error()), "symlink") || strings.Contains(strings.ToLower(err.Error()), "not a directory")) {
		t.Fatalf("expected symlink rejection, got %v", err)
	}
}

func TestAccountFileManagerRejectsRecursiveCopyAndArchive(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("linux file manager test")
	}
	u, err := user.Current()
	if err != nil || !validUser(u.Username) {
		t.Skip("current user unavailable")
	}
	base := filepath.Join(t.TempDir(), "home")
	home := filepath.Join(base, u.Username)
	if err := os.MkdirAll(filepath.Join(home, "tree"), 0750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(home, "tree", "file.txt"), []byte("hello"), 0640); err != nil {
		t.Fatal(err)
	}
	a := New(Config{AllowMutations: true, CertificationMode: true, AccountHomeBase: base})
	if err := a.CopyAccountPath(u.Username, "tree", "tree/copy"); err == nil || !strings.Contains(err.Error(), "into itself") {
		t.Fatalf("expected recursive copy rejection, got %v", err)
	}
	if _, err := a.CreateAccountZip(u.Username, "tree", "tree/archive.zip"); err == nil || !strings.Contains(err.Error(), "inside the source") {
		t.Fatalf("expected recursive archive rejection, got %v", err)
	}
}
