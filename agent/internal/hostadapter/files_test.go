package hostadapter

import (
	"os"
	"os/user"
	"path/filepath"
	"runtime"
	"testing"
)

func TestAccountFilesNoSymlinkEscape(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("linux openat test")
	}
	u, err := user.Current()
	if err != nil {
		t.Skip(err)
	}
	if !validUser(u.Username) {
		t.Skip("current username incompatible with hosting validator")
	}
	tmp := t.TempDir()
	base := filepath.Join(tmp, "home")
	home := filepath.Join(base, u.Username)
	if err := os.MkdirAll(filepath.Join(home, "domains"), 0750); err != nil {
		t.Fatal(err)
	}
	a := New(Config{AllowMutations: true, CertificationMode: true, AccountHomeBase: base})
	got, err := a.WriteAccountFile(u.Username, "domains/example.test/public/index.html", "safe")
	if err != nil {
		t.Fatal(err)
	}
	if got.Size != 4 {
		t.Fatalf("bad write %+v", got)
	}
	items, err := a.ListAccountFiles(u.Username, "domains/example.test/public")
	if err != nil {
		t.Fatal(err)
	}
	if len(items) != 1 || items[0].Name != "index.html" {
		t.Fatalf("bad list %+v", items)
	}
	outside := t.TempDir()
	if err := os.Symlink(outside, filepath.Join(home, "domains", "escape")); err != nil {
		t.Fatal(err)
	}
	if _, err := a.ListAccountFiles(u.Username, "domains/escape"); err == nil {
		t.Fatal("expected symlink traversal rejection")
	}
	if _, err := a.WriteAccountFile(u.Username, "domains/escape/pwned", "x"); err == nil {
		t.Fatal("expected write-through-symlink rejection")
	}
	if _, err := os.Stat(filepath.Join(outside, "pwned")); !os.IsNotExist(err) {
		t.Fatal("outside file unexpectedly created")
	}
}
