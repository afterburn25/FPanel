package hostadapter

import (
	"context"
	"os"
	"os/user"
	"path/filepath"
	"runtime"
	"testing"
)

func TestSFTPControlledStack(t *testing.T) {
	if runtime.GOOS == "windows" || os.Geteuid() != 0 {
		t.Skip("requires unix root for chroot ownership test")
	}
	u, err := user.Current()
	if err != nil {
		t.Skip(err)
	}
	tmp := t.TempDir()
	homeBase := filepath.Join(tmp, "home")
	home := filepath.Join(homeBase, u.Username)
	if err := os.MkdirAll(filepath.Join(home, "domains"), 0750); err != nil {
		t.Fatal(err)
	}
	if err := os.Chown(home, 0, 0); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(home, 0755); err != nil {
		t.Fatal(err)
	}
	bin := filepath.Join(tmp, "bin")
	_ = os.MkdirAll(bin, 0755)
	openssl := `#!/bin/sh
printf '$6$sftp$controlledhash\n'
`
	ok := `#!/bin/sh
exit 0
`
	for _, name := range []string{"groupadd", "usermod", "sshd", "systemctl"} {
		if err := os.WriteFile(filepath.Join(bin, name), []byte(ok), 0755); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(bin, "openssl"), []byte(openssl), 0755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", bin+":"+os.Getenv("PATH"))
	a := New(Config{AllowMutations: true, CertificationMode: true, AccountHomeBase: homeBase, SSHDConfigPath: filepath.Join(tmp, "sshd.d", "90-privora-sftp.conf")})
	got, err := a.EnableAccountSFTPPassword(context.Background(), u.Username)
	if err != nil {
		t.Fatal(err)
	}
	if got.Password == "" || got.Auth != "password" {
		t.Fatalf("unexpected result %+v", got)
	}
}
