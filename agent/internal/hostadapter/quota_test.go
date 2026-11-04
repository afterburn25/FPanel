package hostadapter

import (
	"context"
	"os"
	"os/user"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestDiskQuotaValidation(t *testing.T) {
	a := New(Config{AllowMutations: true, CertificationMode: true})
	if _, err := a.ApplyUserDiskQuota(context.Background(), "bad;user", "/", 1024, 2048); err == nil {
		t.Fatal("expected username rejection")
	}
	current, err := user.Current()
	if err != nil {
		t.Skip(err)
	}
	if _, err := a.ApplyUserDiskQuota(context.Background(), current.Username, "relative", 1024, 2048); err == nil {
		t.Fatal("expected filesystem rejection")
	}
	if _, err := a.ApplyUserDiskQuota(context.Background(), current.Username, "/", 4096, 2048); err == nil {
		t.Fatal("expected limit rejection")
	}
}

func TestDiskQuotaControlledClient(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("unix helper test")
	}
	current, err := user.Current()
	if err != nil {
		t.Skip(err)
	}
	tmp := t.TempDir()
	bin := filepath.Join(tmp, "bin")
	_ = os.MkdirAll(bin, 0755)
	logPath := filepath.Join(tmp, "quota.log")
	script := `#!/bin/sh
printf '%s\n' "$*" > "$QUOTA_LOG"
`
	if err := os.WriteFile(filepath.Join(bin, "setquota"), []byte(script), 0755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("QUOTA_LOG", logPath)
	t.Setenv("PATH", bin+":"+os.Getenv("PATH"))
	a := New(Config{AllowMutations: true, CertificationMode: true})
	got, err := a.ApplyUserDiskQuota(context.Background(), current.Username, "/", 10*1024*1024, 12*1024*1024)
	if err != nil {
		t.Fatal(err)
	}
	if !got.Applied {
		t.Fatal("quota was not applied")
	}
	b, _ := os.ReadFile(logPath)
	if !strings.Contains(string(b), "-u "+current.Username+" 10240 12288 0 0 /") {
		t.Fatalf("unexpected quota argv: %s", b)
	}
}
