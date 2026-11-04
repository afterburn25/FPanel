package hostadapter

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestRenderPrivoraNftBatch(t *testing.T) {
	out, err := RenderPrivoraNftBatch([]FirewallRule{{Direction: "inbound", Protocol: "tcp", Port: 443, Source: "203.0.113.0/24", Action: "allow"}})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, "tcp dport 443") || !strings.Contains(out, "ip saddr 203.0.113.0/24") {
		t.Fatalf("unexpected batch: %s", out)
	}
	if _, err := RenderPrivoraNftBatch([]FirewallRule{{Direction: "inbound", Protocol: "tcp", Port: 22, Source: "0.0.0.0/0", Action: "deny"}}); err == nil {
		t.Fatal("expected SSH lockout protection")
	}
	if _, err := RenderPrivoraNftBatch([]FirewallRule{{Direction: "inbound", Protocol: "tcp", Port: 443, Source: "bad;cidr", Action: "allow"}}); err == nil {
		t.Fatal("expected CIDR rejection")
	}
}

func TestApplyNftablesControlledClient(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("unix helper test")
	}
	tmp := t.TempDir()
	bin := filepath.Join(tmp, "bin")
	_ = os.MkdirAll(bin, 0755)
	logPath := filepath.Join(tmp, "nft.log")
	script := `#!/bin/sh
set -eu
printf '%s\n' "$*" >> "$NFT_LOG"
if [ "$1" = "list" ]; then exit 1; fi
exit 0
`
	if err := os.WriteFile(filepath.Join(bin, "nft"), []byte(script), 0755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("NFT_LOG", logPath)
	t.Setenv("PATH", bin+":"+os.Getenv("PATH"))
	a := New(Config{AllowMutations: true, CertificationMode: true, NftablesPath: filepath.Join(tmp, "privora.nft")})
	got, err := a.ApplyNftablesRules(context.Background(), []FirewallRule{{Direction: "inbound", Protocol: "tcp", Port: 443, Source: "0.0.0.0/0", Action: "allow"}})
	if err != nil {
		t.Fatal(err)
	}
	if !got.Validated || !got.Applied || got.RuleCount != 1 {
		t.Fatalf("unexpected result: %+v", got)
	}
	b, err := os.ReadFile(filepath.Join(tmp, "privora.nft"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(b), "dport 443") {
		t.Fatalf("managed file missing rule: %s", b)
	}
	logb, _ := os.ReadFile(logPath)
	if !strings.Contains(string(logb), "-c -f") || !strings.Contains(string(logb), "-f") {
		t.Fatalf("expected check/apply: %s", logb)
	}
}
