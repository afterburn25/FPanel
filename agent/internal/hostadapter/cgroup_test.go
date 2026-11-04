package hostadapter

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestApplyCgroupV2LimitsInCertifiedTestHierarchy(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "cgroup.controllers"), []byte("cpu memory pids io\n"), 0644); err != nil {
		t.Fatal(err)
	}
	a := New(Config{AllowMutations: true, CertificationMode: true, CgroupRoot: root})
	r, err := a.ApplyCgroupV2Limits("acctusr", 250, 2048, 128, 500)
	if err != nil {
		t.Fatal(err)
	}
	if !r.Applied {
		t.Fatal("limits not applied")
	}
	checks := map[string]string{"cpu.max": "250000 100000", "memory.max": "2147483648", "pids.max": "128", "io.weight": "500"}
	for name, want := range checks {
		b, err := os.ReadFile(filepath.Join(root, "privora", "acctusr", name))
		if err != nil {
			t.Fatal(err)
		}
		if strings.TrimSpace(string(b)) != want {
			t.Fatalf("%s=%q want %q", name, b, want)
		}
	}
}

func TestCgroupLimitValidationRejectsUnsafeUser(t *testing.T) {
	root := t.TempDir()
	_ = os.WriteFile(filepath.Join(root, "cgroup.controllers"), []byte("cpu\n"), 0644)
	a := New(Config{AllowMutations: true, CertificationMode: true, CgroupRoot: root})
	if _, err := a.ApplyCgroupV2Limits("../root", 100, 512, 64, 100); err == nil {
		t.Fatal("unsafe username accepted")
	}
}
