package hostadapter

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

func TestRenderNginxAndPHP(t *testing.T) {
	cfg, err := RenderNginxSite("example.test", "acctone", "8.4", "/home/acctone/domains/example.test/public")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(cfg, "php8.4-fpm-acctone.sock") {
		t.Fatalf("socket missing: %s", cfg)
	}
	if _, err := RenderNginxSite("../bad", "acctone", "8.4", "/home/acctone/public"); err == nil {
		t.Fatal("unsafe domain accepted")
	}
	if _, err := RenderNginxSite("example.test", "acctone", "8.4", "/home/other/public"); err == nil {
		t.Fatal("cross-account root accepted")
	}
	pool, err := RenderPHPFPMPool("acctone", "8.4")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(pool, "open_basedir") {
		t.Fatal("pool isolation missing")
	}
}

func TestAtomicWrite(t *testing.T) {
	p := filepath.Join(t.TempDir(), "nested", "file.conf")
	if err := AtomicWrite(p, []byte("one"), 0640); err != nil {
		t.Fatal(err)
	}
	if err := AtomicWrite(p, []byte("two"), 0640); err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(p)
	if string(b) != "two" {
		t.Fatalf("got %q", b)
	}
}

func TestMutationGate(t *testing.T) {
	a := New(Config{AllowMutations: false, CertificationMode: true})
	if err := a.CreateLinuxUser(context.Background(), "acctone"); err == nil {
		t.Fatal("mutation gate bypassed")
	}
}

func TestNginxRealParserWhenAvailable(t *testing.T) {
	if _, ok := commandExists("nginx"); !ok {
		t.Skip("nginx not installed")
	}
	root := t.TempDir()
	for _, d := range []string{"logs", "conf", "home/acctone/domains/example.test/public"} {
		if err := os.MkdirAll(filepath.Join(root, d), 0755); err != nil {
			t.Fatal(err)
		}
	}
	site, err := RenderNginxSite("example.test", "acctone", "8.4", "/home/acctone/domains/example.test/public")
	if err != nil {
		t.Fatal(err)
	}
	full := "pid " + filepath.Join(root, "nginx.pid") + ";\nerror_log " + filepath.Join(root, "logs/error.log") + ";\nevents {}\nhttp {\n include /etc/nginx/mime.types;\n " + site + "\n}\n"
	conf := filepath.Join(root, "conf/nginx.conf")
	if err := AtomicWrite(conf, []byte(full), 0644); err != nil {
		t.Fatal(err)
	}
	a := New(Config{CommandTimeout: 5 * time.Second})
	if err := a.ValidateNginxConfig(context.Background(), conf, root+"/"); err != nil {
		t.Fatalf("real nginx parser rejected generated config: %v", err)
	}
}

func TestLiveLinuxUserLifecycle(t *testing.T) {
	if os.Getenv("PRIVORA_LIVE_HOST_TEST") != "1" {
		t.Skip("set PRIVORA_LIVE_HOST_TEST=1 for destructive sandbox certification")
	}
	if os.Geteuid() != 0 {
		t.Skip("requires root sandbox")
	}
	suffix := time.Now().UnixNano() % 1000000
	username := fmt.Sprintf("pvtest%d", suffix)
	a := New(Config{AllowMutations: true, CertificationMode: true, CommandTimeout: 10 * time.Second})
	_ = a.DeleteLinuxUser(context.Background(), username)
	if err := a.ProvisionAccount(context.Background(), username); err != nil {
		t.Fatal(err)
	}
	deleted := false
	defer func() {
		if !deleted {
			_ = a.DeleteLinuxUser(context.Background(), username)
		}
	}()
	home := filepath.Join("/home", username)
	st, err := os.Stat(home)
	if err != nil {
		t.Fatalf("home not created: %v", err)
	}
	if sys, ok := st.Sys().(*syscall.Stat_t); !ok || sys.Uid != 0 {
		t.Fatalf("SFTP chroot home is not root-owned: %#v", st.Sys())
	}
	domains, err := os.Stat(filepath.Join(home, "domains"))
	if err != nil {
		t.Fatal(err)
	}
	usr, err := user.Lookup(username)
	if err != nil {
		t.Fatal(err)
	}
	wantUID, _ := strconv.ParseUint(usr.Uid, 10, 32)
	if sys, ok := domains.Sys().(*syscall.Stat_t); !ok || uint64(sys.Uid) != wantUID {
		t.Fatalf("writable domains directory is not customer-owned: %#v", domains.Sys())
	}
	if _, err := exec.Command("id", username).CombinedOutput(); err != nil {
		t.Fatalf("id failed: %v", err)
	}
	if err := a.DeleteLinuxUser(context.Background(), username); err != nil {
		t.Fatal(err)
	}
	deleted = true
	if _, err := exec.Command("id", username).CombinedOutput(); err == nil {
		t.Fatal("user still exists after delete")
	}
}

func TestSetLinuxUserLockedUsesCertifiedTypedUsermod(t *testing.T) {
	bin := t.TempDir()
	logPath := filepath.Join(bin, "calls")
	for name, body := range map[string]string{
		"id":      "#!/bin/sh\nexit 0\n",
		"usermod": "#!/bin/sh\nprintf '%s\\n' \"$*\" >> \"$PRIVORA_CALLS\"\n",
	} {
		p := filepath.Join(bin, name)
		if err := os.WriteFile(p, []byte(body), 0755); err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv("PRIVORA_CALLS", logPath)
	t.Setenv("PATH", bin+":"+os.Getenv("PATH"))
	a := New(Config{AllowMutations: true, CertificationMode: true})
	if err := a.SetLinuxUserLocked(context.Background(), "acctusr", true); err != nil {
		t.Fatal(err)
	}
	if err := a.SetLinuxUserLocked(context.Background(), "acctusr", false); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatal(err)
	}
	text := string(b)
	if !strings.Contains(text, "--lock acctusr") || !strings.Contains(text, "--unlock acctusr") {
		t.Fatalf("unexpected usermod calls: %q", text)
	}
	if err := a.SetLinuxUserLocked(context.Background(), "bad;user", true); err == nil {
		t.Fatal("unsafe username accepted")
	}
}

func TestSetLinuxUserSuspendedUsesExpiryGate(t *testing.T) {
	bin := t.TempDir()
	logPath := filepath.Join(bin, "calls")
	for name, body := range map[string]string{
		"id":      "#!/bin/sh\nexit 0\n",
		"usermod": "#!/bin/sh\nprintf '%s\\n' \"$*\" >> \"$PRIVORA_CALLS\"\n",
	} {
		p := filepath.Join(bin, name)
		if err := os.WriteFile(p, []byte(body), 0755); err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv("PRIVORA_CALLS", logPath)
	t.Setenv("PATH", bin+":"+os.Getenv("PATH"))
	a := New(Config{AllowMutations: true, CertificationMode: true})
	if err := a.SetLinuxUserSuspended(context.Background(), "acctusr", true); err != nil {
		t.Fatal(err)
	}
	if err := a.SetLinuxUserSuspended(context.Background(), "acctusr", false); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatal(err)
	}
	text := string(b)
	if !strings.Contains(text, "--expiredate 1 acctusr") || !strings.Contains(text, "--expiredate  acctusr") {
		t.Fatalf("unexpected expiry calls: %q", text)
	}
}

func TestPhpMyAdminCapabilityRequiresPackageRouteAndDedicatedPool(t *testing.T) {
	root := t.TempDir()
	pma := filepath.Join(root, "phpmyadmin")
	if err := os.MkdirAll(pma, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(pma, "index.php"), []byte("<?php"), 0644); err != nil {
		t.Fatal(err)
	}
	nginx := filepath.Join(root, "privora-panel.conf")
	pool := filepath.Join(root, "privora-phpmyadmin.conf")
	a := New(Config{CertificationMode: false, PhpMyAdminRoot: pma, PanelNginxConfig: nginx, PhpMyAdminFPMConfig: pool})
	available, certified, _ := a.phpMyAdminCapability()
	if !available || certified {
		t.Fatalf("package-only state should be available but gated: available=%v certified=%v", available, certified)
	}
	if err := os.WriteFile(nginx, []byte("location = /_privora_phpmyadmin_auth { internal; }\nlocation /phpmyadmin/ { auth_request /_privora_phpmyadmin_auth; }\n"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(pool, []byte("[privora-phpmyadmin]\nlisten=/run/php/php8.4-fpm-privora-phpmyadmin.sock\n"), 0644); err != nil {
		t.Fatal(err)
	}
	available, certified, detail := a.phpMyAdminCapability()
	if !available || !certified || !strings.Contains(detail, "launch=/phpmyadmin/") {
		t.Fatalf("expected certified phpMyAdmin capability, got available=%v certified=%v detail=%q", available, certified, detail)
	}
}
