package hostadapter

import (
	"context"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"
)

func TestComponentCatalogIsStaticAllowList(t *testing.T) {
	defs := componentDefinitions()
	if len(defs) < 25 {
		t.Fatalf("component catalog unexpectedly small: %d", len(defs))
	}
	idRE := regexp.MustCompile(`^[a-z0-9][a-z0-9-]{1,63}$`)
	pkgRE := regexp.MustCompile(`^[a-z0-9][a-z0-9.+-]*$`)
	seen := map[string]bool{}
	for _, d := range defs {
		if !idRE.MatchString(d.ID) {
			t.Fatalf("unsafe component id %q", d.ID)
		}
		if seen[d.ID] {
			t.Fatalf("duplicate component id %q", d.ID)
		}
		seen[d.ID] = true
		if d.Name == "" || d.Category == "" || d.Description == "" || len(d.Packages) == 0 {
			t.Fatalf("incomplete component definition %#v", d)
		}
		for _, p := range d.Packages {
			if !pkgRE.MatchString(p) {
				t.Fatalf("unsafe package token %q for %s", p, d.ID)
			}
		}
	}
}

func TestRequestedComponentMappings(t *testing.T) {
	sqlite, ok := definitionByID("php-pdo-sqlite")
	if !ok || !slices.Equal(sqlite.Packages, []string{"php8.4-sqlite3"}) {
		t.Fatalf("PDO SQLite mapping incorrect: %#v", sqlite)
	}
	ffmpeg, ok := definitionByID("ffmpeg")
	if !ok || !slices.Equal(ffmpeg.Packages, []string{"ffmpeg"}) {
		t.Fatalf("FFmpeg mapping incorrect: %#v", ffmpeg)
	}
	laravel, ok := definitionByID("laravel-stack")
	if !ok || laravel.Special != "laravel-installer" || !laravel.Featured {
		t.Fatalf("Laravel stack mapping incomplete: %#v", laravel)
	}
	for _, required := range []string{"composer", "git", "nodejs", "npm", "php8.4-cli", "php8.4-curl", "php8.4-mbstring", "php8.4-xml", "php8.4-zip", "php8.4-sqlite3"} {
		if !slices.Contains(laravel.Packages, required) {
			t.Fatalf("Laravel stack missing %s", required)
		}
	}
}

func TestComponentStatusDoesNotAcceptArbitraryPackageName(t *testing.T) {
	if _, ok := definitionByID("apt-get-install-anything"); ok {
		t.Fatal("unexpected arbitrary-package component")
	}
	d, _ := definitionByID("php-pdo-sqlite")
	c := componentStatus(d, map[string]string{}, map[string]bool{"php8.4-sqlite3": true})
	if c.Status != "available" || !c.Available || c.Installed {
		t.Fatalf("unexpected available status: %#v", c)
	}
	c = componentStatus(d, map[string]string{"php8.4-sqlite3": "8.4-test"}, map[string]bool{"php8.4-sqlite3": true})
	if c.Status != "installed" || !c.Installed || c.Version != "8.4-test" {
		t.Fatalf("unexpected installed status: %#v", c)
	}
}

func TestConfigEditorCommonMetadata(t *testing.T) {
	a := &Adapter{}
	defs := a.baseEditableConfigs()
	var nginx, php84 *EditableConfig
	for i := range defs {
		switch defs[i].ID {
		case "nginx-main":
			nginx = &defs[i]
		case "php-8.4-fpm":
			php84 = &defs[i]
		}
	}
	if nginx == nil || !nginx.Common || nginx.Category != "Web Server" || nginx.Priority >= 100 {
		t.Fatalf("nginx common metadata incorrect: %#v", nginx)
	}
	if php84 == nil || !php84.Common || php84.Category != "PHP" || php84.Priority >= 100 {
		t.Fatalf("PHP 8.4 common metadata incorrect: %#v", php84)
	}
}

func TestAPTTransactionEscapesAgentCredentialSandboxThroughTransientUnit(t *testing.T) {
	tmp := t.TempDir()
	logPath := filepath.Join(tmp, "systemd-run.args")
	systemdRun := filepath.Join(tmp, "systemd-run")
	aptGet := filepath.Join(tmp, "apt-get")
	if err := os.WriteFile(systemdRun, []byte("#!/bin/sh\nprintf '%s\\n' \"$@\" > \"$PRIVORA_TEST_LOG\"\nexit 0\n"), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(aptGet, []byte("#!/bin/sh\nexit 99\n"), 0755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", tmp)
	t.Setenv("PRIVORA_TEST_LOG", logPath)
	if _, err := runPackageCommand(context.Background(), "apt-get", []string{"-o", "Dpkg::Lock::Timeout=60", "install", "-y", "php8.4-imagick"}, "DEBIAN_FRONTEND=noninteractive", "NEEDRESTART_MODE=a"); err != nil {
		t.Fatalf("isolated apt transaction failed: %v", err)
	}
	raw, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatal(err)
	}
	got := string(raw)
	for _, want := range []string{"--wait", "--collect", "--pipe", "--property=NoNewPrivileges=no", "--property=User=root", "--setenv=DEBIAN_FRONTEND=noninteractive", aptGet, "php8.4-imagick"} {
		if !strings.Contains(got, want) {
			t.Fatalf("systemd-run invocation missing %q:\n%s", want, got)
		}
	}
}

func TestAllCuratedComponentsHaveCertifiedInstallStrategy(t *testing.T) {
	allowedSpecial := map[string]bool{"": true, "laravel-installer": true, "roundcube-webmail": true}
	for _, d := range componentDefinitions() {
		if len(d.Packages) == 0 {
			t.Fatalf("component %s has no package-backed install plan", d.ID)
		}
		if !allowedSpecial[d.Special] {
			t.Fatalf("component %s has uncertified special installer %q", d.ID, d.Special)
		}
	}
}

func TestLaravelComposerProvisionUsesIsolatedCLIAndDisablesPCREJIT(t *testing.T) {
	tmp := t.TempDir()
	logPath := filepath.Join(tmp, "systemd-run.args")
	target := filepath.Join(tmp, "composer-home", "vendor", "bin", "laravel")
	link := filepath.Join(tmp, "bin", "laravel")
	if err := os.MkdirAll(filepath.Dir(link), 0755); err != nil {
		t.Fatal(err)
	}
	systemdRun := filepath.Join(tmp, "systemd-run")
	composer := filepath.Join(tmp, "composer")
	php := filepath.Join(tmp, "php8.4")
	script := "#!/bin/sh\nprintf '%s\\n' \"$@\" > \"$PRIVORA_TEST_LOG\"\n/bin/mkdir -p \"$(/usr/bin/dirname \"$PRIVORA_TEST_LARAVEL_TARGET\")\"\nprintf '#!/bin/sh\\n' > \"$PRIVORA_TEST_LARAVEL_TARGET\"\n/bin/chmod 755 \"$PRIVORA_TEST_LARAVEL_TARGET\"\nexit 0\n"
	if err := os.WriteFile(systemdRun, []byte(script), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(composer, []byte("#!/bin/sh\nexit 99\n"), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(php, []byte("#!/bin/sh\nexit 99\n"), 0755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", tmp)
	t.Setenv("PRIVORA_TEST_LOG", logPath)
	t.Setenv("PRIVORA_TEST_LARAVEL_TARGET", target)
	if err := installLaravelToolingAt(context.Background(), filepath.Join(tmp, "composer-home"), link); err != nil {
		t.Fatalf("Laravel isolated provisioning failed: %v", err)
	}
	raw, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatal(err)
	}
	got := string(raw)
	for _, want := range []string{"--property=NoNewPrivileges=no", "--property=MemoryDenyWriteExecute=no", "--setenv=COMPOSER_ALLOW_SUPERUSER=1", "--setenv=COMPOSER_NO_INTERACTION=1", php, "-d", "pcre.jit=0", composer, "laravel/installer"} {
		if !strings.Contains(got, want) {
			t.Fatalf("Composer isolated invocation missing %q:\n%s", want, got)
		}
	}
	if dst, err := os.Readlink(link); err != nil || dst != target {
		t.Fatalf("Laravel CLI link mismatch: dst=%q err=%v", dst, err)
	}
}
