package hostadapter

import "testing"

func TestPHPVersionExtensionAllowList(t *testing.T) {
	if !allowedPHPVersion("8.2") || !allowedPHPVersion("8.3") || !allowedPHPVersion("8.4") || !allowedPHPVersion("8.5") {
		t.Fatal("supported PHP version missing")
	}
	if allowedPHPVersion("8.6") || allowedPHPVersion("7.4") {
		t.Fatal("unexpected PHP version allowed")
	}
	ids := map[string]bool{}
	for _, d := range componentDefinitions() {
		if ids[d.ID] {
			t.Fatalf("duplicate component id: %s", d.ID)
		}
		ids[d.ID] = true
	}
	for _, id := range []string{"php82-curl", "php83-curl", "php-curl", "php85-curl", "php-bz2", "php-mongodb", "php-opcache", "php-ssh2", "php-tidy", "avif-tools", "metadata-tools", "redis-server", "supervisor", "python3", "golang", "java", "ruby", "rust", "yarn", "pnpm"} {
		if !ids[id] {
			t.Fatalf("required component missing: %s", id)
		}
	}
}

func TestPresetDefinitionsUseVersionScopedComponents(t *testing.T) {
	rows := presetDefinitions("8.3")
	if len(rows) != 4 {
		t.Fatalf("expected four presets, got %d", len(rows))
	}
	found := false
	for _, p := range rows {
		if p.ID == "wordpress" {
			for _, id := range p.ComponentIDs {
				if id == "php83-curl" {
					found = true
				}
			}
		}
	}
	if !found {
		t.Fatal("WordPress preset did not use PHP 8.3 scoped extension IDs")
	}
}
