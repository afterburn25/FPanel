package hosting

import (
	"path/filepath"
	"testing"
)

func TestAdoptDiscoveredAccountAndSiteWithoutPackage(t *testing.T) {
	dir := t.TempDir()
	m := New(filepath.Join(dir, "state.json"), filepath.Join(dir, "mock"), false)
	a, err := m.AdoptDiscoveredAccount(Account{Username: "providerusr", Status: "active"})
	if err != nil {
		t.Fatal(err)
	}
	if a.Package != "Detected" || a.PrimaryDomain != "" {
		t.Fatalf("account=%+v", a)
	}
	s, err := m.AdoptDiscoveredSite(Site{Domain: "existing.example.test", Username: "providerusr", DocumentRoot: "/home/providerusr/public_html", PHPVersion: "unknown", SSL: "configured", Status: "active"})
	if err != nil {
		t.Fatal(err)
	}
	if s.DocumentRoot != "/home/providerusr/public_html" || s.PHPVersion != "unknown" {
		t.Fatalf("site=%+v", s)
	}
}
