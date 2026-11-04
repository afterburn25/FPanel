package hosting

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestCreateSubdomainCanShareParentDocumentRootWithoutOverwritingFiles(t *testing.T) {
	dir := t.TempDir()
	m := New(filepath.Join(dir, "state.json"), filepath.Join(dir, "mock"), true)
	if _, err := m.CreateAccount(Account{Username: "testuser", Package: "Starter", PrimaryDomain: "example.com"}); err != nil {
		t.Fatal(err)
	}
	parent, err := m.CreateSite(Site{Domain: "example.com", Username: "testuser", PHPVersion: "8.4"})
	if err != nil {
		t.Fatal(err)
	}
	parentFS := filepath.Join(dir, "mock", strings.TrimPrefix(parent.DocumentRoot, string(os.PathSeparator)))
	marker := filepath.Join(parentFS, "parent-marker.txt")
	if err := os.WriteFile(marker, []byte("PARENT-CONTENT-MUST-SURVIVE"), 0640); err != nil {
		t.Fatal(err)
	}
	sub, err := m.CreateSite(Site{Domain: "blog.example.com", Username: "testuser", PHPVersion: "8.4", Kind: "subdomain", ParentDomain: "example.com", DocumentRoot: parent.DocumentRoot})
	if err != nil {
		t.Fatal(err)
	}
	if sub.DocumentRoot != parent.DocumentRoot {
		t.Fatalf("subdomain root=%q parent root=%q", sub.DocumentRoot, parent.DocumentRoot)
	}
	got, err := os.ReadFile(marker)
	if err != nil {
		t.Fatalf("parent marker was removed: %v", err)
	}
	if string(got) != "PARENT-CONTENT-MUST-SURVIVE" {
		t.Fatalf("parent content changed: %q", got)
	}
}
