package hostadapter

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

func TestResolveSiteDocumentRootAllowsExistingParentRoot(t *testing.T) {
	base := t.TempDir()
	a := &Adapter{cfg: Config{AccountHomeBase: base}}
	parentFS := filepath.Join(base, "testuser", "domains", "example.com", "public")
	if err := os.MkdirAll(parentFS, 0750); err != nil {
		t.Fatal(err)
	}

	serverRoot, fsRoot, ownTree, exists, err := a.resolveSiteDocumentRoot("blog.example.com", "testuser", "/home/testuser/domains/example.com/public")
	if err != nil {
		t.Fatalf("expected parent root to be accepted: %v", err)
	}
	if serverRoot != "/home/testuser/domains/example.com/public" {
		t.Fatalf("unexpected server root %q", serverRoot)
	}
	if fsRoot != parentFS {
		t.Fatalf("unexpected fs root %q", fsRoot)
	}
	if ownTree != filepath.Join(base, "testuser", "domains", "blog.example.com") {
		t.Fatalf("unexpected own tree %q", ownTree)
	}
	if !exists {
		t.Fatal("expected existing parent root")
	}
}

func TestResolveSiteDocumentRootDefaultsToDedicatedSubdomainRoot(t *testing.T) {
	base := t.TempDir()
	a := &Adapter{cfg: Config{AccountHomeBase: base}}
	serverRoot, _, _, exists, err := a.resolveSiteDocumentRoot("blog.example.com", "testuser", "")
	if err != nil {
		t.Fatal(err)
	}
	if serverRoot != "/home/testuser/domains/blog.example.com/public" {
		t.Fatalf("unexpected default root %q", serverRoot)
	}
	if exists {
		t.Fatal("new default root should not exist in fixture")
	}
}

func TestResolveSiteDocumentRootRejectsUnsafeOrMissingSharedPath(t *testing.T) {
	base := t.TempDir()
	a := &Adapter{cfg: Config{AccountHomeBase: base}}
	if _, _, _, _, err := a.resolveSiteDocumentRoot("blog.example.com", "testuser", "/etc/nginx"); err == nil {
		t.Fatal("expected outside-account root to be rejected")
	}
	if _, _, _, _, err := a.resolveSiteDocumentRoot("blog.example.com", "testuser", "/home/testuser/domains/example.com/missing"); err == nil {
		t.Fatal("expected nonexistent path outside the subdomain's own tree to be rejected")
	}
}

func TestDeleteSiteWithSharedParentRootPreservesParentFiles(t *testing.T) {
	base := t.TempDir()
	bin := filepath.Join(base, "bin")
	available := filepath.Join(base, "nginx-available")
	enabled := filepath.Join(base, "nginx-enabled")
	for _, dir := range []string{bin, available, enabled} {
		if err := os.MkdirAll(dir, 0755); err != nil {
			t.Fatal(err)
		}
	}
	for _, name := range []string{"nginx", "systemctl"} {
		if err := os.WriteFile(filepath.Join(bin, name), []byte("#!/bin/sh\nexit 0\n"), 0755); err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv("PATH", bin+":"+os.Getenv("PATH"))

	parentRoot := filepath.Join(base, "testuser", "domains", "example.com", "public")
	if err := os.MkdirAll(parentRoot, 0750); err != nil {
		t.Fatal(err)
	}
	marker := filepath.Join(parentRoot, "index.php")
	if err := os.WriteFile(marker, []byte("parent"), 0644); err != nil {
		t.Fatal(err)
	}

	conf := filepath.Join(available, "privora-blog.example.com.conf")
	if err := os.WriteFile(conf, []byte("server {}\n"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(conf, filepath.Join(enabled, "privora-blog.example.com.conf")); err != nil {
		t.Fatal(err)
	}

	a := New(Config{AllowMutations: true, CertificationMode: true, AccountHomeBase: base, NginxSitesAvailable: available, NginxSitesEnabled: enabled})
	if err := a.DeleteSiteWithDocumentRoot(context.Background(), "blog.example.com", "testuser", "/home/testuser/domains/example.com/public", true); err != nil {
		t.Fatalf("delete shared-root subdomain: %v", err)
	}
	if _, err := os.Stat(marker); err != nil {
		t.Fatalf("parent file was removed: %v", err)
	}
	if _, err := os.Stat(conf); !os.IsNotExist(err) {
		t.Fatalf("subdomain vhost was not removed: %v", err)
	}
}

func TestDeleteSiteWithDedicatedRootRemovesOnlySubdomainTree(t *testing.T) {
	base := t.TempDir()
	bin := filepath.Join(base, "bin")
	available := filepath.Join(base, "nginx-available")
	enabled := filepath.Join(base, "nginx-enabled")
	for _, dir := range []string{bin, available, enabled} {
		if err := os.MkdirAll(dir, 0755); err != nil {
			t.Fatal(err)
		}
	}
	for _, name := range []string{"nginx", "systemctl"} {
		if err := os.WriteFile(filepath.Join(bin, name), []byte("#!/bin/sh\nexit 0\n"), 0755); err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv("PATH", bin+":"+os.Getenv("PATH"))

	parentRoot := filepath.Join(base, "testuser", "domains", "example.com", "public")
	ownRoot := filepath.Join(base, "testuser", "domains", "blog.example.com", "public")
	if err := os.MkdirAll(parentRoot, 0750); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(ownRoot, 0750); err != nil {
		t.Fatal(err)
	}
	parentMarker := filepath.Join(parentRoot, "index.php")
	ownMarker := filepath.Join(ownRoot, "index.php")
	if err := os.WriteFile(parentMarker, []byte("parent"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(ownMarker, []byte("subdomain"), 0644); err != nil {
		t.Fatal(err)
	}

	conf := filepath.Join(available, "privora-blog.example.com.conf")
	if err := os.WriteFile(conf, []byte("server {}\n"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(conf, filepath.Join(enabled, "privora-blog.example.com.conf")); err != nil {
		t.Fatal(err)
	}

	a := New(Config{AllowMutations: true, CertificationMode: true, AccountHomeBase: base, NginxSitesAvailable: available, NginxSitesEnabled: enabled})
	if err := a.DeleteSiteWithDocumentRoot(context.Background(), "blog.example.com", "testuser", "/home/testuser/domains/blog.example.com/public", true); err != nil {
		t.Fatalf("delete dedicated-root subdomain: %v", err)
	}
	if _, err := os.Stat(filepath.Join(base, "testuser", "domains", "blog.example.com")); !os.IsNotExist(err) {
		t.Fatalf("dedicated subdomain tree was not removed: %v", err)
	}
	if _, err := os.Stat(parentMarker); err != nil {
		t.Fatalf("parent file was removed: %v", err)
	}
}
