package api

import (
	"testing"

	"privora.local/panel/agent/internal/hostadapter"
	"privora.local/panel/agent/internal/hosting"
)

func TestManagedSubdomainDeleteFilesAllowedDedicatedRoot(t *testing.T) {
	site := hosting.Site{Domain: "blog.example.com", Username: "testuser", DocumentRoot: "/home/testuser/domains/blog.example.com/public"}
	ok, reason := managedSubdomainDeleteFilesAllowed(site.Domain, site.Username, site.DocumentRoot, []hosting.Site{site}, nil)
	if !ok || reason != "" {
		t.Fatalf("dedicated root should be deletable, ok=%v reason=%q", ok, reason)
	}
}

func TestManagedSubdomainDeleteFilesPreservesParentRoot(t *testing.T) {
	sub := hosting.Site{Domain: "blog.example.com", Username: "testuser", DocumentRoot: "/home/testuser/domains/example.com/public"}
	parent := hosting.Site{Domain: "example.com", Username: "testuser", DocumentRoot: "/home/testuser/domains/example.com/public"}
	ok, reason := managedSubdomainDeleteFilesAllowed(sub.Domain, sub.Username, sub.DocumentRoot, []hosting.Site{sub, parent}, nil)
	if ok {
		t.Fatal("parent/shared root must never be deleted with subdomain")
	}
	if reason == "" {
		t.Fatal("expected preservation reason")
	}
}

func TestManagedSubdomainDeleteFilesPreservesLiveSharedRoot(t *testing.T) {
	subRoot := "/home/testuser/domains/blog.example.com/public"
	state := []hosting.Site{{Domain: "blog.example.com", Username: "testuser", DocumentRoot: subRoot}}
	live := []hostadapter.LiveSite{
		{Domain: "blog.example.com", Username: "testuser", DocumentRoot: subRoot},
		{Domain: "alias.example.com", Username: "testuser", DocumentRoot: subRoot},
	}
	ok, _ := managedSubdomainDeleteFilesAllowed("blog.example.com", "testuser", subRoot, state, live)
	if ok {
		t.Fatal("root shared by another live vhost must be preserved")
	}
}
