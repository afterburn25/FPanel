package hostops

import "testing"

func TestPlansAreTypedAndGated(t *testing.T) {
	p, err := Build(Request{Kind: "site-config", Username: "acmeweb", Domain: "www.acme.test", PHPVersion: "8.4"})
	if err != nil {
		t.Fatal(err)
	}
	if p.Executable || p.Gate == "" || len(p.Steps) < 2 {
		t.Fatalf("unexpected plan: %#v", p)
	}
	for _, s := range append(append([]Step{}, p.Steps...), p.Validation...) {
		if s.Program == "/bin/sh" || s.Program == "/usr/bin/bash" {
			t.Fatalf("shell execution forbidden: %#v", s)
		}
	}
}

func TestPlannerRejectsInjection(t *testing.T) {
	bad := []Request{
		{Kind: "account-create", Username: "root;id"},
		{Kind: "site-config", Username: "acmeweb", Domain: "../../etc/passwd", PHPVersion: "8.4"},
		{Kind: "site-config", Username: "acmeweb", Domain: "ok.example", PHPVersion: "8.4;id"},
		{Kind: "database-create", Database: "db;drop", DBUser: "user"},
		{Kind: "firewall-allow", Port: 22, Protocol: "tcp;id", CIDR: "0.0.0.0/0"},
	}
	for _, in := range bad {
		if _, err := Build(in); err == nil {
			t.Fatalf("expected rejection: %#v", in)
		}
	}
}
