package hostadapter

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestBINDProvisionTransactionWithFakeTools(t *testing.T) {
	bin := t.TempDir()
	for name, body := range map[string]string{"named-checkzone": "exit 0", "systemctl": "exit 0"} {
		if err := os.WriteFile(filepath.Join(bin, name), []byte("#!/bin/sh\n"+body+"\n"), 0755); err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv("PATH", bin+":"+os.Getenv("PATH"))
	root := t.TempDir()
	a := New(Config{AllowMutations: true, CertificationMode: true, DNSZoneDir: filepath.Join(root, "zones"), DNSIndexPath: filepath.Join(root, "privora-zones.conf"), DNSService: "bind9"})
	r, err := a.ProvisionBINDZone(context.Background(), "example.test", []DNSRecord{{Type: "A", Name: "@", Value: "192.0.2.10", TTL: 300}})
	if err != nil {
		t.Fatal(err)
	}
	if !r.Validated || !r.Reloaded {
		t.Fatalf("%+v", r)
	}
	if _, err := os.Stat(r.ZoneFile); err != nil {
		t.Fatal(err)
	}
}
func TestBINDRollbackOnValidationFailure(t *testing.T) {
	bin := t.TempDir()
	os.WriteFile(filepath.Join(bin, "named-checkzone"), []byte("#!/bin/sh\nexit 1\n"), 0755)
	os.WriteFile(filepath.Join(bin, "systemctl"), []byte("#!/bin/sh\nexit 0\n"), 0755)
	t.Setenv("PATH", bin+":"+os.Getenv("PATH"))
	root := t.TempDir()
	zoneDir := filepath.Join(root, "zones")
	os.MkdirAll(zoneDir, 0750)
	zonePath := filepath.Join(zoneDir, "example.test.zone")
	os.WriteFile(zonePath, []byte("old"), 0640)
	a := New(Config{AllowMutations: true, CertificationMode: true, DNSZoneDir: zoneDir, DNSIndexPath: filepath.Join(root, "index.conf")})
	if _, err := a.ProvisionBINDZone(context.Background(), "example.test", []DNSRecord{{Type: "A", Name: "@", Value: "192.0.2.10", TTL: 300}}); err == nil {
		t.Fatal("validation failure accepted")
	}
	b, _ := os.ReadFile(zonePath)
	if string(b) != "old" {
		t.Fatalf("rollback failed: %s", b)
	}
}

func TestReadUpdateDeleteManagedBINDRecords(t *testing.T) {
	bin := t.TempDir()
	for name, body := range map[string]string{"named-checkzone": "exit 0", "systemctl": "exit 0"} {
		if err := os.WriteFile(filepath.Join(bin, name), []byte("#!/bin/sh\n"+body+"\n"), 0755); err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv("PATH", bin+":"+os.Getenv("PATH"))
	root := t.TempDir()
	a := New(Config{AllowMutations: true, CertificationMode: true, DNSZoneDir: filepath.Join(root, "zones"), DNSIndexPath: filepath.Join(root, "privora-zones.conf"), DNSService: "bind9"})
	_, err := a.ProvisionBINDZoneWithNameservers(context.Background(), "example.test", "ns1.host.test", "ns2.host.test", []DNSRecord{{Type: "A", Name: "@", Value: "192.0.2.10", TTL: 300}, {Type: "TXT", Name: "_dmarc", Value: "v=DMARC1; p=none", TTL: 3600}})
	if err != nil {
		t.Fatal(err)
	}
	zone, err := a.ReadBINDZone("example.test")
	if err != nil || len(zone.Records) < 4 { // 2 NS + 2 custom
		t.Fatalf("unexpected zone read: %+v %v", zone, err)
	}
	if _, err := a.UpsertBINDRecords(context.Background(), "example.test", []DNSRecord{{Type: "A", Name: "app", Value: "192.0.2.20", TTL: 300}}); err != nil {
		t.Fatal(err)
	}
	if _, err := a.DeleteBINDRecord(context.Background(), "example.test", DNSRecord{Type: "A", Name: "app", Value: "192.0.2.20"}); err != nil {
		t.Fatal(err)
	}
	zone, err = a.ReadBINDZone("example.test")
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range zone.Records {
		if r.Name == "app" && r.Type == "A" {
			t.Fatal("deleted record remains in live zone")
		}
	}
}

func TestReplaceBINDRecordChangesIdentityAndPreservesRootNS(t *testing.T) {
	bin := t.TempDir()
	for name, body := range map[string]string{"named-checkzone": "exit 0", "systemctl": "exit 0"} {
		if err := os.WriteFile(filepath.Join(bin, name), []byte("#!/bin/sh\n"+body+"\n"), 0755); err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv("PATH", bin+":"+os.Getenv("PATH"))
	root := t.TempDir()
	a := New(Config{AllowMutations: true, CertificationMode: true, DNSZoneDir: filepath.Join(root, "zones"), DNSIndexPath: filepath.Join(root, "privora-zones.conf"), DNSService: "bind9"})
	if _, err := a.ProvisionBINDZoneWithNameservers(context.Background(), "example.test", "ns1.host.test", "ns2.host.test", []DNSRecord{{Type: "A", Name: "app", Value: "192.0.2.20", TTL: 300}}); err != nil {
		t.Fatal(err)
	}
	if _, err := a.ReplaceBINDRecord(context.Background(), "example.test", DNSRecord{Type: "A", Name: "app", Value: "192.0.2.20", TTL: 300}, DNSRecord{Type: "AAAA", Name: "api", Value: "2001:db8::20", TTL: 600}); err != nil {
		t.Fatal(err)
	}
	zone, err := a.ReadBINDZone("example.test")
	if err != nil {
		t.Fatal(err)
	}
	oldFound, newFound, ns1, ns2 := false, false, false, false
	for _, r := range zone.Records {
		if r.Type == "A" && r.Name == "app" && r.Value == "192.0.2.20" {
			oldFound = true
		}
		if r.Type == "AAAA" && r.Name == "api" && r.Value == "2001:db8::20" && r.TTL == 600 {
			newFound = true
		}
		if r.Type == "NS" && isDNSZoneApexOwner(r.Name, "example.test") && strings.TrimSuffix(r.Value, ".") == "ns1.host.test" {
			ns1 = true
		}
		if r.Type == "NS" && isDNSZoneApexOwner(r.Name, "example.test") && strings.TrimSuffix(r.Value, ".") == "ns2.host.test" {
			ns2 = true
		}
	}
	if oldFound || !newFound || !ns1 || !ns2 {
		t.Fatalf("transactional replace did not preserve expected zone state: %+v", zone.Records)
	}
}

func TestReplaceBINDRecordRejectsRootAuthority(t *testing.T) {
	a := New(Config{AllowMutations: true, CertificationMode: true})
	if _, err := a.ReplaceBINDRecord(context.Background(), "example.test", DNSRecord{Type: "NS", Name: "@", Value: "ns1.example.test", TTL: 3600}, DNSRecord{Type: "NS", Name: "@", Value: "ns3.example.test", TTL: 3600}); err == nil {
		t.Fatal("expected root authoritative NS replacement to be rejected")
	}
	if _, err := a.ReplaceBINDRecord(context.Background(), "example.test", DNSRecord{Type: "SOA", Name: "@", Value: "x"}, DNSRecord{Type: "TXT", Name: "@", Value: "x"}); err == nil {
		t.Fatal("expected SOA replacement to be rejected")
	}
}
