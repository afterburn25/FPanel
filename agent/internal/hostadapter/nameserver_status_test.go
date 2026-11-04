package hostadapter

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestInspectNameserverSetupReportsReady(t *testing.T) {
	bin := t.TempDir()
	scripts := map[string]string{
		"systemctl": "exit 0",
		"dig": `case "$*" in
*" example.test NS") printf 'ns2.example.test.\nns1.example.test.\n' ;;
*" ns1.example.test A") printf '192.0.2.10\n' ;;
*" ns2.example.test A") printf '192.0.2.10\n' ;;
esac
exit 0`,
	}
	for name, body := range scripts {
		if err := os.WriteFile(filepath.Join(bin, name), []byte("#!/bin/sh\n"+body+"\n"), 0755); err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv("PATH", bin+":"+os.Getenv("PATH"))
	root := t.TempDir()
	zoneDir := filepath.Join(root, "zones")
	if err := os.MkdirAll(zoneDir, 0755); err != nil {
		t.Fatal(err)
	}
	zone := `$TTL 3600
@ 3600 IN SOA ns1.example.test. hostmaster.example.test. (
  1 3600 900 1209600 300 )
@ 3600 IN NS ns1.example.test.
@ 3600 IN NS ns2.example.test.
ns1 3600 IN A 192.0.2.10
ns2 3600 IN A 192.0.2.10
`
	if err := os.WriteFile(filepath.Join(zoneDir, "example.test.zone"), []byte(zone), 0644); err != nil {
		t.Fatal(err)
	}
	a := New(Config{DNSZoneDir: zoneDir, DNSIndexPath: filepath.Join(root, "zones.conf"), DNSService: "bind9"})
	got := a.InspectNameserverSetup(context.Background(), NameserverSetupConfig{BaseDomain: "example.test", Primary: "ns1.example.test", Secondary: "ns2.example.test", IPv4: "192.0.2.10"})
	if !got.DNSZoneConfigured || !got.NameserverServiceRunning || !got.GlueRegistered || !got.DelegationActive {
		t.Fatalf("unexpected setup status: %+v", got)
	}
}

func TestInspectNameserverSetupAcceptsFQDNApexAndInheritedOwner(t *testing.T) {
	bin := t.TempDir()
	for name, body := range map[string]string{
		"systemctl": "exit 0",
		"dig":       "exit 0",
	} {
		if err := os.WriteFile(filepath.Join(bin, name), []byte("#!/bin/sh\n"+body+"\n"), 0755); err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv("PATH", bin+":"+os.Getenv("PATH"))
	root := t.TempDir()
	zoneDir := filepath.Join(root, "zones")
	if err := os.MkdirAll(zoneDir, 0755); err != nil {
		t.Fatal(err)
	}
	zone := `$TTL 3600
example.test. IN SOA ns1.example.test. hostmaster.example.test. ( 1 3600 900 1209600 300 )
example.test. IN NS ns1.example.test.
              IN NS ns2.example.test.
ns1 3600 IN A 192.0.2.10
ns2 3600 IN A 192.0.2.10
`
	if err := os.WriteFile(filepath.Join(zoneDir, "example.test.zone"), []byte(zone), 0644); err != nil {
		t.Fatal(err)
	}
	a := New(Config{DNSZoneDir: zoneDir, DNSIndexPath: filepath.Join(root, "zones.conf"), DNSService: "bind9"})
	got := a.InspectNameserverSetup(context.Background(), NameserverSetupConfig{BaseDomain: "example.test", Primary: "ns1.example.test", Secondary: "ns2.example.test", IPv4: "192.0.2.10"})
	if !got.DNSZoneConfigured {
		t.Fatalf("valid FQDN/inherited-owner apex NS pair was reported unconfigured: %+v", got)
	}
	if got.DNSZoneSource != "managed-zone-file" {
		t.Fatalf("unexpected DNS zone source: %+v", got)
	}
}

func TestInspectNameserverSetupAcceptsLoadedLegacyZoneOutsidePrivoraDirectory(t *testing.T) {
	bin := t.TempDir()
	scripts := map[string]string{
		"systemctl": "exit 0",
		"dig": `case "$*" in
*"@127.0.0.1"*" example.test NS") cat <<'OUT'
;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 1
;; flags: qr aa; QUERY: 1, ANSWER: 2, AUTHORITY: 0, ADDITIONAL: 1
;; ANSWER SECTION:
example.test. 3600 IN NS ns1.example.test.
example.test. 3600 IN NS ns2.example.test.
OUT
;;
*" +short example.test NS") printf 'ns1.example.test.\nns2.example.test.\n' ;;
*" +short ns1.example.test A") printf '192.0.2.10\n' ;;
*" +short ns2.example.test A") printf '192.0.2.10\n' ;;
esac
exit 0`,
	}
	for name, body := range scripts {
		if err := os.WriteFile(filepath.Join(bin, name), []byte("#!/bin/sh\n"+body+"\n"), 0755); err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv("PATH", bin+":"+os.Getenv("PATH"))
	root := t.TempDir()
	a := New(Config{DNSZoneDir: filepath.Join(root, "privora-zones"), DNSIndexPath: filepath.Join(root, "zones.conf"), DNSService: "bind9"})
	got := a.InspectNameserverSetup(context.Background(), NameserverSetupConfig{BaseDomain: "example.test", Primary: "ns1.example.test", Secondary: "ns2.example.test", IPv4: "192.0.2.10"})
	if !got.DNSZoneConfigured {
		t.Fatalf("loaded authoritative legacy zone was reported unconfigured: %+v", got)
	}
	if !strings.HasPrefix(got.DNSZoneSource, "local-authoritative-server:") {
		t.Fatalf("expected local-authoritative-server source: %+v", got)
	}
}

func TestAuthoritativeSOAFromDigRequiresExactApex(t *testing.T) {
	raw := `;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 2
;; flags: qr aa; QUERY: 1, ANSWER: 1
privoralabs.com. 3600 IN SOA ns1.privoralabs.com. hostmaster.privoralabs.com. 1 3600 900 1209600 300
`
	if !authoritativeSOAFromDig(raw, "privoralabs.com") {
		t.Fatal("authoritative exact SOA was not recognized")
	}
	if authoritativeSOAFromDig(raw, "demo.privoralabs.com") {
		t.Fatal("parent-zone SOA must not be mistaken for a child zone")
	}
}

func TestInspectNameserverSetupTreatsIPv6GlueAsOptionalWhenIPv4IsConfirmed(t *testing.T) {
	bin := t.TempDir()
	scripts := map[string]string{
		"systemctl": "exit 0",
		"dig": `case "$*" in
*" example.test NS") printf 'ns1.example.test.\nns2.example.test.\n' ;;
*" ns1.example.test A") printf '192.0.2.10\n' ;;
*" ns2.example.test A") printf '192.0.2.10\n' ;;
*" ns1.example.test AAAA") : ;;
*" ns2.example.test AAAA") : ;;
esac
exit 0`,
	}
	for name, body := range scripts {
		if err := os.WriteFile(filepath.Join(bin, name), []byte("#!/bin/sh\n"+body+"\n"), 0755); err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv("PATH", bin+":"+os.Getenv("PATH"))
	root := t.TempDir()
	zoneDir := filepath.Join(root, "zones")
	if err := os.MkdirAll(zoneDir, 0755); err != nil {
		t.Fatal(err)
	}
	zone := `$TTL 3600
@ 3600 IN SOA ns1.example.test. hostmaster.example.test. ( 1 3600 900 1209600 300 )
@ 3600 IN NS ns1.example.test.
@ 3600 IN NS ns2.example.test.
ns1 3600 IN A 192.0.2.10
ns2 3600 IN A 192.0.2.10
`
	if err := os.WriteFile(filepath.Join(zoneDir, "example.test.zone"), []byte(zone), 0644); err != nil {
		t.Fatal(err)
	}
	a := New(Config{DNSZoneDir: zoneDir, DNSIndexPath: filepath.Join(root, "zones.conf"), DNSService: "bind9"})
	got := a.InspectNameserverSetup(context.Background(), NameserverSetupConfig{BaseDomain: "example.test", Primary: "ns1.example.test", Secondary: "ns2.example.test", IPv4: "192.0.2.10", IPv6: "2001:db8::10"})
	if !got.GlueRegistered || !got.GlueIPv4Registered || got.GlueIPv6Registered {
		t.Fatalf("IPv4-confirmed glue should remain operational when optional IPv6 glue is absent: %+v", got)
	}
	if !strings.Contains(got.Detail, "IPv4 glue is reachable") {
		t.Fatalf("missing optional IPv6 detail: %+v", got)
	}
}
