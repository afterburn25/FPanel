package hostadapter

import (
	"archive/tar"
	"compress/gzip"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestDNSAndDatabaseRenderers(t *testing.T) {
	zone, err := RenderDNSZone("example.test", []DNSRecord{{Type: "A", Name: "@", Value: "192.0.2.10", TTL: 300}, {Type: "TXT", Name: "_dmarc", Value: "v=DMARC1; p=reject", TTL: 300}}, 2026081801)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(zone, "192.0.2.10") || !strings.Contains(zone, "DMARC1") {
		t.Fatal("zone incomplete")
	}
	if _, err := RenderDNSZone("../bad", nil, 1); err == nil {
		t.Fatal("bad domain accepted")
	}
	sql, err := MariaDBCreateSQL("acct_app", "acct_user")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(sql, "CREATE DATABASE") {
		t.Fatal("sql missing")
	}
	if _, err := MariaDBCreateSQL("bad-name;DROP", "u"); err == nil {
		t.Fatal("unsafe db accepted")
	}
}

func TestLocalBackup(t *testing.T) {
	if _, ok := commandExists("tar"); !ok {
		t.Skip("tar absent")
	}
	if _, ok := commandExists("zstd"); !ok {
		t.Skip("zstd absent")
	}
	root := t.TempDir()
	src := filepath.Join(root, "site")
	if err := os.MkdirAll(src, 0750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(src, "index.html"), []byte("hello"), 0640); err != nil {
		t.Fatal(err)
	}
	dst := filepath.Join(root, "backups", "site.tar.zst")
	r, err := New(Config{AllowMutations: true, CertificationMode: true}).CreateLocalBackup(context.Background(), src, dst)
	if err != nil {
		t.Fatal(err)
	}
	if r.Size <= 0 || len(r.SHA256) != 64 {
		t.Fatalf("bad result %+v", r)
	}
}

func writeTarGz(t *testing.T, path string, entries map[string]string) {
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	gz := gzip.NewWriter(f)
	tw := tar.NewWriter(gz)
	for name, body := range entries {
		b := []byte(body)
		h := &tar.Header{Name: name, Mode: 0640, Size: int64(len(b))}
		if err := tw.WriteHeader(h); err != nil {
			t.Fatal(err)
		}
		if _, err := tw.Write(b); err != nil {
			t.Fatal(err)
		}
	}
	tw.Close()
	gz.Close()
	f.Close()
}
func TestInspectCPanelBackup(t *testing.T) {
	p := filepath.Join(t.TempDir(), "cpmove-acct.tar.gz")
	writeTarGz(t, p, map[string]string{"homedir/public_html/index.php": "ok", "mysql/acct.sql": "sql", "dns/example.test.db": "zone"})
	m, err := InspectCPanelBackup(p)
	if err != nil {
		t.Fatal(err)
	}
	if !m.HasHomedir || !m.HasMysql || !m.HasDNS {
		t.Fatalf("manifest %+v", m)
	}
	bad := filepath.Join(t.TempDir(), "bad.tar.gz")
	writeTarGz(t, bad, map[string]string{"../escape": "x"})
	if _, err := InspectCPanelBackup(bad); err == nil {
		t.Fatal("traversal accepted")
	}
}

func TestVerifiedSiteRestoreKeepsRollback(t *testing.T) {
	if _, ok := commandExists("tar"); !ok {
		t.Skip("tar absent")
	}
	if _, ok := commandExists("zstd"); !ok {
		t.Skip("zstd absent")
	}
	root := t.TempDir()
	target := filepath.Join(root, "example.test")
	if err := os.MkdirAll(target, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(target, "index.html"), []byte("backup-version"), 0644); err != nil {
		t.Fatal(err)
	}
	a := New(Config{AllowMutations: true, CertificationMode: true})
	b, err := a.CreateLocalBackup(context.Background(), target, filepath.Join(root, "backup.tar.zst"))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(target, "index.html"), []byte("current-version"), 0644); err != nil {
		t.Fatal(err)
	}
	r, err := a.RestoreLocalBackup(context.Background(), b.Path, b.SHA256, target)
	if err != nil {
		t.Fatal(err)
	}
	got, _ := os.ReadFile(filepath.Join(target, "index.html"))
	if string(got) != "backup-version" {
		t.Fatalf("restore content=%q", got)
	}
	old, _ := os.ReadFile(filepath.Join(r.RollbackPath, "index.html"))
	if string(old) != "current-version" {
		t.Fatalf("rollback content=%q", old)
	}
	if _, err := a.RestoreLocalBackup(context.Background(), b.Path, strings.Repeat("0", 64), target); err == nil {
		t.Fatal("restore accepted wrong digest")
	}
}

func TestRenderDNSZoneSplitsAndRoundTripsLongDKIMTXT(t *testing.T) {
	value := "v=DKIM1; k=rsa; p=" + strings.Repeat("A", 392)
	zone, err := RenderDNSZone("example.test", []DNSRecord{{Type: "TXT", Name: "mail._domainkey", Value: value, TTL: 3600}}, 2026082601)
	if err != nil {
		t.Fatal(err)
	}
	line := ""
	for _, row := range strings.Split(zone, "\n") {
		if strings.Contains(row, "mail._domainkey") {
			line = row
			break
		}
	}
	if line == "" || strings.Count(line, `"`) < 4 {
		t.Fatalf("expected split quoted DKIM TXT, got %q", line)
	}
	parsed := parseBINDZoneFile("example.test", "example.test.zone", []byte(zone))
	if len(parsed.Records) != 3 {
		t.Fatalf("expected NS, NS, TXT records, got %#v", parsed.Records)
	}
	got := ""
	for _, r := range parsed.Records {
		if r.Type == "TXT" && r.Name == "mail._domainkey" {
			got = r.Value
		}
	}
	if got != value {
		t.Fatalf("DKIM TXT round trip mismatch: got len=%d want len=%d", len(got), len(value))
	}
}
