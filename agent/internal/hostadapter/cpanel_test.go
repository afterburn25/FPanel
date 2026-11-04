package hostadapter

import (
	"archive/tar"
	"compress/gzip"
	"os"
	"path/filepath"
	"testing"
)

func makeCPanelTGZ(t *testing.T, entries map[string]string, symlink bool) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "backup.tar.gz")
	f, err := os.Create(p)
	if err != nil {
		t.Fatal(err)
	}
	gz := gzip.NewWriter(f)
	tw := tar.NewWriter(gz)
	for name, body := range entries {
		h := &tar.Header{Name: name, Mode: 0600, Size: int64(len(body)), Typeflag: tar.TypeReg}
		if err := tw.WriteHeader(h); err != nil {
			t.Fatal(err)
		}
		if _, err := tw.Write([]byte(body)); err != nil {
			t.Fatal(err)
		}
	}
	if symlink {
		h := &tar.Header{Name: "homedir/link", Typeflag: tar.TypeSymlink, Linkname: "/etc/passwd"}
		if err := tw.WriteHeader(h); err != nil {
			t.Fatal(err)
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gz.Close(); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	return p
}
func TestStageCPanelBackup(t *testing.T) {
	p := makeCPanelTGZ(t, map[string]string{"homedir/public_html/index.php": "<?php echo 1;", "mysql/app.sql": "select 1;", "dns/example.db": "zone"}, false)
	dest := filepath.Join(t.TempDir(), "staged")
	got, err := StageCPanelBackup(p, dest, 1<<20)
	if err != nil {
		t.Fatal(err)
	}
	if !got.Manifest.HasHomedir || !got.Manifest.HasMysql || !got.Manifest.HasDNS || got.Bytes == 0 {
		t.Fatalf("bad stage result: %+v", got)
	}
	b, err := os.ReadFile(filepath.Join(dest, "homedir/public_html/index.php"))
	if err != nil {
		t.Fatal(err)
	}
	if string(b) != "<?php echo 1;" {
		t.Fatalf("bad extracted file: %q", b)
	}
}
func TestStageCPanelRejectsLinksAndSize(t *testing.T) {
	p := makeCPanelTGZ(t, map[string]string{"homedir/a": "1234567890"}, true)
	if _, err := StageCPanelBackup(p, filepath.Join(t.TempDir(), "links"), 1<<20); err == nil {
		t.Fatal("expected link rejection")
	}
	p2 := makeCPanelTGZ(t, map[string]string{"homedir/a": "1234567890"}, false)
	if _, err := StageCPanelBackup(p2, filepath.Join(t.TempDir(), "large"), 5); err == nil {
		t.Fatal("expected size rejection")
	}
}
