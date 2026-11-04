package hostadapter

import (
	"archive/zip"
	"os"
	"path/filepath"
	"testing"
)

func writeTestZip(t *testing.T, names ...string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "package.zip")
	f, err := os.Create(p)
	if err != nil {
		t.Fatal(err)
	}
	zw := zip.NewWriter(f)
	for _, name := range names {
		w, err := zw.Create("privora/" + name)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := w.Write([]byte("{}")); err != nil {
			t.Fatal(err)
		}
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestDetectPrivoraArchiveKind(t *testing.T) {
	if got := detectPrivoraArchiveKind(writeTestZip(t, "FULL-CORE-MANIFEST.json")); got != "full-core" {
		t.Fatalf("full-core detected as %q", got)
	}
	if got := detectPrivoraArchiveKind(writeTestZip(t, "UPDATE-MANIFEST.json", "UPDATE-MANIFEST.sig")); got != "update" {
		t.Fatalf("update detected as %q", got)
	}
	if got := detectPrivoraArchiveKind(writeTestZip(t, "README.md")); got != "unknown" {
		t.Fatalf("unknown package detected as %q", got)
	}
}
