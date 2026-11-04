package hostadapter

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestValidateHTTPSURL(t *testing.T) {
	for _, v := range []string{"https://updates.example.test/a", "https://cdn.example.test/v/release.tar.zst?x=1"} {
		if e := validateHTTPSURL(v); e != nil {
			t.Fatal(e)
		}
	}
	for _, v := range []string{"http://x/a", "file:///tmp/a", "https://u:p@x/a", "https://x/a#f", "bad"} {
		if e := validateHTTPSURL(v); e == nil {
			t.Fatalf("accepted %s", v)
		}
	}
}

func TestAppendUpdateLaunchJournal(t *testing.T) {
	a := New(Config{UpdateStateRoot: t.TempDir()})
	id := "20260820T000000Z-deadbeefdeadbeef"
	now := "2026-08-20T04:20:00Z"
	if err := a.appendUpdateLaunchJournal(id, map[string]string{
		"started_at":       now,
		"phase":            "launch",
		"status":           "running",
		"phase_started_at": now,
		"activity_at":      now,
		"operation":        "Launching privileged update worker",
	}); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(filepath.Join(a.cfg.UpdateStateRoot, id, "journal.env"))
	if err != nil {
		t.Fatal(err)
	}
	s := string(b)
	for _, want := range []string{"phase=launch", "status=running", "operation=Launching\\ privileged\\ update\\ worker"} {
		if !strings.Contains(s, want) {
			t.Fatalf("journal missing %q: %s", want, s)
		}
	}
}
