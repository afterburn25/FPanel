package hostadapter

import (
	"os"
	"os/user"
	"path/filepath"
	"runtime"
	"testing"
)

func TestAccountAnalyticsParsesOwnedNginxLogs(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("linux analytics test")
	}
	u, err := user.Current()
	if err != nil || !validUser(u.Username) {
		t.Skip("current user unavailable")
	}
	root := t.TempDir()
	homeBase := filepath.Join(root, "home")
	home := filepath.Join(homeBase, u.Username)
	logDir := filepath.Join(root, "logs")
	if err := os.MkdirAll(filepath.Join(home, "domains/example.test/public"), 0750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(home, "domains/example.test/public/index.html"), []byte("hello"), 0640); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(logDir, 0750); err != nil {
		t.Fatal(err)
	}
	access := `203.0.113.10 - - [21/Aug/2026:12:00:00 -0500] "GET / HTTP/1.1" 200 1200 "-" "Mozilla/5.0"
203.0.113.11 - - [21/Aug/2026:12:01:00 -0500] "GET /missing HTTP/1.1" 404 321 "https://example.test/" "Mozilla/5.0"
203.0.113.10 - - [21/Aug/2026:12:02:00 -0500] "POST /api HTTP/1.1" 500 99 "-" "curl/8"
`
	if err := os.WriteFile(filepath.Join(logDir, "example.test.access.log"), []byte(access), 0640); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(logDir, "example.test.error.log"), []byte("2026/08/21 12:02:00 [error] sample upstream error\n"), 0640); err != nil {
		t.Fatal(err)
	}
	a := New(Config{CertificationMode: true, AccountHomeBase: homeBase, NginxLogDir: logDir})
	got, err := a.AccountAnalytics(u.Username, []string{"example.test"})
	if err != nil {
		t.Fatal(err)
	}
	if got.Requests != 3 || got.UniqueVisitors != 2 || got.HTTP4xx != 1 || got.HTTP5xx != 1 {
		t.Fatalf("bad traffic summary: %+v", got)
	}
	if got.BandwidthBytes != 1620 {
		t.Fatalf("bad bandwidth %d", got.BandwidthBytes)
	}
	if len(got.TopPaths) == 0 || len(got.RecentVisitors) != 3 || len(got.RecentErrors) < 2 {
		t.Fatalf("missing analytics detail: %+v", got)
	}
	if got.Usage.FileCount == 0 || got.Usage.DiskBytes < 5 {
		t.Fatalf("missing disk usage: %+v", got.Usage)
	}
}
