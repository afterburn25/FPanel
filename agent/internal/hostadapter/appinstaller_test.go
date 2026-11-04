package hostadapter

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"syscall"
	"testing"
)

func signManifestFixture(t *testing.T, dir string, m AppReleaseManifest) (string, string, string) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(m)
	sum := sha256.Sum256(raw)
	// SignPKCS1v15 uses the same SHA-256 identifier as the production verifier.
	sig, err := rsa.SignPKCS1v15(rand.Reader, key, cryptoHashSHA256(), sum[:])
	if err != nil {
		t.Fatal(err)
	}
	mp := filepath.Join(dir, "releases.json")
	sp := mp + ".sig"
	kp := filepath.Join(dir, "pub.pem")
	if err = os.WriteFile(mp, raw, 0600); err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(sp, sig, 0600); err != nil {
		t.Fatal(err)
	}
	pubDER, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	pub := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubDER})
	if err = os.WriteFile(kp, pub, 0600); err != nil {
		t.Fatal(err)
	}
	return mp, sp, kp
}

// tiny wrapper keeps the test source concise without changing production crypto.
func cryptoHashSHA256() crypto.Hash { return crypto.SHA256 }

func TestSignedAppManifest(t *testing.T) {
	dir := t.TempDir()
	sha := sha256.Sum256([]byte("fixture"))
	m := AppReleaseManifest{Schema: "privora-app-release-manifest-v1", GeneratedAt: "2026-08-18T00:00:00Z", Releases: []AppRelease{{Template: "wordpress", Version: "1.2.3", URL: "https://example.test/app.tar.gz", SHA256: hex.EncodeToString(sha[:]), Archive: "tar.gz", StripComponents: 1, MaxBytes: 1024 * 1024, Bootstrap: "wordpress", Current: true}}}
	mp, sp, kp := signManifestFixture(t, dir, m)
	a := New(Config{CertificationMode: true, AppManifestPath: mp, AppManifestSigPath: sp, AppManifestPublicKey: kp})
	got, err := a.LoadSignedAppManifest()
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Releases) != 1 || got.Releases[0].Template != "wordpress" {
		t.Fatalf("unexpected manifest: %#v", got)
	}
	raw, _ := os.ReadFile(mp)
	raw = append(raw, ' ')
	_ = os.WriteFile(mp, raw, 0600)
	if _, err = a.LoadSignedAppManifest(); err == nil {
		t.Fatal("tampered manifest accepted")
	}
}

func TestExtractZipRejectsSymlinkAndTraversal(t *testing.T) {
	mk := func(name string, mode os.FileMode) string {
		p := filepath.Join(t.TempDir(), "x.zip")
		f, _ := os.Create(p)
		zw := zip.NewWriter(f)
		h := &zip.FileHeader{Name: name, Method: zip.Store}
		h.SetMode(mode)
		w, _ := zw.CreateHeader(h)
		_, _ = w.Write([]byte("x"))
		_ = zw.Close()
		_ = f.Close()
		return p
	}
	if err := extractZip(mk("../escape.php", 0644), t.TempDir(), 0, 1024); err == nil {
		t.Fatal("traversal accepted")
	}
	if err := extractZip(mk("link", os.ModeSymlink|0777), t.TempDir(), 0, 1024); err == nil {
		t.Fatal("symlink accepted")
	}
}

func TestExtractTarRejectsLinks(t *testing.T) {
	p := filepath.Join(t.TempDir(), "x.tar.gz")
	var b bytes.Buffer
	gz := gzip.NewWriter(&b)
	tw := tar.NewWriter(gz)
	_ = tw.WriteHeader(&tar.Header{Name: "root/file", Mode: 0644, Size: 1, Typeflag: tar.TypeReg})
	_, _ = tw.Write([]byte("x"))
	_ = tw.WriteHeader(&tar.Header{Name: "root/link", Linkname: "/etc/passwd", Mode: 0777, Typeflag: tar.TypeSymlink})
	_ = tw.Close()
	_ = gz.Close()
	_ = os.WriteFile(p, b.Bytes(), 0600)
	if err := extractTarGz(p, t.TempDir(), 1, 1024); err == nil {
		t.Fatal("tar symlink accepted")
	}
}

func TestAppTargetContainment(t *testing.T) {
	root := "/home/acme/domains/example.test/public"
	if got, err := appTarget(root, "blog"); err != nil || got != root+"/blog" {
		t.Fatalf("got %q err %v", got, err)
	}
	for _, bad := range []string{"../x", "/tmp/x", "a/../../x", "a\\b"} {
		if _, err := appTarget(root, bad); err == nil {
			t.Fatalf("accepted %q", bad)
		}
	}
}

func TestCuratedAppEndToEndSignedTLSPublish(t *testing.T) {
	u, err := user.Lookup("nobody")
	if err != nil {
		t.Skip("nobody user unavailable")
	}
	base := t.TempDir()
	account := filepath.Join(base, "nobody")
	doc := filepath.Join(account, "domains", "app.example.test", "public")
	if err = os.MkdirAll(doc, 0750); err != nil {
		t.Fatal(err)
	}
	// Build a tiny safe ZIP with one top-level directory to exercise strip_components.
	var zb bytes.Buffer
	zw := zip.NewWriter(&zb)
	h := &zip.FileHeader{Name: "grav/index.php", Method: zip.Deflate}
	h.SetMode(0644)
	w, _ := zw.CreateHeader(h)
	_, _ = io.WriteString(w, "<?php echo 'ok';\n")
	_ = zw.Close()
	sum := sha256.Sum256(zb.Bytes())
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/grav.zip" {
			http.NotFound(w, r)
			return
		}
		w.WriteHeader(200)
		_, _ = w.Write(zb.Bytes())
	}))
	defer srv.Close()
	manifest := AppReleaseManifest{Schema: "privora-app-release-manifest-v1", GeneratedAt: "2026-08-18T00:00:00Z", Releases: []AppRelease{{Template: "grav", Version: "1.0.0", URL: srv.URL + "/grav.zip", SHA256: hex.EncodeToString(sum[:]), Archive: "zip", StripComponents: 1, MaxBytes: 1024 * 1024, Bootstrap: "none", Current: true}}}
	mp, sp, kp := signManifestFixture(t, t.TempDir(), manifest)
	a := New(Config{AllowMutations: true, CertificationMode: true, AccountHomeBase: base, AppManifestPath: mp, AppManifestSigPath: sp, AppManifestPublicKey: kp, HTTPClient: srv.Client()})
	got, err := a.InstallCuratedApp(context.Background(), AppExecutionRequest{InstallID: "install_test123", Template: "grav", Domain: "app.example.test", Owner: "nobody", RelativePath: ".", DocumentRoot: doc})
	if err != nil {
		t.Fatal(err)
	}
	if got.Status != "published-setup-required" {
		t.Fatalf("status=%s", got.Status)
	}
	b, err := os.ReadFile(filepath.Join(doc, "index.php"))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(b, []byte("echo 'ok'")) {
		t.Fatalf("unexpected payload %q", b)
	}
	if _, err = os.Stat(filepath.Join(doc, ".privora-app.json")); err != nil {
		t.Fatal(err)
	}
	// Verify the publish tree was assigned to the requested hosting identity.
	st, err := os.Stat(filepath.Join(doc, "index.php"))
	if err != nil {
		t.Fatal(err)
	}
	sys, ok := st.Sys().(*syscall.Stat_t)
	if !ok {
		t.Fatal("missing stat_t")
	}
	wantUID, _ := strconv.Atoi(u.Uid)
	if int(sys.Uid) != wantUID {
		t.Fatalf("uid=%d want=%d", sys.Uid, wantUID)
	}
}

func TestCuratedJoomlaHeadlessBootstrapUsesStdin(t *testing.T) {
	u, err := user.Lookup("nobody")
	if err != nil {
		t.Skip("nobody user unavailable")
	}
	uid, err := strconv.Atoi(u.Uid)
	if err != nil {
		t.Fatal(err)
	}
	gid, err := strconv.Atoi(u.Gid)
	if err != nil {
		t.Fatal(err)
	}
	base, err := os.MkdirTemp("/var/tmp", "privora-joomla-test-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(base) })
	if err := os.Chmod(base, 0755); err != nil {
		t.Fatal(err)
	}
	account := filepath.Join(base, "nobody")
	doc := filepath.Join(account, "domains", "joomla.example.test", "public")
	if err := os.MkdirAll(doc, 0755); err != nil {
		t.Fatal(err)
	}
	// The production Joomla bootstrap executes as the hosting account identity.
	// Make the fixture document root writable by that identity instead of relying
	// on root-owned /tmp defaults, which can make the test fail before Joomla runs.
	if err := os.Chown(doc, uid, gid); err != nil {
		t.Fatal(err)
	}
	for _, p := range []string{account, filepath.Join(account, "domains"), filepath.Join(account, "domains", "joomla.example.test")} {
		if err := os.Chmod(p, 0755); err != nil {
			t.Fatal(err)
		}
	}

	// Fake a local MariaDB client so the test exercises the real Privora DB
	// provisioning/rollback path without requiring a database daemon.
	fakeDB := fakeClient(t, "mariadb", `input=$(cat); case "$input" in SELECT*) exit 0;; *) exit 0;; esac`)
	t.Setenv("PATH", fakeDB+":"+os.Getenv("PATH"))

	// Tiny signed Joomla-like package. The PHP CLI fixture reads its answers
	// exclusively from stdin and creates configuration.php on success.
	var zb bytes.Buffer
	zw := zip.NewWriter(&zb)
	files := map[string]string{
		"joomla/index.php": "<?php echo 'joomla';\n",
		"joomla/installation/joomla.php": `<?php
$lines=file('php://stdin', FILE_IGNORE_NEW_LINES);
if (count($lines) < 12) { fwrite(STDERR, "missing-stdin\n"); exit(31); }
if ($lines[0] !== 'Joomla Test' || $lines[2] !== 'siteadmin' || $lines[4] !== 'admin@joomla.example.test') { fwrite(STDERR, "bad-input\n"); exit(32); }
$root=dirname(__DIR__);
$ok=file_put_contents($root.'/configuration.php', "<?php\n// installed\n");
if ($ok === false) { fwrite(STDERR, 'write-failed root='.$root.' uid='.(function_exists('posix_geteuid')?posix_geteuid():'na').' perms='.substr(sprintf('%o',fileperms($root)),-4)."\n"); exit(33); }
echo "installed\n";
`,
	}
	for name, body := range files {
		h := &zip.FileHeader{Name: name, Method: zip.Deflate}
		h.SetMode(0644)
		w, _ := zw.CreateHeader(h)
		_, _ = io.WriteString(w, body)
	}
	_ = zw.Close()
	sum := sha256.Sum256(zb.Bytes())
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/joomla.zip" {
			http.NotFound(w, r)
			return
		}
		_, _ = w.Write(zb.Bytes())
	}))
	defer srv.Close()
	manifest := AppReleaseManifest{Schema: "privora-app-release-manifest-v1", GeneratedAt: "2026-08-19T00:00:00Z", Releases: []AppRelease{{Template: "joomla", Version: "test-1", URL: srv.URL + "/joomla.zip", SHA256: hex.EncodeToString(sum[:]), Archive: "zip", StripComponents: 1, MaxBytes: 1024 * 1024, Bootstrap: "joomla", Current: true}}}
	mp, sp, kp := signManifestFixture(t, t.TempDir(), manifest)
	a := New(Config{AllowMutations: true, CertificationMode: true, AccountHomeBase: base, AppManifestPath: mp, AppManifestSigPath: sp, AppManifestPublicKey: kp, HTTPClient: srv.Client()})
	got, err := a.InstallCuratedApp(context.Background(), AppExecutionRequest{InstallID: "install_joomla1", Template: "joomla", Domain: "joomla.example.test", Owner: "nobody", RelativePath: ".", DocumentRoot: doc, DatabaseEngine: "mariadb", SiteTitle: "Joomla Test", AdminUser: "siteadmin", AdminEmail: "admin@joomla.example.test", AdminPassword: "Safe-Joomla-Password-2026!"})
	if err != nil {
		t.Fatal(err)
	}
	if got.Status != "installed" || got.BootstrapMode != "joomla" {
		t.Fatalf("%+v", got)
	}
	if _, err := os.Stat(filepath.Join(doc, "configuration.php")); err != nil {
		t.Fatal(err)
	}
	if got.DatabasePassword == "" {
		t.Fatal("expected one-time database credential")
	}
}
