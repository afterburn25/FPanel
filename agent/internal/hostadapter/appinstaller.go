package hostadapter

import (
	"archive/tar"
	"archive/zip"
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
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

type AppReleaseManifest struct {
	Schema      string       `json:"schema"`
	GeneratedAt string       `json:"generated_at"`
	Releases    []AppRelease `json:"releases"`
}

type AppRelease struct {
	Template        string `json:"template"`
	Version         string `json:"version"`
	URL             string `json:"url"`
	SHA256          string `json:"sha256"`
	Archive         string `json:"archive"`
	StripComponents int    `json:"strip_components"`
	MaxBytes        int64  `json:"max_bytes"`
	Bootstrap       string `json:"bootstrap"`
	Current         bool   `json:"current"`
}

type AppExecutionRequest struct {
	InstallID      string
	Template       string
	Version        string
	Domain         string
	Owner          string
	RelativePath   string
	DocumentRoot   string
	DatabaseEngine string
	AdminUser      string
	AdminPassword  string
	AdminEmail     string
	SiteTitle      string
}

type AppExecutionResult struct {
	Template         string `json:"template"`
	Version          string `json:"version"`
	Domain           string `json:"domain"`
	Owner            string `json:"owner"`
	Target           string `json:"target"`
	Database         string `json:"database,omitempty"`
	DatabaseUser     string `json:"database_user,omitempty"`
	DatabasePassword string `json:"database_password,omitempty"` // returned once; never persisted
	AdminUser        string `json:"admin_user,omitempty"`
	AdminPassword    string `json:"admin_password,omitempty"` // returned once when Privora generated it
	Status           string `json:"status"`
	BootstrapMode    string `json:"bootstrap_mode"`
}

func parseRSAPublicKey(b []byte) (*rsa.PublicKey, error) {
	block, _ := pem.Decode(b)
	if block == nil {
		return nil, errors.New("invalid PEM public key")
	}
	if k, err := x509.ParsePKIXPublicKey(block.Bytes); err == nil {
		if r, ok := k.(*rsa.PublicKey); ok {
			return r, nil
		}
	}
	if r, err := x509.ParsePKCS1PublicKey(block.Bytes); err == nil {
		return r, nil
	}
	return nil, errors.New("public key is not RSA")
}

func verifyDetachedRSA(data, sig, pubPEM []byte) error {
	pub, err := parseRSAPublicKey(pubPEM)
	if err != nil {
		return err
	}
	sum := sha256.Sum256(data)
	if err := rsa.VerifyPKCS1v15(pub, crypto.SHA256, sum[:], sig); err != nil {
		return fmt.Errorf("signature verification failed: %w", err)
	}
	return nil
}

func (a *Adapter) LoadSignedAppManifest() (AppReleaseManifest, error) {
	if err := a.requireCertified("app-installer"); err != nil {
		return AppReleaseManifest{}, err
	}
	raw, err := os.ReadFile(a.cfg.AppManifestPath)
	if err != nil {
		return AppReleaseManifest{}, fmt.Errorf("read app manifest: %w", err)
	}
	sig, err := os.ReadFile(a.cfg.AppManifestSigPath)
	if err != nil {
		return AppReleaseManifest{}, fmt.Errorf("read app manifest signature: %w", err)
	}
	pub, err := os.ReadFile(a.cfg.AppManifestPublicKey)
	if err != nil {
		return AppReleaseManifest{}, fmt.Errorf("read app public key: %w", err)
	}
	if err := verifyDetachedRSA(raw, sig, pub); err != nil {
		return AppReleaseManifest{}, err
	}
	var m AppReleaseManifest
	if err := json.Unmarshal(raw, &m); err != nil {
		return m, err
	}
	if m.Schema != "privora-app-release-manifest-v1" {
		return m, errors.New("unsupported app release manifest schema")
	}
	if len(m.Releases) > 512 {
		return m, errors.New("app release manifest too large")
	}
	current := map[string]int{}
	for _, r := range m.Releases {
		if err := validateAppRelease(r); err != nil {
			return m, err
		}
		if r.Current {
			current[r.Template]++
		}
	}
	seen := map[string]bool{}
	for _, r := range m.Releases {
		seen[r.Template] = true
	}
	for template := range seen {
		if current[template] != 1 {
			return m, fmt.Errorf("app template %s must have exactly one current release", template)
		}
	}
	return m, nil
}

func validateAppRelease(r AppRelease) error {
	if !regexpSafeSlug(r.Template) || len(r.Version) < 1 || len(r.Version) > 64 {
		return errors.New("invalid app release identity")
	}
	u, err := url.Parse(r.URL)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil {
		return errors.New("app release URL must be HTTPS")
	}
	if len(r.SHA256) != 64 {
		return errors.New("invalid app release sha256")
	}
	if _, err := hex.DecodeString(r.SHA256); err != nil {
		return errors.New("invalid app release sha256")
	}
	if r.Archive != "zip" && r.Archive != "tar.gz" {
		return errors.New("unsupported app archive format")
	}
	if r.StripComponents < 0 || r.StripComponents > 4 {
		return errors.New("invalid strip_components")
	}
	if r.MaxBytes < 1024 || r.MaxBytes > 1024*1024*1024 {
		return errors.New("invalid app max_bytes")
	}
	switch r.Bootstrap {
	case "wordpress", "joomla", "guided-web", "none":
	default:
		return errors.New("unsupported app bootstrap mode")
	}
	return nil
}

func regexpSafeSlug(v string) bool {
	if len(v) < 2 || len(v) > 48 {
		return false
	}
	for i, c := range v {
		if (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || (i > 0 && c == '-') {
			continue
		}
		return false
	}
	return true
}

func selectAppRelease(m AppReleaseManifest, template, version string) (AppRelease, error) {
	template = strings.ToLower(strings.TrimSpace(template))
	version = strings.TrimSpace(version)
	var found *AppRelease
	for i := range m.Releases {
		r := m.Releases[i]
		if r.Template != template {
			continue
		}
		if version != "" {
			if r.Version != version {
				continue
			}
		} else if !r.Current {
			continue
		}
		cp := r
		found = &cp
		break
	}
	if found == nil {
		return AppRelease{}, errors.New("no signed curated release available for application")
	}
	return *found, nil
}

func (a *Adapter) secureHTTPDownload(ctx context.Context, rawURL, dest, expectedSHA string, max int64) error {
	client := &http.Client{Timeout: 90 * time.Second}
	if a.cfg.HTTPClient != nil {
		cp := *a.cfg.HTTPClient
		client = &cp
		if client.Timeout == 0 {
			client.Timeout = 90 * time.Second
		}
	}
	client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		if len(via) >= 4 {
			return errors.New("too many redirects")
		}
		if req.URL.Scheme != "https" {
			return errors.New("app download redirect must remain HTTPS")
		}
		return nil
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return err
	}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("app source returned HTTP %d", resp.StatusCode)
	}
	f, err := os.OpenFile(dest, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	h := sha256.New()
	n, copyErr := io.Copy(io.MultiWriter(f, h), io.LimitReader(resp.Body, max+1))
	closeErr := f.Close()
	if copyErr != nil {
		os.Remove(dest)
		return copyErr
	}
	if closeErr != nil {
		os.Remove(dest)
		return closeErr
	}
	if n > max {
		os.Remove(dest)
		return errors.New("app source exceeds signed size limit")
	}
	if hex.EncodeToString(h.Sum(nil)) != strings.ToLower(expectedSHA) {
		os.Remove(dest)
		return errors.New("app source sha256 mismatch")
	}
	return nil
}

func cleanedArchivePath(name string, strip int) (string, error) {
	if strings.Contains(name, "\\") || strings.ContainsRune(name, '\x00') || filepath.IsAbs(name) {
		return "", errors.New("unsafe archive path")
	}
	p := filepath.Clean(strings.TrimPrefix(name, "./"))
	if p == "." {
		return "", nil
	}
	parts := strings.Split(filepath.ToSlash(p), "/")
	for _, x := range parts {
		if x == "" || x == "." || x == ".." {
			return "", errors.New("unsafe archive path")
		}
	}
	if len(parts) <= strip {
		return "", nil
	}
	p = filepath.Join(parts[strip:]...)
	if p == "." || p == ".." || strings.HasPrefix(p, ".."+string(os.PathSeparator)) {
		return "", errors.New("unsafe archive path")
	}
	return p, nil
}

func extractZip(src, dest string, strip int, maxBytes int64) error {
	zr, err := zip.OpenReader(src)
	if err != nil {
		return err
	}
	defer zr.Close()
	if len(zr.File) > 50000 {
		return errors.New("archive contains too many files")
	}
	var total int64
	for _, zf := range zr.File {
		rel, err := cleanedArchivePath(zf.Name, strip)
		if err != nil {
			return err
		}
		if rel == "" {
			continue
		}
		mode := zf.Mode()
		if mode&os.ModeSymlink != 0 || !mode.IsRegular() && !mode.IsDir() {
			return errors.New("archive contains unsupported file type")
		}
		target := filepath.Join(dest, rel)
		if !strings.HasPrefix(filepath.Clean(target), filepath.Clean(dest)+string(os.PathSeparator)) {
			return errors.New("archive path escapes staging root")
		}
		if mode.IsDir() {
			if err := os.MkdirAll(target, 0750); err != nil {
				return err
			}
			continue
		}
		total += int64(zf.UncompressedSize64)
		if total > maxBytes {
			return errors.New("expanded archive exceeds signed size limit")
		}
		if err := os.MkdirAll(filepath.Dir(target), 0750); err != nil {
			return err
		}
		rc, err := zf.Open()
		if err != nil {
			return err
		}
		f, err := os.OpenFile(target, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0640)
		if err != nil {
			rc.Close()
			return err
		}
		_, e1 := io.CopyN(f, rc, int64(zf.UncompressedSize64))
		e2 := f.Close()
		e3 := rc.Close()
		if e1 != nil && !errors.Is(e1, io.EOF) {
			return e1
		}
		if e2 != nil {
			return e2
		}
		if e3 != nil {
			return e3
		}
	}
	return nil
}

func extractTarGz(src, dest string, strip int, maxBytes int64) error {
	f, err := os.Open(src)
	if err != nil {
		return err
	}
	defer f.Close()
	gz, err := gzip.NewReader(f)
	if err != nil {
		return err
	}
	defer gz.Close()
	tr := tar.NewReader(gz)
	var total int64
	files := 0
	for {
		h, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return err
		}
		files++
		if files > 50000 {
			return errors.New("archive contains too many files")
		}
		rel, err := cleanedArchivePath(h.Name, strip)
		if err != nil {
			return err
		}
		if rel == "" {
			continue
		}
		target := filepath.Join(dest, rel)
		if !strings.HasPrefix(filepath.Clean(target), filepath.Clean(dest)+string(os.PathSeparator)) {
			return errors.New("archive path escapes staging root")
		}
		switch h.Typeflag {
		case tar.TypeDir:
			if err := os.MkdirAll(target, 0750); err != nil {
				return err
			}
		case tar.TypeReg, tar.TypeRegA:
			if h.Size < 0 {
				return errors.New("negative archive size")
			}
			total += h.Size
			if total > maxBytes {
				return errors.New("expanded archive exceeds signed size limit")
			}
			if err := os.MkdirAll(filepath.Dir(target), 0750); err != nil {
				return err
			}
			out, err := os.OpenFile(target, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0640)
			if err != nil {
				return err
			}
			_, e1 := io.CopyN(out, tr, h.Size)
			e2 := out.Close()
			if e1 != nil {
				return e1
			}
			if e2 != nil {
				return e2
			}
		default:
			return errors.New("archive contains links or unsupported file type")
		}
	}
	return nil
}

func appTarget(documentRoot, relative string) (string, error) {
	root := filepath.Clean(documentRoot)
	if !filepath.IsAbs(root) || root == string(os.PathSeparator) {
		return "", errors.New("invalid site document root")
	}
	relative = strings.TrimSpace(relative)
	if relative == "" || relative == "." {
		return root, nil
	}
	if filepath.IsAbs(relative) || strings.Contains(relative, "\\") || strings.ContainsRune(relative, '\x00') {
		return "", errors.New("invalid install path")
	}
	clean := filepath.Clean(relative)
	if clean != relative || clean == ".." || strings.HasPrefix(clean, "../") {
		return "", errors.New("invalid install path")
	}
	target := filepath.Join(root, clean)
	if !strings.HasPrefix(filepath.Clean(target), root+string(os.PathSeparator)) {
		return "", errors.New("install path escapes site")
	}
	return target, nil
}

func numericUser(username string) (int, int, error) {
	u, err := user.Lookup(username)
	if err != nil {
		return 0, 0, err
	}
	uid, err := strconv.Atoi(u.Uid)
	if err != nil {
		return 0, 0, err
	}
	gid, err := strconv.Atoi(u.Gid)
	return uid, gid, err
}
func chownTreeNoLinks(root string, uid, gid int) error {
	return filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		info, err := d.Info()
		if err != nil {
			return err
		}
		if info.Mode()&os.ModeSymlink != 0 {
			return errors.New("symlink appeared in staging tree")
		}
		if err := os.Lchown(path, uid, gid); err != nil {
			return err
		}
		if d.IsDir() {
			return os.Chmod(path, 0750)
		}
		return os.Chmod(path, 0640)
	})
}

func randomHex(n int) string { b := make([]byte, n); _, _ = rand.Read(b); return hex.EncodeToString(b) }

func writeWordPressConfig(target string, db DatabaseProvisionResult) error {
	salts := make([]string, 8)
	for i := range salts {
		salts[i] = randomHex(32)
	}
	cfg := fmt.Sprintf(`<?php
`+"define('DB_NAME', %q);\ndefine('DB_USER', %q);\ndefine('DB_PASSWORD', %q);\ndefine('DB_HOST', 'localhost');\ndefine('DB_CHARSET', 'utf8mb4');\ndefine('DB_COLLATE', '');\n"+
		"define('AUTH_KEY', %q);\ndefine('SECURE_AUTH_KEY', %q);\ndefine('LOGGED_IN_KEY', %q);\ndefine('NONCE_KEY', %q);\ndefine('AUTH_SALT', %q);\ndefine('SECURE_AUTH_SALT', %q);\ndefine('LOGGED_IN_SALT', %q);\ndefine('NONCE_SALT', %q);\n"+
		"$table_prefix='wp_';\ndefine('WP_DEBUG', false);\nif (!defined('ABSPATH')) define('ABSPATH', __DIR__ . '/');\nrequire_once ABSPATH . 'wp-settings.php';\n",
		db.Database, db.User, db.Password, salts[0], salts[1], salts[2], salts[3], salts[4], salts[5], salts[6], salts[7])
	return AtomicWrite(filepath.Join(target, "wp-config.php"), []byte(cfg), 0640)
}

func (a *Adapter) bootstrapWordPress(ctx context.Context, target, owner string, req AppExecutionRequest) error {
	if req.AdminUser == "" {
		req.AdminUser = "admin"
	}
	if req.SiteTitle == "" {
		req.SiteTitle = req.Domain
	}
	if len(req.AdminUser) > 60 || len(req.AdminPassword) < 12 || len(req.AdminPassword) > 256 || len(req.AdminEmail) > 254 || strings.ContainsAny(req.AdminUser, "\r\n\x00") || strings.ContainsAny(req.AdminEmail, "\r\n\x00") {
		return errors.New("invalid WordPress administrator bootstrap data")
	}
	if _, ok := commandExists("php"); !ok {
		return errors.New("php CLI not installed")
	}
	payload, _ := json.Marshal(map[string]string{"title": req.SiteTitle, "user": req.AdminUser, "password": req.AdminPassword, "email": req.AdminEmail})
	code := `chdir($argv[1]); $p=json_decode(stream_get_contents(STDIN),true); define('WP_INSTALLING',true); require 'wp-load.php'; require_once ABSPATH.'wp-admin/includes/upgrade.php'; if (is_blog_installed()) { fwrite(STDERR,"already-installed"); exit(17); } $r=wp_install($p['title'],$p['user'],$p['email'],true,'',$p['password']); if (empty($r['user_id'])) exit(18); echo "installed";`
	cctx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()
	var outb, errb strings.Builder
	if err := a.runAsSystemUserIO(cctx, 60*time.Second, owner, "php", []string{"-r", code, target}, strings.NewReader(string(payload)), &outb, &errb, ""); err != nil {
		return fmt.Errorf("WordPress bootstrap failed: %w: %s", err, strings.TrimSpace(errb.String()))
	}
	if strings.TrimSpace(outb.String()) != "installed" {
		return errors.New("WordPress bootstrap did not confirm installation")
	}
	return nil
}

func (a *Adapter) bootstrapJoomla(ctx context.Context, target, owner string, req AppExecutionRequest, db DatabaseProvisionResult) error {
	if req.AdminUser == "" {
		req.AdminUser = "siteadmin"
	}
	if req.SiteTitle == "" {
		req.SiteTitle = req.Domain
	}
	if req.AdminEmail == "" {
		req.AdminEmail = "admin@" + req.Domain
	}
	if len(req.AdminUser) > 60 || len(req.AdminPassword) < 12 || len(req.AdminPassword) > 256 || len(req.AdminEmail) > 254 || strings.ContainsAny(req.AdminUser, "\r\n\x00") || strings.ContainsAny(req.AdminEmail, "\r\n\x00") || strings.ContainsAny(req.SiteTitle, "\r\n\x00") {
		return errors.New("invalid Joomla administrator bootstrap data")
	}
	if db.Database == "" || db.User == "" || db.Password == "" {
		return errors.New("Joomla release requires provisioned database")
	}
	if _, ok := commandExists("php"); !ok {
		return errors.New("php CLI not installed")
	}
	installer := filepath.Join(target, "installation", "joomla.php")
	if st, err := os.Stat(installer); err != nil || !st.Mode().IsRegular() {
		return errors.New("Joomla CLI installer not found")
	}
	dbType := "mysqli"
	if db.Engine == "postgresql" {
		dbType = "pgsql"
	}
	prefix := "p" + randomHex(2) + "_"
	// Joomla's interactive CLI prompts keep both the database and administrator
	// passwords off argv/proc. The signed release version is separately pinned,
	// and each promoted release must pass this bootstrap test before catalog promotion.
	answers := []string{
		req.SiteTitle,
		"Privora Administrator",
		req.AdminUser,
		req.AdminPassword,
		req.AdminEmail,
		dbType,
		"localhost",
		db.User,
		db.Password,
		db.Database,
		prefix,
		"0",
		"",
	}
	cctx, cancel := context.WithTimeout(ctx, 120*time.Second)
	defer cancel()
	var outb, errb strings.Builder
	if err := a.runAsSystemUserIO(cctx, 120*time.Second, owner, "php", []string{"installation/joomla.php", "install"}, strings.NewReader(strings.Join(answers, "\n")+"\n"), &outb, &errb, target); err != nil {
		return fmt.Errorf("Joomla bootstrap failed: %w: %s", err, strings.TrimSpace(errb.String()))
	}
	if st, err := os.Stat(filepath.Join(target, "configuration.php")); err != nil || !st.Mode().IsRegular() {
		return fmt.Errorf("Joomla bootstrap did not create configuration.php: %s", strings.TrimSpace(outb.String()))
	}
	return nil
}

func (a *Adapter) InstallCuratedApp(ctx context.Context, req AppExecutionRequest) (AppExecutionResult, error) {
	if !a.cfg.AllowMutations {
		return AppExecutionResult{}, errors.New("host mutations disabled")
	}
	if err := a.requireCertified("app-installer"); err != nil {
		return AppExecutionResult{}, err
	}
	if !validUser(req.Owner) || !validDomain(req.Domain) || !regexpSafeSlug(strings.ToLower(req.Template)) {
		return AppExecutionResult{}, errors.New("invalid app install request")
	}
	if req.InstallID != "" {
		if len(req.InstallID) > 80 || strings.ContainsAny(req.InstallID, "/\x00\r\n") || strings.Contains(req.InstallID, "..") {
			return AppExecutionResult{}, errors.New("invalid application install id")
		}
		for _, c := range req.InstallID {
			if !((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '_' || c == '-') {
				return AppExecutionResult{}, errors.New("invalid application install id")
			}
		}
	}
	target, err := appTarget(req.DocumentRoot, req.RelativePath)
	if err != nil {
		return AppExecutionResult{}, err
	}
	ownerRoot := filepath.Join(a.cfg.AccountHomeBase, req.Owner, "domains", strings.ToLower(req.Domain))
	if !strings.HasPrefix(filepath.Clean(target), filepath.Clean(ownerRoot)+string(os.PathSeparator)) {
		return AppExecutionResult{}, errors.New("target is not inside owned domain")
	}
	manifest, err := a.LoadSignedAppManifest()
	if err != nil {
		return AppExecutionResult{}, err
	}
	rel, err := selectAppRelease(manifest, strings.ToLower(req.Template), req.Version)
	if err != nil {
		return AppExecutionResult{}, err
	}
	stageID := req.InstallID
	if stageID == "" {
		stageID = "install-" + randomHex(8)
	}
	// Stage below the root-owned hosting home so the final rename is same-filesystem
	// and the hosting user cannot modify the private staging tree.
	stageBase := filepath.Join(a.cfg.AccountHomeBase, req.Owner, ".privora-staging", stageID)
	if err := os.MkdirAll(stageBase, 0700); err != nil {
		return AppExecutionResult{}, err
	}
	defer os.RemoveAll(stageBase)
	archive := filepath.Join(stageBase, "source."+strings.ReplaceAll(rel.Archive, ".", "_"))
	extract := filepath.Join(stageBase, "extract")
	if err := os.MkdirAll(extract, 0700); err != nil {
		return AppExecutionResult{}, err
	}
	if err := a.secureHTTPDownload(ctx, rel.URL, archive, rel.SHA256, rel.MaxBytes); err != nil {
		return AppExecutionResult{}, err
	}
	switch rel.Archive {
	case "zip":
		err = extractZip(archive, extract, rel.StripComponents, rel.MaxBytes*4)
	case "tar.gz":
		err = extractTarGz(archive, extract, rel.StripComponents, rel.MaxBytes*4)
	}
	if err != nil {
		return AppExecutionResult{}, err
	}
	entries, err := os.ReadDir(extract)
	if err != nil || len(entries) == 0 {
		return AppExecutionResult{}, errors.New("application archive extracted no files")
	}
	if st, err := os.Stat(target); err == nil && st.IsDir() {
		existing, _ := os.ReadDir(target)
		if len(existing) > 0 {
			return AppExecutionResult{}, errors.New("install target is not empty")
		}
	} else if err != nil && !os.IsNotExist(err) {
		return AppExecutionResult{}, err
	}
	var db DatabaseProvisionResult
	suffix := randomHex(3)
	if len(req.InstallID) >= 6 {
		suffix = strings.ToLower(req.InstallID[len(req.InstallID)-6:])
	}
	dbName := strings.ToLower(req.Owner + "_" + strings.ReplaceAll(req.Template, "-", "_") + "_" + suffix)
	if len(dbName) > 60 {
		dbName = dbName[:60]
	}
	dbUser := strings.ToLower(req.Owner + "_a_" + suffix)
	if len(dbUser) > 31 {
		dbUser = dbUser[:31]
	}
	if req.DatabaseEngine != "" {
		switch req.DatabaseEngine {
		case "mysql":
			db, err = a.ProvisionMySQL(ctx, dbName, dbUser, "")
		case "mariadb":
			db, err = a.ProvisionMariaDB(ctx, dbName, dbUser, "")
		case "postgresql":
			db, err = a.ProvisionPostgreSQL(ctx, dbName, dbUser, "")
		default:
			err = errors.New("unsupported application database")
		}
		if err != nil {
			return AppExecutionResult{}, err
		}
	}
	rollbackDB := func() {
		if db.Database == "" {
			return
		}
		if db.Engine == "mysql" {
			_, _ = a.runInput(context.Background(), fmt.Sprintf("DROP USER IF EXISTS %s@'localhost'; DROP DATABASE IF EXISTS `%s`;\n", sqlLiteral(db.User), db.Database), "mysql", "--protocol=socket", "--batch")
		} else if db.Engine == "mariadb" {
			_, _ = a.runInput(context.Background(), fmt.Sprintf("DROP USER IF EXISTS %s@'localhost'; DROP DATABASE IF EXISTS `%s`;\n", sqlLiteral(db.User), db.Database), "mariadb", "--protocol=socket", "--batch")
		} else if db.Engine == "postgresql" {
			_, _ = a.runInput(context.Background(), fmt.Sprintf("DROP DATABASE IF EXISTS \"%s\"; DROP ROLE IF EXISTS \"%s\";\n", db.Database, db.User), "runuser", "-u", "postgres", "--", "psql", "--no-psqlrc", "--set=ON_ERROR_STOP=1")
		}
	}
	generatedAdminPassword := ""
	if rel.Bootstrap == "wordpress" || rel.Bootstrap == "joomla" {
		if req.AdminUser == "" {
			if rel.Bootstrap == "joomla" {
				req.AdminUser = "siteadmin"
			} else {
				req.AdminUser = "admin"
			}
		}
		if req.AdminEmail == "" {
			req.AdminEmail = "admin@" + req.Domain
		}
		if req.SiteTitle == "" {
			req.SiteTitle = req.Domain
		}
	}
	if (rel.Bootstrap == "wordpress" || rel.Bootstrap == "joomla") && req.AdminPassword == "" {
		generatedAdminPassword, err = randomPassword(24)
		if err != nil {
			rollbackDB()
			return AppExecutionResult{}, err
		}
		req.AdminPassword = generatedAdminPassword
	}
	if rel.Bootstrap == "wordpress" {
		if db.Database == "" {
			return AppExecutionResult{}, errors.New("WordPress release requires provisioned database")
		}
		if err = writeWordPressConfig(extract, db); err != nil {
			rollbackDB()
			return AppExecutionResult{}, err
		}
	}
	if rel.Bootstrap == "joomla" && db.Database == "" {
		rollbackDB()
		return AppExecutionResult{}, errors.New("Joomla release requires provisioned database")
	}
	uid, gid, err := numericUser(req.Owner)
	if err != nil {
		rollbackDB()
		return AppExecutionResult{}, err
	}
	if err = chownTreeNoLinks(extract, uid, gid); err != nil {
		rollbackDB()
		return AppExecutionResult{}, err
	}
	parent := filepath.Dir(target)
	if err = os.MkdirAll(parent, 0750); err != nil {
		rollbackDB()
		return AppExecutionResult{}, err
	}
	if st, er := os.Stat(target); er == nil && st.IsDir() {
		_ = os.Remove(target)
	}
	if err = os.Rename(extract, target); err != nil {
		rollbackDB()
		return AppExecutionResult{}, fmt.Errorf("atomic publish failed: %w", err)
	}
	rollbackPublish := func() { _ = os.RemoveAll(target); rollbackDB() }
	status := "published-setup-required"
	if rel.Bootstrap == "wordpress" {
		if err = a.bootstrapWordPress(ctx, target, req.Owner, req); err != nil {
			rollbackPublish()
			return AppExecutionResult{}, err
		}
		status = "installed"
	}
	if rel.Bootstrap == "joomla" {
		if err = a.bootstrapJoomla(ctx, target, req.Owner, req, db); err != nil {
			rollbackPublish()
			return AppExecutionResult{}, err
		}
		status = "installed"
	}
	marker, _ := json.MarshalIndent(map[string]any{"schema": "privora-app-install-v1", "template": req.Template, "version": rel.Version, "domain": req.Domain, "installed_at": time.Now().UTC(), "bootstrap": rel.Bootstrap}, "", "  ")
	_ = AtomicWrite(filepath.Join(target, ".privora-app.json"), marker, 0640)
	_ = os.Chown(filepath.Join(target, ".privora-app.json"), uid, gid)
	return AppExecutionResult{Template: req.Template, Version: rel.Version, Domain: req.Domain, Owner: req.Owner, Target: target, Database: db.Database, DatabaseUser: db.User, DatabasePassword: db.Password, AdminUser: req.AdminUser, AdminPassword: generatedAdminPassword, Status: status, BootstrapMode: rel.Bootstrap}, nil
}
