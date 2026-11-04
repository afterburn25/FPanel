package hostadapter

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

type SiteProvisionResult struct {
	Domain         string `json:"domain"`
	Username       string `json:"username"`
	PHPVersion     string `json:"php_version"`
	DocumentRoot   string `json:"document_root"`
	NginxConfig    string `json:"nginx_config"`
	PHPPoolConfig  string `json:"php_pool_config"`
	NginxValidated bool   `json:"nginx_validated"`
	Reloaded       bool   `json:"reloaded"`
}

func (a *Adapter) ProvisionAccount(ctx context.Context, username string) error {
	if err := a.CreateLinuxUser(ctx, username); err != nil {
		return err
	}
	home := filepath.Join(a.cfg.AccountHomeBase, username)
	cleanup := func() { _ = a.DeleteLinuxUser(context.Background(), username) }
	writable := []string{filepath.Join(home, "domains"), filepath.Join(home, "tmp"), filepath.Join(home, "logs")}
	for _, d := range writable {
		if err := os.MkdirAll(d, 0750); err != nil {
			cleanup()
			return err
		}
	}
	// OpenSSH ChrootDirectory requires every path component of the jail root
	// to be root-owned and not writable by the jailed user. Keep /home/user as
	// root:root and grant the hosting account ownership only of writable
	// subdirectories inside the jail.
	if _, err := a.run(ctx, "chown", "root:root", home); err != nil {
		cleanup()
		return err
	}
	if err := os.Chmod(home, 0755); err != nil {
		cleanup()
		return err
	}
	for _, d := range writable {
		if _, err := a.run(ctx, "chown", "-R", username+":"+username, d); err != nil {
			cleanup()
			return err
		}
		if err := os.Chmod(d, 0750); err != nil {
			cleanup()
			return err
		}
	}
	return nil
}

func (a *Adapter) resolveSiteDocumentRoot(domain, username, requested string) (serverRoot, fsRoot, ownDomainTree string, rootExists bool, err error) {
	domain = strings.ToLower(strings.TrimSpace(domain))
	serverBase := filepath.Clean(filepath.Join("/home", username, "domains"))
	defaultRoot := filepath.Join(serverBase, domain, "public")
	serverRoot = filepath.Clean(strings.TrimSpace(requested))
	if strings.TrimSpace(requested) == "" {
		serverRoot = defaultRoot
	}
	if !filepath.IsAbs(serverRoot) || serverRoot == serverBase || !strings.HasPrefix(serverRoot+string(os.PathSeparator), serverBase+string(os.PathSeparator)) {
		return "", "", "", false, errors.New("document root must stay inside the hosting account domains directory")
	}
	rel, relErr := filepath.Rel(serverBase, serverRoot)
	if relErr != nil || rel == "." || strings.HasPrefix(rel, ".."+string(os.PathSeparator)) || rel == ".." {
		return "", "", "", false, errors.New("unsafe document root")
	}
	fsBase := filepath.Clean(filepath.Join(a.cfg.AccountHomeBase, username, "domains"))
	fsRoot = filepath.Join(fsBase, rel)
	ownDomainTree = filepath.Join(fsBase, domain)
	if !strings.HasPrefix(filepath.Clean(fsRoot)+string(os.PathSeparator), fsBase+string(os.PathSeparator)) {
		return "", "", "", false, errors.New("unsafe document root")
	}

	st, statErr := os.Stat(fsRoot)
	if statErr == nil {
		if !st.IsDir() {
			return "", "", "", false, errors.New("document root exists but is not a directory")
		}
		resolved, evalErr := filepath.EvalSymlinks(fsRoot)
		if evalErr != nil {
			return "", "", "", false, fmt.Errorf("resolve document root: %w", evalErr)
		}
		resolvedBase, evalBaseErr := filepath.EvalSymlinks(fsBase)
		if evalBaseErr != nil {
			resolvedBase = fsBase
		}
		resolved = filepath.Clean(resolved)
		resolvedBase = filepath.Clean(resolvedBase)
		if resolved == resolvedBase || !strings.HasPrefix(resolved+string(os.PathSeparator), resolvedBase+string(os.PathSeparator)) {
			return "", "", "", false, errors.New("document root resolves outside the hosting account domains directory")
		}
		return serverRoot, fsRoot, ownDomainTree, true, nil
	}
	if !errors.Is(statErr, os.ErrNotExist) {
		return "", "", "", false, statErr
	}

	// New custom directories may only be created inside this subdomain's own
	// domain tree. Existing directories elsewhere in the same hosting account
	// may be shared intentionally (for example, the parent domain document root).
	ownServerTree := filepath.Join(serverBase, domain)
	if serverRoot == ownServerTree || !strings.HasPrefix(serverRoot+string(os.PathSeparator), ownServerTree+string(os.PathSeparator)) {
		return "", "", "", false, errors.New("custom document root does not exist; choose an existing account directory or a new path inside the subdomain's own directory")
	}
	return serverRoot, fsRoot, ownDomainTree, false, nil
}

func (a *Adapter) ProvisionSite(ctx context.Context, domain, username, phpVersion string) (SiteProvisionResult, error) {
	return a.ProvisionSiteWithDocumentRoot(ctx, domain, username, phpVersion, "")
}

// ProvisionSiteWithDocumentRoot provisions a vhost using either Privora's
// dedicated default root or an explicit safe root inside the same hosting
// account. Existing roots are never recursively chowned or overwritten, which
// permits a subdomain to intentionally share its parent website's content.
func (a *Adapter) ProvisionSiteWithDocumentRoot(ctx context.Context, domain, username, phpVersion, requestedRoot string) (SiteProvisionResult, error) {
	if !a.cfg.AllowMutations {
		return SiteProvisionResult{}, errors.New("host mutations disabled")
	}
	if err := a.requireCertified("nginx"); err != nil {
		return SiteProvisionResult{}, err
	}
	if err := a.requireCertified("php-fpm"); err != nil {
		return SiteProvisionResult{}, err
	}
	if !validDomain(domain) || !validUser(username) || !phpRE.MatchString(phpVersion) {
		return SiteProvisionResult{}, errors.New("invalid site input")
	}
	domain = strings.ToLower(strings.TrimSpace(domain))
	if _, err := a.run(ctx, "id", username); err != nil {
		return SiteProvisionResult{}, errors.New("hosting user does not exist")
	}
	phpPoolDir := filepath.Join(a.cfg.PHPFPMPoolDir, phpVersion, "fpm", "pool.d")
	if st, err := os.Stat(phpPoolDir); err != nil || !st.IsDir() {
		return SiteProvisionResult{}, fmt.Errorf("PHP-FPM %s pool directory unavailable: %s", phpVersion, phpPoolDir)
	}
	if _, ok := commandExists("nginx"); !ok {
		return SiteProvisionResult{}, errors.New("nginx not installed")
	}
	if _, ok := commandExists("systemctl"); !ok {
		return SiteProvisionResult{}, errors.New("systemctl not installed")
	}

	serverRoot, docRoot, ownDomainTree, rootExists, err := a.resolveSiteDocumentRoot(domain, username, requestedRoot)
	if err != nil {
		return SiteProvisionResult{}, err
	}
	siteCfg, err := RenderNginxSite(domain, username, phpVersion, serverRoot)
	if err != nil {
		return SiteProvisionResult{}, err
	}
	poolCfg, err := RenderPHPFPMPool(username, phpVersion)
	if err != nil {
		return SiteProvisionResult{}, err
	}
	nginxPath := filepath.Join(a.cfg.NginxSitesAvailable, "privora-"+domain+".conf")
	enabledPath := filepath.Join(a.cfg.NginxSitesEnabled, "privora-"+domain+".conf")
	poolPath := filepath.Join(phpPoolDir, "privora-"+username+".conf")

	// A new vhost must never overwrite existing Privora configuration.
	for _, path := range []string{nginxPath, enabledPath} {
		if _, statErr := os.Lstat(path); statErr == nil {
			return SiteProvisionResult{}, errors.New("site already exists")
		} else if !errors.Is(statErr, os.ErrNotExist) {
			return SiteProvisionResult{}, statErr
		}
	}

	// The subdomain's own tree must not pre-exist. A requested shared root is
	// allowed only because that root is an already-existing directory elsewhere
	// in the same hosting account.
	if _, statErr := os.Stat(ownDomainTree); statErr == nil {
		if !rootExists || filepath.Clean(docRoot) != filepath.Clean(ownDomainTree) {
			return SiteProvisionResult{}, errors.New("site document tree already exists")
		}
	} else if !errors.Is(statErr, os.ErrNotExist) {
		return SiteProvisionResult{}, statErr
	}

	oldNginx, nginxHad := readIfExists(nginxPath)
	oldPool, poolHad := readIfExists(poolPath)
	oldLink, linkHad := symlinkTarget(enabledPath)
	createdOwnTree := false
	rollback := func() {
		restoreFile(nginxPath, oldNginx, nginxHad, 0644)
		restoreFile(poolPath, oldPool, poolHad, 0640)
		_ = os.Remove(enabledPath)
		if linkHad {
			_ = os.Symlink(oldLink, enabledPath)
		}
		if createdOwnTree {
			_ = os.RemoveAll(ownDomainTree)
		}
	}

	if !rootExists {
		if err := os.MkdirAll(docRoot, 0750); err != nil {
			return SiteProvisionResult{}, err
		}
		createdOwnTree = true
		if _, err := a.run(ctx, "chown", "-R", username+":"+username, ownDomainTree); err != nil {
			rollback()
			return SiteProvisionResult{}, err
		}
	}
	if err := AtomicWrite(nginxPath, []byte(siteCfg), 0644); err != nil {
		rollback()
		return SiteProvisionResult{}, err
	}
	if err := AtomicWrite(poolPath, []byte(poolCfg), 0640); err != nil {
		rollback()
		return SiteProvisionResult{}, err
	}
	_ = os.Remove(enabledPath)
	if err := os.Symlink(nginxPath, enabledPath); err != nil {
		rollback()
		return SiteProvisionResult{}, err
	}
	if _, err := a.run(ctx, "nginx", "-t"); err != nil {
		rollback()
		return SiteProvisionResult{}, fmt.Errorf("nginx validation failed; rolled back: %w", err)
	}
	phpService := "php" + phpVersion + "-fpm"
	if _, err := a.run(ctx, "systemctl", "reload", phpService); err != nil {
		rollback()
		return SiteProvisionResult{}, fmt.Errorf("PHP-FPM reload failed; rolled back: %w", err)
	}
	if _, err := a.run(ctx, "systemctl", "reload", "nginx"); err != nil {
		rollback()
		return SiteProvisionResult{}, fmt.Errorf("nginx reload failed; rolled back: %w", err)
	}
	return SiteProvisionResult{Domain: domain, Username: username, PHPVersion: phpVersion, DocumentRoot: serverRoot, NginxConfig: nginxPath, PHPPoolConfig: poolPath, NginxValidated: true, Reloaded: true}, nil
}

func readIfExists(path string) ([]byte, bool) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, false
	}
	return b, true
}
func restoreFile(path string, b []byte, had bool, mode os.FileMode) {
	if had {
		_ = AtomicWrite(path, b, mode)
	} else {
		_ = os.Remove(path)
	}
}
func symlinkTarget(path string) (string, bool) {
	v, err := os.Readlink(path)
	if err != nil {
		return "", false
	}
	return v, true
}

func (a *Adapter) DetectAccountPHPVersion(username string) string {
	if !validUser(username) {
		return ""
	}
	matches, _ := filepath.Glob(filepath.Join(a.cfg.PHPFPMPoolDir, "*", "fpm", "pool.d", "privora-"+username+".conf"))
	versions := []string{}
	for _, path := range matches {
		parts := strings.Split(filepath.Clean(path), string(os.PathSeparator))
		for i, part := range parts {
			if part == "php" && i+1 < len(parts) && phpRE.MatchString(parts[i+1]) {
				versions = append(versions, parts[i+1])
				break
			}
		}
	}
	sort.Strings(versions)
	if len(versions) == 0 {
		return ""
	}
	return versions[len(versions)-1]
}

func (a *Adapter) RepairSiteNginx(ctx context.Context, domain, username, phpVersion, documentRoot string) (SiteProvisionResult, error) {
	if !a.cfg.AllowMutations {
		return SiteProvisionResult{}, errors.New("host mutations disabled")
	}
	if err := a.requireCertified("nginx"); err != nil {
		return SiteProvisionResult{}, err
	}
	if !validDomain(domain) || !validUser(username) || !phpRE.MatchString(phpVersion) {
		return SiteProvisionResult{}, errors.New("invalid site repair input")
	}
	domain = strings.ToLower(strings.TrimSpace(domain))
	root := filepath.Clean(strings.TrimSpace(documentRoot))
	expected := filepath.Clean(filepath.Join(a.cfg.AccountHomeBase, username, "domains", domain, "public"))
	if root == "" || root == "." {
		root = expected
	}
	if root != expected {
		return SiteProvisionResult{}, errors.New("document root does not match hosting layout")
	}
	if st, err := os.Stat(root); err != nil || !st.IsDir() {
		return SiteProvisionResult{}, errors.New("existing website document root is missing")
	}
	poolPath := filepath.Join(a.cfg.PHPFPMPoolDir, phpVersion, "fpm", "pool.d", "privora-"+username+".conf")
	if st, err := os.Stat(poolPath); err != nil || !st.Mode().IsRegular() {
		return SiteProvisionResult{}, errors.New("existing account PHP-FPM pool is missing")
	}
	cfg, err := RenderNginxSite(domain, username, phpVersion, filepath.Join("/home", username, "domains", domain, "public"))
	if err != nil {
		return SiteProvisionResult{}, err
	}
	fullchain := filepath.Join("/etc/letsencrypt/live", domain, "fullchain.pem")
	privkey := filepath.Join("/etc/letsencrypt/live", domain, "privkey.pem")
	if regularOrSymlinkExists(fullchain) && regularOrSymlinkExists(privkey) {
		if tlsCfg, tlsErr := RenderNginxSiteTLS(domain, username, phpVersion, filepath.Join("/home", username, "domains", domain, "public"), fullchain, privkey); tlsErr == nil {
			cfg = tlsCfg
		}
	}
	nginxPath := filepath.Join(a.cfg.NginxSitesAvailable, "privora-"+domain+".conf")
	enabledPath := filepath.Join(a.cfg.NginxSitesEnabled, "privora-"+domain+".conf")
	oldNginx, nginxHad := readIfExists(nginxPath)
	oldLink, linkHad := symlinkTarget(enabledPath)
	rollback := func() {
		restoreFile(nginxPath, oldNginx, nginxHad, 0644)
		_ = os.Remove(enabledPath)
		if linkHad {
			_ = os.Symlink(oldLink, enabledPath)
		}
		_, _ = a.run(context.Background(), "nginx", "-t")
		_, _ = a.run(context.Background(), "systemctl", "reload", "nginx")
	}
	if err := AtomicWrite(nginxPath, []byte(cfg), 0644); err != nil {
		return SiteProvisionResult{}, err
	}
	_ = os.Remove(enabledPath)
	if err := os.Symlink(nginxPath, enabledPath); err != nil {
		rollback()
		return SiteProvisionResult{}, err
	}
	if _, err := a.run(ctx, "nginx", "-t"); err != nil {
		rollback()
		return SiteProvisionResult{}, fmt.Errorf("nginx validation failed; rolled back: %w", err)
	}
	if _, err := a.run(ctx, "systemctl", "reload", "nginx"); err != nil {
		rollback()
		return SiteProvisionResult{}, fmt.Errorf("nginx reload failed; rolled back: %w", err)
	}
	return SiteProvisionResult{Domain: domain, Username: username, PHPVersion: phpVersion, DocumentRoot: filepath.Join("/home", username, "domains", domain, "public"), NginxConfig: nginxPath, PHPPoolConfig: poolPath, NginxValidated: true, Reloaded: true}, nil
}

func (a *Adapter) SwitchSitePHP(ctx context.Context, domain, username, oldVersion, newVersion string) (SiteProvisionResult, error) {
	if !a.cfg.AllowMutations {
		return SiteProvisionResult{}, errors.New("host mutations disabled")
	}
	if !phpRE.MatchString(oldVersion) || !phpRE.MatchString(newVersion) {
		return SiteProvisionResult{}, errors.New("unsupported PHP version")
	}
	if oldVersion == newVersion {
		return SiteProvisionResult{}, errors.New("site already uses requested PHP version")
	}
	// Provision into the new PHP pool first. The same Nginx config path is atomically replaced.
	res, err := a.ProvisionSite(ctx, domain, username, newVersion)
	if err != nil {
		return SiteProvisionResult{}, err
	}
	oldPool := filepath.Join(a.cfg.PHPFPMPoolDir, oldVersion, "fpm", "pool.d", "privora-"+username+".conf")
	_ = os.Remove(oldPool)
	if _, ok := commandExists("systemctl"); ok {
		_, _ = a.run(ctx, "systemctl", "reload", "php"+oldVersion+"-fpm")
	}
	return res, nil
}

// DeleteSite removes a website vhost from the live server. Website content is
// preserved unless deleteFiles is explicitly requested. PHP pools are account
// scoped in Privora and are intentionally retained because another domain can
// share the same hosting owner.
func (a *Adapter) DeleteSite(ctx context.Context, domain, username string, deleteFiles bool) error {
	defaultRoot := filepath.Join("/home", username, "domains", strings.ToLower(strings.TrimSpace(domain)), "public")
	return a.DeleteSiteWithDocumentRoot(ctx, domain, username, defaultRoot, deleteFiles)
}

// DeleteSiteWithDocumentRoot only permits recursive content deletion when the
// configured root belongs to this site's dedicated domain tree. Shared parent
// roots and other account roots are always preserved.
func (a *Adapter) DeleteSiteWithDocumentRoot(ctx context.Context, domain, username, documentRoot string, deleteFiles bool) error {
	if !a.cfg.AllowMutations {
		return errors.New("host mutations disabled")
	}
	if err := a.requireCertified("nginx"); err != nil {
		return err
	}
	domain = strings.ToLower(strings.TrimSpace(domain))
	if !validDomain(domain) || !validUser(username) {
		return errors.New("invalid site input")
	}
	// Resolve destructive content cleanup before mutating the vhost. A shared
	// parent/custom root is a valid serving target, but it is never owned by
	// this subdomain and therefore must never be recursively removed.
	if deleteFiles {
		serverDomainDir := filepath.Clean(filepath.Join("/home", username, "domains", domain))
		serverRoot := filepath.Clean(strings.TrimSpace(documentRoot))
		if serverRoot == "" || (serverRoot != serverDomainDir && !strings.HasPrefix(serverRoot+string(os.PathSeparator), serverDomainDir+string(os.PathSeparator))) {
			deleteFiles = false
		}
	}
	nginxPath := filepath.Join(a.cfg.NginxSitesAvailable, "privora-"+domain+".conf")
	enabledPath := filepath.Join(a.cfg.NginxSitesEnabled, "privora-"+domain+".conf")
	oldNginx, nginxHad := readIfExists(nginxPath)
	oldLink, linkHad := symlinkTarget(enabledPath)
	rollback := func() {
		restoreFile(nginxPath, oldNginx, nginxHad, 0644)
		_ = os.Remove(enabledPath)
		if linkHad {
			_ = os.Symlink(oldLink, enabledPath)
		}
	}
	if err := os.Remove(enabledPath); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if err := os.Remove(nginxPath); err != nil && !errors.Is(err, os.ErrNotExist) {
		rollback()
		return err
	}
	if _, err := a.run(ctx, "nginx", "-t"); err != nil {
		rollback()
		return fmt.Errorf("nginx validation failed; rolled back: %w", err)
	}
	if _, err := a.run(ctx, "systemctl", "reload", "nginx"); err != nil {
		rollback()
		return fmt.Errorf("nginx reload failed; rolled back: %w", err)
	}
	if deleteFiles {
		domainDir := filepath.Clean(filepath.Join(a.cfg.AccountHomeBase, username, "domains", domain))
		base := filepath.Clean(filepath.Join(a.cfg.AccountHomeBase, username, "domains")) + string(os.PathSeparator)
		if !strings.HasPrefix(domainDir+string(os.PathSeparator), base) {
			return errors.New("unsafe website content path")
		}
		if err := os.RemoveAll(domainDir); err != nil {
			return fmt.Errorf("website disabled but content cleanup failed: %w", err)
		}
	}
	return nil
}

// DeleteAccountRuntime removes Privora-created PHP-FPM pool files for a hosting
// account after all of its websites have been disabled. It does not remove the
// Linux identity or account home; DeleteLinuxUser performs that final step.
func (a *Adapter) DeleteAccountRuntime(ctx context.Context, username string) error {
	if !a.cfg.AllowMutations {
		return errors.New("host mutations disabled")
	}
	if err := a.requireCertified("php-fpm"); err != nil {
		return err
	}
	if !validUser(username) {
		return errors.New("invalid username")
	}
	paths, err := filepath.Glob(filepath.Join(a.cfg.PHPFPMPoolDir, "*", "fpm", "pool.d", "privora-"+username+".conf"))
	if err != nil {
		return err
	}
	versions := map[string]bool{}
	for _, pool := range paths {
		parts := strings.Split(filepath.Clean(pool), string(os.PathSeparator))
		for i := 0; i+2 < len(parts); i++ {
			if parts[i+1] == "fpm" && parts[i+2] == "pool.d" {
				versions[parts[i]] = true
				break
			}
		}
		if err := os.Remove(pool); err != nil && !errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("remove PHP-FPM pool: %w", err)
		}
	}
	for version := range versions {
		service := "php" + version + "-fpm"
		if _, err := a.run(ctx, "systemctl", "is-active", "--quiet", service); err != nil {
			continue
		}
		if _, err := a.run(ctx, "systemctl", "reload", service); err != nil {
			return fmt.Errorf("reload %s after account cleanup: %w", service, err)
		}
	}
	return nil
}
