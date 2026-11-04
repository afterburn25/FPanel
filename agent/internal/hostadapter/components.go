package hostadapter

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

type ServerComponent struct {
	ID              string         `json:"id"`
	Name            string         `json:"name"`
	Category        string         `json:"category"`
	Description     string         `json:"description"`
	Tags            []string       `json:"tags"`
	Packages        []string       `json:"packages"`
	Installed       bool           `json:"installed"`
	Available       bool           `json:"available"`
	Partial         bool           `json:"partial"`
	Status          string         `json:"status"`
	StatusReason    string         `json:"status_reason"`
	Version         string         `json:"version,omitempty"`
	Featured        bool           `json:"featured,omitempty"`
	Removable       bool           `json:"removable,omitempty"`
	RestartServices []string       `json:"restart_services,omitempty"`
	BinaryPath      string         `json:"binary_path,omitempty"`
	Details         map[string]any `json:"details,omitempty"`
}

type componentDefinition struct {
	ID              string
	Name            string
	Category        string
	Description     string
	Tags            []string
	Packages        []string
	Featured        bool
	Removable       bool
	RestartServices []string
	Special         string
}

var componentOperationMu sync.Mutex

type ComponentProgressFunc func(percent int, phase, message string)

func reportComponentProgress(cb ComponentProgressFunc, percent int, phase, message string) {
	if cb != nil {
		cb(percent, phase, message)
	}
}

func phpComponent(id, name, description, pkg string, tags ...string) componentDefinition {
	allTags := append([]string{"php", "php8.4", "extension", "module"}, tags...)
	return componentDefinition{ID: id, Name: name, Category: "PHP Extensions", Description: description, Tags: allTags, Packages: []string{pkg}, Removable: true, RestartServices: []string{"php8.4-fpm", "privora-panel-fpm"}}
}

func staticComponentDefinitions() []componentDefinition {
	return []componentDefinition{
		{ID: "laravel-stack", Name: "Laravel Development Stack", Category: "Application Stacks", Description: "Laravel 13-ready server tooling: Composer, Laravel installer, Git, Node/NPM and the PHP 8.4 modules commonly needed by modern Laravel applications.", Tags: []string{"laravel", "artisan", "composer", "php", "php8.4", "node", "npm", "vite", "framework", "development"}, Packages: []string{"composer", "git", "unzip", "curl", "nodejs", "npm", "php8.4-cli", "php8.4-curl", "php8.4-mbstring", "php8.4-xml", "php8.4-zip", "php8.4-sqlite3"}, Featured: true, RestartServices: []string{"php8.4-fpm", "privora-panel-fpm"}, Special: "laravel-installer"},

		{ID: "roundcube-webmail", Name: "Roundcube Webmail", Category: "Mail & Webmail", Description: "Privora-certified browser webmail with a dedicated PHP-FPM pool, panel-session gate and local Dovecot/Postfix mailbox authentication.", Tags: []string{"roundcube", "webmail", "mail", "email", "imap", "smtp", "dovecot", "postfix"}, Packages: []string{"roundcube-core", "roundcube-sqlite3", "sqlite3", "php8.4-sqlite3", "php8.4-mbstring", "php8.4-xml", "php8.4-intl"}, Featured: true, RestartServices: []string{"php8.4-fpm"}, Special: "roundcube-webmail"},

		phpComponent("php-pdo-mysql", "PDO MySQL / MySQLi", "MySQL and MariaDB PDO/MySQLi drivers for PHP 8.4 applications.", "php8.4-mysql", "pdo", "mysql", "mysqli", "mariadb", "database"),
		phpComponent("php-pdo-pgsql", "PDO PostgreSQL", "PostgreSQL PDO and pgsql drivers for PHP 8.4 applications.", "php8.4-pgsql", "pdo", "postgres", "postgresql", "pgsql", "database"),
		phpComponent("php-pdo-sqlite", "PDO SQLite / SQLite3", "SQLite PDO and SQLite3 support for PHP 8.4, including Laravel SQLite projects.", "php8.4-sqlite3", "pdo", "sqlite", "sqlite3", "database", "laravel"),
		phpComponent("php-bcmath", "BCMath", "Arbitrary precision mathematics support.", "php8.4-bcmath", "math", "decimal"),
		phpComponent("php-curl", "cURL", "HTTP/client networking extension used by Composer and many web applications.", "php8.4-curl", "http", "api", "composer"),
		phpComponent("php-gd", "GD", "Common image creation and manipulation support.", "php8.4-gd", "image", "graphics", "jpeg", "png"),
		phpComponent("php-gmp", "GMP", "High precision arithmetic via GNU Multiple Precision.", "php8.4-gmp", "math", "crypto"),
		phpComponent("php-imagick", "Imagick", "ImageMagick bindings for advanced image processing.", "php8.4-imagick", "image", "imagemagick", "graphics"),
		phpComponent("php-imap", "IMAP", "PHP IMAP mailbox access support.", "php8.4-imap", "mail", "email"),
		phpComponent("php-intl", "Intl", "Internationalization, locale, formatter and Unicode support.", "php8.4-intl", "intl", "icu", "locale"),
		phpComponent("php-ldap", "LDAP", "LDAP directory connectivity for PHP applications.", "php8.4-ldap", "directory", "authentication"),
		phpComponent("php-mbstring", "Mbstring", "Multibyte string handling required by many PHP frameworks.", "php8.4-mbstring", "unicode", "laravel", "composer"),
		phpComponent("php-soap", "SOAP", "SOAP web-service client/server extension.", "php8.4-soap", "xml", "webservice"),
		phpComponent("php-xml", "XML / DOM", "DOM, SimpleXML, XMLReader and XMLWriter support.", "php8.4-xml", "dom", "simplexml", "composer", "laravel"),
		phpComponent("php-zip", "ZIP", "ZIP archive support for Composer and PHP applications.", "php8.4-zip", "archive", "composer", "laravel"),
		phpComponent("php-redis", "Redis Extension", "Native PHP Redis client extension.", "php8.4-redis", "cache", "session", "queue"),
		phpComponent("php-memcached", "Memcached Extension", "PHP Memcached client extension.", "php8.4-memcached", "cache", "session"),
		phpComponent("php-apcu", "APCu", "In-process user data cache for PHP applications.", "php8.4-apcu", "cache", "performance"),

		{ID: "ffmpeg", Name: "FFmpeg", Category: "Media & Images", Description: "Video/audio conversion, probing, transcoding and thumbnail generation.", Tags: []string{"ffmpeg", "video", "audio", "transcode", "media", "ffprobe"}, Packages: []string{"ffmpeg"}, Featured: true, Removable: true},
		{ID: "imagemagick", Name: "ImageMagick", Category: "Media & Images", Description: "Command-line image conversion, resizing and processing tools.", Tags: []string{"imagemagick", "convert", "magick", "image", "graphics"}, Packages: []string{"imagemagick"}, Removable: true},
		{ID: "graphicsmagick", Name: "GraphicsMagick", Category: "Media & Images", Description: "Image processing utilities compatible with many web workloads.", Tags: []string{"graphicsmagick", "gm", "image", "graphics"}, Packages: []string{"graphicsmagick"}, Removable: true},
		{ID: "webp-tools", Name: "WebP Tools", Category: "Media & Images", Description: "WebP encode/decode command-line tools.", Tags: []string{"webp", "cwebp", "dwebp", "image", "compression"}, Packages: []string{"webp"}, Removable: true},
		{ID: "ghostscript", Name: "Ghostscript", Category: "Media & Images", Description: "PostScript/PDF interpreter used by document and image workflows.", Tags: []string{"ghostscript", "pdf", "postscript", "document"}, Packages: []string{"ghostscript"}, Removable: true},

		{ID: "composer", Name: "Composer", Category: "Developer Tools", Description: "PHP dependency manager used by Laravel and modern PHP applications.", Tags: []string{"composer", "php", "dependencies", "laravel"}, Packages: []string{"composer"}, Featured: true},
		{ID: "git", Name: "Git", Category: "Developer Tools", Description: "Distributed source control for deployments and application development.", Tags: []string{"git", "source", "repository", "deploy"}, Packages: []string{"git"}},
		{ID: "nodejs", Name: "Node.js", Category: "Developer Tools", Description: "JavaScript runtime used by frontend build pipelines.", Tags: []string{"node", "nodejs", "javascript", "vite", "laravel"}, Packages: []string{"nodejs"}},
		{ID: "npm", Name: "NPM", Category: "Developer Tools", Description: "Node package manager used by Vite and frontend assets.", Tags: []string{"npm", "node", "javascript", "vite", "laravel"}, Packages: []string{"npm"}},
		{ID: "jq", Name: "jq", Category: "Developer Tools", Description: "Command-line JSON processor useful for APIs and automation.", Tags: []string{"jq", "json", "cli", "automation"}, Packages: []string{"jq"}, Removable: true},
		{ID: "sqlite3-cli", Name: "SQLite CLI", Category: "Database Tools", Description: "SQLite command-line database client.", Tags: []string{"sqlite", "sqlite3", "database", "cli"}, Packages: []string{"sqlite3"}, Removable: true},
		{ID: "mysql-client", Name: "MySQL Client", Category: "Database Tools", Description: "Command-line client tools for MySQL-compatible servers.", Tags: []string{"mysql", "mariadb", "database", "client"}, Packages: []string{"default-mysql-client"}},
		{ID: "postgres-client", Name: "PostgreSQL Client", Category: "Database Tools", Description: "psql and PostgreSQL client utilities.", Tags: []string{"postgres", "postgresql", "psql", "database", "client"}, Packages: []string{"postgresql-client"}},
		{ID: "redis-tools", Name: "Redis Tools", Category: "Database Tools", Description: "redis-cli and related Redis command-line utilities.", Tags: []string{"redis", "cache", "redis-cli", "database"}, Packages: []string{"redis-tools"}},

		{ID: "curl-cli", Name: "cURL CLI", Category: "Server Utilities", Description: "Command-line HTTP and transfer client.", Tags: []string{"curl", "http", "download", "api"}, Packages: []string{"curl"}},
		{ID: "wget", Name: "Wget", Category: "Server Utilities", Description: "Command-line network downloader.", Tags: []string{"wget", "download", "http"}, Packages: []string{"wget"}, Removable: true},
		{ID: "archive-tools", Name: "ZIP / Unzip", Category: "Server Utilities", Description: "ZIP archive creation and extraction tools.", Tags: []string{"zip", "unzip", "archive", "compression"}, Packages: []string{"zip", "unzip"}},
		{ID: "zstd", Name: "Zstandard", Category: "Server Utilities", Description: "Fast modern compression tooling used by Privora backups.", Tags: []string{"zstd", "compression", "backup"}, Packages: []string{"zstd"}},
		{ID: "rsync", Name: "Rsync", Category: "Server Utilities", Description: "Efficient file synchronization and migration utility.", Tags: []string{"rsync", "sync", "migration", "backup"}, Packages: []string{"rsync"}},
		{ID: "memcached", Name: "Memcached Server", Category: "Caching & Queues", Description: "Distributed in-memory cache daemon.", Tags: []string{"memcached", "cache", "performance"}, Packages: []string{"memcached"}, Removable: true},
		{ID: "redis-server", Name: "Redis Server", Category: "Caching & Queues", Description: "In-memory data store for cache, sessions and queues.", Tags: []string{"redis", "cache", "session", "queue"}, Packages: []string{"redis-server"}, Removable: true},
		{ID: "supervisor", Name: "Supervisor", Category: "Caching & Queues", Description: "Process supervisor for application workers and queues.", Tags: []string{"supervisor", "worker", "queue", "process"}, Packages: []string{"supervisor"}, Removable: true},
		{ID: "avif-tools", Name: "AVIF Tools", Category: "Media & Images", Description: "AVIF image encode/decode command-line utilities.", Tags: []string{"avif", "image", "compression"}, Packages: []string{"libavif-bin"}, Removable: true},
		{ID: "metadata-tools", Name: "Media Metadata Tools", Category: "Media & Images", Description: "ExifTool metadata inspection and editing utilities.", Tags: []string{"exiftool", "metadata", "image", "media"}, Packages: []string{"libimage-exiftool-perl"}, Removable: true},
		{ID: "python3", Name: "Python 3", Category: "Developer Tools", Description: "Python 3 runtime for web applications and automation.", Tags: []string{"python", "python3", "development"}, Packages: []string{"python3"}},
		{ID: "python-pip", Name: "Python pip", Category: "Developer Tools", Description: "Python package installer.", Tags: []string{"python", "pip", "packages"}, Packages: []string{"python3-pip"}, Removable: true},
		{ID: "golang", Name: "Go", Category: "Developer Tools", Description: "Go compiler and toolchain.", Tags: []string{"go", "golang", "compiler", "development"}, Packages: []string{"golang-go"}, Removable: true},
		{ID: "java", Name: "Java Runtime", Category: "Developer Tools", Description: "Default headless Java runtime.", Tags: []string{"java", "jre", "development"}, Packages: []string{"default-jre-headless"}, Removable: true},
		{ID: "ruby", Name: "Ruby", Category: "Developer Tools", Description: "Ruby language runtime.", Tags: []string{"ruby", "development"}, Packages: []string{"ruby"}, Removable: true},
		{ID: "rust", Name: "Rust / Cargo", Category: "Developer Tools", Description: "Rust compiler and Cargo package/build tool.", Tags: []string{"rust", "cargo", "compiler", "development"}, Packages: []string{"rustc", "cargo"}, Removable: true},
		{ID: "yarn", Name: "Yarn", Category: "Developer Tools", Description: "Yarn JavaScript package manager.", Tags: []string{"yarn", "node", "javascript"}, Packages: []string{"yarnpkg"}, Removable: true},
		{ID: "pnpm", Name: "pnpm", Category: "Developer Tools", Description: "Fast disk-efficient JavaScript package manager when provided by the configured repositories.", Tags: []string{"pnpm", "node", "javascript"}, Packages: []string{"pnpm"}, Removable: true},
	}
}

func componentDefinitions() []componentDefinition {
	defs := staticComponentDefinitions()
	seen := make(map[string]bool, len(defs))
	for _, d := range defs {
		seen[d.ID] = true
	}
	for _, d := range phpExtensionDefinitions() {
		if seen[d.ID] {
			continue
		}
		seen[d.ID] = true
		defs = append(defs, d)
	}
	return defs
}

func definitionByID(id string) (componentDefinition, bool) {
	id = strings.TrimSpace(strings.ToLower(id))
	for _, d := range componentDefinitions() {
		if d.ID == id {
			return d, true
		}
	}
	return componentDefinition{}, false
}

func aptInventory(ctx context.Context) (map[string]string, map[string]bool, error) {
	if _, err := exec.LookPath("apt-get"); err != nil {
		return nil, nil, errors.New("Extensions & Components is currently certified for Debian/Ubuntu APT hosts")
	}
	versions := map[string]string{}
	installedCmd := exec.CommandContext(ctx, "dpkg-query", "-W", "-f=${binary:Package}\t${Version}\n")
	if raw, err := installedCmd.Output(); err == nil {
		for _, line := range strings.Split(string(raw), "\n") {
			parts := strings.SplitN(line, "\t", 2)
			if len(parts) != 2 {
				continue
			}
			name := strings.TrimSpace(parts[0])
			if i := strings.IndexByte(name, ':'); i >= 0 {
				name = name[:i]
			}
			if name != "" {
				versions[name] = strings.TrimSpace(parts[1])
			}
		}
	} else {
		return nil, nil, fmt.Errorf("could not read installed package inventory: %w", err)
	}
	available := map[string]bool{}
	cacheCmd := exec.CommandContext(ctx, "apt-cache", "pkgnames")
	raw, err := cacheCmd.Output()
	if err != nil {
		return nil, nil, fmt.Errorf("could not read APT package catalog: %w", err)
	}
	for _, name := range strings.Fields(string(raw)) {
		available[name] = true
	}
	return versions, available, nil
}

func laravelInstallerPresent() bool {
	for _, p := range []string{"/usr/local/bin/laravel", "/opt/privora-panel/tooling/composer/vendor/bin/laravel"} {
		if st, err := os.Stat(p); err == nil && !st.IsDir() {
			return true
		}
	}
	return false
}

func componentStatus(d componentDefinition, installed map[string]string, available map[string]bool) ServerComponent {
	c := ServerComponent{ID: d.ID, Name: d.Name, Category: d.Category, Description: d.Description, Tags: append([]string(nil), d.Tags...), Packages: append([]string(nil), d.Packages...), Featured: d.Featured, Removable: d.Removable, RestartServices: append([]string(nil), d.RestartServices...)}
	installedCount, availableCount := 0, 0
	versions := []string{}
	for _, p := range d.Packages {
		if v, ok := installed[p]; ok {
			installedCount++
			availableCount++
			if len(d.Packages) == 1 {
				versions = append(versions, v)
			}
		} else if available[p] {
			availableCount++
		}
	}
	specialOK := d.Special == ""
	specialPresent := false
	switch d.Special {
	case "laravel-installer":
		specialPresent = laravelInstallerPresent()
		specialOK = specialPresent
	case "roundcube-webmail":
		specialPresent = webmailRuntimeConfigured()
		specialOK = specialPresent
	}
	c.Installed = installedCount == len(d.Packages) && specialOK
	c.Partial = !c.Installed && (installedCount > 0 || specialPresent)
	c.Available = availableCount == len(d.Packages)
	if len(versions) == 1 {
		c.Version = versions[0]
	}
	switch {
	case c.Installed:
		c.Status = "installed"
		c.StatusReason = "Installed on this server"
	case c.Partial && c.Available:
		c.Status = "partial"
		c.StatusReason = fmt.Sprintf("Partially installed (%d/%d package dependencies present)", installedCount, len(d.Packages))
	case c.Available:
		c.Status = "available"
		c.StatusReason = "Available from configured APT repositories"
	default:
		missing := []string{}
		for _, p := range d.Packages {
			if _, ok := installed[p]; !ok && !available[p] {
				missing = append(missing, p)
			}
		}
		c.Status = "unsupported"
		if len(missing) > 0 {
			c.StatusReason = "Unavailable package(s): " + strings.Join(missing, ", ")
		} else {
			c.StatusReason = "Not available for this host"
		}
	}
	return c
}

func (a *Adapter) ServerComponents(ctx context.Context) ([]ServerComponent, string, error) {
	cctx, cancel := context.WithTimeout(ctx, 25*time.Second)
	defer cancel()
	installed, available, err := aptInventory(cctx)
	defs := componentDefinitions()
	out := make([]ServerComponent, 0, len(defs))
	if err != nil {
		for _, d := range defs {
			out = append(out, ServerComponent{ID: d.ID, Name: d.Name, Category: d.Category, Description: d.Description, Tags: append([]string(nil), d.Tags...), Packages: append([]string(nil), d.Packages...), Status: "unsupported", StatusReason: err.Error(), Featured: d.Featured, Removable: false, RestartServices: append([]string(nil), d.RestartServices...)})
		}
		return out, "unsupported", nil
	}
	for _, d := range defs {
		c := componentStatus(d, installed, available)
		a.enrichServerComponent(cctx, &c)
		out = append(out, c)
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Featured != out[j].Featured {
			return out[i].Featured
		}
		if out[i].Category != out[j].Category {
			return out[i].Category < out[j].Category
		}
		return out[i].Name < out[j].Name
	})
	return out, "apt", nil
}

func runPackageCommand(ctx context.Context, name string, args []string, extraEnv ...string) (string, error) {
	// APT intentionally drops privileges to the _apt sandbox user while fetching.
	// The long-running Privora Agent is hardened and may not retain CAP_SETUID on
	// every certified host. Run only typed/allow-listed APT transactions in a
	// separate transient systemd service rather than weakening the Agent unit.
	if filepath.Base(name) == "apt-get" {
		return runAPTTransaction(ctx, args, extraEnv...)
	}
	cctx, cancel := context.WithTimeout(ctx, 8*time.Minute)
	defer cancel()
	cmd := exec.CommandContext(cctx, name, args...)
	cmd.Env = append(os.Environ(), extraEnv...)
	var out bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &out
	if err := cmd.Run(); err != nil {
		tail := out.String()
		if len(tail) > 5000 {
			tail = tail[len(tail)-5000:]
		}
		return tail, fmt.Errorf("%s failed: %w: %s", name, err, strings.TrimSpace(tail))
	}
	return out.String(), nil
}

func runAPTTransaction(ctx context.Context, args []string, extraEnv ...string) (string, error) {
	aptGet, err := exec.LookPath("apt-get")
	if err != nil {
		return "", errors.New("apt-get is not available on this host")
	}
	allowedEnv := map[string]bool{"DEBIAN_FRONTEND": true, "NEEDRESTART_MODE": true}
	out, err := runIsolatedRootCommand(ctx, "privora-apt", 8*time.Minute, aptGet, args, allowedEnv, extraEnv...)
	if err != nil {
		return out, fmt.Errorf("apt-get isolated transaction failed: %w", err)
	}
	return out, nil
}

func (a *Adapter) restartComponentServices(ctx context.Context, services []string) []string {
	restarted := []string{}
	for _, service := range services {
		if service == "" {
			continue
		}
		active := exec.CommandContext(ctx, "systemctl", "is-active", "--quiet", service)
		if active.Run() != nil {
			continue
		}
		if _, err := runPackageCommand(ctx, "systemctl", []string{"restart", service}); err == nil {
			restarted = append(restarted, service)
		}
	}
	return restarted
}

func installLaravelTooling(ctx context.Context) error {
	return installLaravelToolingAt(ctx, "/opt/privora-panel/tooling/composer", "/usr/local/bin/laravel")
}

func installLaravelToolingAt(ctx context.Context, home, link string) error {
	composer, err := exec.LookPath("composer")
	if err != nil {
		return errors.New("Composer was installed but its executable is not available")
	}
	php, err := exec.LookPath("php8.4")
	if err != nil {
		php, err = exec.LookPath("php")
		if err != nil {
			return errors.New("PHP CLI is required to provision the Laravel installer")
		}
	}
	if err := os.MkdirAll(home, 0755); err != nil {
		return err
	}
	// Composer can trigger PCRE JIT in PHP. The Agent intentionally runs with
	// MemoryDenyWriteExecute=true, so the typed Composer transaction is isolated
	// in a transient root unit and PCRE JIT is explicitly disabled for this CLI
	// process. We do not weaken the long-running Agent sandbox.
	allowedEnv := map[string]bool{
		"COMPOSER_HOME": true, "COMPOSER_ALLOW_SUPERUSER": true,
		"COMPOSER_NO_INTERACTION": true, "COMPOSER_PROCESS_TIMEOUT": true,
	}
	args := []string{"-d", "pcre.jit=0", composer, "global", "require", "laravel/installer", "--no-interaction", "--no-ansi", "--prefer-dist"}
	if _, err := runIsolatedRootCommand(ctx, "privora-composer", 8*time.Minute, php, args, allowedEnv,
		"COMPOSER_HOME="+home, "COMPOSER_ALLOW_SUPERUSER=1", "COMPOSER_NO_INTERACTION=1", "COMPOSER_PROCESS_TIMEOUT=420"); err != nil {
		return fmt.Errorf("Laravel installer provisioning failed: %w", err)
	}
	target := filepath.Join(home, "vendor", "bin", "laravel")
	if st, err := os.Stat(target); err != nil || st.IsDir() {
		return errors.New("Laravel installer completed but the laravel executable was not produced")
	}
	_ = os.Remove(link)
	if err := os.Symlink(target, link); err != nil {
		return fmt.Errorf("could not publish laravel CLI: %w", err)
	}
	return nil
}

func (a *Adapter) InstallServerComponent(ctx context.Context, id string) (ServerComponent, []string, error) {
	return a.InstallServerComponentWithProgress(ctx, id, nil)
}

func (a *Adapter) InstallServerComponentWithProgress(ctx context.Context, id string, progress ComponentProgressFunc) (ServerComponent, []string, error) {
	reportComponentProgress(progress, 6, "validating", "Validating Privora component policy")
	if !a.cfg.AllowMutations {
		return ServerComponent{}, nil, errors.New("host mutations disabled")
	}
	d, ok := definitionByID(id)
	if !ok {
		return ServerComponent{}, nil, errors.New("component is not in the Privora allow-list")
	}
	switch d.Special {
	case "", "laravel-installer", "roundcube-webmail":
	default:
		return ServerComponent{}, nil, fmt.Errorf("component installer backend is not certified: %s", d.Special)
	}
	componentOperationMu.Lock()
	defer componentOperationMu.Unlock()

	reportComponentProgress(progress, 12, "inventory", "Checking installed and repository package state")
	installed, available, err := aptInventory(ctx)
	if err != nil {
		return ServerComponent{}, nil, err
	}
	missing := []string{}
	for _, p := range d.Packages {
		if _, ok := installed[p]; ok {
			continue
		}
		if !available[p] {
			missing = append(missing, p)
		}
	}
	if len(missing) > 0 {
		return ServerComponent{}, nil, fmt.Errorf("component cannot be installed because these packages are unavailable: %s", strings.Join(missing, ", "))
	}
	reportComponentProgress(progress, 22, "packages", "Installing allow-listed packages")
	if d.Special == "roundcube-webmail" {
		reportComponentProgress(progress, 26, "configuring", "Installing and configuring Roundcube webmail")
		if err := a.configureRoundcubeWebmail(ctx, true); err != nil {
			return ServerComponent{}, nil, err
		}
		reportComponentProgress(progress, 82, "configuring", "Roundcube package configuration completed")
	} else {
		args := []string{"-o", "Dpkg::Lock::Timeout=60", "install", "-y"}
		args = append(args, d.Packages...)
		if _, err := runPackageCommand(ctx, "apt-get", args, "DEBIAN_FRONTEND=noninteractive", "NEEDRESTART_MODE=a"); err != nil {
			return ServerComponent{}, nil, err
		}
		reportComponentProgress(progress, 72, "packages", "Package transaction completed")
		if d.Special == "laravel-installer" {
			reportComponentProgress(progress, 76, "composer", "Provisioning Laravel CLI with Composer")
			if err := installLaravelTooling(ctx); err != nil {
				return ServerComponent{}, nil, err
			}
			reportComponentProgress(progress, 88, "composer", "Laravel CLI provisioning completed")
		}
	}
	reportComponentProgress(progress, 91, "restarting", "Restarting affected services")
	restarted := a.restartComponentServices(ctx, d.RestartServices)
	reportComponentProgress(progress, 96, "verifying", "Verifying installed component")
	installed, available, err = aptInventory(ctx)
	if err != nil {
		return ServerComponent{}, restarted, err
	}
	c := componentStatus(d, installed, available)
	if !c.Installed {
		return c, restarted, errors.New("package transaction completed but the component did not verify as installed")
	}
	reportComponentProgress(progress, 100, "complete", "Component installed and verified")
	return c, restarted, nil
}

func (a *Adapter) RemoveServerComponent(ctx context.Context, id string) (ServerComponent, []string, error) {
	if !a.cfg.AllowMutations {
		return ServerComponent{}, nil, errors.New("host mutations disabled")
	}
	d, ok := definitionByID(id)
	if !ok {
		return ServerComponent{}, nil, errors.New("component is not in the Privora allow-list")
	}
	if !d.Removable {
		return ServerComponent{}, nil, errors.New("Privora does not offer automatic removal for this shared/core component")
	}
	componentOperationMu.Lock()
	defer componentOperationMu.Unlock()
	if _, err := exec.LookPath("apt-get"); err != nil {
		return ServerComponent{}, nil, errors.New("component removal is currently certified for Debian/Ubuntu APT hosts")
	}
	args := []string{"-o", "Dpkg::Lock::Timeout=60", "remove", "-y"}
	args = append(args, d.Packages...)
	if _, err := runPackageCommand(ctx, "apt-get", args, "DEBIAN_FRONTEND=noninteractive", "NEEDRESTART_MODE=a"); err != nil {
		return ServerComponent{}, nil, err
	}
	restarted := a.restartComponentServices(ctx, d.RestartServices)
	installed, available, err := aptInventory(ctx)
	if err != nil {
		return ServerComponent{}, restarted, err
	}
	return componentStatus(d, installed, available), restarted, nil
}
