package hostadapter

import (
	"context"
	"errors"
	"fmt"
	"os/exec"
	"sort"
	"strings"
)

var supportedPHPVersions = []string{"8.2", "8.3", "8.4", "8.5"}

type PHPVersionStatus struct {
	Version      string `json:"version"`
	Installed    bool   `json:"installed"`
	Available    bool   `json:"available"`
	CLI          bool   `json:"cli"`
	FPM          bool   `json:"fpm"`
	FPMActive    bool   `json:"fpm_active"`
	Protected    bool   `json:"protected"`
	Status       string `json:"status"`
	StatusReason string `json:"status_reason"`
}

type PHPExtensionStatus struct {
	Version      string `json:"version"`
	ID           string `json:"id"`
	Name         string `json:"name"`
	Module       string `json:"module"`
	Package      string `json:"package,omitempty"`
	Installed    bool   `json:"installed"`
	Available    bool   `json:"available"`
	Removable    bool   `json:"removable"`
	Source       string `json:"source"`
	Status       string `json:"status"`
	StatusReason string `json:"status_reason"`
}

type phpExtensionSpec struct {
	Slug          string
	Name          string
	Module        string
	PackageSuffix string
}

var phpExtensionSpecs = []phpExtensionSpec{
	{"bcmath", "BCMath", "bcmath", "bcmath"}, {"bz2", "BZ2", "bz2", "bz2"},
	{"curl", "cURL", "curl", "curl"}, {"dom", "DOM", "dom", "xml"},
	{"exif", "EXIF", "exif", ""}, {"fileinfo", "Fileinfo", "fileinfo", ""},
	{"ftp", "FTP", "ftp", ""}, {"gd", "GD", "gd", "gd"},
	{"gmp", "GMP", "gmp", "gmp"}, {"imagick", "Imagick", "imagick", "imagick"},
	{"imap", "IMAP", "imap", "imap"}, {"intl", "Intl", "intl", "intl"},
	{"ldap", "LDAP", "ldap", "ldap"}, {"mbstring", "Mbstring", "mbstring", "mbstring"},
	{"memcached", "Memcached", "memcached", "memcached"}, {"mongodb", "MongoDB", "mongodb", "mongodb"},
	{"mysqli", "MySQLi", "mysqli", "mysql"}, {"opcache", "OPcache", "Zend OPcache", "opcache"},
	{"pcntl", "PCNTL", "pcntl", ""}, {"pdo", "PDO", "PDO", ""},
	{"pdo-mysql", "PDO MySQL", "pdo_mysql", "mysql"}, {"pdo-pgsql", "PDO PostgreSQL", "pdo_pgsql", "pgsql"},
	{"pdo-sqlite", "PDO SQLite", "pdo_sqlite", "sqlite3"}, {"pgsql", "PostgreSQL", "pgsql", "pgsql"},
	{"redis", "Redis", "redis", "redis"}, {"soap", "SOAP", "soap", "soap"},
	{"sodium", "Sodium", "sodium", ""}, {"sqlite", "SQLite3", "sqlite3", "sqlite3"},
	{"ssh2", "SSH2", "ssh2", "ssh2"}, {"tidy", "Tidy", "tidy", "tidy"},
	{"xml", "XML", "xml", "xml"}, {"xsl", "XSL", "xsl", "xml"}, {"zip", "ZIP", "zip", "zip"},
}

func allowedPHPVersion(v string) bool {
	for _, x := range supportedPHPVersions {
		if v == x {
			return true
		}
	}
	return false
}

func phpExtensionComponentID(version, slug string) string {
	if version == "8.4" {
		switch slug {
		case "pdo-mysql":
			return "php-pdo-mysql"
		case "pdo-pgsql":
			return "php-pdo-pgsql"
		case "pdo-sqlite":
			return "php-pdo-sqlite"
		default:
			return "php-" + slug
		}
	}
	return "php" + strings.ReplaceAll(version, ".", "") + "-" + slug
}

func phpExtensionDefinitions() []componentDefinition {
	out := []componentDefinition{}
	for _, v := range supportedPHPVersions {
		for _, sp := range phpExtensionSpecs {
			if sp.PackageSuffix == "" {
				continue
			}
			pkg := "php" + v + "-" + sp.PackageSuffix
			out = append(out, componentDefinition{
				ID: phpExtensionComponentID(v, sp.Slug), Name: sp.Name + " · PHP " + v,
				Category: "PHP Extensions", Description: sp.Name + " support for PHP " + v + ".",
				Tags:     []string{"php", "php" + v, "extension", "module", sp.Slug, sp.Module},
				Packages: []string{pkg}, Removable: true,
				RestartServices: []string{"php" + v + "-fpm"},
			})
		}
	}
	return out
}

func (a *Adapter) PHPVersions(ctx context.Context) []PHPVersionStatus {
	installed, available, invErr := aptInventory(ctx)
	runtimes := a.PHPRuntimes(ctx)
	byVersion := map[string]PHPRuntime{}
	for _, r := range runtimes {
		byVersion[r.Version] = r
	}
	out := make([]PHPVersionStatus, 0, len(supportedPHPVersions))
	for _, v := range supportedPHPVersions {
		r, ok := byVersion[v]
		_, cliInstalled := installed["php"+v+"-cli"]
		_, fpmInstalled := installed["php"+v+"-fpm"]
		st := PHPVersionStatus{Version: v, Installed: ok || cliInstalled || fpmInstalled, CLI: r.CLI || cliInstalled, FPM: r.FPM || fpmInstalled, FPMActive: r.FPMActive, Protected: v == "8.4"}
		st.Available = available["php"+v+"-cli"] && available["php"+v+"-fpm"]
		if invErr != nil {
			st.Status = "unknown"
			st.StatusReason = invErr.Error()
		} else if st.Installed {
			st.Status = "installed"
			st.StatusReason = "Installed on this server"
		} else if st.Available {
			st.Status = "available"
			st.StatusReason = "Available from configured APT repositories"
		} else {
			st.Status = "unavailable"
			st.StatusReason = "Not available from configured APT repositories"
		}
		out = append(out, st)
	}
	return out
}

func normalizePHPModuleName(v string) string { return strings.ToLower(strings.TrimSpace(v)) }

func (a *Adapter) PHPExtensions(ctx context.Context) []PHPExtensionStatus {
	installedPkgs, availablePkgs, invErr := aptInventory(ctx)
	runtimes := a.PHPRuntimes(ctx)
	byVersion := map[string]PHPRuntime{}
	for _, r := range runtimes {
		byVersion[r.Version] = r
	}
	out := []PHPExtensionStatus{}
	for _, v := range supportedPHPVersions {
		r, runtimeInstalled := byVersion[v]
		mods := map[string]bool{}
		for _, m := range r.Extensions {
			mods[normalizePHPModuleName(m)] = true
		}
		// Common aliases seen in mods-available.
		if mods["opcache"] {
			mods["zend opcache"] = true
		}
		for _, sp := range phpExtensionSpecs {
			pkg := ""
			source := "bundled"
			pkgInstalled, pkgAvailable := false, false
			if sp.PackageSuffix != "" {
				pkg = "php" + v + "-" + sp.PackageSuffix
				_, pkgInstalled = installedPkgs[pkg]
				pkgAvailable = availablePkgs[pkg]
				source = "package"
			}
			modInstalled := mods[normalizePHPModuleName(sp.Module)] || mods[normalizePHPModuleName(sp.Slug)]
			e := PHPExtensionStatus{Version: v, ID: phpExtensionComponentID(v, sp.Slug), Name: sp.Name, Module: sp.Module, Package: pkg, Installed: runtimeInstalled && (modInstalled || pkgInstalled), Source: source}
			if invErr != nil {
				e.Status = "unknown"
				e.StatusReason = invErr.Error()
			} else if !runtimeInstalled {
				e.Status = "runtime-missing"
				e.StatusReason = "PHP " + v + " is not installed"
			} else if e.Installed {
				e.Status = "installed"
				e.StatusReason = "Loaded/installed for PHP " + v
			} else if source == "package" && pkgAvailable {
				e.Status = "available"
				e.Available = true
				e.Removable = true
				e.StatusReason = "Available as " + pkg
			} else if source == "bundled" {
				e.Status = "bundled-unavailable"
				e.StatusReason = "This module is supplied by the PHP core/common build; no independent package is available"
			} else {
				e.Status = "unavailable"
				e.StatusReason = "Package is not available from configured repositories"
			}
			if e.Installed && source == "package" {
				e.Available = true
				e.Removable = true
			}
			out = append(out, e)
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Version != out[j].Version {
			return out[i].Version > out[j].Version
		}
		return out[i].Name < out[j].Name
	})
	return out
}

func (a *Adapter) InstallPHPVersion(ctx context.Context, version string) (PHPVersionStatus, []string, error) {
	if !a.cfg.AllowMutations {
		return PHPVersionStatus{}, nil, errors.New("host mutations disabled")
	}
	if !allowedPHPVersion(version) {
		return PHPVersionStatus{}, nil, errors.New("PHP version is not in the Privora allow-list")
	}
	installed, available, err := aptInventory(ctx)
	if err != nil {
		return PHPVersionStatus{}, nil, err
	}
	pkgs := []string{"php" + version + "-cli", "php" + version + "-fpm", "php" + version + "-common", "php" + version + "-curl", "php" + version + "-mbstring", "php" + version + "-xml", "php" + version + "-zip"}
	todo := []string{}
	for _, p := range pkgs {
		if _, ok := installed[p]; ok {
			continue
		}
		if !available[p] {
			return PHPVersionStatus{}, nil, fmt.Errorf("required PHP package is unavailable: %s", p)
		}
		todo = append(todo, p)
	}
	if len(todo) > 0 {
		args := []string{"-o", "Dpkg::Lock::Timeout=60", "install", "-y"}
		args = append(args, todo...)
		if _, err := runPackageCommand(ctx, "apt-get", args, "DEBIAN_FRONTEND=noninteractive", "NEEDRESTART_MODE=a"); err != nil {
			return PHPVersionStatus{}, nil, err
		}
	}
	restarted := a.restartComponentServices(ctx, []string{"php" + version + "-fpm"})
	for _, st := range a.PHPVersions(ctx) {
		if st.Version == version && st.Installed {
			return st, restarted, nil
		}
	}
	return PHPVersionStatus{Version: version}, restarted, errors.New("PHP package transaction completed but runtime did not verify as installed")
}

func (a *Adapter) RemovePHPVersion(ctx context.Context, version string) (PHPVersionStatus, error) {
	if !a.cfg.AllowMutations {
		return PHPVersionStatus{}, errors.New("host mutations disabled")
	}
	if !allowedPHPVersion(version) {
		return PHPVersionStatus{}, errors.New("PHP version is not in the Privora allow-list")
	}
	if version == "8.4" {
		return PHPVersionStatus{}, errors.New("PHP 8.4 is protected because Privora control-plane services depend on it")
	}
	args := []string{"-o", "Dpkg::Lock::Timeout=60", "remove", "-y", "php" + version + "-fpm", "php" + version + "-cli"}
	if _, err := runPackageCommand(ctx, "apt-get", args, "DEBIAN_FRONTEND=noninteractive", "NEEDRESTART_MODE=a"); err != nil {
		return PHPVersionStatus{}, err
	}
	for _, st := range a.PHPVersions(ctx) {
		if st.Version == version {
			return st, nil
		}
	}
	return PHPVersionStatus{Version: version, Status: "removed", StatusReason: "Runtime removed"}, nil
}

type ComponentPreset struct {
	ID               string   `json:"id"`
	Name             string   `json:"name"`
	Description      string   `json:"description"`
	PHPVersion       string   `json:"php_version"`
	ComponentIDs     []string `json:"component_ids"`
	AlreadyInstalled []string `json:"already_installed"`
	WillInstall      []string `json:"will_install"`
	Unavailable      []string `json:"unavailable"`
	Conflict         []string `json:"conflict"`
	RequiresRestart  []string `json:"requires_restart"`
	Ready            bool     `json:"ready"`
}

func presetDefinitions(version string) []ComponentPreset {
	ext := func(slug string) string { return phpExtensionComponentID(version, slug) }
	return []ComponentPreset{
		{ID: "wordpress", Name: "WordPress", Description: "Common WordPress PHP and image dependencies.", PHPVersion: version, ComponentIDs: []string{ext("curl"), ext("gd"), ext("imagick"), ext("mbstring"), ext("xml"), ext("zip"), ext("pdo-mysql")}},
		{ID: "woocommerce", Name: "WooCommerce", Description: "WordPress plus commerce-oriented math and internationalization dependencies.", PHPVersion: version, ComponentIDs: []string{ext("curl"), ext("gd"), ext("imagick"), ext("mbstring"), ext("xml"), ext("zip"), ext("pdo-mysql"), ext("bcmath"), ext("intl")}},
		{ID: "laravel", Name: "Laravel", Description: "Laravel runtime dependencies and Composer/developer tooling.", PHPVersion: version, ComponentIDs: []string{"composer", "git", "nodejs", "npm", ext("bcmath"), ext("curl"), ext("mbstring"), ext("xml"), ext("zip"), ext("pdo-sqlite")}},
		{ID: "video-processing", Name: "Video Processing", Description: "FFmpeg/image stack and PHP image/file metadata support.", PHPVersion: version, ComponentIDs: []string{"ffmpeg", "imagemagick", "avif-tools", "metadata-tools", ext("imagick"), ext("gd")}},
	}
}

func (a *Adapter) ComponentPresets(ctx context.Context, version string) []ComponentPreset {
	if !allowedPHPVersion(version) {
		version = "8.4"
	}
	comps, _, _ := a.ServerComponents(ctx)
	byID := map[string]ServerComponent{}
	for _, c := range comps {
		byID[c.ID] = c
	}
	out := presetDefinitions(version)
	for i := range out {
		restarts := map[string]bool{}
		for _, id := range out[i].ComponentIDs {
			c, ok := byID[id]
			if !ok || (!c.Installed && !c.Available) {
				out[i].Unavailable = append(out[i].Unavailable, id)
				continue
			}
			if c.Installed {
				out[i].AlreadyInstalled = append(out[i].AlreadyInstalled, id)
			} else {
				out[i].WillInstall = append(out[i].WillInstall, id)
			}
			for _, svc := range c.RestartServices {
				restarts[svc] = true
			}
		}
		for svc := range restarts {
			out[i].RequiresRestart = append(out[i].RequiresRestart, svc)
		}
		sort.Strings(out[i].RequiresRestart)
		out[i].Ready = len(out[i].Unavailable) == 0 && len(out[i].Conflict) == 0
	}
	return out
}

func (a *Adapter) ApplyComponentPreset(ctx context.Context, presetID, version string) (ComponentPreset, []string, error) {
	return a.ApplyComponentPresetWithProgress(ctx, presetID, version, nil)
}

func (a *Adapter) ApplyComponentPresetWithProgress(ctx context.Context, presetID, version string, progress ComponentProgressFunc) (ComponentPreset, []string, error) {
	reportComponentProgress(progress, 5, "preview", "Checking preset requirements")
	presets := a.ComponentPresets(ctx, version)
	var p *ComponentPreset
	for i := range presets {
		if presets[i].ID == presetID {
			p = &presets[i]
			break
		}
	}
	if p == nil {
		return ComponentPreset{}, nil, errors.New("preset is not in the Privora allow-list")
	}
	if !p.Ready {
		return *p, nil, errors.New("preset has unavailable/conflicting requirements; preview must be clean before apply")
	}
	if len(p.WillInstall) == 0 {
		reportComponentProgress(progress, 100, "complete", "Preset requirements are already satisfied")
		return *p, nil, nil
	}
	restartedSet := map[string]bool{}
	total := len(p.WillInstall)
	for idx, id := range p.WillInstall {
		base := 10 + (idx * 80 / total)
		span := 80 / total
		if span < 1 {
			span = 1
		}
		name := id
		reportComponentProgress(progress, base, "installing", fmt.Sprintf("Installing preset requirement %d of %d: %s", idx+1, total, name))
		_, restarted, err := a.InstallServerComponentWithProgress(ctx, id, func(child int, phase, message string) {
			mapped := base + child*span/100
			if mapped > 90 {
				mapped = 90
			}
			reportComponentProgress(progress, mapped, phase, fmt.Sprintf("%s · %s", name, message))
		})
		if err != nil {
			return *p, nil, fmt.Errorf("preset stopped while installing %s: %w", id, err)
		}
		for _, svc := range restarted {
			restartedSet[svc] = true
		}
	}
	restarted := []string{}
	for svc := range restartedSet {
		restarted = append(restarted, svc)
	}
	sort.Strings(restarted)
	reportComponentProgress(progress, 94, "verifying", "Verifying complete preset")
	refreshed := a.ComponentPresets(ctx, version)
	for _, x := range refreshed {
		if x.ID == presetID {
			reportComponentProgress(progress, 100, "complete", "Preset applied and verified")
			return x, restarted, nil
		}
	}
	return *p, restarted, nil
}

func commandVersion(ctx context.Context, name string, args ...string) string {
	p, err := exec.LookPath(name)
	if err != nil {
		return ""
	}
	b, err := exec.CommandContext(ctx, p, args...).CombinedOutput()
	if err != nil {
		return ""
	}
	line := strings.TrimSpace(string(b))
	if i := strings.IndexByte(line, '\n'); i >= 0 {
		line = line[:i]
	}
	if len(line) > 240 {
		line = line[:240]
	}
	return line
}

func serviceState(ctx context.Context, service string) map[string]any {
	d := map[string]any{"service": service, "active": false, "enabled": false}
	if _, err := exec.LookPath("systemctl"); err != nil {
		return d
	}
	if b, err := exec.CommandContext(ctx, "systemctl", "is-active", service).Output(); err == nil {
		d["active"] = strings.TrimSpace(string(b)) == "active"
	}
	if b, err := exec.CommandContext(ctx, "systemctl", "is-enabled", service).Output(); err == nil {
		d["enabled"] = strings.TrimSpace(string(b)) == "enabled"
	}
	return d
}

func (a *Adapter) enrichServerComponent(ctx context.Context, c *ServerComponent) {
	if c.Details == nil {
		c.Details = map[string]any{}
	}
	binaryArgs := map[string]struct {
		name string
		args []string
	}{
		"ffmpeg": {"ffmpeg", []string{"-version"}}, "imagemagick": {"convert", []string{"-version"}},
		"graphicsmagick": {"gm", []string{"version"}}, "ghostscript": {"gs", []string{"--version"}},
		"composer": {"composer", []string{"--version"}}, "git": {"git", []string{"--version"}},
		"nodejs": {"node", []string{"--version"}}, "npm": {"npm", []string{"--version"}},
		"python3": {"python3", []string{"--version"}}, "python-pip": {"pip3", []string{"--version"}},
		"golang": {"go", []string{"version"}}, "java": {"java", []string{"-version"}},
		"ruby": {"ruby", []string{"--version"}}, "rust": {"rustc", []string{"--version"}},
		"yarn": {"yarnpkg", []string{"--version"}}, "pnpm": {"pnpm", []string{"--version"}},
	}
	if x, ok := binaryArgs[c.ID]; ok {
		if path, err := exec.LookPath(x.name); err == nil {
			c.BinaryPath = path
			c.Details["binary_path"] = path
			c.Details["tool_version"] = commandVersion(ctx, x.name, x.args...)
		}
	}
	if c.ID == "ffmpeg" {
		if p, err := exec.LookPath("ffprobe"); err == nil {
			c.Details["ffprobe_available"] = true
			c.Details["ffprobe_path"] = p
			c.Details["ffprobe_version"] = commandVersion(ctx, "ffprobe", "-version")
		} else {
			c.Details["ffprobe_available"] = false
		}
		if p, err := exec.LookPath("ffmpeg"); err == nil {
			if b, err := exec.CommandContext(ctx, p, "-hide_banner", "-codecs").CombinedOutput(); err == nil {
				count := 0
				for _, line := range strings.Split(string(b), "\n") {
					if strings.HasPrefix(line, " ") && len(line) > 8 {
						count++
					}
				}
				c.Details["codec_entries"] = count
			}
		}
	}
	switch c.ID {
	case "redis-server":
		c.Details["service"] = serviceState(ctx, "redis-server.service")
	case "memcached":
		c.Details["service"] = serviceState(ctx, "memcached.service")
	case "supervisor":
		c.Details["service"] = serviceState(ctx, "supervisor.service")
	}
	if len(c.Details) == 0 {
		c.Details = nil
	}
}
