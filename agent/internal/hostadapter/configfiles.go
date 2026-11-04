package hostadapter

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

type EditableConfig struct {
	ID          string `json:"id"`
	Label       string `json:"label"`
	Path        string `json:"path"`
	Family      string `json:"family"`
	Category    string `json:"category"`
	Description string `json:"description,omitempty"`
	Service     string `json:"service"`
	Kind        string `json:"kind,omitempty"`
	Common      bool   `json:"common,omitempty"`
	Priority    int    `json:"priority,omitempty"`
	SHA256      string `json:"sha256,omitempty"`
	Modified    string `json:"modified_at,omitempty"`
	Size        int64  `json:"size_bytes,omitempty"`
}

type ConfigWriteResult struct {
	EditableConfig
	BackupPath string `json:"backup_path"`
	Validated  bool   `json:"validated"`
	Reloaded   bool   `json:"reloaded"`
}

func configSHA(b []byte) string { h := sha256.Sum256(b); return hex.EncodeToString(h[:]) }

func (a *Adapter) baseEditableConfigs() []EditableConfig {
	defs := []EditableConfig{
		{ID: "nginx-main", Label: "Nginx Main Configuration", Path: "/etc/nginx/nginx.conf", Family: "nginx", Category: "Web Server", Description: "Global Nginx worker, HTTP, logging and include settings.", Service: "nginx", Kind: "core", Common: true, Priority: 10},
		{ID: "apache-main", Label: "Apache Main Configuration", Path: "/etc/apache2/apache2.conf", Family: "apache", Category: "Web Server", Description: "Global Apache server configuration on Debian/Ubuntu.", Service: "apache2", Kind: "core", Common: true, Priority: 20},
		{ID: "httpd-main", Label: "httpd Main Configuration", Path: "/etc/httpd/conf/httpd.conf", Family: "apache", Category: "Web Server", Description: "Global Apache/httpd server configuration on RHEL-family hosts.", Service: "httpd", Kind: "core", Common: true, Priority: 20},
		{ID: "bind-options", Label: "BIND Options", Path: "/etc/bind/named.conf.options", Family: "bind", Category: "DNS", Description: "Resolver, listen, recursion and DNS service options.", Service: "bind9", Kind: "core", Common: true, Priority: 40},
		{ID: "bind-local", Label: "BIND Local Zones", Path: "/etc/bind/named.conf.local", Family: "bind", Category: "DNS", Description: "Local zone declarations and Privora DNS includes.", Service: "bind9", Kind: "core", Common: false, Priority: 60},
		{ID: "named-main", Label: "named Main Configuration", Path: "/etc/named.conf", Family: "bind", Category: "DNS", Description: "Global named configuration on RHEL-family hosts.", Service: "named", Kind: "core", Common: true, Priority: 40},
	}
	for _, v := range []string{"8.2", "8.3", "8.4", "8.5"} {
		priority := 35
		common := false
		if v == "8.4" {
			priority = 15
			common = true
		}
		defs = append(defs, EditableConfig{ID: "php-" + v + "-fpm", Label: "PHP " + v + " FPM php.ini", Path: "/etc/php/" + v + "/fpm/php.ini", Family: "php", Category: "PHP", Description: "PHP " + v + " runtime limits, uploads, errors, sessions and extension settings.", Service: "php" + v + "-fpm", Kind: "core", Common: common, Priority: priority})
	}
	return defs
}

func dynamicConfigID(prefix, basename string) string {
	return prefix + "-" + hex.EncodeToString([]byte(basename))
}
func decodeDynamicID(id, prefix string) (string, bool) {
	p := prefix + "-"
	if !strings.HasPrefix(id, p) {
		return "", false
	}
	b, err := hex.DecodeString(strings.TrimPrefix(id, p))
	if err != nil {
		return "", false
	}
	name := string(b)
	if name == "" || filepath.Base(name) != name || strings.ContainsAny(name, "/\\\x00") {
		return "", false
	}
	return name, true
}

func (a *Adapter) EditableConfigs() []EditableConfig {
	out := []EditableConfig{}
	for _, d := range a.baseEditableConfigs() {
		if st, err := os.Stat(d.Path); err == nil && st.Mode().IsRegular() {
			b, _ := os.ReadFile(d.Path)
			d.SHA256 = configSHA(b)
			d.Size = st.Size()
			d.Modified = st.ModTime().UTC().Format(time.RFC3339)
			out = append(out, d)
		}
	}
	for _, spec := range []struct{ dir, prefix, family, service, label string }{
		{a.cfg.NginxSitesAvailable, "nginx-site", "nginx", "nginx", "Nginx vhost"},
		{"/etc/apache2/sites-available", "apache-site", "apache", "apache2", "Apache vhost"},
		{"/etc/httpd/conf.d", "httpd-site", "apache", "httpd", "httpd vhost"},
	} {
		entries, _ := os.ReadDir(spec.dir)
		for _, e := range entries {
			if e.IsDir() {
				continue
			}
			name := e.Name()
			if filepath.Base(name) != name {
				continue
			}
			path := filepath.Join(spec.dir, name)
			st, err := os.Stat(path)
			if err != nil || !st.Mode().IsRegular() {
				continue
			}
			b, _ := os.ReadFile(path)
			out = append(out, EditableConfig{ID: dynamicConfigID(spec.prefix, name), Label: spec.label + " · " + name, Path: path, Family: spec.family, Category: "Web Server", Description: "Per-site virtual host configuration. Advanced: editing this file can affect only the selected site.", Service: spec.service, Kind: "vhost", Common: false, Priority: 200, SHA256: configSHA(b), Size: st.Size(), Modified: st.ModTime().UTC().Format(time.RFC3339)})
		}
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Common != out[j].Common {
			return out[i].Common
		}
		if out[i].Priority != out[j].Priority {
			return out[i].Priority < out[j].Priority
		}
		if out[i].Category != out[j].Category {
			return out[i].Category < out[j].Category
		}
		return out[i].Label < out[j].Label
	})
	return out
}

func (a *Adapter) editableConfigByID(id string) (EditableConfig, error) {
	for _, d := range a.EditableConfigs() {
		if d.ID == id {
			return d, nil
		}
	}
	return EditableConfig{}, errors.New("configuration file is not approved or is not installed on this host")
}

func (a *Adapter) ReadEditableConfig(id string) (EditableConfig, string, error) {
	d, err := a.editableConfigByID(id)
	if err != nil {
		return EditableConfig{}, "", err
	}
	b, err := os.ReadFile(d.Path)
	if err != nil {
		return EditableConfig{}, "", err
	}
	if len(b) > 2<<20 {
		return EditableConfig{}, "", errors.New("configuration file exceeds editor size limit")
	}
	d.SHA256 = configSHA(b)
	return d, string(b), nil
}

func (a *Adapter) validateConfig(ctx context.Context, d EditableConfig) error {
	switch d.Family {
	case "nginx":
		_, err := a.run(ctx, "nginx", "-t")
		return err
	case "apache":
		if d.Service == "httpd" {
			_, err := a.run(ctx, "httpd", "-t")
			return err
		}
		_, err := a.run(ctx, "apache2ctl", "configtest")
		return err
	case "bind":
		_, err := a.run(ctx, "named-checkconf")
		return err
	case "php":
		bin := strings.TrimSuffix(d.Service, "-fpm")
		_, err := a.run(ctx, "php-fpm"+strings.TrimPrefix(bin, "php"), "-t")
		return err
	default:
		return errors.New("unsupported configuration family")
	}
}

func (a *Adapter) WriteEditableConfig(ctx context.Context, id, content, expectedSHA string) (ConfigWriteResult, error) {
	if !a.cfg.AllowMutations {
		return ConfigWriteResult{}, errors.New("host mutations disabled")
	}
	if len(content) > 2<<20 || strings.ContainsRune(content, '\x00') {
		return ConfigWriteResult{}, errors.New("invalid configuration content")
	}
	d, old, err := a.ReadEditableConfig(id)
	if err != nil {
		return ConfigWriteResult{}, err
	}
	oldBytes := []byte(old)
	currentSHA := configSHA(oldBytes)
	if expectedSHA != "" && !strings.EqualFold(strings.TrimSpace(expectedSHA), currentSHA) {
		return ConfigWriteResult{}, errors.New("configuration changed since it was opened; reload before saving")
	}
	backupDir := "/var/lib/privora-panel/config-backups"
	if err := os.MkdirAll(backupDir, 0750); err != nil {
		return ConfigWriteResult{}, err
	}
	backup := filepath.Join(backupDir, strings.ReplaceAll(id, "/", "_")+"-"+time.Now().UTC().Format("20060102T150405Z")+".bak")
	if err := AtomicWrite(backup, oldBytes, 0600); err != nil {
		return ConfigWriteResult{}, err
	}
	st, _ := os.Stat(d.Path)
	mode := os.FileMode(0644)
	if st != nil {
		mode = st.Mode().Perm()
	}
	if err := AtomicWrite(d.Path, []byte(content), mode); err != nil {
		return ConfigWriteResult{}, err
	}
	rollback := func() { _ = AtomicWrite(d.Path, oldBytes, mode) }
	if err := a.validateConfig(ctx, d); err != nil {
		rollback()
		return ConfigWriteResult{}, fmt.Errorf("configuration validation failed; previous file restored: %w", err)
	}
	reloaded := false
	if d.Service != "" {
		if _, err := a.run(ctx, "systemctl", "reload", d.Service); err != nil {
			rollback()
			_ = a.validateConfig(context.Background(), d)
			return ConfigWriteResult{}, fmt.Errorf("service reload failed; previous file restored: %w", err)
		}
		reloaded = true
	}
	fresh, _, _ := a.ReadEditableConfig(id)
	return ConfigWriteResult{EditableConfig: fresh, BackupPath: backup, Validated: true, Reloaded: reloaded}, nil
}
