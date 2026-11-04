package hostadapter

import (
	"context"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

var phpVersionDirRE = regexp.MustCompile(`^8\.[0-9]+$`)

type PHPRuntime struct {
	Version       string   `json:"version"`
	CLI           bool     `json:"cli"`
	FPM           bool     `json:"fpm"`
	FPMService    string   `json:"fpm_service"`
	FPMActive     bool     `json:"fpm_active"`
	Socket        string   `json:"socket"`
	PHPIni        string   `json:"php_ini"`
	PoolDirectory string   `json:"pool_directory"`
	Extensions    []string `json:"extensions"`
	Switchable    bool     `json:"switchable"`
}

func (a *Adapter) PHPRuntimes(ctx context.Context) []PHPRuntime {
	base := "/etc/php"
	entries, _ := os.ReadDir(base)
	out := []PHPRuntime{}
	for _, entry := range entries {
		if !entry.IsDir() || !phpVersionDirRE.MatchString(entry.Name()) {
			continue
		}
		v := entry.Name()
		r := PHPRuntime{Version: v}
		if _, err := os.Stat(filepath.Join("/usr/bin", "php"+v)); err == nil {
			r.CLI = true
		} else if p, ok := commandExists("php"); ok {
			_ = p
			// The unversioned binary is only treated as evidence for the
			// version whose /etc/php tree exists and whose CLI ini directory
			// is present. This avoids advertising arbitrary versions.
			if _, err := os.Stat(filepath.Join(base, v, "cli")); err == nil {
				r.CLI = true
			}
		}
		fpmDir := filepath.Join(base, v, "fpm")
		if st, err := os.Stat(fpmDir); err == nil && st.IsDir() {
			r.FPM = true
			r.FPMService = "php" + v + "-fpm.service"
			r.Socket = filepath.Join("/run/php", "php"+v+"-fpm.sock")
			r.PHPIni = filepath.Join(fpmDir, "php.ini")
			r.PoolDirectory = filepath.Join(fpmDir, "pool.d")
			if text, err := a.run(ctx, "systemctl", "is-active", r.FPMService); err == nil && strings.TrimSpace(text) == "active" {
				r.FPMActive = true
			}
		}
		mods := filepath.Join(base, v, "mods-available")
		if files, err := os.ReadDir(mods); err == nil {
			for _, f := range files {
				if f.IsDir() || !strings.HasSuffix(f.Name(), ".ini") {
					continue
				}
				r.Extensions = append(r.Extensions, strings.TrimSuffix(f.Name(), ".ini"))
			}
			sort.Strings(r.Extensions)
		}
		r.Switchable = r.FPM && r.FPMActive && a.certifiedFor("php-fpm")
		out = append(out, r)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Version > out[j].Version })
	return out
}
