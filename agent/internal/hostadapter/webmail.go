package hostadapter

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

const (
	webmailRoot      = "/usr/share/roundcube"
	webmailConfig    = "/etc/roundcube/config.inc.php"
	webmailEnv       = "/etc/privora-panel/webmail.env"
	webmailFPMConfig = "/etc/php/8.4/fpm/pool.d/privora-webmail.conf"
	webmailFPMSocket = "/run/php/php8.4-fpm-privora-webmail.sock"
)

func readWebmailLaunchURL() string {
	raw, err := os.ReadFile(webmailEnv)
	if err != nil {
		return ""
	}
	for _, line := range strings.Split(string(raw), "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "PRIVORA_WEBMAIL_URL=") {
			u := strings.Trim(strings.TrimSpace(strings.TrimPrefix(line, "PRIVORA_WEBMAIL_URL=")), "\"'")
			if strings.HasPrefix(u, "/") || strings.HasPrefix(u, "https://") {
				return u
			}
		}
	}
	return ""
}

func webmailRuntimeConfigured() bool {
	for _, p := range []string{filepath.Join(webmailRoot, "index.php"), webmailConfig, webmailEnv, webmailFPMConfig} {
		st, err := os.Stat(p)
		if err != nil || !st.Mode().IsRegular() {
			return false
		}
	}
	return readWebmailLaunchURL() == "/webmail/"
}

func (a *Adapter) webmailCapability() (bool, bool, string) {
	index := filepath.Join(webmailRoot, "index.php")
	if st, err := os.Stat(index); err != nil || !st.Mode().IsRegular() {
		return false, false, "Roundcube package files are not installed"
	}
	if !webmailRuntimeConfigured() {
		return false, false, "Roundcube detected, but Privora webmail configuration is incomplete"
	}
	nginxPath := a.cfg.PanelNginxConfig
	if strings.TrimSpace(nginxPath) == "" {
		nginxPath = "/etc/nginx/sites-available/privora-panel.conf"
	}
	nginxRaw, nerr := os.ReadFile(nginxPath)
	fpmRaw, ferr := os.ReadFile(webmailFPMConfig)
	routeOK := nerr == nil && bytes.Contains(nginxRaw, []byte("location /webmail/")) && bytes.Contains(nginxRaw, []byte("/_privora_webmail_auth"))
	poolOK := ferr == nil && bytes.Contains(fpmRaw, []byte("[privora-webmail]")) && bytes.Contains(fpmRaw, []byte(webmailFPMSocket))
	socketOK := false
	if st, err := os.Stat(webmailFPMSocket); err == nil && st.Mode()&os.ModeSocket != 0 {
		socketOK = true
	}
	if !routeOK || !poolOK || !socketOK {
		detail := []string{}
		if !routeOK {
			detail = append(detail, "panel route missing")
		}
		if !poolOK {
			detail = append(detail, "dedicated FPM pool missing")
		}
		if !socketOK {
			detail = append(detail, "dedicated FPM socket unavailable")
		}
		return false, false, "Roundcube detected; " + strings.Join(detail, "; ")
	}
	return true, true, "Roundcube · launch=/webmail/ · panel-session gated"
}

func (a *Adapter) configureRoundcubeWebmail(ctx context.Context, installPackages bool) error {
	root := strings.TrimSpace(os.Getenv("PRIVORA_PANEL_ROOT"))
	if root == "" {
		root = "/opt/privora-panel"
	}
	script := filepath.Join(root, "scripts", "configure-webmail.sh")
	st, err := os.Stat(script)
	if err != nil || st.IsDir() {
		return errors.New("Privora webmail configurator is missing")
	}
	args := []string{script}
	if !installPackages {
		args = append(args, "--configure-only")
	}
	bash, err := exec.LookPath("bash")
	if err != nil {
		return errors.New("bash is required for the Privora webmail configurator")
	}
	// The configurator may install Debian packages and restart services. Run the
	// fixed Privora-owned script in a transient root unit so apt can use its _apt
	// sandbox and package maintainer scripts are not constrained by the Agent's
	// NoNewPrivileges/MemoryDenyWriteExecute policy.
	out, err := runIsolatedRootCommand(ctx, "privora-webmail", 10*time.Minute, bash, args,
		map[string]bool{"PRIVORA_PANEL_ROOT": true}, "PRIVORA_PANEL_ROOT="+root)
	if err != nil {
		tail := out
		if len(tail) > 5000 {
			tail = tail[len(tail)-5000:]
		}
		return fmt.Errorf("Roundcube configuration failed: %w: %s", err, strings.TrimSpace(tail))
	}
	available, certified, detail := a.webmailCapability()
	if !available || !certified {
		return fmt.Errorf("Roundcube configuration completed but did not certify: %s", detail)
	}
	return nil
}
