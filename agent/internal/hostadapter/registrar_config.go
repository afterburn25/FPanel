package hostadapter

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"os"
	"regexp"
	"strings"
	"time"
)

var registrarProviderRE = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._ -]{0,63}$`)

type RegistrarConnectionConfig struct {
	Provider   string `json:"provider"`
	AdapterURL string `json:"adapter_url"`
	Token      string `json:"token"`
}

func envQuote(v string) string {
	v = strings.ReplaceAll(v, `\\`, `\\\\`)
	v = strings.ReplaceAll(v, `"`, `\\"`)
	return `"` + v + `"`
}

func replaceEnvValue(content, key, value string) string {
	line := key + "=" + envQuote(value)
	rows := strings.Split(content, "\n")
	found := false
	for i, row := range rows {
		if strings.HasPrefix(strings.TrimSpace(row), key+"=") {
			rows[i] = line
			found = true
		}
	}
	if !found {
		rows = append(rows, line)
	}
	return strings.TrimRight(strings.Join(rows, "\n"), "\n") + "\n"
}

// ConfigureRegistrarConnection persists a Privora-compatible registrar adapter
// connection and schedules an agent refresh after the current API response is
// returned. The bearer token is never returned by this method.
func (a *Adapter) ConfigureRegistrarConnection(ctx context.Context, cfg RegistrarConnectionConfig) error {
	if !a.cfg.AllowMutations {
		return errors.New("host mutations disabled")
	}
	cfg.Provider = strings.TrimSpace(cfg.Provider)
	cfg.AdapterURL = strings.TrimSpace(cfg.AdapterURL)
	cfg.Token = strings.TrimSpace(cfg.Token)
	if !registrarProviderRE.MatchString(cfg.Provider) {
		return errors.New("invalid registrar provider label")
	}
	if cfg.Token == "" || len(cfg.Token) > 4096 || strings.ContainsAny(cfg.Token, "\r\n") {
		return errors.New("invalid registrar API token")
	}
	u, err := url.Parse(strings.TrimRight(cfg.AdapterURL, "/"))
	if err != nil || u.Host == "" {
		return errors.New("invalid registrar adapter URL")
	}
	if u.Scheme != "https" && u.Hostname() != "127.0.0.1" && u.Hostname() != "localhost" && u.Hostname() != "::1" {
		return errors.New("registrar adapter must use HTTPS unless it is local")
	}

	old, err := os.ReadFile(a.cfg.AgentEnvPath)
	if err != nil {
		return fmt.Errorf("read agent environment: %w", err)
	}
	next := string(old)
	next = replaceEnvValue(next, "PRIVORA_REGISTRAR_PROVIDER", cfg.Provider)
	next = replaceEnvValue(next, "PRIVORA_REGISTRAR_ADAPTER_URL", strings.TrimRight(cfg.AdapterURL, "/"))
	next = replaceEnvValue(next, "PRIVORA_REGISTRAR_TOKEN", cfg.Token)
	if err := AtomicWrite(a.cfg.AgentEnvPath, []byte(next), 0600); err != nil {
		return fmt.Errorf("write registrar connection: %w", err)
	}

	// Restarting the agent synchronously from its own request would terminate
	// the response. Schedule a one-shot systemd job instead.
	unit := fmt.Sprintf("privora-registrar-refresh-%d", time.Now().UTC().UnixNano())
	if _, err := a.run(ctx, "systemd-run", "--quiet", "--unit", unit, "--on-active=2s", "/bin/systemctl", "restart", "privora-panel-agent.service"); err != nil {
		_ = AtomicWrite(a.cfg.AgentEnvPath, old, 0600)
		return fmt.Errorf("schedule registrar connection refresh: %w", err)
	}
	return nil
}
