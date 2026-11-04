package hostadapter

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

type RegistrarGlueResult struct {
	Connected bool   `json:"connected"`
	Provider  string `json:"provider,omitempty"`
	Status    string `json:"status"`
	Detail    string `json:"detail,omitempty"`
}

type RegistrarGlueRequest struct {
	BaseDomain  string   `json:"base_domain"`
	Primary     string   `json:"primary"`
	Secondary   string   `json:"secondary"`
	IPv4        string   `json:"ipv4,omitempty"`
	IPv6        string   `json:"ipv6,omitempty"`
	Nameservers []string `json:"nameservers"`
}

func (a *Adapter) RegistrarStatus() RegistrarGlueResult {
	if strings.TrimSpace(a.cfg.RegistrarAdapterURL) == "" || strings.TrimSpace(a.cfg.RegistrarToken) == "" {
		return RegistrarGlueResult{Connected: false, Provider: strings.TrimSpace(a.cfg.RegistrarProvider), Status: "not-connected", Detail: "registrar API connection required for registry glue and delegation"}
	}
	return RegistrarGlueResult{Connected: true, Provider: strings.TrimSpace(a.cfg.RegistrarProvider), Status: "connected"}
}

func (a *Adapter) SyncRegistrarGlue(ctx context.Context, req RegistrarGlueRequest) (RegistrarGlueResult, error) {
	return a.registrarMutation(ctx, "/v1/glue/sync", req)
}

func (a *Adapter) DeleteRegistrarGlue(ctx context.Context, req RegistrarGlueRequest) (RegistrarGlueResult, error) {
	return a.registrarMutation(ctx, "/v1/glue/delete", req)
}

func (a *Adapter) registrarMutation(ctx context.Context, path string, payload RegistrarGlueRequest) (RegistrarGlueResult, error) {
	status := a.RegistrarStatus()
	if !status.Connected {
		return status, nil
	}
	base, err := url.Parse(strings.TrimRight(a.cfg.RegistrarAdapterURL, "/"))
	if err != nil || base.Host == "" {
		return RegistrarGlueResult{}, errors.New("invalid registrar adapter URL")
	}
	if base.Scheme != "https" && base.Hostname() != "127.0.0.1" && base.Hostname() != "localhost" && base.Hostname() != "::1" {
		return RegistrarGlueResult{}, errors.New("registrar adapter must use HTTPS unless it is local")
	}
	endpoint, err := base.Parse(path)
	if err != nil {
		return RegistrarGlueResult{}, err
	}
	body, _ := json.Marshal(payload)
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint.String(), bytes.NewReader(body))
	if err != nil {
		return RegistrarGlueResult{}, err
	}
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("Authorization", "Bearer "+a.cfg.RegistrarToken)
	client := &http.Client{Timeout: 20 * time.Second}
	if a.cfg.HTTPClient != nil {
		cp := *a.cfg.HTTPClient
		if cp.Timeout == 0 || cp.Timeout > 20*time.Second {
			cp.Timeout = 20 * time.Second
		}
		client = &cp
	}
	resp, err := client.Do(httpReq)
	if err != nil {
		return RegistrarGlueResult{}, fmt.Errorf("registrar adapter request failed: %w", err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return RegistrarGlueResult{}, fmt.Errorf("registrar adapter returned HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(raw)))
	}
	out := RegistrarGlueResult{Connected: true, Provider: strings.TrimSpace(a.cfg.RegistrarProvider), Status: "synced"}
	if len(raw) != 0 {
		_ = json.Unmarshal(raw, &out)
		out.Connected = true
		if out.Provider == "" {
			out.Provider = strings.TrimSpace(a.cfg.RegistrarProvider)
		}
		if out.Status == "" {
			out.Status = "synced"
		}
	}
	return out, nil
}
