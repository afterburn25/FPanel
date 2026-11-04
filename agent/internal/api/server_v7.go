package api

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"privora.local/panel/agent/internal/audit"
	"privora.local/panel/agent/internal/hostadapter"
	"privora.local/panel/agent/internal/hosting"
	"privora.local/panel/agent/internal/platform"
	"privora.local/panel/agent/internal/resources"
)

func (s *Server) v7MailQueue(w http.ResponseWriter, r *http.Request) {
	if s.cfg.Mock {
		writeJSON(w, 200, map[string]any{"queue": []any{}, "source": "simulation"})
		return
	}
	q, err := s.host.MailQueue(r.Context())
	if err != nil {
		writeJSON(w, 409, map[string]any{"error": err.Error()})
		return
	}
	writeJSON(w, 200, map[string]any{"queue": q, "count": len(q), "source": "postfix"})
}
func (s *Server) v7MailQueueRetry(w http.ResponseWriter, r *http.Request) {
	if s.cfg.Mock {
		writeJSON(w, 200, map[string]any{"ok": true, "simulation": true})
		return
	}
	err := s.host.RetryMailQueue(r.Context(), r.PathValue("id"))
	resultAudit(s, r, "mail.queue.retry", r.PathValue("id"), err)
	if err != nil {
		writeJSON(w, 409, map[string]any{"error": err.Error()})
		return
	}
	writeJSON(w, 200, map[string]any{"ok": true})
}
func (s *Server) v7MailQueueDelete(w http.ResponseWriter, r *http.Request) {
	if s.cfg.Mock {
		writeJSON(w, 200, map[string]any{"ok": true, "simulation": true})
		return
	}
	err := s.host.DeleteMailQueue(r.Context(), r.PathValue("id"))
	resultAudit(s, r, "mail.queue.delete", r.PathValue("id"), err)
	if err != nil {
		writeJSON(w, 409, map[string]any{"error": err.Error()})
		return
	}
	writeJSON(w, 200, map[string]any{"ok": true})
}
func (s *Server) v7MailDelivery(w http.ResponseWriter, r *http.Request) {
	if s.cfg.Mock {
		writeJSON(w, 200, map[string]any{"events": []any{}, "source": "simulation"})
		return
	}
	n, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	events, err := s.host.MailDeliveryEvents(r.Context(), r.URL.Query().Get("query"), n)
	if err != nil {
		writeJSON(w, 409, map[string]any{"error": err.Error()})
		return
	}
	writeJSON(w, 200, map[string]any{"events": events, "source": "mail-log"})
}
func (s *Server) v7MailFilters(w http.ResponseWriter, r *http.Request) {
	address := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("address")))
	owner := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("owner")))
	all := s.platform.ListMailFilters()
	out := []platform.MailFilter{}
	for _, v := range all {
		if address != "" && v.Address != address {
			continue
		}
		if owner != "" && v.Owner != owner {
			continue
		}
		out = append(out, v)
	}
	writeJSON(w, 200, map[string]any{"filters": out})
}
func (s *Server) reconcileMailboxFilters(ctx context.Context, address string) error {
	all := s.platform.ListMailFilters()
	rows := []hostadapter.SieveFilter{}
	for _, v := range all {
		if v.Address == address {
			rows = append(rows, hostadapter.SieveFilter{ID: v.ID, Name: v.Name, Field: v.Field, Operator: v.Operator, Value: v.Value, Action: v.Action, Destination: v.Destination, Enabled: v.Enabled})
		}
	}
	if s.cfg.Mock {
		return nil
	}
	_, err := s.host.ApplyMailboxSieve(ctx, address, rows)
	return err
}
func (s *Server) v7MailFilterUpsert(w http.ResponseWriter, r *http.Request) {
	var in platform.MailFilter
	if !decodeBody(w, r, &in, 1<<16) {
		return
	}
	var previous *platform.MailFilter
	if in.ID != "" {
		for _, row := range s.platform.ListMailFilters() {
			if row.ID == in.ID {
				x := row
				previous = &x
				break
			}
		}
	}
	v, err := s.platform.UpsertMailFilter(in)
	if err == nil {
		err = s.reconcileMailboxFilters(r.Context(), v.Address)
	}
	if err != nil {
		// Keep durable intent and the compiled Sieve file transactional.
		if previous != nil {
			_, _ = s.platform.UpsertMailFilter(*previous)
		} else if v.ID != "" {
			_ = s.platform.DeleteMailFilter(v.ID)
		}
	}
	resultAudit(s, r, "mail.filter.upsert", in.Address, err)
	if err != nil {
		writeJSON(w, 409, map[string]any{"error": err.Error()})
		return
	}
	v.Status = "active"
	_, _ = s.platform.UpsertMailFilter(v)
	writeJSON(w, 201, map[string]any{"ok": true, "filter": v})
}
func (s *Server) v7MailFilterDelete(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	var previous *platform.MailFilter
	for _, v := range s.platform.ListMailFilters() {
		if v.ID == id {
			x := v
			previous = &x
			break
		}
	}
	if previous == nil {
		writeJSON(w, 404, map[string]any{"error": "mail filter not found"})
		return
	}
	err := s.platform.DeleteMailFilter(id)
	if err == nil {
		err = s.reconcileMailboxFilters(r.Context(), previous.Address)
	}
	if err != nil {
		_, _ = s.platform.UpsertMailFilter(*previous)
		_ = s.reconcileMailboxFilters(r.Context(), previous.Address)
	}
	resultAudit(s, r, "mail.filter.delete", id, err)
	if err != nil {
		writeJSON(w, 409, map[string]any{"error": err.Error()})
		return
	}
	writeJSON(w, 200, map[string]any{"ok": true})
}

func backupPolicyDueV7(p platform.BackupPolicy, now time.Time) bool {
	if !p.Enabled || p.Destination != "local" {
		return false
	}
	if p.LastRun.IsZero() {
		return true
	}
	d := now.Sub(p.LastRun)
	switch strings.ToLower(strings.TrimSpace(p.Schedule)) {
	case "hourly":
		return d >= time.Hour
	case "daily":
		return d >= 24*time.Hour
	case "weekly":
		return d >= 7*24*time.Hour
	case "monthly":
		return d >= 28*24*time.Hour
	default:
		return false // custom cron is retained as intent until a certified cron parser is enabled.
	}
}

func (s *Server) executeBackupPolicyV7(ctx context.Context, p platform.BackupPolicy) (resources.Backup, error) {
	if p.Destination != "local" {
		return resources.Backup{}, errors.New("remote backup transport is not certified")
	}
	if !s.cfg.Mock && !s.cfg.HostMutations {
		return resources.Backup{}, errors.New("real host mutations are disabled")
	}
	if s.cfg.Mock {
		return s.resources.CreateBackup(p.Scope, p.Resource, p.Destination)
	}
	var source string
	switch p.Scope {
	case "account":
		if live, ok := s.liveAccount(ctx, p.Resource); ok {
			source = live.Home
		}
	case "site":
		if live, ok := s.liveSite(ctx, p.Resource); ok {
			source = filepath.Dir(live.DocumentRoot)
		}
	default:
		return resources.Backup{}, errors.New("scheduled live backup supports account or site scope")
	}
	if source == "" {
		return resources.Backup{}, errors.New("backup resource not found")
	}
	root := s.cfg.BackupRoot
	if root == "" {
		root = "/var/backups/privora-panel"
	}
	name := strings.NewReplacer("/", "_", "\\", "_", "..", "_").Replace(p.Resource)
	dst := filepath.Join(root, name+"-"+time.Now().UTC().Format("20060102T150405Z")+".tar.zst")
	br, err := s.host.CreateLocalBackup(ctx, source, dst)
	if err != nil {
		return resources.Backup{}, err
	}
	v, err := s.resources.RecordScheduledBackup(p.Scope, p.Resource, br.Path, br.SHA256, uint64(br.Size), p.ID)
	if err != nil {
		return resources.Backup{}, err
	}
	if p.Verify {
		verified, verifyErr := s.host.VerifyLocalBackup(ctx, v.Destination, v.SHA256)
		if verifyErr != nil {
			return v, fmt.Errorf("backup created but verification failed: %w", verifyErr)
		}
		v, _ = s.resources.MarkBackupVerified(v.ID, verified.VerifiedAt)
	}
	s.pruneBackupPolicyV7(p)
	return v, nil
}

func (s *Server) pruneBackupPolicyV7(p platform.BackupPolicy) {
	if p.Retention < 1 {
		return
	}
	rows := []resources.Backup{}
	for _, b := range s.resources.ListBackups() {
		if b.PolicyID == p.ID {
			rows = append(rows, b)
		}
	}
	if len(rows) <= p.Retention {
		return
	}
	root := s.cfg.BackupRoot
	if root == "" {
		root = "/var/backups/privora-panel"
	}
	rootAbs, _ := filepath.Abs(root)
	for _, b := range rows[p.Retention:] {
		pathAbs, _ := filepath.Abs(b.Destination)
		if pathAbs == "" || rootAbs == "" || !strings.HasPrefix(pathAbs, rootAbs+string(os.PathSeparator)) {
			continue
		}
		if err := os.Remove(pathAbs); err != nil && !errors.Is(err, os.ErrNotExist) {
			continue
		}
		_ = s.resources.DeleteBackupRecord(b.ID)
	}
}

func (s *Server) v7BackupPolicyRun(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	var target *platform.BackupPolicy
	for _, p := range s.platform.ListBackupPolicies() {
		if p.ID == id {
			x := p
			target = &x
			break
		}
	}
	if target == nil {
		writeJSON(w, 404, map[string]any{"error": "backup policy not found"})
		return
	}
	v, err := s.executeBackupPolicyV7(r.Context(), *target)
	status := "success"
	if err != nil {
		status = "failure: " + err.Error()
	}
	_, _ = s.platform.UpdateBackupPolicyRun(id, status, time.Now().UTC())
	resultAudit(s, r, "backup.policy.run", target.Resource, err)
	if err != nil {
		writeJSON(w, 409, map[string]any{"error": err.Error()})
		return
	}
	writeJSON(w, 200, map[string]any{"ok": true, "backup": v})
}

// StartBackground enables real scheduled backup execution and periodic metric capture.
// It is called only by the production agent process, never implicitly by Handler tests.
func (s *Server) StartBackground(ctx context.Context) {
	_ = s.platform.EnsureDefaultAlertRules()
	go func() {
		ticker := time.NewTicker(time.Minute)
		defer ticker.Stop()
		lastMetrics := time.Time{}
		for {
			select {
			case <-ctx.Done():
				return
			case now := <-ticker.C:
				if !s.cfg.Mock && time.Since(lastMetrics) >= 5*time.Minute {
					if m, err := s.host.CollectLiveMetrics(ctx); err == nil {
						_, _ = s.platform.CaptureMetric(platform.MetricSample{CPU: m.CPUPercent, Memory: m.MemoryPercent, Disk: m.DiskPercent, Load: m.Load1, MailQueue: m.MailQueue, PHPBusy: m.PHPBusy})
						_, _ = s.platform.EvaluateAlertRules(now)
						lastMetrics = now
					}
				}
				for _, p := range s.platform.ListBackupPolicies() {
					if !backupPolicyDueV7(p, now) {
						continue
					}
					_, err := s.executeBackupPolicyV7(ctx, p)
					status := "success"
					if err != nil {
						status = "failure: " + err.Error()
					}
					_, _ = s.platform.UpdateBackupPolicyRun(p.ID, status, now)
					outcome := "success"
					if err != nil {
						outcome = "failure"
					}
					_ = s.audit.Write(audit.Record{Actor: "scheduler", Operation: "backup.policy.run", Resource: p.Resource, Outcome: outcome})
				}
			}
		}
	}()
}

func (s *Server) v7BackupPolicies(w http.ResponseWriter, r *http.Request) {
	owner := strings.TrimSpace(r.URL.Query().Get("owner"))
	all := s.platform.ListBackupPolicies()
	out := []platform.BackupPolicy{}
	for _, v := range all {
		if owner == "" || v.Owner == owner {
			out = append(out, v)
		}
	}
	writeJSON(w, 200, map[string]any{"policies": out, "destinations": []string{"local"}})
}
func (s *Server) v7BackupPolicyUpsert(w http.ResponseWriter, r *http.Request) {
	var in platform.BackupPolicy
	if !decodeBody(w, r, &in, 1<<16) {
		return
	}
	v, err := s.platform.UpsertBackupPolicy(in)
	resultAudit(s, r, "backup.policy.upsert", in.Resource, err)
	if err != nil {
		writeJSON(w, 400, map[string]any{"error": err.Error()})
		return
	}
	writeJSON(w, 201, map[string]any{"ok": true, "policy": v, "note": "Local execution is certified; remote destinations require their configured transport before runs are accepted."})
}
func (s *Server) v7BackupPolicyDelete(w http.ResponseWriter, r *http.Request) {
	err := s.platform.DeleteBackupPolicy(r.PathValue("id"))
	resultAudit(s, r, "backup.policy.delete", r.PathValue("id"), err)
	if err != nil {
		writeJSON(w, 404, map[string]any{"error": err.Error()})
		return
	}
	writeJSON(w, 200, map[string]any{"ok": true})
}
func (s *Server) v7BackupVerify(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	b, ok := s.resources.BackupByID(id)
	if !ok {
		writeJSON(w, 404, map[string]any{"error": "backup not found"})
		return
	}
	if s.cfg.Mock {
		writeJSON(w, 200, map[string]any{"ok": true, "simulation": true, "verification": map[string]any{"status": "verified"}})
		return
	}
	v, err := s.host.VerifyLocalBackup(r.Context(), b.Destination, b.SHA256)
	if err == nil {
		_, _ = s.resources.MarkBackupVerified(id, v.VerifiedAt)
	}
	resultAudit(s, r, "backup.verify", id, err)
	if err != nil {
		writeJSON(w, 409, map[string]any{"error": err.Error()})
		return
	}
	writeJSON(w, 200, map[string]any{"ok": true, "verification": v})
}

func (s *Server) v7APIKeyRevoke(w http.ResponseWriter, r *http.Request) {
	v, err := s.platform.RevokeAPIKey(r.PathValue("id"))
	resultAudit(s, r, "api_key.revoke", r.PathValue("id"), err)
	if err != nil {
		writeJSON(w, 404, map[string]any{"error": err.Error()})
		return
	}
	writeJSON(w, 200, map[string]any{"ok": true, "api_key": v})
}
func (s *Server) v7APIKeyRotate(w http.ResponseWriter, r *http.Request) {
	v, secret, err := s.platform.RotateAPIKey(r.PathValue("id"))
	resultAudit(s, r, "api_key.rotate", r.PathValue("id"), err)
	if err != nil {
		writeJSON(w, 404, map[string]any{"error": err.Error()})
		return
	}
	writeJSON(w, 200, map[string]any{"ok": true, "api_key": v, "secret_once": secret})
}

func (s *Server) v7MonitoringLive(w http.ResponseWriter, r *http.Request) {
	if s.cfg.Mock {
		writeJSON(w, 200, map[string]any{"live": map[string]any{"cpu_percent": 12.5, "memory_percent": 33.0, "disk_percent": 41.0, "load_1": 0.2, "mail_queue": 0}, "simulation": true})
		return
	}
	v, err := s.host.CollectLiveMetrics(r.Context())
	if err != nil {
		writeJSON(w, 409, map[string]any{"error": err.Error()})
		return
	}
	if r.URL.Query().Get("capture") == "1" {
		sample := platform.MetricSample{CPU: v.CPUPercent, Memory: v.MemoryPercent, Disk: v.DiskPercent, Load: v.Load1, MailQueue: v.MailQueue, PHPBusy: v.PHPBusy}
		_, _ = s.platform.CaptureMetric(sample)
		_, _ = s.platform.EvaluateAlertRules(time.Now().UTC())
	}
	writeJSON(w, 200, map[string]any{"live": v, "history": s.platform.ListMetrics(), "alerts": s.platform.ListAlertRules(), "incidents": s.platform.ListIncidents()})
}

func (s *Server) v7AlertRuleDelete(w http.ResponseWriter, r *http.Request) {
	err := s.platform.DeleteAlertRule(r.PathValue("id"))
	resultAudit(s, r, "monitoring.alert.delete", r.PathValue("id"), err)
	if err != nil {
		writeJSON(w, 404, map[string]any{"error": err.Error()})
		return
	}
	writeJSON(w, 200, map[string]any{"ok": true})
}

func (s *Server) v7IncidentResolve(w http.ResponseWriter, r *http.Request) {
	v, err := s.platform.ResolveIncident(r.PathValue("id"))
	resultAudit(s, r, "monitoring.incident.resolve", r.PathValue("id"), err)
	if err != nil {
		writeJSON(w, 404, map[string]any{"error": err.Error()})
		return
	}
	writeJSON(w, 200, map[string]any{"ok": true, "incident": v})
}

func (s *Server) v7SecurityAdvisor(w http.ResponseWriter, r *http.Request) {
	if s.cfg.Mock {
		writeJSON(w, 200, map[string]any{"score": 92, "findings": []any{}, "simulation": true})
		return
	}
	findings := s.host.SecurityAdvice(r.Context())
	score := 100
	for _, f := range findings {
		switch f.Severity {
		case "critical":
			score -= 20
		case "warning":
			score -= 8
		}
	}
	if score < 0 {
		score = 0
	}
	writeJSON(w, 200, map[string]any{"score": score, "findings": findings})
}
func (s *Server) v7SecurityFix(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Fix string `json:"fix"`
	}
	if !decodeBody(w, r, &in, 1<<14) {
		return
	}
	if s.cfg.Mock {
		writeJSON(w, 200, map[string]any{"ok": true, "simulation": true})
		return
	}
	err := s.host.ApplySecurityFix(r.Context(), in.Fix)
	resultAudit(s, r, "security.advisor.fix", in.Fix, err)
	if err != nil {
		writeJSON(w, 409, map[string]any{"error": err.Error()})
		return
	}
	writeJSON(w, 200, map[string]any{"ok": true, "fix": in.Fix})
}

func (s *Server) v7SitePolicies(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, 200, map[string]any{"policies": s.platform.ListSitePolicies()})
}
func (s *Server) v7SitePolicySet(w http.ResponseWriter, r *http.Request) {
	domain := strings.ToLower(r.PathValue("domain"))
	var in platform.SitePolicy
	if !decodeBody(w, r, &in, 1<<16) {
		return
	}
	in.Domain = domain
	if in.Owner == "" {
		if site, ok := s.liveSite(r.Context(), domain); ok {
			in.Owner = site.Username
		}
	}
	previous, hadPrevious := s.platform.GetSitePolicy(domain)
	v, err := s.platform.SetSitePolicy(in)
	if err == nil && !s.cfg.Mock {
		err = s.host.ApplySitePolicy(r.Context(), domain, hostadapter.SitePolicyInput{ForceHTTPS: v.ForceHTTPS, HSTS: v.HSTS, HSTSMaxAge: v.HSTSMaxAge, RedirectTarget: v.RedirectTarget, DirectoryIndex: v.DirectoryIndex, HotlinkProtection: v.HotlinkProtection})
	}
	if err != nil {
		if hadPrevious {
			_, _ = s.platform.SetSitePolicy(previous)
		} else {
			_ = s.platform.DeleteSitePolicy(domain)
		}
	}
	resultAudit(s, r, "site.policy.set", domain, err)
	if err != nil {
		writeJSON(w, 409, map[string]any{"error": err.Error()})
		return
	}
	v.Status = "active"
	_, _ = s.platform.SetSitePolicy(v)
	writeJSON(w, 200, map[string]any{"ok": true, "policy": v})
}

func (s *Server) v7DatabaseActivity(w http.ResponseWriter, r *http.Request) {
	engine := strings.ToLower(r.URL.Query().Get("engine"))
	if engine == "" {
		engine = "mariadb"
	}
	if s.cfg.Mock {
		writeJSON(w, 200, map[string]any{"engine": engine, "activity": []any{}, "simulation": true})
		return
	}
	rows, err := s.host.DatabaseActivity(r.Context(), engine)
	if err != nil {
		writeJSON(w, 409, map[string]any{"error": err.Error()})
		return
	}
	writeJSON(w, 200, map[string]any{"engine": engine, "activity": rows})
}
func (s *Server) v7DatabaseKill(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Engine string `json:"engine"`
	}
	if !decodeBody(w, r, &in, 1<<14) {
		return
	}
	if s.cfg.Mock {
		writeJSON(w, 200, map[string]any{"ok": true, "simulation": true})
		return
	}
	err := s.host.KillDatabaseSession(r.Context(), strings.ToLower(in.Engine), r.PathValue("id"))
	resultAudit(s, r, "database.session.kill", r.PathValue("id"), err)
	if err != nil {
		writeJSON(w, 409, map[string]any{"error": err.Error()})
		return
	}
	writeJSON(w, 200, map[string]any{"ok": true})
}

func (s *Server) v7AppsDiscover(w http.ResponseWriter, r *http.Request) {
	if s.cfg.Mock {
		writeJSON(w, 200, map[string]any{"applications": []any{}, "simulation": true})
		return
	}
	inv := s.host.DiscoverInventory(r.Context())
	out := []hostadapter.AppDiscovery{}
	for _, site := range inv.Sites {
		if !site.Enabled || site.DocumentRoot == "" || site.Username == "" {
			continue
		}
		v, err := s.host.DiscoverApplication(r.Context(), site.Domain, site.Username, site.DocumentRoot)
		if err == nil {
			out = append(out, v)
		}
	}
	writeJSON(w, 200, map[string]any{"applications": out})
}
func (s *Server) findV7App(ctx context.Context, domain string) (hostadapter.AppDiscovery, error) {
	inv := s.host.DiscoverInventory(ctx)
	for _, site := range inv.Sites {
		if strings.EqualFold(site.Domain, domain) {
			return s.host.DiscoverApplication(ctx, site.Domain, site.Username, site.DocumentRoot)
		}
	}
	return hostadapter.AppDiscovery{}, errors.New("website not found")
}
func mutatingAppActionV7(action string) bool {
	return map[string]bool{"cache-flush": true, "core-update": true, "plugin-update-all": true, "theme-update-all": true, "maintenance-on": true, "maintenance-off": true, "cache-clear": true, "config-clear": true, "route-clear": true, "view-clear": true, "optimize": true, "optimize-clear": true, "queue-restart": true, "storage-link": true, "migrate": true}[action]
}

func (s *Server) backupApplicationBeforeMutationV7(ctx context.Context, app hostadapter.AppDiscovery, action string) (resources.Backup, error) {
	if !mutatingAppActionV7(action) || s.cfg.Mock {
		return resources.Backup{}, nil
	}
	root := s.cfg.BackupRoot
	if root == "" {
		root = "/var/backups/privora-panel"
	}
	name := strings.NewReplacer("/", "_", "\\", "_", "..", "_").Replace(app.Domain)
	dst := filepath.Join(root, name+"-pre-app-"+strings.ReplaceAll(action, "-", "_")+"-"+time.Now().UTC().Format("20060102T150405Z")+".tar.zst")
	br, err := s.host.CreateLocalBackup(ctx, app.Root, dst)
	if err != nil {
		return resources.Backup{}, fmt.Errorf("pre-change backup failed: %w", err)
	}
	v, err := s.resources.RecordRealBackup("site", app.Domain, br.Path, br.SHA256, uint64(br.Size))
	if err != nil {
		return resources.Backup{}, err
	}
	return v, nil
}

func (s *Server) v7AppAction(w http.ResponseWriter, r *http.Request) {
	domain := strings.ToLower(r.PathValue("domain"))
	var in struct {
		Action string `json:"action"`
	}
	if !decodeBody(w, r, &in, 1<<14) {
		return
	}
	if s.cfg.Mock {
		writeJSON(w, 200, map[string]any{"ok": true, "simulation": true})
		return
	}
	app, err := s.findV7App(r.Context(), domain)
	if err == nil {
		var safetyBackup resources.Backup
		if mutatingAppActionV7(in.Action) {
			safetyBackup, err = s.backupApplicationBeforeMutationV7(r.Context(), app, in.Action)
		}
		if err == nil {
			var out string
			out, err = s.host.RunApplicationAction(r.Context(), app, in.Action)
			if err == nil {
				resultAudit(s, r, "application.action."+in.Action, domain, nil)
				writeJSON(w, 200, map[string]any{"ok": true, "application": app, "output": out, "safety_backup": safetyBackup})
				return
			}
		}
	}
	resultAudit(s, r, "application.action."+in.Action, domain, err)
	writeJSON(w, 409, map[string]any{"error": err.Error()})
}

func (s *Server) v7DNSSECStatus(w http.ResponseWriter, r *http.Request) {
	if s.cfg.Mock {
		writeJSON(w, 200, map[string]any{"dnssec": map[string]any{"domain": r.PathValue("domain"), "enabled": false}, "simulation": true})
		return
	}
	v, err := s.host.DNSSECStatus(r.Context(), r.PathValue("domain"))
	if err != nil {
		writeJSON(w, 409, map[string]any{"error": err.Error()})
		return
	}
	writeJSON(w, 200, map[string]any{"dnssec": v})
}
func (s *Server) v7DNSSECSet(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Enabled bool `json:"enabled"`
	}
	if !decodeBody(w, r, &in, 1<<14) {
		return
	}
	if s.cfg.Mock {
		writeJSON(w, 200, map[string]any{"ok": true, "simulation": true})
		return
	}
	v, err := s.host.SetDNSSEC(r.Context(), r.PathValue("domain"), in.Enabled)
	resultAudit(s, r, "dns.dnssec.set", r.PathValue("domain"), err)
	if err != nil {
		writeJSON(w, 409, map[string]any{"error": err.Error()})
		return
	}
	writeJSON(w, 200, map[string]any{"ok": true, "dnssec": v})
}
func (s *Server) v7DNSTemplates(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, 200, map[string]any{"templates": s.platform.ListDNSTemplates()})
}
func (s *Server) v7DNSTemplateUpsert(w http.ResponseWriter, r *http.Request) {
	var in platform.DNSTemplate
	if !decodeBody(w, r, &in, 256<<10) {
		return
	}
	v, err := s.platform.UpsertDNSTemplate(in)
	resultAudit(s, r, "dns.template.upsert", in.Name, err)
	if err != nil {
		writeJSON(w, 400, map[string]any{"error": err.Error()})
		return
	}
	writeJSON(w, 201, map[string]any{"ok": true, "template": v})
}
func (s *Server) v7DNSTemplateDelete(w http.ResponseWriter, r *http.Request) {
	err := s.platform.DeleteDNSTemplate(r.PathValue("id"))
	if err != nil {
		writeJSON(w, 404, map[string]any{"error": err.Error()})
		return
	}
	writeJSON(w, 200, map[string]any{"ok": true})
}
func (s *Server) v7DNSTemplateApply(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Domain string `json:"domain"`
	}
	if !decodeBody(w, r, &in, 1<<16) {
		return
	}
	var tpl *platform.DNSTemplate
	for _, v := range s.platform.ListDNSTemplates() {
		if v.ID == r.PathValue("id") {
			x := v
			tpl = &x
			break
		}
	}
	if tpl == nil {
		writeJSON(w, 404, map[string]any{"error": "DNS template not found"})
		return
	}
	var zone resources.DNSZone
	ok := false
	for _, z := range s.resources.ListDNSZones() {
		if strings.EqualFold(z.Domain, in.Domain) {
			zone = z
			ok = true
			break
		}
	}
	if !ok {
		writeJSON(w, 404, map[string]any{"error": "Privora-managed DNS zone not found"})
		return
	}
	records := append([]resources.DNSRecord(nil), zone.Records...)
	for _, x := range tpl.Records {
		records = append(records, resources.DNSRecord{Type: strings.ToUpper(x.Type), Name: x.Name, Value: x.Value, TTL: x.TTL})
	}
	previousRecords := append([]resources.DNSRecord(nil), zone.Records...)
	if _, err := s.resources.ReplaceDNSZoneRecords(zone.Domain, records); err != nil {
		writeJSON(w, 409, map[string]any{"error": err.Error()})
		return
	}
	if !s.cfg.Mock {
		ns := s.nameserversForDomain(zone.Domain)
		hostRows := make([]hostadapter.DNSRecord, 0, len(records))
		for _, x := range records {
			hostRows = append(hostRows, hostadapter.DNSRecord{Type: x.Type, Name: x.Name, Value: x.Value, TTL: x.TTL})
		}
		if _, err := s.host.ProvisionBINDZoneWithNameservers(r.Context(), zone.Domain, ns.Primary, ns.Secondary, hostRows); err != nil {
			_, _ = s.resources.ReplaceDNSZoneRecords(zone.Domain, previousRecords)
			rollbackRows := make([]hostadapter.DNSRecord, 0, len(previousRecords))
			for _, x := range previousRecords {
				rollbackRows = append(rollbackRows, hostadapter.DNSRecord{Type: x.Type, Name: x.Name, Value: x.Value, TTL: x.TTL})
			}
			_, _ = s.host.ProvisionBINDZoneWithNameservers(context.Background(), zone.Domain, ns.Primary, ns.Secondary, rollbackRows)
			writeJSON(w, 409, map[string]any{"error": err.Error()})
			return
		}
	}
	s.auditMutation(r, "dns.template.apply", zone.Domain, "success")
	writeJSON(w, 200, map[string]any{"ok": true, "domain": zone.Domain, "records": records})
}

func (s *Server) calculateReadiness(ctx context.Context) (int, []platform.ReadinessItem) {
	score := 100
	items := []platform.ReadinessItem{}
	add := func(area, res, sev, status, summary, action string) {
		items = append(items, platform.ReadinessItem{ID: fmt.Sprintf("%s-%d", area, len(items)+1), Area: area, Resource: res, Severity: sev, Status: status, Summary: summary, RepairAction: action})
		if status == "action-required" {
			if sev == "critical" {
				score -= 15
			} else {
				score -= 6
			}
		}
	}
	if s.cfg.Mock {
		add("server", "mock", "info", "pass", "Simulation readiness profile active.", "")
		return score, items
	}
	// Critical control-plane and hosting services are checked from the same
	// allow-list used by Service Manager; absent services are ignored, inactive
	// installed services are repairable.
	for _, svc := range []string{"nginx", "privora-panel-fpm", "postfix", "dovecot", "bind9", "mariadb", "mysql", "postgresql"} {
		if !s.cfg.AllowedServices[svc] {
			continue
		}
		load, _ := s.runner.Run(ctx, "systemctl", "show", svc, "--property=LoadState", "--value")
		if strings.TrimSpace(load) == "" || strings.TrimSpace(load) == "not-found" {
			continue
		}
		state, err := s.runner.Run(ctx, "systemctl", "is-active", svc)
		if err != nil || strings.TrimSpace(state) != "active" {
			add("service", svc, "critical", "action-required", "Required service is not active.", "service.restart:"+svc)
		}
	}
	inv := s.host.DiscoverInventory(ctx)
	for _, w := range inv.Warnings {
		add("inventory", "server", "warning", "action-required", w, "")
	}
	zones := map[string]bool{}
	for _, z := range inv.DNSZones {
		zones[strings.ToLower(z.Domain)] = true
	}
	certs := map[string]hostadapter.LiveCertificate{}
	for _, c := range inv.Certificates {
		certs[strings.ToLower(c.Domain)] = c
	}
	for _, site := range inv.Sites {
		if !site.Enabled {
			add("website", site.Domain, "critical", "action-required", "Website vhost is not enabled.", "website.repair:"+site.Domain)
		}
		if !zones[strings.ToLower(site.Domain)] {
			add("dns", site.Domain, "warning", "action-required", "No local authoritative DNS zone was discovered.", "dns.repair-all")
		}
		if c, ok := certs[strings.ToLower(site.Domain)]; !ok || c.Status != "active" {
			add("ssl", site.Domain, "warning", "action-required", "No active certificate was confirmed for this website.", "ssl.autossl:"+site.Domain)
		} else if !c.ExpiresAt.IsZero() && time.Until(c.ExpiresAt) < 14*24*time.Hour {
			add("ssl", site.Domain, "warning", "action-required", "Certificate expires in less than 14 days.", "ssl.autossl:"+site.Domain)
		}
	}
	for _, f := range s.host.SecurityAdvice(ctx) {
		if f.Status == "action-required" {
			add("security", f.ID, f.Severity, "action-required", f.Title+": "+f.Detail, f.Fix)
		}
	}
	if len(s.resources.ListBackups()) == 0 {
		add("backup", "server", "warning", "action-required", "No Privora backup has been recorded yet.", "")
	}
	if score < 0 {
		score = 0
	}
	if score == 100 {
		add("server", "server", "info", "pass", "No readiness blockers were found in the current live inventory.", "")
	}
	return score, items
}
func (s *Server) v7Readiness(w http.ResponseWriter, r *http.Request) {
	score, items := s.calculateReadiness(r.Context())
	status := "ready"
	if score < 85 {
		status = "attention"
	}
	if score < 60 {
		status = "critical"
	}
	run, _ := s.platform.RecordReadiness(score, status, items)
	writeJSON(w, 200, map[string]any{"readiness": run})
}
func (s *Server) v7ReadinessHistory(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, 200, map[string]any{"runs": s.platform.ListReadinessRuns()})
}
func (s *Server) repairWebsiteV7(ctx context.Context, domain string) error {
	var site hosting.Site
	found := false
	if saved, ok := s.hosting.GetSite(domain); ok {
		site = saved
		found = true
	}
	if !found {
		for _, a := range s.hosting.ListAccounts() {
			if strings.EqualFold(a.PrimaryDomain, domain) {
				site = hosting.Site{Domain: domain, Username: a.Username, DocumentRoot: filepath.Join("/home", a.Username, "domains", domain, "public")}
				found = true
				break
			}
		}
	}
	if !found {
		return errors.New("durable hosting identity not found")
	}
	if site.DocumentRoot == "" {
		site.DocumentRoot = filepath.Join("/home", site.Username, "domains", domain, "public")
	}
	php := site.PHPVersion
	if php == "" || php == "unknown" {
		php = s.host.DetectAccountPHPVersion(site.Username)
	}
	if php == "" {
		return errors.New("PHP-FPM version could not be inferred")
	}
	_, err := s.host.RepairSiteNginx(ctx, domain, site.Username, php, site.DocumentRoot)
	if err == nil {
		s.host.InvalidateInventory()
	}
	return err
}
func (s *Server) runReadinessRepairV7(ctx context.Context, action string) error {
	if !s.cfg.Mock && !s.cfg.HostMutations {
		return errors.New("real host mutations are disabled")
	}
	switch {
	case action == "panel-permissions":
		if !s.cfg.Mock {
			return s.host.RepairPanelPermissions(ctx)
		}
	case action == "mail-auth":
		if !s.cfg.Mock {
			return s.host.ReconcileMailAuthentication(ctx)
		}
	case action == "dns.repair-all":
		if s.cfg.Mock {
			return nil
		}
		for _, site := range s.host.DiscoverInventory(ctx).Sites {
			if site.Domain == "" {
				continue
			}
			for _, meta := range s.resources.ListDNSZones() {
				if !strings.EqualFold(meta.Domain, site.Domain) {
					continue
				}
				hostRows := []hostadapter.DNSRecord{}
				for _, x := range meta.Records {
					hostRows = append(hostRows, hostadapter.DNSRecord{Type: x.Type, Name: x.Name, Value: x.Value, TTL: x.TTL})
				}
				ns := s.nameserversForDomain(site.Domain)
				if _, e := s.host.ProvisionBINDZoneWithNameservers(ctx, site.Domain, ns.Primary, ns.Secondary, hostRows); e != nil {
					return e
				}
				break
			}
		}
	case strings.HasPrefix(action, "website.repair:"):
		if !s.cfg.Mock {
			return s.repairWebsiteV7(ctx, strings.TrimPrefix(action, "website.repair:"))
		}
	case strings.HasPrefix(action, "ssl.autossl:"):
		if s.cfg.Mock {
			return nil
		}
		domain := strings.TrimPrefix(action, "ssl.autossl:")
		var site hosting.Site
		found := false
		for _, v := range s.host.DiscoverInventory(ctx).Sites {
			if strings.EqualFold(v.Domain, domain) {
				site = hosting.Site{Domain: v.Domain, Username: v.Username, DocumentRoot: v.DocumentRoot, PHPVersion: v.PHPVersion}
				found = true
				break
			}
		}
		if !found {
			return errors.New("website not found for AutoSSL repair")
		}
		res := s.autoProvisionSiteSSL(ctx, site)
		if fmt.Sprint(res["status"]) != "valid" {
			return fmt.Errorf("AutoSSL repair did not reach valid state: %v", res["detail"])
		}
	case strings.HasPrefix(action, "service.restart:"):
		svc := strings.TrimPrefix(action, "service.restart:")
		if !s.cfg.AllowedServices[svc] {
			return errors.New("service is not allow-listed")
		}
		if s.cfg.Mock {
			return nil
		}
		load, _ := s.runner.Run(ctx, "systemctl", "show", svc, "--property=LoadState", "--value")
		if strings.TrimSpace(load) == "" || strings.TrimSpace(load) == "not-found" {
			return errors.New("service is not installed")
		}
		_, err := s.runner.Run(ctx, "systemctl", "restart", svc)
		return err
	case action == "ssh-key-only" || action == "ssh-disable-root" || action == "firewall-enable" || action == "fail2ban-enable":
		if !s.cfg.Mock {
			return s.host.ApplySecurityFix(ctx, action)
		}
	default:
		return errors.New("unsupported readiness repair action")
	}
	return nil
}

func (s *Server) v7ReadinessRepair(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Action string `json:"action"`
	}
	if !decodeBody(w, r, &in, 1<<16) {
		return
	}
	if in.Action == "repair-all" {
		_, items := s.calculateReadiness(r.Context())
		seen := map[string]bool{}
		results := []map[string]any{}
		failed := 0
		for _, item := range items {
			action := strings.TrimSpace(item.RepairAction)
			if action == "" || seen[action] {
				continue
			}
			seen[action] = true
			err := s.runReadinessRepairV7(r.Context(), action)
			outcome := "success"
			detail := ""
			if err != nil {
				outcome = "failure"
				detail = err.Error()
				failed++
			}
			_ = s.audit.Write(audit.Record{Actor: actor(r), Operation: "readiness.repair", Resource: action, Outcome: outcome, RequestID: requestID(r)})
			results = append(results, map[string]any{"action": action, "status": outcome, "detail": detail})
		}
		score, refreshed := s.calculateReadiness(r.Context())
		status := "ready"
		if score < 85 {
			status = "attention"
		}
		if score < 60 {
			status = "critical"
		}
		run, _ := s.platform.RecordReadiness(score, status, refreshed)
		writeJSON(w, 200, map[string]any{"ok": failed == 0, "failed": failed, "results": results, "readiness": run})
		return
	}
	err := s.runReadinessRepairV7(r.Context(), in.Action)
	resultAudit(s, r, "readiness.repair", in.Action, err)
	if err != nil {
		writeJSON(w, 409, map[string]any{"error": err.Error()})
		return
	}
	score, items := s.calculateReadiness(r.Context())
	status := "ready"
	if score < 85 {
		status = "attention"
	}
	if score < 60 {
		status = "critical"
	}
	run, _ := s.platform.RecordReadiness(score, status, items)
	writeJSON(w, 200, map[string]any{"ok": true, "action": in.Action, "readiness": run})
}
