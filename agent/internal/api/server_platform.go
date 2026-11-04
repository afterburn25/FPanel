package api

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"privora.local/panel/agent/internal/audit"
	"privora.local/panel/agent/internal/hostadapter"
	"privora.local/panel/agent/internal/hosting"
	"privora.local/panel/agent/internal/hostops"
	"privora.local/panel/agent/internal/platform"
	"privora.local/panel/agent/internal/updater"
)

func decodeBody(w http.ResponseWriter, r *http.Request, v any, limit int64) bool {
	if limit <= 0 {
		limit = 1 << 20
	}
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, limit))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		writeJSON(w, 400, map[string]any{"error": "invalid JSON"})
		return false
	}
	return true
}

func resultAudit(s *Server, r *http.Request, op, resource string, err error) {
	outcome := "success"
	if err != nil {
		outcome = "failure"
	}
	s.auditMutation(r, op, resource, outcome)
}

func (s *Server) platformSummary(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, 200, map[string]any{"summary": s.platform.Summary(), "horizons": s.platform.ListHorizons(), "mock": s.platform.IsMock()})
}

func (s *Server) cronJobs(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, 200, map[string]any{"cron_jobs": s.platform.ListCronJobs()})
}
func (s *Server) createCronJob(w http.ResponseWriter, r *http.Request) {
	var in platform.CronJob
	if !decodeBody(w, r, &in, 1<<20) {
		return
	}
	v, err := s.platform.CreateCronJob(in)
	resultAudit(s, r, "cron.create", in.Owner, err)
	if err != nil {
		writeJSON(w, 400, map[string]any{"error": err.Error()})
		return
	}
	writeJSON(w, 201, map[string]any{"ok": true, "cron_job": v})
}
func (s *Server) runCronJob(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	v, err := s.platform.RunCron(id)
	resultAudit(s, r, "cron.run", id, err)
	if err != nil {
		status := 400
		if strings.Contains(err.Error(), "not enabled") {
			status = 501
		}
		writeJSON(w, status, map[string]any{"error": err.Error()})
		return
	}
	writeJSON(w, 200, map[string]any{"ok": true, "cron_job": v, "simulation": s.cfg.Mock})
}

func (s *Server) appCatalog(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, 200, map[string]any{"catalog": platform.AppCatalog()})
}
func (s *Server) appInstalls(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, 200, map[string]any{"app_installs": s.platform.ListAppInstalls()})
}
func (s *Server) createAppInstall(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Template      string `json:"template"`
		Version       string `json:"version,omitempty"`
		Domain        string `json:"domain"`
		Owner         string `json:"owner"`
		Path          string `json:"path"`
		Database      string `json:"database,omitempty"`
		Runtime       string `json:"runtime,omitempty"`
		AdminUser     string `json:"admin_user,omitempty"`
		AdminPassword string `json:"admin_password,omitempty"`
		AdminEmail    string `json:"admin_email,omitempty"`
		SiteTitle     string `json:"site_title,omitempty"`
	}
	if !decodeBody(w, r, &in, 1<<20) {
		return
	}
	plan, err := s.platform.CreateAppInstall(platform.AppInstall{Template: in.Template, Domain: in.Domain, Owner: in.Owner, Path: in.Path, Database: in.Database, Runtime: in.Runtime})
	if err != nil {
		resultAudit(s, r, "application.install.plan", in.Owner+":"+in.Domain+":"+in.Template, err)
		writeJSON(w, 400, map[string]any{"error": err.Error()})
		return
	}
	if s.cfg.Mock {
		resultAudit(s, r, "application.install.plan", in.Owner+":"+in.Domain+":"+in.Template, nil)
		writeJSON(w, 201, map[string]any{"ok": true, "app_install": plan, "host_mutation": false, "adapter_gated": true})
		return
	}
	site, ok := s.hosting.GetSite(in.Domain)
	if !ok || site.Username != in.Owner {
		_, _ = s.platform.UpdateAppInstall(plan.ID, "failed-ownership-check", "", "", "", "", "")
		err = fmt.Errorf("site is not owned by hosting account")
		resultAudit(s, r, "application.install.execute", in.Owner+":"+in.Domain+":"+in.Template, err)
		writeJSON(w, 403, map[string]any{"error": err.Error()})
		return
	}
	res, err := s.host.InstallCuratedApp(r.Context(), hostadapter.AppExecutionRequest{InstallID: plan.ID, Template: in.Template, Version: in.Version, Domain: in.Domain, Owner: in.Owner, RelativePath: in.Path, DocumentRoot: site.DocumentRoot, DatabaseEngine: plan.Database, AdminUser: in.AdminUser, AdminPassword: in.AdminPassword, AdminEmail: in.AdminEmail, SiteTitle: in.SiteTitle})
	if err != nil {
		_, _ = s.platform.UpdateAppInstall(plan.ID, "failed-rolled-back", "", "", "", "", "")
		resultAudit(s, r, "application.install.execute", in.Owner+":"+in.Domain+":"+in.Template, err)
		writeJSON(w, 502, map[string]any{"error": err.Error(), "app_install": plan})
		return
	}
	v, recErr := s.platform.UpdateAppInstall(plan.ID, res.Status, res.Version, res.Target, res.Database, res.DatabaseUser, res.BootstrapMode)
	if recErr != nil {
		resultAudit(s, r, "application.install.record", plan.ID, recErr)
		writeJSON(w, 500, map[string]any{"error": recErr.Error()})
		return
	}
	resultAudit(s, r, "application.install.execute", in.Owner+":"+in.Domain+":"+in.Template, nil)
	credentials := map[string]string{}
	if res.DatabaseUser != "" {
		credentials["database_name"] = res.Database
		credentials["database_user"] = res.DatabaseUser
		credentials["database_password"] = res.DatabasePassword
	}
	if res.AdminUser != "" {
		credentials["admin_user"] = res.AdminUser
	}
	if res.AdminPassword != "" {
		credentials["admin_password"] = res.AdminPassword
	}
	writeJSON(w, 201, map[string]any{"ok": true, "app_install": v, "host_mutation": true, "adapter_gated": false, "credentials": credentials, "credentials_returned_once": len(credentials) > 0})
}
func (s *Server) deployments(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, 200, map[string]any{"deployments": s.platform.ListDeployments()})
}
func (s *Server) createDeployment(w http.ResponseWriter, r *http.Request) {
	var in platform.Deployment
	if !decodeBody(w, r, &in, 1<<20) {
		return
	}
	v, err := s.platform.CreateDeployment(in)
	resultAudit(s, r, "deployment.create", in.Domain, err)
	if err != nil {
		writeJSON(w, 400, map[string]any{"error": err.Error()})
		return
	}
	writeJSON(w, 201, map[string]any{"ok": true, "deployment": v, "simulation": true})
}

func (s *Server) mailDomains(w http.ResponseWriter, r *http.Request) {
	domains := s.platform.ListMailDomains()
	if !s.cfg.Mock {
		for i := range domains {
			ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
			live, err := s.host.InspectMailDomainReadiness(ctx, domains[i].Domain)
			cancel()
			if err == nil {
				domains[i].MailHost = live.MailHost
				domains[i].TLSReady = live.TLSReady
				domains[i].DNSReady = live.DNSReady
				domains[i].DKIM = live.DKIM
				domains[i].SPF = live.SPF
				domains[i].Status = live.Status
				domains[i].Detail = "Live readiness checked " + live.CheckedAt
			}
		}
	}
	writeJSON(w, 200, map[string]any{"mail_domains": domains})
}
func (s *Server) mailDomainConfiguration(w http.ResponseWriter, r *http.Request) {
	domain := strings.TrimSuffix(strings.ToLower(strings.TrimSpace(r.PathValue("domain"))), ".")
	if s.cfg.Mock {
		cfg := hostadapter.MailClientConfiguration{Domain: domain, MailHost: "mail." + domain, UsernameFormat: "Full email address (user@" + domain + ")", PasswordFormat: "Mailbox password", Configured: true, TLSReady: true, PostfixActive: true, DovecotActive: true, RspamdActive: true, DKIMSelector: "mail", DKIMRecordName: "mail._domainkey." + domain, CheckedAt: time.Now().UTC().Format(time.RFC3339), Services: []hostadapter.MailClientService{{ID: "imap", Protocol: "IMAP", Direction: "incoming", Server: "mail." + domain, Port: 993, Security: "SSL/TLS", Authentication: "Password", AuthenticationRequired: true, UsernameFormat: "Full email address", Enabled: true, Listening: true}, {ID: "pop3", Protocol: "POP3", Direction: "incoming", Server: "mail." + domain, Port: 995, Security: "SSL/TLS", Authentication: "Password", AuthenticationRequired: true, UsernameFormat: "Full email address", Enabled: true, Listening: true}, {ID: "smtp-465", Protocol: "SMTP", Direction: "outgoing", Server: "mail." + domain, Port: 465, Security: "SSL/TLS", Authentication: "Password", AuthenticationRequired: true, UsernameFormat: "Full email address", Enabled: true, Listening: true}, {ID: "smtp-587", Protocol: "SMTP", Direction: "outgoing", Server: "mail." + domain, Port: 587, Security: "STARTTLS", Authentication: "Password", AuthenticationRequired: true, UsernameFormat: "Full email address", Enabled: true, Listening: true}}}
		writeJSON(w, 200, map[string]any{"configuration": cfg, "simulation": true})
		return
	}
	cfg, err := s.host.InspectMailClientConfiguration(r.Context(), domain)
	if err != nil {
		writeJSON(w, 400, map[string]any{"error": err.Error()})
		return
	}
	writeJSON(w, 200, map[string]any{"configuration": cfg, "simulation": false})
}

func (s *Server) createMailDomain(w http.ResponseWriter, r *http.Request) {
	var in platform.MailDomain
	if !decodeBody(w, r, &in, 1<<16) {
		return
	}
	if s.cfg.Mock {
		v, err := s.platform.CreateMailDomain(in)
		resultAudit(s, r, "mail.domain.create", in.Domain, err)
		if err != nil {
			writeJSON(w, 400, map[string]any{"error": err.Error()})
			return
		}
		writeJSON(w, 201, map[string]any{"ok": true, "mail_domain": v, "simulation": true})
		return
	}
	if !s.cfg.HostMutations {
		writeJSON(w, 409, map[string]any{"error": "real host mutations are disabled"})
		return
	}
	prov, err := s.host.ConfigureMailDomain(r.Context(), in.Domain, in.Owner, in.DMARC)
	resultAudit(s, r, "mail.domain.create", in.Domain, err)
	if err != nil {
		writeJSON(w, 400, map[string]any{"error": err.Error()})
		return
	}
	v, err := s.platform.RecordRealMailDomain(platform.MailDomain{Domain: prov.Domain, Owner: prov.Owner, DKIM: prov.DKIM, SPF: prov.SPF, DMARC: prov.DMARC, Webmail: true, MailHost: prov.MailHost, TLSReady: prov.TLSReady, DNSReady: prov.DNSReady, Detail: prov.Detail, Status: prov.Status})
	if err != nil {
		writeJSON(w, 500, map[string]any{"error": err.Error()})
		return
	}
	writeJSON(w, 201, map[string]any{"ok": true, "mail_domain": v, "required_dns": prov.RequiredDNS, "simulation": false})
}
func (s *Server) deleteMailDomainAuthentication(w http.ResponseWriter, r *http.Request) {
	domain := strings.TrimSuffix(strings.ToLower(strings.TrimSpace(r.PathValue("domain"))), ".")
	if s.cfg.Mock {
		err := s.platform.DeleteMailDomain(domain)
		resultAudit(s, r, "mail.domain.authentication.delete", domain, err)
		if err != nil {
			writeJSON(w, 400, map[string]any{"error": err.Error()})
			return
		}
		writeJSON(w, 200, map[string]any{"ok": true, "domain": domain, "authentication_removed": true, "simulation": true})
		return
	}
	if !s.cfg.HostMutations {
		writeJSON(w, 409, map[string]any{"error": "real host mutations are disabled"})
		return
	}
	if err := s.host.RemoveMailDomainAuthentication(r.Context(), domain); err != nil {
		resultAudit(s, r, "mail.domain.authentication.delete", domain, err)
		writeJSON(w, 400, map[string]any{"error": err.Error()})
		return
	}
	err := s.platform.DeleteMailDomain(domain)
	resultAudit(s, r, "mail.domain.authentication.delete", domain, err)
	if err != nil {
		writeJSON(w, 500, map[string]any{"error": err.Error()})
		return
	}
	writeJSON(w, 200, map[string]any{"ok": true, "domain": domain, "authentication_removed": true, "website_preserved": true, "mailboxes_preserved": true, "mx_preserved": true, "simulation": false})
}

func (s *Server) mailAliases(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, 200, map[string]any{"mail_aliases": s.platform.ListMailAliases()})
}
func (s *Server) createMailAlias(w http.ResponseWriter, r *http.Request) {
	var in platform.MailAlias
	if !decodeBody(w, r, &in, 1<<16) {
		return
	}
	if s.cfg.Mock {
		v, err := s.platform.CreateMailAlias(in)
		resultAudit(s, r, "mail.alias.create", in.Address, err)
		if err != nil {
			writeJSON(w, 400, map[string]any{"error": err.Error()})
			return
		}
		writeJSON(w, 201, map[string]any{"ok": true, "mail_alias": v, "simulation": true})
		return
	}
	if !s.cfg.HostMutations {
		writeJSON(w, 409, map[string]any{"error": "real host mutations are disabled"})
		return
	}
	err := s.host.ProvisionMailAlias(r.Context(), in.Address, in.Destination)
	resultAudit(s, r, "mail.alias.create", in.Address, err)
	if err != nil {
		writeJSON(w, 400, map[string]any{"error": err.Error()})
		return
	}
	in.Status = "active-real"
	v, err := s.platform.RecordRealMailAlias(in)
	if err != nil {
		writeJSON(w, 500, map[string]any{"error": err.Error()})
		return
	}
	writeJSON(w, 201, map[string]any{"ok": true, "mail_alias": v, "simulation": false})
}
func (s *Server) updateMailAlias(w http.ResponseWriter, r *http.Request) {
	address := strings.ToLower(strings.TrimSpace(r.PathValue("address")))
	var in struct {
		Destination string `json:"destination"`
	}
	if !decodeBody(w, r, &in, 1<<16) {
		return
	}
	in.Destination = strings.ToLower(strings.TrimSpace(in.Destination))
	if s.cfg.Mock {
		v, err := s.platform.UpdateMailAlias(address, in.Destination)
		resultAudit(s, r, "mail.alias.update", address, err)
		if err != nil {
			writeJSON(w, 400, map[string]any{"error": err.Error()})
			return
		}
		writeJSON(w, 200, map[string]any{"ok": true, "mail_alias": v, "simulation": true})
		return
	}
	if !s.cfg.HostMutations {
		writeJSON(w, 409, map[string]any{"error": "real host mutations are disabled"})
		return
	}
	err := s.host.UpdateMailAlias(r.Context(), address, in.Destination)
	resultAudit(s, r, "mail.alias.update", address, err)
	if err != nil {
		writeJSON(w, 400, map[string]any{"error": err.Error()})
		return
	}
	v, err := s.platform.UpdateMailAlias(address, in.Destination)
	if err != nil {
		writeJSON(w, 500, map[string]any{"error": err.Error()})
		return
	}
	writeJSON(w, 200, map[string]any{"ok": true, "mail_alias": v, "simulation": false})
}

func (s *Server) deleteMailAlias(w http.ResponseWriter, r *http.Request) {
	address := strings.ToLower(strings.TrimSpace(r.PathValue("address")))
	if s.cfg.Mock {
		err := s.platform.DeleteMailAlias(address)
		resultAudit(s, r, "mail.alias.delete", address, err)
		if err != nil {
			writeJSON(w, 400, map[string]any{"error": err.Error()})
			return
		}
		writeJSON(w, 200, map[string]any{"ok": true, "address": address, "simulation": true})
		return
	}
	if !s.cfg.HostMutations {
		writeJSON(w, 409, map[string]any{"error": "real host mutations are disabled"})
		return
	}
	err := s.host.DeleteMailAlias(r.Context(), address)
	resultAudit(s, r, "mail.alias.delete", address, err)
	if err != nil {
		writeJSON(w, 400, map[string]any{"error": err.Error()})
		return
	}
	if err = s.platform.DeleteMailAlias(address); err != nil {
		writeJSON(w, 500, map[string]any{"error": "forwarder was removed from Postfix but Privora metadata cleanup failed: " + err.Error()})
		return
	}
	writeJSON(w, 200, map[string]any{"ok": true, "address": address, "simulation": false})
}

func (s *Server) reputationChecks(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, 200, map[string]any{"reputation": s.platform.ListReputation()})
}
func (s *Server) checkReputation(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Target string `json:"target"`
	}
	if !decodeBody(w, r, &in, 1<<16) {
		return
	}
	v, err := s.platform.CheckReputation(in.Target)
	resultAudit(s, r, "mail.reputation.check", in.Target, err)
	if err != nil {
		writeJSON(w, 400, map[string]any{"error": err.Error()})
		return
	}
	writeJSON(w, 201, map[string]any{"ok": true, "reputation": v, "simulation": true})
}

func (s *Server) bans(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, 200, map[string]any{"bans": s.platform.ListBans()})
}
func (s *Server) createBan(w http.ResponseWriter, r *http.Request) {
	var in platform.Ban
	if !decodeBody(w, r, &in, 1<<16) {
		return
	}
	v, err := s.platform.CreateBan(in)
	resultAudit(s, r, "security.ban.create", in.Source, err)
	if err != nil {
		writeJSON(w, 400, map[string]any{"error": err.Error()})
		return
	}
	writeJSON(w, 201, map[string]any{"ok": true, "ban": v, "simulation": true})
}
func (s *Server) malwareScans(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, 200, map[string]any{"malware_scans": s.platform.ListMalwareScans()})
}
func (s *Server) startMalwareScan(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Scope  string `json:"scope"`
		Target string `json:"target"`
	}
	if !decodeBody(w, r, &in, 1<<16) {
		return
	}
	v, err := s.platform.StartMalwareScan(in.Scope, in.Target)
	resultAudit(s, r, "security.malware.scan", in.Target, err)
	if err != nil {
		writeJSON(w, 400, map[string]any{"error": err.Error()})
		return
	}
	writeJSON(w, 201, map[string]any{"ok": true, "malware_scan": v, "simulation": true})
}
func (s *Server) integrityChecks(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, 200, map[string]any{"integrity_checks": s.platform.ListIntegrityChecks()})
}
func (s *Server) runIntegrityCheck(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Scope  string `json:"scope"`
		Target string `json:"target"`
	}
	if !decodeBody(w, r, &in, 1<<16) {
		return
	}
	v, err := s.platform.RunIntegrityCheck(in.Scope, in.Target)
	resultAudit(s, r, "security.integrity.check", in.Target, err)
	if err != nil {
		writeJSON(w, 400, map[string]any{"error": err.Error()})
		return
	}
	writeJSON(w, 201, map[string]any{"ok": true, "integrity_check": v, "simulation": true})
}
func (s *Server) sshPolicy(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, 200, map[string]any{"ssh_policy": s.platform.GetSSHPolicy(), "backend": func() string {
		if s.cfg.Mock {
			return "simulation"
		}
		return "policy-only"
	}()})
}
func (s *Server) setSSHPolicy(w http.ResponseWriter, r *http.Request) {
	var in platform.SSHPolicy
	if !decodeBody(w, r, &in, 1<<16) {
		return
	}
	v, err := s.platform.SetSSHPolicy(in)
	resultAudit(s, r, "security.ssh.policy", "sshd", err)
	if err != nil {
		writeJSON(w, 400, map[string]any{"error": err.Error()})
		return
	}
	writeJSON(w, 200, map[string]any{"ok": true, "ssh_policy": v, "host_mutation": false})
}
func (s *Server) securityPosture(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, 200, s.platform.SecurityPosture())
}

func (s *Server) metrics(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, 200, map[string]any{"metrics": s.platform.ListMetrics()})
}
func (s *Server) captureMetric(w http.ResponseWriter, r *http.Request) {
	var in platform.MetricSample
	if !decodeBody(w, r, &in, 1<<16) {
		return
	}
	v, err := s.platform.CaptureMetric(in)
	resultAudit(s, r, "monitoring.metric.capture", "server", err)
	if err != nil {
		writeJSON(w, 400, map[string]any{"error": err.Error()})
		return
	}
	writeJSON(w, 201, map[string]any{"ok": true, "metric": v})
}
func (s *Server) alertRules(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, 200, map[string]any{"alert_rules": s.platform.ListAlertRules()})
}
func (s *Server) createAlertRule(w http.ResponseWriter, r *http.Request) {
	var in platform.AlertRule
	if !decodeBody(w, r, &in, 1<<16) {
		return
	}
	v, err := s.platform.CreateAlertRule(in)
	resultAudit(s, r, "monitoring.alert.create", in.Metric, err)
	if err != nil {
		writeJSON(w, 400, map[string]any{"error": err.Error()})
		return
	}
	writeJSON(w, 201, map[string]any{"ok": true, "alert_rule": v})
}
func (s *Server) incidents(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, 200, map[string]any{"incidents": s.platform.ListIncidents()})
}

func (s *Server) updatePolicy(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, 200, map[string]any{"update_policy": s.platform.GetUpdatePolicy()})
}
func (s *Server) setUpdatePolicy(w http.ResponseWriter, r *http.Request) {
	var in platform.UpdatePolicy
	if !decodeBody(w, r, &in, 1<<16) {
		return
	}
	previous := s.platform.GetUpdatePolicy()
	v, err := s.platform.SetUpdatePolicy(in)
	if err == nil && !s.cfg.Mock {
		if !s.cfg.HostMutations {
			err = fmt.Errorf("real host mutations are disabled")
		} else {
			err = s.host.WriteUpdatePolicy(v.Channel, v.SecurityAuto, v.PackageAuto, v.MajorVersionsManual, v.AutoReboot, v.RebootWindow)
		}
		if err != nil {
			_, _ = s.platform.SetUpdatePolicy(previous)
		}
	}
	resultAudit(s, r, "system.update.policy", "server", err)
	if err != nil {
		writeJSON(w, 409, map[string]any{"error": err.Error()})
		return
	}
	writeJSON(w, 200, map[string]any{"ok": true, "update_policy": v, "host_policy_synced": !s.cfg.Mock})
}

func (s *Server) updateCenter(w http.ResponseWriter, _ *http.Request) {
	policy := s.platform.GetUpdatePolicy()
	last, err := updater.LatestJournal("/var/lib/privora-panel/update-transactions")
	var latest any
	if err == nil {
		latest = last
	}
	writeJSON(w, 200, map[string]any{"version": currentVersion, "policy": policy, "security_plan": updater.BuildPlan("current-security", policy.Channel, true, true), "full_plan": updater.BuildPlan("next-signed-release", policy.Channel, false, false), "last_transaction": latest, "automatic_timer": "privora-maintenance.timer", "rollback_helper": "/usr/local/sbin/privora-update-rollback", "signed_release_required": true, "upload_update_supported": true, "upload_max_bytes": 536870912, "root_reauth_required": true, "root_reauth_available": s.cfg.Mock || s.host.RootReauthAvailable()})
}
func (s *Server) runSafeUpdate(w http.ResponseWriter, r *http.Request) {
	var in hostadapter.UpdateStart
	if !decodeBody(w, r, &in, 1<<16) {
		return
	}
	if s.cfg.Mock {
		resultAudit(s, r, "system.update.start", in.Mode, nil)
		writeJSON(w, 202, map[string]any{"ok": true, "job": map[string]any{"id": "mock-update", "status": "accepted", "mode": in.Mode, "channel": in.Channel}, "plan": updater.BuildPlan("mock-next-release", in.Channel, false, in.Mode == "security"), "simulation": true})
		return
	}
	job, err := s.host.StartSafeUpdate(r.Context(), in)
	resultAudit(s, r, "system.update.start", in.Mode, err)
	if err != nil {
		writeJSON(w, 409, map[string]any{"error": err.Error()})
		return
	}
	writeJSON(w, 202, map[string]any{"ok": true, "job": job})
}
func (s *Server) resourceLimits(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, 200, map[string]any{"resource_limits": s.platform.ListResourceLimits()})
}
func (s *Server) setResourceLimit(w http.ResponseWriter, r *http.Request) {
	var in platform.ResourceLimit
	if !decodeBody(w, r, &in, 1<<16) {
		return
	}
	enforcement := map[string]any{"cgroup": false, "disk_quota": false, "bandwidth": false}
	warnings := []string{}
	if !s.cfg.Mock {
		if !s.cfg.HostMutations {
			writeJSON(w, 403, map[string]any{"error": "real host mutations are disabled"})
			return
		}
		if _, ok := s.liveAccount(r.Context(), in.Owner); !ok {
			writeJSON(w, 404, map[string]any{"error": "hosting account not found on live host"})
			return
		}
		cg, err := s.host.ApplyCgroupV2Limits(in.Owner, in.CPUPercent, in.MemoryMB, in.PIDs, in.IOWeight)
		if err != nil {
			resultAudit(s, r, "resources.limit.set", in.Owner, err)
			writeJSON(w, 409, map[string]any{"error": "resource policy could not be enforced safely: " + err.Error(), "resource_limit": in})
			return
		}
		enforcement["cgroup"] = cg.Applied
		warnings = append(warnings, "disk quota remains policy-tracked unless filesystem quota support is certified on this host")
		warnings = append(warnings, "bandwidth quota is measured and policy-tracked; hard traffic shaping is not enabled")
	}
	v, err := s.platform.SetResourceLimit(in)
	resultAudit(s, r, "resources.limit.set", in.Owner, err)
	if err != nil {
		writeJSON(w, 400, map[string]any{"error": err.Error()})
		return
	}
	writeJSON(w, 200, map[string]any{"ok": true, "resource_limit": v, "host_adapter": !s.cfg.Mock, "enforcement": enforcement, "warnings": warnings, "enforcement_complete": s.cfg.Mock || (enforcement["cgroup"] == true)})
}
func (s *Server) processes(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, 200, map[string]any{"processes": s.platform.MockProcesses(), "simulation": true})
}
func (s *Server) storage(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, 200, map[string]any{"volumes": s.platform.MockStorage(), "simulation": true})
}
func (s *Server) network(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, 200, map[string]any{"interfaces": s.platform.MockNetwork(), "simulation": true})
}
func (s *Server) resellerBrands(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, 200, map[string]any{"brands": s.platform.ListBrands()})
}
func (s *Server) setResellerBrand(w http.ResponseWriter, r *http.Request) {
	var in platform.ResellerBrand
	if !decodeBody(w, r, &in, 1<<16) {
		return
	}
	v, err := s.platform.SetBrand(in)
	resultAudit(s, r, "reseller.brand.set", in.Reseller, err)
	if err != nil {
		writeJSON(w, 400, map[string]any{"error": err.Error()})
		return
	}
	writeJSON(w, 200, map[string]any{"ok": true, "brand": v})
}

func (s *Server) delegates(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, 200, map[string]any{"delegates": s.platform.ListDelegates()})
}
func (s *Server) createDelegate(w http.ResponseWriter, r *http.Request) {
	var in platform.Delegate
	if !decodeBody(w, r, &in, 1<<16) {
		return
	}
	v, err := s.platform.CreateDelegate(in)
	resultAudit(s, r, "delegate.create", in.Owner+":"+in.Username, err)
	if err != nil {
		writeJSON(w, 400, map[string]any{"error": err.Error()})
		return
	}
	writeJSON(w, 201, map[string]any{"ok": true, "delegate": v})
}
func (s *Server) migrations(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, 200, map[string]any{"migrations": s.platform.ListMigrations()})
}
func (s *Server) createMigration(w http.ResponseWriter, r *http.Request) {
	var in platform.Migration
	if !decodeBody(w, r, &in, 1<<20) {
		return
	}
	var v platform.Migration
	var err error
	simulation := s.cfg.Mock
	if s.cfg.Mock {
		v, err = s.platform.CreateMigration(in)
	} else if !s.cfg.HostMutations {
		err = fmt.Errorf("real host mutations are disabled")
	} else if in.SourceType != "cpanel" {
		err = fmt.Errorf("only local cPanel staging is certified in real-host mode")
	} else if filepath.Base(in.Source) != in.Source || in.Source == "." || in.Source == "" {
		err = fmt.Errorf("cPanel source must be a file name from the migration inbox")
	} else {
		inbox := s.cfg.MigrationInbox
		if inbox == "" {
			inbox = "/var/lib/privora-panel/migration-inbox"
		}
		root := s.cfg.MigrationRoot
		if root == "" {
			root = "/var/lib/privora-panel/migrations"
		}
		source := filepath.Join(inbox, in.Source)
		if st, statErr := os.Lstat(source); statErr != nil || !st.Mode().IsRegular() {
			err = fmt.Errorf("cPanel backup is missing or not a regular file")
		} else {
			destination := filepath.Join(root, in.Account+"-"+time.Now().UTC().Format("20060102T150405.000000000Z"))
			stage, stageErr := hostadapter.StageCPanelBackup(source, destination, 20<<30)
			if stageErr != nil {
				err = stageErr
			} else {
				in.Source = filepath.Base(source)
				in.Destination = stage.Destination
				steps := []string{"safe-archive-inspection", "private-staging-extract", fmt.Sprintf("entries:%d", stage.Manifest.Entries), fmt.Sprintf("bytes:%d", stage.Bytes), "awaiting-resource-mapping"}
				v, err = s.platform.RecordRealMigration(in, steps)
			}
		}
	}
	resultAudit(s, r, "migration.create", in.Account, err)
	if err != nil {
		writeJSON(w, 400, map[string]any{"error": err.Error()})
		return
	}
	writeJSON(w, 201, map[string]any{"ok": true, "migration": v, "simulation": simulation})
}
func (s *Server) clusters(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, 200, map[string]any{"clusters": s.platform.ListClusters()})
}
func (s *Server) createCluster(w http.ResponseWriter, r *http.Request) {
	var in platform.ClusterResource
	if !decodeBody(w, r, &in, 1<<16) {
		return
	}
	v, err := s.platform.CreateCluster(in)
	resultAudit(s, r, "cluster.create", in.Name, err)
	if err != nil {
		writeJSON(w, 400, map[string]any{"error": err.Error()})
		return
	}
	writeJSON(w, 201, map[string]any{"ok": true, "cluster": v, "simulation": true})
}
func (s *Server) loadBalancers(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, 200, map[string]any{"load_balancers": s.platform.ListLoadBalancers()})
}
func (s *Server) createLoadBalancer(w http.ResponseWriter, r *http.Request) {
	var in platform.LoadBalancer
	if !decodeBody(w, r, &in, 1<<16) {
		return
	}
	v, err := s.platform.CreateLoadBalancer(in)
	resultAudit(s, r, "loadbalancer.create", in.Name, err)
	if err != nil {
		writeJSON(w, 400, map[string]any{"error": err.Error()})
		return
	}
	writeJSON(w, 201, map[string]any{"ok": true, "load_balancer": v, "simulation": true})
}
func (s *Server) provisionProfiles(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, 200, map[string]any{"profiles": s.platform.ListProfiles()})
}
func (s *Server) createProvisionProfile(w http.ResponseWriter, r *http.Request) {
	var in platform.ProvisionProfile
	if !decodeBody(w, r, &in, 1<<16) {
		return
	}
	v, err := s.platform.CreateProfile(in)
	resultAudit(s, r, "provision.profile.create", in.Name, err)
	if err != nil {
		writeJSON(w, 400, map[string]any{"error": err.Error()})
		return
	}
	writeJSON(w, 201, map[string]any{"ok": true, "profile": v})
}
func (s *Server) apiKeys(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, 200, map[string]any{"api_keys": s.platform.ListAPIKeys()})
}
func (s *Server) createAPIKey(w http.ResponseWriter, r *http.Request) {
	var in platform.APIKey
	if !decodeBody(w, r, &in, 1<<16) {
		return
	}
	v, secret, err := s.platform.CreateAPIKey(in)
	resultAudit(s, r, "api_key.create", in.Name, err)
	if err != nil {
		writeJSON(w, 400, map[string]any{"error": err.Error()})
		return
	}
	writeJSON(w, 201, map[string]any{"ok": true, "api_key": v, "secret_once": secret})
}
func (s *Server) webhooks(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, 200, map[string]any{"webhooks": s.platform.ListWebhooks()})
}
func (s *Server) createWebhook(w http.ResponseWriter, r *http.Request) {
	var in platform.Webhook
	if !decodeBody(w, r, &in, 1<<16) {
		return
	}
	v, err := s.platform.CreateWebhook(in)
	resultAudit(s, r, "webhook.create", in.URL, err)
	if err != nil {
		writeJSON(w, 400, map[string]any{"error": err.Error()})
		return
	}
	writeJSON(w, 201, map[string]any{"ok": true, "webhook": v})
}

func (s *Server) plugins(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, 200, map[string]any{"plugins": s.platform.ListPlugins()})
}
func (s *Server) installPlugin(w http.ResponseWriter, r *http.Request) {
	var in platform.Plugin
	if !decodeBody(w, r, &in, 1<<16) {
		return
	}
	v, err := s.platform.InstallPlugin(in)
	resultAudit(s, r, "plugin.install", in.Name, err)
	if err != nil {
		writeJSON(w, 400, map[string]any{"error": err.Error()})
		return
	}
	writeJSON(w, 201, map[string]any{"ok": true, "plugin": v, "simulation": true})
}
func (s *Server) invoices(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, 200, map[string]any{"invoices": s.platform.ListInvoices()})
}
func (s *Server) createInvoice(w http.ResponseWriter, r *http.Request) {
	var in platform.Invoice
	if !decodeBody(w, r, &in, 1<<16) {
		return
	}
	v, err := s.platform.CreateInvoice(in)
	resultAudit(s, r, "billing.invoice.create", in.Customer, err)
	if err != nil {
		writeJSON(w, 400, map[string]any{"error": err.Error()})
		return
	}
	writeJSON(w, 201, map[string]any{"ok": true, "invoice": v, "simulation": true})
}
func (s *Server) notifications(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, 200, map[string]any{"notifications": s.platform.ListNotifications()})
}
func (s *Server) createNotification(w http.ResponseWriter, r *http.Request) {
	var in platform.Notification
	if !decodeBody(w, r, &in, 1<<16) {
		return
	}
	v, err := s.platform.CreateNotification(in)
	resultAudit(s, r, "notification.queue", in.Recipient, err)
	if err != nil {
		writeJSON(w, 400, map[string]any{"error": err.Error()})
		return
	}
	writeJSON(w, 201, map[string]any{"ok": true, "notification": v, "simulation": true})
}
func (s *Server) diagnostics(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, 200, map[string]any{"diagnostics": s.platform.ListDiagnostics()})
}
func (s *Server) runDiagnostic(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Scope string `json:"scope"`
	}
	if !decodeBody(w, r, &in, 1<<16) {
		return
	}
	v, err := s.platform.RunDiagnostic(in.Scope)
	resultAudit(s, r, "diagnostic.run", in.Scope, err)
	if err != nil {
		writeJSON(w, 400, map[string]any{"error": err.Error()})
		return
	}
	writeJSON(w, 201, map[string]any{"ok": true, "diagnostic": v})
}
func (s *Server) repairs(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, 200, map[string]any{"repairs": s.platform.ListRepairs()})
}
func (s *Server) runRepair(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Resource string `json:"resource"`
		Action   string `json:"action"`
	}
	if !decodeBody(w, r, &in, 1<<16) {
		return
	}
	v, err := s.platform.RunRepair(in.Resource, in.Action)
	resultAudit(s, r, "repair.run", in.Resource, err)
	if err != nil {
		writeJSON(w, 400, map[string]any{"error": err.Error()})
		return
	}
	writeJSON(w, 201, map[string]any{"ok": true, "repair": v, "simulation": true})
}
func (s *Server) revisions(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, 200, map[string]any{"revisions": s.platform.ListRevisions()})
}
func (s *Server) createRevision(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Resource string `json:"resource"`
		Digest   string `json:"digest"`
	}
	if !decodeBody(w, r, &in, 1<<16) {
		return
	}
	v, err := s.platform.CreateRevision(in.Resource, in.Digest)
	resultAudit(s, r, "config.revision.create", in.Resource, err)
	if err != nil {
		writeJSON(w, 400, map[string]any{"error": err.Error()})
		return
	}
	writeJSON(w, 201, map[string]any{"ok": true, "revision": v})
}
func (s *Server) secrets(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, 200, map[string]any{"secrets": s.platform.ListSecrets()})
}
func (s *Server) createSecretRef(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Name string `json:"name"`
		Type string `json:"type"`
	}
	if !decodeBody(w, r, &in, 1<<16) {
		return
	}
	v, err := s.platform.CreateSecretRef(in.Name, in.Type)
	resultAudit(s, r, "secret.reference.create", in.Name, err)
	if err != nil {
		writeJSON(w, 400, map[string]any{"error": err.Error()})
		return
	}
	writeJSON(w, 201, map[string]any{"ok": true, "secret": v})
}
func (s *Server) releases(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, 200, map[string]any{"releases": s.platform.ListReleases()})
}
func (s *Server) addRelease(w http.ResponseWriter, r *http.Request) {
	var in platform.SignedRelease
	if !decodeBody(w, r, &in, 1<<16) {
		return
	}
	v, err := s.platform.AddSignedRelease(in)
	resultAudit(s, r, "release.record", in.Version, err)
	if err != nil {
		writeJSON(w, 400, map[string]any{"error": err.Error()})
		return
	}
	writeJSON(w, 201, map[string]any{"ok": true, "release": v})
}

func (s *Server) exports(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, 200, map[string]any{"exports": s.platform.ListExports()})
}
func (s *Server) createExport(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Account   string `json:"account"`
		Encrypted bool   `json:"encrypted"`
	}
	if !decodeBody(w, r, &in, 1<<16) {
		return
	}
	v, err := s.platform.CreateExport(in.Account, in.Encrypted)
	resultAudit(s, r, "export.create", in.Account, err)
	if err != nil {
		writeJSON(w, 400, map[string]any{"error": err.Error()})
		return
	}
	writeJSON(w, 201, map[string]any{"ok": true, "export": v, "simulation": true})
}
func (s *Server) recommendations(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, 200, map[string]any{"recommendations": s.platform.ListRecommendations()})
}
func (s *Server) createRecommendation(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Resource  string `json:"resource"`
		Current   string `json:"current"`
		Suggested string `json:"suggested"`
		Impact    string `json:"impact"`
	}
	if !decodeBody(w, r, &in, 1<<16) {
		return
	}
	v, err := s.platform.CreateRecommendation(in.Resource, in.Current, in.Suggested, in.Impact)
	resultAudit(s, r, "performance.recommendation.create", in.Resource, err)
	if err != nil {
		writeJSON(w, 400, map[string]any{"error": err.Error()})
		return
	}
	writeJSON(w, 201, map[string]any{"ok": true, "recommendation": v})
}
func (s *Server) staging(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, 200, map[string]any{"staging": s.platform.ListStaging()})
}
func (s *Server) createStaging(w http.ResponseWriter, r *http.Request) {
	var in platform.StagingEnvironment
	if !decodeBody(w, r, &in, 1<<16) {
		return
	}
	v, err := s.platform.CreateStaging(in)
	resultAudit(s, r, "staging.create", in.ProductionDomain, err)
	if err != nil {
		writeJSON(w, 400, map[string]any{"error": err.Error()})
		return
	}
	writeJSON(w, 201, map[string]any{"ok": true, "staging": v, "simulation": true})
}
func (s *Server) isolationProfiles(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, 200, map[string]any{"isolation": s.platform.ListIsolation()})
}
func (s *Server) setIsolationProfile(w http.ResponseWriter, r *http.Request) {
	var in platform.IsolationProfile
	if !decodeBody(w, r, &in, 1<<16) {
		return
	}
	v, err := s.platform.SetIsolation(in)
	resultAudit(s, r, "isolation.policy.set", in.Owner, err)
	if err != nil {
		writeJSON(w, 400, map[string]any{"error": err.Error()})
		return
	}
	writeJSON(w, 200, map[string]any{"ok": true, "isolation": v, "host_adapter": false})
}
func (s *Server) accountControls(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, 200, map[string]any{"account_controls": s.platform.ListAccountControls()})
}
func (s *Server) createAccountControl(w http.ResponseWriter, r *http.Request) {
	var in platform.AccountControl
	if !decodeBody(w, r, &in, 16<<10) {
		return
	}
	v, err := s.platform.CreateAccountControl(in)
	resultAudit(s, r, "account.control.create", in.Owner+":"+in.Kind, err)
	if err != nil {
		writeJSON(w, 400, map[string]any{"error": err.Error()})
		return
	}
	writeJSON(w, 201, map[string]any{"ok": true, "account_control": v, "host_mutation": false})
}

func (s *Server) certification(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, 200, map[string]any{"certification": s.platform.ListCertification()})
}
func (s *Server) recordCertification(w http.ResponseWriter, r *http.Request) {
	var in platform.CertificationGate
	if !decodeBody(w, r, &in, 1<<20) {
		return
	}
	v, err := s.platform.RecordCertification(in)
	resultAudit(s, r, "certification.record", in.Name, err)
	if err != nil {
		writeJSON(w, 400, map[string]any{"error": err.Error()})
		return
	}
	writeJSON(w, 201, map[string]any{"ok": true, "certification": v})
}
func (s *Server) horizons(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, 200, map[string]any{"horizons": s.platform.ListHorizons(), "version": "5.0.0-dev.6", "generated_at": time.Now().UTC()})
}

func (s *Server) auditVerify(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, 200, audit.Verify(s.cfg.AuditPath))
}

func (s *Server) verifyAPIKey(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Token string `json:"token"`
		IP    string `json:"ip"`
	}
	if !decodeBody(w, r, &in, 1<<16) {
		return
	}
	key, ok := s.platform.VerifyAPIKeyForIP(in.Token, in.IP)
	if !ok {
		writeJSON(w, 401, map[string]any{"valid": false, "error": "invalid API key"})
		return
	}
	writeJSON(w, 200, map[string]any{"ok": true, "valid": true, "api_key": key})
}

func (s *Server) controlSuite(w http.ResponseWriter, _ *http.Request) {
	caps := s.host.Probe()
	byName := map[string]hostadapter.Capability{}
	for _, c := range caps {
		byName[c.Name] = c
	}
	status := func(names ...string) string {
		if len(names) == 0 {
			return "core"
		}
		available, certified := true, true
		for _, name := range names {
			c, ok := byName[name]
			if !ok || !c.Available {
				available = false
			}
			if !ok || !c.Certified {
				certified = false
			}
		}
		if available && certified && s.cfg.HostMutations && !s.cfg.Mock {
			return "live"
		}
		if available {
			return "adapter-gated"
		}
		return "dependency-missing"
	}
	modules := []map[string]any{
		{"id": "accounts", "name": "Account lifecycle, Packages, Feature Manager & Resellers", "status": "core", "detail": "account create/suspend/unsuspend/delete, package/feature policy and reseller records"},
		{"id": "services", "name": "Service Manager & safe configuration editor", "status": "live", "detail": "installed-service discovery plus allow-listed actions and validated config rollback"},
		{"id": "php", "name": "MultiPHP / PHP-FPM manager", "status": status("php-fpm"), "detail": "installed runtime inventory, FPM status, extensions and per-site switching"},
		{"id": "database", "name": "MySQL / MariaDB / phpMyAdmin", "status": status("mariadb"), "detail": "database adapter plus phpMyAdmin capability detection"},
		{"id": "mail", "name": "Mail server suite", "status": status("postfix", "dovecot"), "detail": "domains, mailboxes, aliases, DKIM/SPF/DMARC policy and Rspamd capability"},
		{"id": "ssl", "name": "SSL / AutoSSL manager", "status": status("acme"), "detail": "Let's Encrypt issuance and renewal-state inventory"},
		{"id": "backup", "name": "Backup & Restore Center", "status": status("backup-zstd", "backup-rsync"), "detail": "verified local account/site backup foundation; SHA-256 verified site restore is live, account/server restore remains gated"},
		{"id": "security", "name": "Security Center", "status": status("nftables"), "detail": "firewall, SSH policy, bans, malware/integrity contracts plus Fail2Ban/ModSecurity/ClamAV detection"},
		{"id": "system", "name": "Server / network / IP administration", "status": "live", "detail": "process, storage and interface inventory; dangerous address/routing mutation remains gated"},
		{"id": "migration", "name": "Migration / Transfer Tool", "status": status("migration-rsync", "migration-ssh"), "detail": "cPanel/generic transfer contracts with source adapter certification required for live copy"},
		{"id": "monitoring", "name": "Monitoring, logs & notifications", "status": "core", "detail": "metrics, alerts, incidents, service logs and notification records"},
		{"id": "developer", "name": "API, hooks & plugin framework", "status": "core", "detail": "scoped API keys, webhooks, plugin registry and audit boundary"},
		{"id": "dnscluster", "name": "DNS clustering & multi-server", "status": status("dns-cluster"), "detail": "cluster contracts and node roles; remote authenticated replication is certification-gated"},
	}
	writeJSON(w, 200, map[string]any{"modules": modules, "capabilities": caps, "host_mutations_enabled": s.cfg.HostMutations && !s.cfg.Mock})
}

func (s *Server) hostPlan(w http.ResponseWriter, r *http.Request) {
	var in hostops.Request
	if !decodeBody(w, r, &in, 1<<16) {
		return
	}
	plan, err := hostops.Build(in)
	resultAudit(s, r, "host.plan", in.Kind, err)
	if err != nil {
		writeJSON(w, 400, map[string]any{"error": err.Error()})
		return
	}
	writeJSON(w, 200, map[string]any{"ok": true, "plan": plan, "host_mutation": false})
}

func (s *Server) hostCapabilities(w http.ResponseWriter, _ *http.Request) {
	caps := s.host.Probe()
	engines := []map[string]any{}
	capRows := make([]map[string]any, 0, len(caps))
	for _, c := range caps {
		row := map[string]any{"name": c.Name, "available": c.Available, "certified": c.Certified, "dependency": c.Dependency, "detail": c.Detail}
		if c.Name == "mysql" || c.Name == "mariadb" || c.Name == "postgresql" {
			engines = append(engines, map[string]any{"engine": c.Name, "available": c.Available, "certified": c.Certified, "detail": c.Detail})
		}
		if c.Name == "phpmyadmin" {
			if c.Available && c.Certified {
				row["launch_url"] = "/phpmyadmin/"
			} else {
				row["launch_url"] = ""
			}
		}
		if c.Name == "webmail" {
			client := ""
			for _, name := range []string{"Roundcube", "SnappyMail", "RainLoop"} {
				if strings.Contains(c.Detail, name) {
					client = name
					break
				}
			}
			row["client"] = client
			if i := strings.Index(c.Detail, "launch="); i >= 0 {
				row["launch_url"] = strings.TrimSpace(c.Detail[i+7:])
			} else {
				row["launch_url"] = ""
			}
		}
		capRows = append(capRows, row)
	}
	writeJSON(w, 200, map[string]any{"host_mutations_enabled": s.cfg.HostMutations && !s.cfg.Mock, "capabilities": capRows, "database_engines": engines})
}
func (s *Server) hostInventory(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, 200, map[string]any{"inventory": s.host.DiscoverInventory(r.Context()), "source": "live-host"})
}

func (s *Server) hostReconcile(w http.ResponseWriter, r *http.Request) {
	inv := s.host.DiscoverInventory(r.Context())
	primary := map[string]string{}
	for _, site := range inv.Sites {
		if site.Username != "" && primary[site.Username] == "" {
			primary[site.Username] = site.Domain
		}
	}
	accountsImported, sitesImported := 0, 0
	errorsFound := []string{}
	for _, live := range inv.Accounts {
		if _, err := s.hosting.AdoptDiscoveredAccount(hosting.Account{Username: live.Username, PrimaryDomain: primary[live.Username], Package: "Detected", Status: live.Status}); err != nil {
			errorsFound = append(errorsFound, "account "+live.Username+": "+err.Error())
			continue
		}
		accountsImported++
	}
	for _, live := range inv.Sites {
		if live.Username == "" {
			continue
		}
		status := "disabled"
		if live.Enabled {
			status = "active"
		}
		if _, err := s.hosting.AdoptDiscoveredSite(hosting.Site{Domain: live.Domain, Username: live.Username, DocumentRoot: live.DocumentRoot, PHPVersion: live.PHPVersion, SSL: live.SSL, Status: status}); err != nil {
			errorsFound = append(errorsFound, "site "+live.Domain+": "+err.Error())
			continue
		}
		sitesImported++
	}
	s.auditMutation(r, "host.reconcile", "live-host-inventory", "success")
	writeJSON(w, 200, map[string]any{"ok": true, "source": "live-host", "accounts_imported": accountsImported, "sites_imported": sitesImported, "reconcile_notices": errorsFound, "inventory": inv})
}

func (s *Server) prepareUploadedUpdate(w http.ResponseWriter, r *http.Request) {
	var in hostadapter.UploadPrepare
	if !decodeBody(w, r, &in, 1<<16) {
		return
	}
	if s.cfg.Mock {
		v := hostadapter.UploadInspection{OK: true, UploadID: "20260820T000000Z-deadbeefdeadbeef", OriginalName: in.OriginalName, Version: "5.0.0-dev.7.0", Channel: "developer", CreatedAt: time.Now().UTC().Format(time.RFC3339), PayloadSHA256: strings.Repeat("a", 64), ZipSHA256: strings.Repeat("b", 64), SizeBytes: 12345, PayloadBytes: 12000}
		resultAudit(s, r, "system.update.upload.prepare", v.Version, nil)
		writeJSON(w, 201, map[string]any{"ok": true, "upload": v, "root_reauth_required": true})
		return
	}
	v, err := s.host.PrepareUploadedUpdate(r.Context(), in)
	resultAudit(s, r, "system.update.upload.prepare", v.Version, err)
	if err != nil {
		writeJSON(w, 409, map[string]any{"error": err.Error()})
		return
	}
	writeJSON(w, 201, map[string]any{"ok": true, "upload": v, "root_reauth_required": true})
}

func (s *Server) startUploadedUpdate(w http.ResponseWriter, r *http.Request) {
	var in hostadapter.UploadInstallStart
	if !decodeBody(w, r, &in, 1<<16) {
		return
	}
	in.Actor = actor(r)
	if s.cfg.Mock {
		if in.RootPassword == "" {
			resultAudit(s, r, "system.update.upload.start", in.UploadID, fmt.Errorf("root authentication failed"))
			writeJSON(w, 403, map[string]any{"error": "root authentication failed"})
			return
		}
		resultAudit(s, r, "system.update.upload.start", in.UploadID, nil)
		writeJSON(w, 202, map[string]any{"ok": true, "job": map[string]any{"id": in.UploadID, "status": "accepted", "mode": "uploaded"}, "root_reauthorized": true})
		return
	}
	job, err := s.host.StartUploadedUpdate(r.Context(), in)
	// Never include, format, or audit the root credential itself.
	in.RootPassword = ""
	resultAudit(s, r, "system.update.upload.start", in.UploadID, err)
	if err != nil {
		status := 409
		if strings.Contains(err.Error(), "root authentication failed") {
			status = 403
		}
		writeJSON(w, status, map[string]any{"error": err.Error()})
		return
	}
	writeJSON(w, 202, map[string]any{"ok": true, "job": job, "root_reauthorized": true})
}

func (s *Server) updateTransaction(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if s.cfg.Mock {
		writeJSON(w, 200, map[string]any{"transaction": updater.Journal{ID: id, OldVersion: "5.0.0-dev.6.14", NewVersion: "5.0.0-dev.7.0", Phase: "health", Status: "running", UpdatedAt: time.Now().UTC()}})
		return
	}
	j, err := updater.TransactionJournal("/var/lib/privora-panel/update-transactions", id)
	if err != nil {
		if os.IsNotExist(err) {
			writeJSON(w, 404, map[string]any{"error": "update transaction not found"})
			return
		}
		writeJSON(w, 400, map[string]any{"error": err.Error()})
		return
	}
	writeJSON(w, 200, map[string]any{"transaction": j})
}
