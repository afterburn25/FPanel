package api

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"privora.local/panel/agent/internal/audit"
	"privora.local/panel/agent/internal/billingledger"
	"privora.local/panel/agent/internal/config"
	"privora.local/panel/agent/internal/hostadapter"
	"privora.local/panel/agent/internal/hosting"
	"privora.local/panel/agent/internal/platform"
	"privora.local/panel/agent/internal/resources"
	"privora.local/panel/agent/internal/runner"
	systeminfo "privora.local/panel/agent/internal/system"
)

type Server struct {
	cfg          config.Config
	runner       runner.Runner
	audit        *audit.Logger
	hosting      *hosting.Manager
	resources    *resources.Manager
	platform     *platform.Manager
	host         *hostadapter.Adapter
	ledger       *billingledger.Ledger
	ledgerErr    error
	nonceMu      sync.Mutex
	nonces       map[string]time.Time
	softwareJobs *softwareJobManager
}

func New(cfg config.Config, r runner.Runner, a *audit.Logger) *Server {
	ledger, ledgerErr := billingledger.Open(cfg.StatePath + ".ledger.jsonl")
	return &Server{cfg: cfg, runner: r, audit: a, hosting: hosting.New(cfg.StatePath, cfg.MockRoot, cfg.Mock), resources: resources.New(cfg.StatePath+".resources", cfg.Mock), platform: platform.New(cfg.StatePath+".platform", cfg.Mock), host: hostadapter.New(hostadapter.Config{AllowMutations: cfg.HostMutations && !cfg.Mock, CertificationPath: cfg.HostCertificationPath, RegistrarProvider: cfg.RegistrarProvider, RegistrarAdapterURL: cfg.RegistrarAdapterURL, RegistrarToken: cfg.RegistrarToken}), ledger: ledger, ledgerErr: ledgerErr, nonces: map[string]time.Time{}, softwareJobs: newSoftwareJobManager()}
}
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /v1/health", s.health)
	mux.HandleFunc("GET /v1/system", s.system)
	mux.HandleFunc("GET /v1/services", s.services)
	mux.HandleFunc("GET /v1/services/{service}/logs", s.serviceLogs)
	mux.HandleFunc("POST /v1/services/{service}/{action}", s.serviceAction)
	mux.HandleFunc("GET /v1/packages/updates", s.packageUpdates)
	mux.HandleFunc("GET /v1/components", s.serverComponents)
	mux.HandleFunc("GET /v1/software/jobs", s.softwareJobsList)
	mux.HandleFunc("POST /v1/software/jobs", s.startSoftwareJob)
	mux.HandleFunc("GET /v1/software/jobs/{id}", s.softwareJobStatus)
	mux.HandleFunc("GET /v1/components/presets", s.componentPresets)
	mux.HandleFunc("POST /v1/components/presets/{id}/apply", s.applyComponentPreset)
	mux.HandleFunc("POST /v1/components/{id}/install", s.installServerComponent)
	mux.HandleFunc("DELETE /v1/components/{id}", s.removeServerComponent)
	mux.HandleFunc("GET /v1/hosting/accounts", s.accounts)
	mux.HandleFunc("POST /v1/hosting/accounts", s.createAccount)
	mux.HandleFunc("POST /v1/hosting/accounts/bulk", s.bulkAccountAction)
	mux.HandleFunc("GET /v1/hosting/accounts/{user}", s.accountDetail)
	mux.HandleFunc("PATCH /v1/hosting/accounts/{user}", s.updateAccount)
	mux.HandleFunc("POST /v1/hosting/accounts/{user}/password", s.accountPassword)
	mux.HandleFunc("GET /v1/hosting/accounts/{user}/termination-plan", s.accountTerminationPlan)
	mux.HandleFunc("DELETE /v1/hosting/accounts/{user}", s.deleteAccount)
	mux.HandleFunc("POST /v1/hosting/accounts/{user}/package", s.accountPackage)
	mux.HandleFunc("POST /v1/hosting/accounts/{user}/{action}", s.accountAction)
	mux.HandleFunc("GET /v1/sites", s.sites)
	mux.HandleFunc("POST /v1/sites/{domain}/repair", s.repairSiteConfiguration)
	mux.HandleFunc("POST /v1/sites", s.createSite)
	mux.HandleFunc("POST /v1/subdomains", s.createSubdomain)
	mux.HandleFunc("DELETE /v1/sites/{domain}", s.deleteSite)
	mux.HandleFunc("POST /v1/sites/{domain}/php", s.setSitePHP)
	mux.HandleFunc("GET /v1/php/runtimes", s.phpRuntimes)
	mux.HandleFunc("GET /v1/php/versions", s.phpVersions)
	mux.HandleFunc("POST /v1/php/versions/{version}/install", s.installPHPVersion)
	mux.HandleFunc("DELETE /v1/php/versions/{version}", s.removePHPVersion)
	mux.HandleFunc("GET /v1/php/extensions", s.phpExtensions)
	mux.HandleFunc("GET /v1/files/{user}", s.files)
	mux.HandleFunc("POST /v1/files/{user}/write", s.writeFile)
	mux.HandleFunc("GET /v1/files/{user}/read", s.readFile)
	mux.HandleFunc("POST /v1/files/{user}/mkdir", s.mkdirFile)
	mux.HandleFunc("POST /v1/files/{user}/upload", s.uploadFile)
	mux.HandleFunc("POST /v1/files/{user}/rename", s.renameFile)
	mux.HandleFunc("POST /v1/files/{user}/copy", s.copyFile)
	mux.HandleFunc("DELETE /v1/files/{user}/path", s.deleteFile)
	mux.HandleFunc("POST /v1/files/{user}/chmod", s.chmodFile)
	mux.HandleFunc("GET /v1/files/{user}/search", s.searchFiles)
	mux.HandleFunc("POST /v1/files/{user}/archive", s.archiveFile)
	mux.HandleFunc("POST /v1/files/{user}/extract", s.extractFile)
	mux.HandleFunc("GET /v1/hosting/accounts/{user}/usage", s.accountUsage)
	mux.HandleFunc("GET /v1/resources/summary", s.resourceSummary)
	mux.HandleFunc("GET /v1/sftp", s.sftpAccounts)
	mux.HandleFunc("POST /v1/sftp", s.createSFTPAccount)
	mux.HandleFunc("GET /v1/firewall/rules", s.firewallRules)
	mux.HandleFunc("POST /v1/firewall/rules", s.createFirewallRule)
	mux.HandleFunc("GET /v1/applications", s.applications)
	mux.HandleFunc("POST /v1/applications", s.createApplication)
	mux.HandleFunc("GET /v1/databases", s.databases)
	mux.HandleFunc("POST /v1/databases", s.createDatabase)
	mux.HandleFunc("DELETE /v1/databases/{name}", s.deleteDatabase)
	mux.HandleFunc("POST /v1/databases/{name}/password", s.rotateDatabasePassword)
	mux.HandleFunc("POST /v1/databases/{name}/user", s.renameDatabaseUser)
	mux.HandleFunc("GET /v1/databases/{name}/inspect", s.inspectDatabase)
	mux.HandleFunc("POST /v1/databases/{name}/maintenance", s.maintainDatabase)
	mux.HandleFunc("POST /v1/databases/{name}/export", s.exportDatabase)
	mux.HandleFunc("POST /v1/databases/{name}/import", s.importDatabase)
	mux.HandleFunc("GET /v1/dns/zones", s.dnsZones)
	mux.HandleFunc("POST /v1/dns/zones", s.createDNSZone)
	mux.HandleFunc("POST /v1/dns/repair-hosted", s.repairHostedDNS)
	mux.HandleFunc("GET /v1/dns/zones/{domain}", s.dnsZone)
	mux.HandleFunc("DELETE /v1/dns/zones/{domain}", s.deleteDNSZone)
	mux.HandleFunc("POST /v1/dns/zones/{domain}/records", s.upsertDNSRecord)
	mux.HandleFunc("POST /v1/dns/zones/{domain}/records/replace", s.replaceDNSRecord)
	mux.HandleFunc("DELETE /v1/dns/zones/{domain}/records", s.deleteDNSRecord)
	mux.HandleFunc("GET /v1/dns/nameservers", s.nameservers)
	mux.HandleFunc("POST /v1/dns/nameservers", s.setNameservers)
	mux.HandleFunc("POST /v1/dns/nameserver-assignment", s.setNameserverAssignment)
	mux.HandleFunc("DELETE /v1/dns/nameservers", s.deleteNameservers)
	mux.HandleFunc("POST /v1/dns/registrar", s.configureRegistrar)
	mux.HandleFunc("GET /v1/config-files", s.configFiles)
	mux.HandleFunc("GET /v1/config-files/{id}", s.configFile)
	mux.HandleFunc("POST /v1/config-files/{id}", s.writeConfigFile)
	mux.HandleFunc("GET /v1/ssl", s.certificates)
	mux.HandleFunc("POST /v1/ssl/issue", s.issueCertificate)
	mux.HandleFunc("POST /v1/ssl/autossl", s.runAutoSSL)
	mux.HandleFunc("GET /v1/ssl/{domain}/inspect", s.inspectCertificate)
	mux.HandleFunc("POST /v1/ssl/{domain}/csr", s.generateCertificateCSR)
	mux.HandleFunc("POST /v1/ssl/{domain}/custom", s.installCustomCertificate)
	mux.HandleFunc("POST /v1/ssl/{domain}/revoke", s.revokeCertificate)
	mux.HandleFunc("GET /v1/backups", s.backups)
	mux.HandleFunc("POST /v1/backups", s.createBackup)
	mux.HandleFunc("POST /v1/backups/{id}/restore", s.restoreBackup)
	mux.HandleFunc("GET /v1/mailboxes", s.mailboxes)
	mux.HandleFunc("POST /v1/mailboxes", s.createMailbox)
	mux.HandleFunc("PATCH /v1/mailboxes/{address}", s.updateMailbox)
	mux.HandleFunc("DELETE /v1/mailboxes/{address}", s.deleteMailbox)
	mux.HandleFunc("GET /v1/resellers", s.resellers)
	mux.HandleFunc("POST /v1/resellers", s.createReseller)
	mux.HandleFunc("PATCH /v1/resellers/{name}", s.updateReseller)
	mux.HandleFunc("DELETE /v1/resellers/{name}", s.deleteReseller)
	mux.HandleFunc("GET /v1/fleet/nodes", s.nodes)
	mux.HandleFunc("POST /v1/fleet/nodes", s.createNode)
	mux.HandleFunc("GET /v1/cloud/instances", s.instances)
	mux.HandleFunc("POST /v1/cloud/instances", s.createInstance)
	mux.HandleFunc("GET /v1/fabric/workloads", s.workloads)
	mux.HandleFunc("POST /v1/fabric/workloads", s.createWorkload)
	mux.HandleFunc("GET /v1/automation/runs", s.automations)
	mux.HandleFunc("POST /v1/automation/provision", s.automationProvision)
	// 0.19-0.39: tasks, app deployment, mail/security/monitoring.
	mux.HandleFunc("GET /v1/platform/summary", s.platformSummary)
	mux.HandleFunc("GET /v1/control-suite", s.controlSuite)
	mux.HandleFunc("GET /v1/tasks/cron", s.cronJobs)
	mux.HandleFunc("POST /v1/tasks/cron", s.createCronJob)
	mux.HandleFunc("POST /v1/tasks/cron/{id}/run", s.runCronJob)
	mux.HandleFunc("GET /v1/apps/catalog", s.appCatalog)
	mux.HandleFunc("GET /v1/apps/installer/installs", s.appInstalls)
	mux.HandleFunc("POST /v1/apps/installer/install", s.createAppInstall)
	mux.HandleFunc("GET /v1/deployments", s.deployments)
	mux.HandleFunc("POST /v1/deployments", s.createDeployment)
	mux.HandleFunc("GET /v1/mail/domains", s.mailDomains)
	mux.HandleFunc("POST /v1/mail/domains", s.createMailDomain)
	mux.HandleFunc("GET /v1/mail/domains/{domain}/configuration", s.mailDomainConfiguration)
	mux.HandleFunc("DELETE /v1/mail/domains/{domain}/authentication", s.deleteMailDomainAuthentication)
	mux.HandleFunc("GET /v1/mail/aliases", s.mailAliases)
	mux.HandleFunc("POST /v1/mail/aliases", s.createMailAlias)
	mux.HandleFunc("PATCH /v1/mail/aliases/{address}", s.updateMailAlias)
	mux.HandleFunc("DELETE /v1/mail/aliases/{address}", s.deleteMailAlias)
	mux.HandleFunc("GET /v1/mail/reputation", s.reputationChecks)
	mux.HandleFunc("POST /v1/mail/reputation/check", s.checkReputation)
	mux.HandleFunc("GET /v1/security/bans", s.bans)
	mux.HandleFunc("POST /v1/security/bans", s.createBan)
	mux.HandleFunc("GET /v1/security/malware", s.malwareScans)
	mux.HandleFunc("POST /v1/security/malware", s.startMalwareScan)
	mux.HandleFunc("GET /v1/security/integrity", s.integrityChecks)
	mux.HandleFunc("POST /v1/security/integrity", s.runIntegrityCheck)
	mux.HandleFunc("GET /v1/security/ssh", s.sshPolicy)
	mux.HandleFunc("POST /v1/security/ssh", s.setSSHPolicy)
	mux.HandleFunc("GET /v1/security/posture", s.securityPosture)
	mux.HandleFunc("GET /v1/audit/verify", s.auditVerify)
	mux.HandleFunc("GET /v1/monitoring/metrics", s.metrics)
	mux.HandleFunc("POST /v1/monitoring/metrics", s.captureMetric)
	mux.HandleFunc("GET /v1/monitoring/alerts", s.alertRules)
	mux.HandleFunc("POST /v1/monitoring/alerts", s.createAlertRule)
	mux.HandleFunc("GET /v1/monitoring/incidents", s.incidents)
	// 0.40-0.49: update policy, resource controls and host inventory.
	mux.HandleFunc("GET /v1/system/update-policy", s.updatePolicy)
	mux.HandleFunc("POST /v1/system/update-policy", s.setUpdatePolicy)
	mux.HandleFunc("GET /v1/system/update-center", s.updateCenter)
	mux.HandleFunc("POST /v1/system/update-run", s.runSafeUpdate)
	mux.HandleFunc("POST /v1/system/update-upload/prepare", s.prepareUploadedUpdate)
	mux.HandleFunc("POST /v1/system/update-upload/start", s.startUploadedUpdate)
	mux.HandleFunc("GET /v1/system/update-transactions/{id}", s.updateTransaction)
	mux.HandleFunc("GET /v1/resources/limits", s.resourceLimits)
	mux.HandleFunc("POST /v1/resources/limits", s.setResourceLimit)
	mux.HandleFunc("GET /v1/system/processes", s.processes)
	mux.HandleFunc("GET /v1/system/storage", s.storage)
	mux.HandleFunc("GET /v1/system/network", s.network)
	mux.HandleFunc("GET /v1/reseller/brands", s.resellerBrands)
	mux.HandleFunc("POST /v1/reseller/brands", s.setResellerBrand)
	// 0.50-0.69: delegation, migration, clusters, HA and API contracts.
	mux.HandleFunc("GET /v1/delegates", s.delegates)
	mux.HandleFunc("POST /v1/delegates", s.createDelegate)
	mux.HandleFunc("GET /v1/migrations", s.migrations)
	mux.HandleFunc("POST /v1/migrations", s.createMigration)
	mux.HandleFunc("GET /v1/clusters", s.clusters)
	mux.HandleFunc("POST /v1/clusters", s.createCluster)
	mux.HandleFunc("GET /v1/load-balancers", s.loadBalancers)
	mux.HandleFunc("POST /v1/load-balancers", s.createLoadBalancer)
	mux.HandleFunc("GET /v1/provision/profiles", s.provisionProfiles)
	mux.HandleFunc("POST /v1/provision/profiles", s.createProvisionProfile)
	mux.HandleFunc("GET /v1/api-keys", s.apiKeys)
	mux.HandleFunc("POST /v1/api-keys", s.createAPIKey)
	mux.HandleFunc("POST /v1/api-keys/verify", s.verifyAPIKey)
	mux.HandleFunc("GET /v1/webhooks", s.webhooks)
	mux.HandleFunc("POST /v1/webhooks", s.createWebhook)
	// 0.70-0.89: extensions, billing contracts, diagnostics and recovery.
	mux.HandleFunc("GET /v1/plugins", s.plugins)
	mux.HandleFunc("POST /v1/plugins", s.installPlugin)
	mux.HandleFunc("GET /v1/billing/invoices", s.invoices)
	mux.HandleFunc("POST /v1/billing/invoices", s.createInvoice)
	mux.HandleFunc("GET /v1/billing/ledger/verify", s.verifyBillingLedger)
	mux.HandleFunc("POST /v1/billing/ledger", s.postBillingTransaction)
	mux.HandleFunc("GET /v1/notifications", s.notifications)
	mux.HandleFunc("POST /v1/notifications", s.createNotification)
	mux.HandleFunc("GET /v1/diagnostics", s.diagnostics)
	mux.HandleFunc("POST /v1/diagnostics", s.runDiagnostic)
	mux.HandleFunc("GET /v1/repairs", s.repairs)
	mux.HandleFunc("POST /v1/repairs", s.runRepair)
	mux.HandleFunc("GET /v1/config/revisions", s.revisions)
	mux.HandleFunc("POST /v1/config/revisions", s.createRevision)
	mux.HandleFunc("GET /v1/secrets", s.secrets)
	mux.HandleFunc("POST /v1/secrets", s.createSecretRef)
	mux.HandleFunc("GET /v1/releases", s.releases)
	mux.HandleFunc("POST /v1/releases", s.addRelease)
	// 0.90-0.99 + 1.0-5.0 maturity/certification contracts.
	mux.HandleFunc("GET /v1/exports", s.exports)
	mux.HandleFunc("POST /v1/exports", s.createExport)
	mux.HandleFunc("GET /v1/performance/recommendations", s.recommendations)
	mux.HandleFunc("POST /v1/performance/recommendations", s.createRecommendation)
	mux.HandleFunc("GET /v1/staging", s.staging)
	mux.HandleFunc("POST /v1/staging", s.createStaging)
	mux.HandleFunc("GET /v1/isolation", s.isolationProfiles)
	mux.HandleFunc("POST /v1/isolation", s.setIsolationProfile)
	mux.HandleFunc("GET /v1/account-controls", s.accountControls)
	mux.HandleFunc("POST /v1/account-controls", s.createAccountControl)
	mux.HandleFunc("GET /v1/certification", s.certification)
	mux.HandleFunc("POST /v1/certification", s.recordCertification)
	mux.HandleFunc("GET /v1/horizons", s.horizons)
	mux.HandleFunc("POST /v1/host/plans", s.hostPlan)
	mux.HandleFunc("GET /v1/host/capabilities", s.hostCapabilities)
	mux.HandleFunc("GET /v1/host/inventory", s.hostInventory)
	mux.HandleFunc("POST /v1/host/reconcile", s.hostReconcile)
	// 6.91-7.0 — production control-plane expansion.
	mux.HandleFunc("GET /v1/mail/queue", s.v7MailQueue)
	mux.HandleFunc("POST /v1/mail/queue/{id}/retry", s.v7MailQueueRetry)
	mux.HandleFunc("DELETE /v1/mail/queue/{id}", s.v7MailQueueDelete)
	mux.HandleFunc("GET /v1/mail/delivery", s.v7MailDelivery)
	mux.HandleFunc("GET /v1/mail/filters", s.v7MailFilters)
	mux.HandleFunc("POST /v1/mail/filters", s.v7MailFilterUpsert)
	mux.HandleFunc("DELETE /v1/mail/filters/{id}", s.v7MailFilterDelete)
	mux.HandleFunc("GET /v1/backup/policies", s.v7BackupPolicies)
	mux.HandleFunc("POST /v1/backup/policies", s.v7BackupPolicyUpsert)
	mux.HandleFunc("DELETE /v1/backup/policies/{id}", s.v7BackupPolicyDelete)
	mux.HandleFunc("POST /v1/backup/policies/{id}/run", s.v7BackupPolicyRun)
	mux.HandleFunc("POST /v1/backups/{id}/verify", s.v7BackupVerify)
	mux.HandleFunc("DELETE /v1/api-keys/{id}", s.v7APIKeyRevoke)
	mux.HandleFunc("POST /v1/api-keys/{id}/rotate", s.v7APIKeyRotate)
	mux.HandleFunc("GET /v1/monitoring/live", s.v7MonitoringLive)
	mux.HandleFunc("DELETE /v1/monitoring/alerts/{id}", s.v7AlertRuleDelete)
	mux.HandleFunc("POST /v1/monitoring/incidents/{id}/resolve", s.v7IncidentResolve)
	mux.HandleFunc("GET /v1/security/advisor", s.v7SecurityAdvisor)
	mux.HandleFunc("POST /v1/security/advisor/fix", s.v7SecurityFix)
	mux.HandleFunc("GET /v1/sites/policies", s.v7SitePolicies)
	mux.HandleFunc("POST /v1/sites/{domain}/policy", s.v7SitePolicySet)
	mux.HandleFunc("GET /v1/databases/activity", s.v7DatabaseActivity)
	mux.HandleFunc("POST /v1/databases/activity/{id}/kill", s.v7DatabaseKill)
	mux.HandleFunc("GET /v1/apps/discover", s.v7AppsDiscover)
	mux.HandleFunc("POST /v1/apps/{domain}/action", s.v7AppAction)
	mux.HandleFunc("GET /v1/dns/zones/{domain}/dnssec", s.v7DNSSECStatus)
	mux.HandleFunc("POST /v1/dns/zones/{domain}/dnssec", s.v7DNSSECSet)
	mux.HandleFunc("GET /v1/dns/templates", s.v7DNSTemplates)
	mux.HandleFunc("POST /v1/dns/templates", s.v7DNSTemplateUpsert)
	mux.HandleFunc("DELETE /v1/dns/templates/{id}", s.v7DNSTemplateDelete)
	mux.HandleFunc("POST /v1/dns/templates/{id}/apply", s.v7DNSTemplateApply)
	mux.HandleFunc("GET /v1/readiness", s.v7Readiness)
	mux.HandleFunc("GET /v1/readiness/history", s.v7ReadinessHistory)
	mux.HandleFunc("POST /v1/readiness/repair", s.v7ReadinessRepair)
	return securityHeaders(s.requireToken(mux))
}
func writeJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}
func signaturePayload(method, requestURI, timestamp, nonce string, body []byte) []byte {
	h := sha256.Sum256(body)
	return []byte(method + "\n" + requestURI + "\n" + timestamp + "\n" + nonce + "\n" + hex.EncodeToString(h[:]))
}

func (s *Server) requireToken(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if s.cfg.AgentToken == "" {
			writeJSON(w, 500, map[string]any{"error": "agent token not configured"})
			return
		}
		timestamp := strings.TrimSpace(r.Header.Get("X-Privora-Timestamp"))
		nonce := strings.TrimSpace(r.Header.Get("X-Privora-Nonce"))
		sig := strings.TrimSpace(r.Header.Get("X-Privora-Signature"))
		if timestamp == "" || nonce == "" || sig == "" || len(nonce) < 16 || len(nonce) > 128 {
			writeJSON(w, 401, map[string]any{"error": "signed agent authentication required"})
			return
		}
		ts, err := time.Parse(time.RFC3339, timestamp)
		if err != nil || time.Since(ts) > 90*time.Second || time.Until(ts) > 90*time.Second {
			writeJSON(w, 401, map[string]any{"error": "agent request timestamp is stale"})
			return
		}
		body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 2<<20))
		if err != nil {
			writeJSON(w, 400, map[string]any{"error": "unable to read request body"})
			return
		}
		r.Body = io.NopCloser(bytes.NewReader(body))
		mac := hmac.New(sha256.New, []byte(s.cfg.AgentToken))
		_, _ = mac.Write(signaturePayload(r.Method, r.URL.RequestURI(), timestamp, nonce, body))
		expected := hex.EncodeToString(mac.Sum(nil))
		if subtle.ConstantTimeCompare([]byte(strings.ToLower(sig)), []byte(expected)) != 1 {
			writeJSON(w, 401, map[string]any{"error": "invalid agent request signature"})
			return
		}
		now := time.Now().UTC()
		s.nonceMu.Lock()
		for k, expires := range s.nonces {
			if now.After(expires) {
				delete(s.nonces, k)
			}
		}
		if _, exists := s.nonces[nonce]; exists {
			s.nonceMu.Unlock()
			writeJSON(w, 409, map[string]any{"error": "agent request replay rejected"})
			return
		}
		s.nonces[nonce] = now.Add(2 * time.Minute)
		s.nonceMu.Unlock()
		next.ServeHTTP(w, r)
	})
}

func actor(r *http.Request) string {
	v := strings.TrimSpace(r.Header.Get("X-Privora-Actor"))
	if v == "" {
		return "local-panel"
	}
	if len(v) > 100 {
		return v[:100]
	}
	return v
}
func requestID(r *http.Request) string {
	v := strings.TrimSpace(r.Header.Get("X-Privora-Request-ID"))
	if len(v) > 100 {
		return ""
	}
	return v
}
func (s *Server) auditMutation(r *http.Request, op, res, outcome string) {
	_ = s.audit.Write(audit.Record{Actor: actor(r), Operation: op, Resource: res, Outcome: outcome, RequestID: requestID(r)})
}
func (s *Server) health(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, 200, map[string]any{"ok": true, "version": currentVersion, "mock": s.cfg.Mock, "capabilities": []string{"services", "updates", "hosting-accounts", "sites", "subdomains", "site-delete", "php-switching", "files", "config-editor", "extensions-components", "nameserver-manager", "sftp", "databases", "dns", "ssl", "backups", "mail", "resellers", "firewall-gated", "apps-dev", "curated-app-installer", "account-controls", "one-command-vps-bootstrap", "signed-safe-updater", "automatic-maintenance", "fleet-mtls-core", "cloud-durable-core", "automation-durable-core", "fabric-durable-core"}, "platform_horizon": "5.0-development-contracts"})
}
func (s *Server) system(w http.ResponseWriter, _ *http.Request) { writeJSON(w, 200, systeminfo.Read()) }
func (s *Server) services(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 3*time.Second)
	defer cancel()
	states := map[string]string{}
	keys := make([]string, 0, len(s.cfg.AllowedServices))
	for k := range s.cfg.AllowedServices {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, service := range keys {
		if !s.cfg.Mock {
			load, _ := s.runner.Run(ctx, "systemctl", "show", service, "--property=LoadState", "--value")
			load = strings.TrimSpace(load)
			if load == "" || load == "not-found" {
				continue
			}
		}
		out, err := s.runner.Run(ctx, "systemctl", "is-active", service)
		if err != nil && strings.TrimSpace(out) == "" {
			states[service] = "unknown"
		} else {
			states[service] = strings.TrimSpace(out)
		}
	}
	writeJSON(w, 200, map[string]any{"services": states})
}
func (s *Server) serviceAction(w http.ResponseWriter, r *http.Request) {
	service, action := r.PathValue("service"), r.PathValue("action")
	if !s.cfg.AllowedServices[service] {
		writeJSON(w, 403, map[string]any{"error": "service is not allow-listed"})
		return
	}
	if !s.cfg.Mock {
		ctx, cancel := context.WithTimeout(r.Context(), 3*time.Second)
		load, _ := s.runner.Run(ctx, "systemctl", "show", service, "--property=LoadState", "--value")
		cancel()
		if v := strings.TrimSpace(load); v == "" || v == "not-found" {
			writeJSON(w, 404, map[string]any{"error": "service is not installed on this host"})
			return
		}
	}
	if action != "start" && action != "stop" && action != "restart" && action != "reload" {
		writeJSON(w, 400, map[string]any{"error": "unsupported action"})
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()
	_, err := s.runner.Run(ctx, "systemctl", action, service)
	outcome := "success"
	if err != nil {
		outcome = "failure"
	}
	s.auditMutation(r, "service."+action, service, outcome)
	if err != nil {
		writeJSON(w, 500, map[string]any{"error": "service operation failed"})
		return
	}
	writeJSON(w, 200, map[string]any{"ok": true, "service": service, "action": action})
}
func (s *Server) serviceLogs(w http.ResponseWriter, r *http.Request) {
	service := r.PathValue("service")
	if !s.cfg.AllowedServices[service] {
		writeJSON(w, 403, map[string]any{"error": "service is not allow-listed"})
		return
	}
	if s.cfg.Mock {
		writeJSON(w, 200, map[string]any{"service": service, "lines": []string{"Privora mock log stream", "Service health check passed", "No recent errors"}})
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 4*time.Second)
	defer cancel()
	out, err := s.runner.Run(ctx, "journalctl", "-u", service, "-n", "60", "--no-pager")
	if err != nil {
		writeJSON(w, 500, map[string]any{"error": "unable to read logs"})
		return
	}
	writeJSON(w, 200, map[string]any{"service": service, "lines": strings.Split(strings.TrimSpace(out), "\n")})
}
func runPackageProbe(ctx context.Context, command string, args ...string) ([]byte, error) {
	cmd := exec.Command(command, args...)
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	var output bytes.Buffer
	cmd.Stdout = &output
	cmd.Stderr = &output
	if err := cmd.Start(); err != nil {
		return nil, err
	}
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	select {
	case err := <-done:
		return output.Bytes(), err
	case <-ctx.Done():
		_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
		<-done
		return output.Bytes(), ctx.Err()
	}
}

func (s *Server) serverComponents(w http.ResponseWriter, r *http.Request) {
	components, manager, err := s.host.ServerComponents(r.Context())
	if err != nil {
		writeJSON(w, 500, map[string]any{"error": err.Error()})
		return
	}
	installed, available, partial := 0, 0, 0
	for _, c := range components {
		if c.Installed {
			installed++
		} else if c.Partial {
			partial++
		} else if c.Available {
			available++
		}
	}
	writeJSON(w, 200, map[string]any{
		"components":      components,
		"package_manager": manager,
		"counts":          map[string]int{"total": len(components), "installed": installed, "available": available, "partial": partial},
		"policy":          "curated-allow-list",
	})
}

func (s *Server) installServerComponent(w http.ResponseWriter, r *http.Request) {
	id := strings.TrimSpace(strings.ToLower(r.PathValue("id")))
	component, restarted, err := s.host.InstallServerComponent(r.Context(), id)
	outcome := "success"
	if err != nil {
		outcome = "failure"
	}
	s.auditMutation(r, "server.component.install", id, outcome)
	if err != nil {
		writeJSON(w, 400, map[string]any{"error": err.Error(), "component": component, "restarted_services": restarted})
		return
	}
	writeJSON(w, 200, map[string]any{"ok": true, "component": component, "restarted_services": restarted})
}

func (s *Server) removeServerComponent(w http.ResponseWriter, r *http.Request) {
	id := strings.TrimSpace(strings.ToLower(r.PathValue("id")))
	component, restarted, err := s.host.RemoveServerComponent(r.Context(), id)
	outcome := "success"
	if err != nil {
		outcome = "failure"
	}
	s.auditMutation(r, "server.component.remove", id, outcome)
	if err != nil {
		writeJSON(w, 400, map[string]any{"error": err.Error(), "component": component, "restarted_services": restarted})
		return
	}
	writeJSON(w, 200, map[string]any{"ok": true, "component": component, "restarted_services": restarted})
}

func (s *Server) componentPresets(w http.ResponseWriter, r *http.Request) {
	version := strings.TrimSpace(r.URL.Query().Get("php_version"))
	if version == "" {
		version = "8.4"
	}
	presets := s.host.ComponentPresets(r.Context(), version)
	writeJSON(w, 200, map[string]any{"presets": presets, "php_version": version, "policy": "preview-before-apply"})
}

func (s *Server) applyComponentPreset(w http.ResponseWriter, r *http.Request) {
	id := strings.TrimSpace(strings.ToLower(r.PathValue("id")))
	var in struct {
		PHPVersion string `json:"php_version"`
	}
	if r.Body != nil {
		_ = json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<16)).Decode(&in)
	}
	if in.PHPVersion == "" {
		in.PHPVersion = "8.4"
	}
	preset, restarted, err := s.host.ApplyComponentPreset(r.Context(), id, in.PHPVersion)
	outcome := "success"
	if err != nil {
		outcome = "failure"
	}
	s.auditMutation(r, "server.component.preset.apply", id+"@"+in.PHPVersion, outcome)
	if err != nil {
		writeJSON(w, 409, map[string]any{"error": err.Error(), "preset": preset, "restarted_services": restarted})
		return
	}
	writeJSON(w, 200, map[string]any{"ok": true, "preset": preset, "restarted_services": restarted})
}

func (s *Server) packageUpdates(w http.ResponseWriter, r *http.Request) {
	if s.cfg.Mock {
		writeJSON(w, 200, map[string]any{"count": 4, "security": 2, "reboot_required": false, "packages": []map[string]string{{"name": "nginx", "current": "1.26.2", "available": "1.26.3", "type": "security"}, {"name": "openssl", "current": "3.3.1", "available": "3.3.2", "type": "security"}, {"name": "curl", "current": "8.9.0", "available": "8.10.0", "type": "normal"}, {"name": "ca-certificates", "current": "20240203", "available": "20240705", "type": "normal"}}})
		return
	}
	// Keep the agent-side package probe comfortably shorter than the PCC client
	// timeout. This guarantees the agent can always return a complete HTTP/JSON
	// response even when apt/dnf is slow or waiting on package-manager state.
	ctx, cancel := context.WithTimeout(r.Context(), 8*time.Second)
	defer cancel()
	pkgs := []map[string]string{}
	manager := "unknown"
	degraded := false
	statusReason := ""
	if apt, err := exec.LookPath("apt"); err == nil {
		manager = "apt"
		b, cmdErr := runPackageProbe(ctx, apt, "list", "--upgradable")
		if cmdErr != nil {
			degraded = true
			if errors.Is(cmdErr, context.DeadlineExceeded) || errors.Is(ctx.Err(), context.DeadlineExceeded) {
				statusReason = "APT inventory timed out; package status will retry on refresh."
			} else {
				statusReason = "APT inventory is temporarily unavailable."
			}
		}
		re := regexp.MustCompile(`\[upgradable from: ([^\]]+)\]`)
		for _, line := range strings.Split(string(b), "\n") {
			line = strings.TrimSpace(line)
			if line == "" || strings.HasPrefix(strings.ToLower(line), "listing") || !strings.Contains(line, "/") {
				continue
			}
			fields := strings.Fields(line)
			if len(fields) < 2 {
				continue
			}
			name := strings.SplitN(fields[0], "/", 2)[0]
			available := fields[1]
			current := "unknown"
			if m := re.FindStringSubmatch(line); len(m) == 2 {
				current = m[1]
			}
			typ := "normal"
			if strings.Contains(strings.ToLower(line), "security") {
				typ = "security"
			}
			pkgs = append(pkgs, map[string]string{"name": name, "current": current, "available": available, "type": typ})
		}
	} else if dnf, err := exec.LookPath("dnf"); err == nil {
		manager = "dnf"
		b, cmdErr := runPackageProbe(ctx, dnf, "-q", "check-update")
		if cmdErr == nil || (cmdErr != nil && strings.Contains(cmdErr.Error(), "exit status 100")) {
			for _, line := range strings.Split(string(b), "\n") {
				f := strings.Fields(line)
				if len(f) < 3 || strings.HasPrefix(line, " ") {
					continue
				}
				if !strings.Contains(f[0], ".") {
					continue
				}
				name := strings.SplitN(f[0], ".", 2)[0]
				typ := "normal"
				if strings.Contains(strings.ToLower(f[2]), "security") {
					typ = "security"
				}
				pkgs = append(pkgs, map[string]string{"name": name, "current": "installed", "available": f[1], "type": typ})
			}
		} else {
			degraded = true
			if errors.Is(cmdErr, context.DeadlineExceeded) || errors.Is(ctx.Err(), context.DeadlineExceeded) {
				statusReason = "DNF inventory timed out; package status will retry on refresh."
			} else {
				statusReason = "DNF inventory is temporarily unavailable."
			}
		}
	}
	security := 0
	for _, p := range pkgs {
		if p["type"] == "security" {
			security++
		}
	}
	_, rebootErr := os.Stat("/var/run/reboot-required")
	writeJSON(w, 200, map[string]any{"count": len(pkgs), "security": security, "reboot_required": rebootErr == nil, "packages": pkgs, "package_manager": manager, "degraded": degraded, "status_reason": statusReason})
}
func decodeJSON(r *http.Request, v any) error {
	dec := json.NewDecoder(http.MaxBytesReader(nil, r.Body, 1<<20))
	dec.DisallowUnknownFields()
	return dec.Decode(v)
}
func (s *Server) liveAccount(ctx context.Context, username string) (hostadapter.LiveAccount, bool) {
	for _, a := range s.host.DiscoverInventory(ctx).Accounts {
		if a.Username == username {
			return a, true
		}
	}
	return hostadapter.LiveAccount{}, false
}

func automaticSiteUsername(domain string) string {
	label := strings.ToLower(strings.Split(strings.TrimSpace(domain), ".")[0])
	var b strings.Builder
	for _, r := range label {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') {
			b.WriteRune(r)
		}
	}
	base := strings.TrimLeft(b.String(), "0123456789")
	if base == "" {
		base = "site"
	}
	if len(base) > 18 {
		base = base[:18]
	}
	return base + "web"
}

func (s *Server) adoptLiveAccount(ctx context.Context, live hostadapter.LiveAccount, primaryDomain string) error {
	_, err := s.hosting.AdoptDiscoveredAccount(hosting.Account{Username: live.Username, PrimaryDomain: primaryDomain, Package: "Detected", Status: live.Status})
	return err
}

// resolveSiteOwner uses the live host as authority. Existing provider-created
// accounts are adopted into Privora state without reprovisioning them. If a
// clean server has no eligible account, Privora creates a dedicated automatic
// owner with no package-selection step and retains it if site provisioning fails.
func (s *Server) resolveSiteOwner(ctx context.Context, domain, requested string) (string, bool, error) {
	requested = strings.ToLower(strings.TrimSpace(requested))
	inv := s.host.DiscoverInventory(ctx)
	active := make([]hostadapter.LiveAccount, 0, len(inv.Accounts))
	for _, a := range inv.Accounts {
		if a.Status == "active" {
			active = append(active, a)
		}
	}
	if requested != "" {
		for _, a := range inv.Accounts {
			if a.Username != requested {
				continue
			}
			if a.Status != "active" {
				return "", false, fmt.Errorf("hosting account %s is not active", requested)
			}
			if err := s.adoptLiveAccount(ctx, a, domain); err != nil {
				return "", false, err
			}
			return a.Username, false, nil
		}
		return "", false, fmt.Errorf("hosting account %s was not found in live host discovery", requested)
	}
	if len(active) == 1 {
		if err := s.adoptLiveAccount(ctx, active[0], domain); err != nil {
			return "", false, err
		}
		return active[0].Username, false, nil
	}
	if len(active) > 1 {
		return "", false, errors.New("multiple active hosting accounts were detected; choose the website owner")
	}
	base := automaticSiteUsername(domain)
	for i := 0; i < 25; i++ {
		username := base
		if i > 0 {
			suffix := fmt.Sprintf("%d", i+1)
			maxBase := 23 - len(suffix)
			if len(username) > maxBase {
				username = username[:maxBase]
			}
			username += suffix
		}
		err := s.host.ProvisionAccount(ctx, username)
		if err != nil {
			if strings.Contains(strings.ToLower(err.Error()), "already exists") {
				continue
			}
			return "", false, err
		}
		_, err = s.hosting.RecordProvisionedAccount(hosting.Account{Username: username, PrimaryDomain: domain, Package: "Automatic"})
		if err != nil {
			_ = s.host.DeleteLinuxUser(context.Background(), username)
			return "", false, err
		}
		return username, true, nil
	}
	return "", false, errors.New("could not allocate an automatic hosting owner")
}

func (s *Server) liveSite(ctx context.Context, domain string) (hostadapter.LiveSite, bool) {
	domain = strings.ToLower(strings.TrimSpace(domain))
	for _, site := range s.host.DiscoverInventory(ctx).Sites {
		if site.Domain == domain {
			return site, true
		}
	}
	return hostadapter.LiveSite{}, false
}

func (s *Server) accounts(w http.ResponseWriter, r *http.Request) {
	if s.cfg.Mock {
		writeJSON(w, 200, map[string]any{"accounts": s.hosting.ListAccounts(), "source": "privora-state"})
		return
	}
	inv := s.host.DiscoverInventory(r.Context())
	meta := map[string]hosting.Account{}
	for _, a := range s.hosting.ListAccounts() {
		meta[a.Username] = a
	}
	sitesByUser := map[string]string{}
	for _, site := range inv.Sites {
		if sitesByUser[site.Username] == "" {
			sitesByUser[site.Username] = site.Domain
		}
	}
	out := make([]hosting.Account, 0, len(inv.Accounts))
	for _, live := range inv.Accounts {
		a := meta[live.Username]
		a.Username = live.Username
		a.Status = live.Status
		if a.PrimaryDomain == "" {
			a.PrimaryDomain = sitesByUser[live.Username]
		}
		if a.Package == "" {
			a.Package = "Discovered"
		}
		out = append(out, a)
	}
	writeJSON(w, 200, map[string]any{"accounts": out, "source": "live-host", "collected_at": inv.CollectedAt, "warnings": inv.Warnings, "diagnostics": inv.Diagnostics})
}
func (s *Server) createAccount(w http.ResponseWriter, r *http.Request) {
	var in hosting.Account
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&in); err != nil {
		writeJSON(w, 400, map[string]any{"error": "invalid JSON"})
		return
	}
	in.Reseller = strings.ToLower(strings.TrimSpace(in.Reseller))
	if in.Reseller != "" {
		reseller, ok := s.resources.GetReseller(in.Reseller)
		if !ok {
			writeJSON(w, 400, map[string]any{"error": "reseller not found"})
			return
		}
		if reseller.Status != "active" {
			writeJSON(w, 409, map[string]any{"error": "reseller is suspended"})
			return
		}
		owned := 0
		for _, existing := range s.hosting.ListAccounts() {
			if existing.Reseller == in.Reseller {
				owned++
			}
		}
		if reseller.MaxAccounts > 0 && owned >= reseller.MaxAccounts {
			writeJSON(w, 409, map[string]any{"error": "reseller account limit reached"})
			return
		}
		if len(reseller.AllowedPackages) > 0 {
			allowed := false
			for _, p := range reseller.AllowedPackages {
				if strings.EqualFold(p, in.Package) {
					allowed = true
					break
				}
			}
			if !allowed {
				writeJSON(w, 403, map[string]any{"error": "package is not allowed for this reseller"})
				return
			}
		}
		if strings.TrimSpace(in.Owner) == "" {
			in.Owner = in.Reseller
		}
	}
	var a hosting.Account
	var err error
	if s.cfg.Mock {
		a, err = s.hosting.CreateAccount(in)
	} else if !s.cfg.HostMutations {
		err = fmt.Errorf("real host mutations are disabled; start agent with --host-mutations after certification")
	} else {
		err = s.host.ProvisionAccount(r.Context(), in.Username)
		if err == nil {
			a, err = s.hosting.RecordProvisionedAccount(in)
			if err != nil {
				_ = s.host.DeleteLinuxUser(context.Background(), in.Username)
			}
		}
	}
	if err != nil {
		s.auditMutation(r, "hosting.account.create", in.Username, "failure")
		writeJSON(w, 400, map[string]any{"error": err.Error()})
		return
	}
	s.auditMutation(r, "hosting.account.create", a.Username, "success")
	writeJSON(w, 201, map[string]any{"ok": true, "account": a})
}
func (s *Server) accountDetail(w http.ResponseWriter, r *http.Request) {
	user := strings.ToLower(strings.TrimSpace(r.PathValue("user")))
	if !regexp.MustCompile(`^[a-z][a-z0-9_]{2,23}$`).MatchString(user) {
		writeJSON(w, 400, map[string]any{"error": "invalid hosting username"})
		return
	}
	meta, metaOK := s.hosting.GetAccount(user)
	var live hostadapter.LiveAccount
	liveOK := false
	if !s.cfg.Mock {
		live, liveOK = s.liveAccount(r.Context(), user)
	}
	if s.cfg.Mock && metaOK {
		live = hostadapter.LiveAccount{Username: meta.Username, Home: filepath.Join("/home", meta.Username), Shell: "/usr/sbin/nologin", Status: meta.Status, Managed: true, Source: "mock"}
		liveOK = true
	}
	if !metaOK && !liveOK {
		writeJSON(w, 404, map[string]any{"error": "account not found"})
		return
	}
	if !metaOK && liveOK {
		meta = hosting.Account{Username: user, Status: live.Status, Package: "Discovered", Owner: "root", ShellPolicy: "none"}
	}
	sites := []hosting.Site{}
	for _, site := range s.hosting.ListSites() {
		if site.Username == user {
			sites = append(sites, site)
		}
	}
	for _, ls := range s.host.DiscoverInventory(r.Context()).Sites {
		if ls.Username == user {
			found := false
			for _, x := range sites {
				if x.Domain == ls.Domain {
					found = true
					break
				}
			}
			if !found {
				sites = append(sites, hosting.Site{Domain: ls.Domain, Username: user, DocumentRoot: ls.DocumentRoot, PHPVersion: ls.PHPVersion, SSL: ls.SSL, Status: "active"})
			}
		}
	}
	var limit any
	for _, l := range s.platform.ListResourceLimits() {
		if l.Owner == user {
			limit = l
			break
		}
	}
	writeJSON(w, 200, map[string]any{"account": meta, "live": live, "live_present": liveOK, "sites": sites, "resource_limit": limit, "account_health": map[string]any{"status": live.Status, "managed": live.Managed, "site_count": len(sites), "metadata_present": metaOK, "shell": live.Shell}})
}

func (s *Server) updateAccount(w http.ResponseWriter, r *http.Request) {
	user := strings.ToLower(strings.TrimSpace(r.PathValue("user")))
	if !regexp.MustCompile(`^[a-z][a-z0-9_]{2,23}$`).MatchString(user) {
		writeJSON(w, 400, map[string]any{"error": "invalid hosting username"})
		return
	}
	var in hosting.AccountUpdate
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&in); err != nil {
		writeJSON(w, 400, map[string]any{"error": "invalid JSON"})
		return
	}
	before, ok := s.hosting.GetAccount(user)
	if !ok {
		if live, found := s.liveAccount(r.Context(), user); found {
			_, _ = s.hosting.AdoptDiscoveredAccount(hosting.Account{Username: user, Status: live.Status, Package: "Detected", Owner: "root", ShellPolicy: "none"})
			before, _ = s.hosting.GetAccount(user)
			ok = true
		}
	}
	if !ok {
		writeJSON(w, 404, map[string]any{"error": "account not found"})
		return
	}
	if in.Reseller != nil && strings.TrimSpace(*in.Reseller) != "" {
		rr, found := s.resources.GetReseller(strings.ToLower(strings.TrimSpace(*in.Reseller)))
		if !found {
			writeJSON(w, 400, map[string]any{"error": "reseller not found"})
			return
		}
		if rr.Status != "active" {
			writeJSON(w, 409, map[string]any{"error": "reseller is suspended"})
			return
		}
	}
	updated, err := s.hosting.UpdateAccount(user, in)
	if err != nil {
		resultAudit(s, r, "hosting.account.update", user, err)
		writeJSON(w, 400, map[string]any{"error": err.Error()})
		return
	}
	if in.ShellPolicy != nil && !s.cfg.Mock {
		if !s.cfg.HostMutations {
			_, _ = s.hosting.UpdateAccount(user, hosting.AccountUpdate{ShellPolicy: &before.ShellPolicy})
			writeJSON(w, 403, map[string]any{"error": "real host mutations are disabled"})
			return
		}
		shell, hostErr := s.host.SetLinuxUserShellPolicy(r.Context(), user, updated.ShellPolicy)
		if hostErr != nil {
			_, _ = s.hosting.UpdateAccount(user, hosting.AccountUpdate{ShellPolicy: &before.ShellPolicy})
			resultAudit(s, r, "hosting.account.shell", user, hostErr)
			writeJSON(w, 400, map[string]any{"error": hostErr.Error()})
			return
		}
		_ = shell
	}
	s.auditMutation(r, "hosting.account.update", user, "success")
	writeJSON(w, 200, map[string]any{"ok": true, "account": updated})
}

func (s *Server) accountPassword(w http.ResponseWriter, r *http.Request) {
	user := strings.ToLower(strings.TrimSpace(r.PathValue("user")))
	if !regexp.MustCompile(`^[a-z][a-z0-9_]{2,23}$`).MatchString(user) {
		writeJSON(w, 400, map[string]any{"error": "invalid hosting username"})
		return
	}
	var in struct {
		Password string `json:"password"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<16)).Decode(&in); err != nil {
		writeJSON(w, 400, map[string]any{"error": "invalid JSON"})
		return
	}
	if len(in.Password) < 12 || len(in.Password) > 1024 || strings.ContainsAny(in.Password, "\x00\r\n") {
		writeJSON(w, 400, map[string]any{"error": "password must be 12-1024 characters without line breaks"})
		return
	}
	if s.cfg.Mock {
		s.auditMutation(r, "hosting.account.password", user, "success")
		writeJSON(w, 200, map[string]any{"ok": true, "username": user, "secret_stored": false})
		return
	}
	if !s.cfg.HostMutations {
		writeJSON(w, 403, map[string]any{"error": "real host mutations are disabled"})
		return
	}
	if _, ok := s.liveAccount(r.Context(), user); !ok {
		writeJSON(w, 404, map[string]any{"error": "account not found on live host"})
		return
	}
	err := s.host.SetLinuxUserPassword(r.Context(), user, in.Password)
	resultAudit(s, r, "hosting.account.password", user, err)
	if err != nil {
		writeJSON(w, 400, map[string]any{"error": err.Error()})
		return
	}
	writeJSON(w, 200, map[string]any{"ok": true, "username": user, "secret_stored": false})
}

func (s *Server) bulkAccountAction(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Users   []string `json:"users"`
		Action  string   `json:"action"`
		Package string   `json:"package"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&in); err != nil {
		writeJSON(w, 400, map[string]any{"error": "invalid JSON"})
		return
	}
	if len(in.Users) == 0 || len(in.Users) > 500 {
		writeJSON(w, 400, map[string]any{"error": "bulk operation requires 1-500 accounts"})
		return
	}
	if in.Action != "suspend" && in.Action != "unsuspend" && in.Action != "package" {
		writeJSON(w, 400, map[string]any{"error": "unsupported bulk action"})
		return
	}
	seen := map[string]bool{}
	results := []map[string]any{}
	failed := 0
	for _, raw := range in.Users {
		user := strings.ToLower(strings.TrimSpace(raw))
		if seen[user] || !regexp.MustCompile(`^[a-z][a-z0-9_]{2,23}$`).MatchString(user) {
			continue
		}
		seen[user] = true
		var err error
		if in.Action == "package" {
			_, err = s.hosting.SetAccountPackage(user, in.Package)
		} else {
			suspended := in.Action == "suspend"
			status := "active"
			if suspended {
				status = "suspended"
			}
			if s.cfg.Mock {
				err = s.hosting.SetAccountStatus(user, status)
			} else if !s.cfg.HostMutations {
				err = errors.New("real host mutations are disabled")
			} else {
				err = s.host.SetLinuxUserSuspended(r.Context(), user, suspended)
				if err == nil && s.hosting.HasAccount(user) {
					err = s.hosting.SetAccountStatus(user, status)
				}
			}
		}
		row := map[string]any{"username": user, "ok": err == nil}
		if err != nil {
			row["error"] = err.Error()
			failed++
		}
		results = append(results, row)
	}
	status := 200
	if failed > 0 {
		status = 207
	}
	s.auditMutation(r, "hosting.account.bulk", in.Action, fmt.Sprintf("completed:%d failed:%d", len(results)-failed, failed))
	writeJSON(w, status, map[string]any{"ok": failed == 0, "action": in.Action, "results": results, "failed": failed})
}

func (s *Server) accountPackage(w http.ResponseWriter, r *http.Request) {
	user := strings.ToLower(strings.TrimSpace(r.PathValue("user")))
	var in struct {
		Package string `json:"package"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<16)).Decode(&in); err != nil {
		writeJSON(w, 400, map[string]any{"error": "invalid JSON"})
		return
	}
	a, err := s.hosting.SetAccountPackage(user, in.Package)
	resultAudit(s, r, "hosting.account.package", user+":"+in.Package, err)
	if err != nil {
		writeJSON(w, 400, map[string]any{"error": err.Error()})
		return
	}
	writeJSON(w, 200, map[string]any{"ok": true, "account": a})
}

func (s *Server) accountAction(w http.ResponseWriter, r *http.Request) {
	user, action := r.PathValue("user"), r.PathValue("action")
	status := ""
	suspended := false
	if action == "suspend" {
		status, suspended = "suspended", true
	} else if action == "unsuspend" {
		status, suspended = "active", false
	} else {
		writeJSON(w, 400, map[string]any{"error": "unsupported account action"})
		return
	}
	var err error
	if s.cfg.Mock {
		err = s.hosting.SetAccountStatus(user, status)
	} else if !s.cfg.HostMutations {
		err = fmt.Errorf("real host mutations are disabled")
	} else if _, ok := s.liveAccount(r.Context(), user); !ok {
		err = fmt.Errorf("account not found on live host")
	} else {
		err = s.host.SetLinuxUserSuspended(r.Context(), user, suspended)
		if err == nil && s.hosting.HasAccount(user) {
			err = s.hosting.SetAccountStatus(user, status)
			if err != nil {
				_ = s.host.SetLinuxUserSuspended(context.Background(), user, !suspended)
			}
		}
	}
	out := "success"
	if err != nil {
		out = "failure"
	}
	s.auditMutation(r, "hosting.account."+action, user, out)
	if err != nil {
		writeJSON(w, 400, map[string]any{"error": err.Error()})
		return
	}
	writeJSON(w, 200, map[string]any{"ok": true, "username": user, "status": status})
}
func (s *Server) deleteAccount(w http.ResponseWriter, r *http.Request) {
	user := strings.ToLower(strings.TrimSpace(r.PathValue("user")))
	if !regexp.MustCompile(`^[a-z][a-z0-9_]{2,23}$`).MatchString(user) {
		writeJSON(w, 400, map[string]any{"error": "invalid hosting username"})
		return
	}
	var in struct {
		DeleteDNS       bool   `json:"delete_dns"`
		PlanFingerprint string `json:"plan_fingerprint"`
	}
	if r.Body != nil {
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<16)).Decode(&in); err != nil && !errors.Is(err, io.EOF) {
			writeJSON(w, 400, map[string]any{"error": "invalid JSON"})
			return
		}
	}
	plan, planErr := s.buildAccountTerminationPlan(r.Context(), user)
	if planErr != nil {
		writeJSON(w, 400, map[string]any{"error": "termination preflight failed: " + planErr.Error()})
		return
	}
	if !plan.Ready {
		writeJSON(w, 409, map[string]any{"error": "account termination is blocked by the current preflight plan", "plan": plan})
		return
	}
	if strings.TrimSpace(in.PlanFingerprint) == "" || subtle.ConstantTimeCompare([]byte(in.PlanFingerprint), []byte(plan.Fingerprint)) != 1 {
		writeJSON(w, 409, map[string]any{"error": "termination plan changed or was not confirmed; run preflight again", "plan": plan})
		return
	}

	if s.cfg.Mock {
		var account hosting.Account
		found := false
		for _, a := range s.hosting.ListAccounts() {
			if a.Username == user {
				account, found = a, true
				break
			}
		}
		if !found {
			writeJSON(w, 404, map[string]any{"error": "account not found"})
			return
		}
		if account.Status != "suspended" {
			writeJSON(w, 409, map[string]any{"error": "account must be suspended before deletion"})
			return
		}
		for _, site := range s.hosting.ListSites() {
			if site.Username == user {
				_, _ = s.hosting.RemoveSite(site.Domain)
			}
		}
		for _, db := range s.resources.ListDatabases() {
			if strings.EqualFold(db.Owner, user) {
				_ = s.resources.RemoveDatabase(db.Name)
			}
		}
		for _, mb := range s.resources.ListMailboxes() {
			if strings.HasSuffix(strings.ToLower(mb.Address), "@"+strings.ToLower(account.PrimaryDomain)) {
				_ = s.resources.RemoveMailbox(mb.Address)
			}
		}
		for _, sf := range s.resources.ListSFTPAccounts() {
			if strings.EqualFold(sf.Owner, user) {
				_ = s.resources.RemoveSFTPAccount(sf.Username)
			}
		}
		for _, app := range s.resources.ListApplications() {
			if strings.EqualFold(app.Owner, user) {
				_ = s.resources.RemoveApplication(app.ID)
			}
		}
		for _, job := range s.platform.ListCronJobs() {
			if strings.EqualFold(job.Owner, user) {
				_ = s.platform.RemoveCronJob(job.ID)
			}
		}
		for _, dep := range s.platform.ListDeployments() {
			if strings.EqualFold(dep.Owner, user) {
				_ = s.platform.RemoveDeployment(dep.ID)
			}
		}
		for _, app := range s.platform.ListAppInstalls() {
			if strings.EqualFold(app.Owner, user) {
				_ = s.platform.RemoveAppInstall(app.ID)
			}
		}
		_, err := s.hosting.RemoveAccount(user)
		if err != nil {
			writeJSON(w, 400, map[string]any{"error": err.Error()})
			return
		}
		s.auditMutation(r, "hosting.account.delete", user, "success")
		writeJSON(w, 200, map[string]any{"ok": true, "username": user, "status": "deleted", "files_deleted": true})
		return
	}
	if !s.cfg.HostMutations {
		writeJSON(w, 403, map[string]any{"error": "real host mutations are disabled"})
		return
	}
	liveAccount, ok := s.liveAccount(r.Context(), user)
	if !ok {
		writeJSON(w, 404, map[string]any{"error": "account not found on live host"})
		return
	}
	if liveAccount.Status != "suspended" {
		writeJSON(w, 409, map[string]any{"error": "account must be suspended before deletion", "required_action": "suspend"})
		return
	}

	s.host.InvalidateInventory()
	inv := s.host.DiscoverInventory(r.Context())
	owned := []hostadapter.LiveSite{}
	ownedDomains := map[string]bool{}
	for _, site := range inv.Sites {
		if site.Username != user {
			continue
		}
		if !site.Managed {
			writeJSON(w, 409, map[string]any{"error": "account owns an externally managed website; remove or adopt that provider configuration before deleting the account", "domain": site.Domain})
			return
		}
		owned = append(owned, site)
		ownedDomains[strings.ToLower(site.Domain)] = true
	}
	deletedDatabases := []string{}
	deletedMailboxes := []string{}
	for _, db := range s.resources.ListDatabases() {
		if !strings.EqualFold(db.Owner, user) {
			continue
		}
		if err := s.host.DeleteDatabase(r.Context(), db.Engine, db.Name, db.User); err != nil {
			s.auditMutation(r, "hosting.account.delete", user, "failure")
			writeJSON(w, 400, map[string]any{"error": "account termination database cleanup failed for " + db.Name + ": " + err.Error(), "deleted_databases": deletedDatabases})
			return
		}
		if err := s.resources.RemoveDatabase(db.Name); err != nil {
			writeJSON(w, 500, map[string]any{"error": "database was removed from the server but Privora metadata cleanup failed for " + db.Name + ": " + err.Error(), "deleted_databases": deletedDatabases})
			return
		}
		deletedDatabases = append(deletedDatabases, db.Engine+":"+db.Name)
	}
	for _, mb := range s.resources.ListMailboxes() {
		if !ownedDomains[strings.ToLower(mb.Domain)] {
			continue
		}
		if err := s.host.DeleteMailbox(r.Context(), mb.Address); err != nil {
			s.auditMutation(r, "hosting.account.delete", user, "failure")
			writeJSON(w, 400, map[string]any{"error": "account termination mailbox cleanup failed for " + mb.Address + ": " + err.Error(), "deleted_databases": deletedDatabases, "deleted_mailboxes": deletedMailboxes})
			return
		}
		if err := s.resources.RemoveMailbox(mb.Address); err != nil {
			writeJSON(w, 500, map[string]any{"error": "mailbox was removed from the server but Privora metadata cleanup failed for " + mb.Address + ": " + err.Error(), "deleted_mailboxes": deletedMailboxes})
			return
		}
		deletedMailboxes = append(deletedMailboxes, mb.Address)
	}
	deletedSites := []string{}
	deletedDNS := []string{}
	for _, site := range owned {
		stateSite, stateSiteOK := s.hosting.GetSite(site.Domain)
		if err := s.host.DeleteSite(r.Context(), site.Domain, user, false); err != nil {
			s.auditMutation(r, "hosting.account.delete", user, "failure")
			writeJSON(w, 400, map[string]any{"error": "failed to remove owned website " + site.Domain + ": " + err.Error(), "deleted_sites": deletedSites})
			return
		}
		deletedSites = append(deletedSites, site.Domain)
		if in.DeleteDNS {
			if stateSiteOK && stateSite.Kind == "subdomain" && stateSite.ParentDomain != "" {
				cleaned, err := s.deleteSubdomainDNS(r.Context(), stateSite)
				if err != nil {
					writeJSON(w, 400, map[string]any{"error": "website removed but subdomain DNS cleanup failed for " + site.Domain + ": " + err.Error(), "deleted_sites": deletedSites})
					return
				}
				if cleaned {
					deletedDNS = append(deletedDNS, site.Domain+" (record in "+stateSite.ParentDomain+")")
				}
			} else {
				for _, zone := range s.host.DiscoverInventory(r.Context()).DNSZones {
					if zone.Domain == site.Domain && zone.Managed {
						if err := s.host.DeleteBINDZone(r.Context(), site.Domain); err != nil {
							writeJSON(w, 400, map[string]any{"error": "website removed but DNS cleanup failed for " + site.Domain + ": " + err.Error(), "deleted_sites": deletedSites})
							return
						}
						deletedDNS = append(deletedDNS, site.Domain)
						if s.resources.HasDNSZone(site.Domain) {
							_, _ = s.resources.DeleteDNSZone(site.Domain)
						}
						break
					}
				}
			}
		}
		if s.hosting.HasAccount(user) {
			if _, ok := s.hosting.GetSite(site.Domain); ok {
				_, _ = s.hosting.RemoveSite(site.Domain)
			}
		}
	}
	if err := s.host.DeleteAccountRuntime(r.Context(), user); err != nil {
		s.auditMutation(r, "hosting.account.delete", user, "failure")
		writeJSON(w, 400, map[string]any{"error": "website cleanup completed but PHP runtime cleanup failed: " + err.Error(), "deleted_sites": deletedSites})
		return
	}
	if err := s.host.DeleteLinuxUser(r.Context(), user); err != nil {
		s.auditMutation(r, "hosting.account.delete", user, "failure")
		writeJSON(w, 400, map[string]any{"error": "website cleanup completed but Linux account deletion failed: " + err.Error(), "deleted_sites": deletedSites})
		return
	}
	if sf := func() error {
		for _, v := range s.resources.ListSFTPAccounts() {
			if strings.EqualFold(v.Owner, user) {
				if err := s.resources.RemoveSFTPAccount(v.Username); err != nil {
					return err
				}
			}
		}
		return nil
	}(); sf != nil {
		writeJSON(w, 500, map[string]any{"error": "Linux account deleted but SFTP metadata cleanup failed: " + sf.Error()})
		return
	}
	for _, v := range s.resources.ListApplications() {
		if strings.EqualFold(v.Owner, user) {
			_ = s.resources.RemoveApplication(v.ID)
		}
	}
	for _, v := range s.platform.ListCronJobs() {
		if strings.EqualFold(v.Owner, user) {
			_ = s.platform.RemoveCronJob(v.ID)
		}
	}
	for _, v := range s.platform.ListDeployments() {
		if strings.EqualFold(v.Owner, user) {
			_ = s.platform.RemoveDeployment(v.ID)
		}
	}
	for _, v := range s.platform.ListAppInstalls() {
		if strings.EqualFold(v.Owner, user) {
			_ = s.platform.RemoveAppInstall(v.ID)
		}
	}
	if s.hosting.HasAccount(user) {
		if _, err := s.hosting.RemoveAccount(user); err != nil {
			writeJSON(w, 400, map[string]any{"error": "Linux account deleted but Privora metadata cleanup failed: " + err.Error(), "deleted_sites": deletedSites})
			return
		}
	}
	s.host.InvalidateInventory()
	s.auditMutation(r, "hosting.account.delete", user, "success")
	writeJSON(w, 200, map[string]any{"ok": true, "username": user, "status": "deleted", "files_deleted": true, "deleted_sites": deletedSites, "deleted_dns_zones": deletedDNS, "deleted_databases": deletedDatabases, "deleted_mailboxes": deletedMailboxes})
}

func mergeWebsiteInventory(liveSites []hostadapter.LiveSite, recordedSites []hosting.Site, accounts []hosting.Account, managedDNS map[string]bool) []hosting.Site {
	meta := map[string]hosting.Site{}
	for _, x := range recordedSites {
		domain := strings.ToLower(strings.TrimSpace(x.Domain))
		if domain != "" {
			meta[domain] = x
		}
	}
	out := make([]hosting.Site, 0, len(liveSites)+len(recordedSites)+len(accounts))
	seen := map[string]bool{}
	for _, live := range liveSites {
		domain := strings.ToLower(strings.TrimSpace(live.Domain))
		if domain == "" || seen[domain] {
			continue
		}
		seen[domain] = true
		x := meta[domain]
		x.Domain = domain
		x.Username = live.Username
		x.DocumentRoot = live.DocumentRoot
		x.PHPVersion = live.PHPVersion
		x.SSL = live.SSL
		if managedDNS[domain] {
			x.DNS = "managed"
		} else if x.DNS == "" {
			x.DNS = "external"
		}
		if live.Enabled {
			x.Status = "active"
			x.StatusReason = "Matched active Nginx server_name"
		} else {
			x.Status = "disabled"
			x.StatusReason = "Matching Nginx vhost exists but is not enabled"
		}
		out = append(out, x)
	}
	// A transient discovery miss must never make a known website vanish from PCC.
	// Keep recorded websites visible and clearly mark them for operator attention.
	for domain, x := range meta {
		if seen[domain] {
			continue
		}
		seen[domain] = true
		x.Domain = domain
		x.Status = "missing"
		x.StatusReason = "Recorded in Privora but no active Nginx server_name was found"
		if x.PHPVersion == "" {
			x.PHPVersion = "unknown"
		}
		if x.SSL == "" {
			x.SSL = "unknown"
		}
		if x.DNS == "" {
			x.DNS = "external"
		}
		out = append(out, x)
	}
	// The account primary domain is durable identity metadata. If a site has not
	// yet been reconciled into site state, surface it instead of silently hiding it.
	for _, a := range accounts {
		domain := strings.ToLower(strings.TrimSpace(a.PrimaryDomain))
		if domain == "" || seen[domain] {
			continue
		}
		seen[domain] = true
		out = append(out, hosting.Site{Domain: domain, Username: a.Username, PHPVersion: "unknown", SSL: "unknown", DNS: "external", Status: "missing", StatusReason: "Primary domain is recorded on the hosting account but no active Nginx server_name was found"})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Domain < out[j].Domain })
	return out
}

func (s *Server) sites(w http.ResponseWriter, r *http.Request) {
	if s.cfg.Mock {
		writeJSON(w, 200, map[string]any{"sites": s.hosting.ListSites(), "source": "privora-state"})
		return
	}
	inv := s.host.DiscoverInventory(r.Context())
	managedDNS := map[string]bool{}
	for _, z := range inv.DNSZones {
		managedDNS[strings.ToLower(strings.TrimSpace(z.Domain))] = z.Managed
	}
	out := mergeWebsiteInventory(inv.Sites, s.hosting.ListSites(), s.hosting.ListAccounts(), managedDNS)
	reconciled := 0
	for i := range out {
		if out[i].Status != "missing" {
			continue
		}
		if direct, ok := s.host.InspectKnownSite(out[i].Domain, out[i].DocumentRoot); ok {
			if direct.Username != "" {
				out[i].Username = direct.Username
			}
			if direct.DocumentRoot != "" {
				out[i].DocumentRoot = direct.DocumentRoot
			}
			if direct.PHPVersion != "" && direct.PHPVersion != "unknown" {
				out[i].PHPVersion = direct.PHPVersion
			}
			if direct.SSL != "" {
				out[i].SSL = direct.SSL
			}
			if direct.Enabled {
				out[i].Status = "active"
				if direct.Source == "domain-vhost-root-reconciled" {
					out[i].StatusReason = "Matched active Nginx vhost by recorded document root during reconciliation"
				} else {
					out[i].StatusReason = "Matched active Nginx server_name during reconciliation"
				}
			} else {
				out[i].Status = "disabled"
				out[i].StatusReason = "Matching Nginx vhost was found but is not enabled"
			}
			reconciled++
		}
	}
	if inv.Diagnostics == nil {
		inv.Diagnostics = map[string]any{}
	}
	inv.Diagnostics["privora_vhosts_reconciled"] = reconciled
	writeJSON(w, 200, map[string]any{"sites": out, "source": "live-host+recorded", "collected_at": inv.CollectedAt, "warnings": inv.Warnings, "diagnostics": inv.Diagnostics})
}
func (s *Server) repairSiteConfiguration(w http.ResponseWriter, r *http.Request) {
	if s.cfg.Mock {
		writeJSON(w, 200, map[string]any{"ok": true, "simulation": true})
		return
	}
	if !s.cfg.HostMutations {
		writeJSON(w, 403, map[string]any{"error": "real host mutations are disabled"})
		return
	}
	domain := strings.ToLower(strings.TrimSpace(r.PathValue("domain")))
	if domain == "" {
		writeJSON(w, 400, map[string]any{"error": "domain is required"})
		return
	}
	var site hosting.Site
	found := false
	if saved, ok := s.hosting.GetSite(domain); ok {
		site = saved
		found = true
	}
	if !found {
		for _, account := range s.hosting.ListAccounts() {
			if strings.EqualFold(strings.TrimSpace(account.PrimaryDomain), domain) {
				site = hosting.Site{Domain: domain, Username: account.Username, DocumentRoot: filepath.Join("/home", account.Username, "domains", domain, "public")}
				found = true
				break
			}
		}
	}
	if !found {
		writeJSON(w, 404, map[string]any{"error": "Privora has no durable hosting identity for this website"})
		return
	}
	if site.DocumentRoot == "" {
		site.DocumentRoot = filepath.Join("/home", site.Username, "domains", domain, "public")
	}
	phpVersion := strings.TrimSpace(site.PHPVersion)
	if phpVersion == "" || phpVersion == "unknown" {
		phpVersion = s.host.DetectAccountPHPVersion(site.Username)
	}
	if phpVersion == "" {
		writeJSON(w, 409, map[string]any{"error": "website PHP-FPM version could not be inferred from the existing account pool"})
		return
	}
	res, err := s.host.RepairSiteNginx(r.Context(), domain, site.Username, phpVersion, site.DocumentRoot)
	if err != nil {
		s.auditMutation(r, "website.repair", domain, "failure")
		writeJSON(w, 400, map[string]any{"error": err.Error()})
		return
	}
	if saved, ok := s.hosting.GetSite(domain); ok {
		if saved.PHPVersion != phpVersion {
			_, _ = s.hosting.RecordPHP(domain, phpVersion)
		}
	} else {
		_, _ = s.hosting.RecordProvisionedSite(hosting.Site{Domain: domain, Username: site.Username, PHPVersion: phpVersion})
	}
	s.host.InvalidateInventory()
	s.auditMutation(r, "website.repair", domain, "success")
	writeJSON(w, 200, map[string]any{"ok": true, "site": res, "status": "active", "php_version": phpVersion})
}

func (s *Server) preflightSiteCreate(ctx context.Context, domain string) error {
	domain = strings.ToLower(strings.TrimSpace(domain))
	if domain == "" {
		return errors.New("domain is required")
	}
	if _, ok := s.hosting.GetSite(domain); ok {
		return errors.New("site already exists")
	}
	if !s.cfg.Mock {
		s.host.InvalidateInventory()
		if live, ok := s.liveSite(ctx, domain); ok {
			return fmt.Errorf("site already exists on live host (%s)", live.Source)
		}
	}
	return nil
}

func publicAddress(v string) bool {
	ip := net.ParseIP(strings.TrimSpace(v))
	return ip != nil && ip.IsGlobalUnicast() && !ip.IsPrivate()
}

func standardSiteDNSRecords(domain, v4, v6 string, includeLocalNameserverGlue bool) ([]hostadapter.DNSRecord, []resources.DNSRecord) {
	hostRecords := []hostadapter.DNSRecord{}
	stateRecords := []resources.DNSRecord{}
	add := func(typ, name, value string, ttl int) {
		if ttl <= 0 {
			ttl = 3600
		}
		hostRecords = append(hostRecords, hostadapter.DNSRecord{Type: typ, Name: name, Value: value, TTL: ttl})
		stateRecords = append(stateRecords, resources.DNSRecord{Type: typ, Name: name, Value: value, TTL: ttl})
	}
	hasMailAddress := false
	if publicAddress(v4) {
		add("A", "@", v4, 3600)
		add("A", "mail", v4, 3600)
		hasMailAddress = true
		if includeLocalNameserverGlue {
			add("A", "ns1", v4, 3600)
			add("A", "ns2", v4, 3600)
		}
	}
	if publicAddress(v6) {
		add("AAAA", "@", v6, 3600)
		add("AAAA", "mail", v6, 3600)
		hasMailAddress = true
		if includeLocalNameserverGlue {
			add("AAAA", "ns1", v6, 3600)
			add("AAAA", "ns2", v6, 3600)
		}
	}
	add("CNAME", "www", domain+".", 3600)
	add("CNAME", "ftp", domain+".", 3600)
	if hasMailAddress {
		add("MX", "@", "10 mail."+domain+".", 3600)
		add("CNAME", "webmail", "mail."+domain+".", 3600)
		add("CNAME", "autodiscover", "mail."+domain+".", 3600)
	}
	add("TXT", "@", "v=spf1 a mx ~all", 3600)
	add("TXT", "_dmarc", "v=DMARC1; p=none", 3600)
	add("CAA", "@", `0 issue "letsencrypt.org"`, 3600)
	return hostRecords, stateRecords
}

// ensureConfiguredNameserverGlue adds address records for authoritative nameservers
// that are in-bailiwick for the zone being created. Once a default nameserver set
// exists (for example ns1.privoralabs.com/ns2.privoralabs.com), BIND requires those
// child hosts to have A/AAAA records inside privoralabs.com itself. Older site-create
// paths omitted these records and named-checkzone could reject the new zone while
// allowing the website transaction to continue.
func ensureConfiguredNameserverGlue(domain, v4, v6 string, ns resources.NameserverConfig, hostRecords []hostadapter.DNSRecord, stateRecords []resources.DNSRecord) ([]hostadapter.DNSRecord, []resources.DNSRecord) {
	domain = strings.ToLower(strings.Trim(strings.TrimSpace(domain), "."))
	seen := map[string]bool{}
	for _, r := range hostRecords {
		seen[strings.ToLower(strings.TrimSpace(r.Name))+"|"+strings.ToUpper(strings.TrimSpace(r.Type))] = true
	}
	add := func(typ, name, value string) {
		key := strings.ToLower(strings.TrimSpace(name)) + "|" + strings.ToUpper(strings.TrimSpace(typ))
		if seen[key] || strings.TrimSpace(value) == "" {
			return
		}
		seen[key] = true
		hostRecords = append(hostRecords, hostadapter.DNSRecord{Type: typ, Name: name, Value: value, TTL: 3600})
		stateRecords = append(stateRecords, resources.DNSRecord{Type: typ, Name: name, Value: value, TTL: 3600})
	}
	for _, raw := range []string{ns.Primary, ns.Secondary} {
		host := strings.ToLower(strings.Trim(strings.TrimSpace(raw), "."))
		if host == "" || domain == "" || !strings.HasSuffix(host, "."+domain) {
			continue
		}
		name := strings.TrimSuffix(host, "."+domain)
		if name == "" {
			continue
		}
		if publicAddress(v4) {
			add("A", name, v4)
		}
		if publicAddress(v6) {
			add("AAAA", name, v6)
		}
	}
	return hostRecords, stateRecords
}

// nameserversForDomain selects the explicitly assigned nameserver set for a
// hosted root domain. A hosted domain must never implicitly select a nameserver
// set merely because both share the same base name: privoralabs.org can
// intentionally publish ns1/ns2.privoralabs.com. Unassigned domains use the
// administrator-selected default set.
func (s *Server) nameserversForDomain(domain string) resources.NameserverConfig {
	domain = strings.ToLower(strings.Trim(strings.TrimSpace(domain), "."))
	if assigned, ok := s.resources.AssignedNameservers(domain); ok {
		return assigned
	}
	return s.resources.Nameservers()
}

func (s *Server) autoProvisionSiteDNS(ctx context.Context, domain string) map[string]any {
	domain = strings.ToLower(strings.TrimSpace(domain))
	result := map[string]any{"domain": domain, "managed": false, "status": "external"}
	v4, v6 := s.host.PrimaryHostAddresses()
	if s.cfg.Mock && !publicAddress(v4) && !publicAddress(v6) {
		v4 = "203.0.113.10"
	}
	if !publicAddress(v4) && !publicAddress(v6) {
		result["status"] = "action-required"
		result["reason"] = "no public server address was detected; external DNS must be pointed to this server"
		result["suggested_ipv4"] = v4
		result["suggested_ipv6"] = v6
		return result
	}
	ns := s.nameserversForDomain(domain)
	hostRecords, stateRecords := standardSiteDNSRecords(domain, v4, v6, ns.Primary == "")
	hostRecords, stateRecords = ensureConfiguredNameserverGlue(domain, v4, v6, ns, hostRecords, stateRecords)
	if s.cfg.Mock {
		if s.resources.HasDNSZone(domain) {
			z, err := s.resources.ReplaceDNSZoneRecords(domain, stateRecords)
			if err != nil {
				result["status"] = "action-required"
				result["reason"] = err.Error()
				return result
			}
			result["managed"] = true
			result["status"] = "managed-updated"
			result["records"] = z.Records
			return result
		}
		z, err := s.resources.CreateDNSZone(resources.DNSZone{Domain: domain, Records: stateRecords})
		if err != nil {
			result["status"] = "action-required"
			result["reason"] = err.Error()
			return result
		}
		result["managed"] = true
		result["status"] = "managed-created"
		result["records"] = z.Records
		return result
	}
	inv := s.host.DiscoverInventory(ctx)
	for _, z := range inv.DNSZones {
		if z.Domain != domain {
			continue
		}
		if !z.Managed {
			result["status"] = "external-existing"
			result["reason"] = "an externally managed authoritative zone already exists; Privora did not overwrite it"
			return result
		}
		var prov hostadapter.DNSProvisionResult
		var err error
		if ns.Primary != "" && ns.Secondary != "" {
			prov, err = s.host.RewriteBINDZoneNameservers(ctx, domain, ns.Primary, ns.Secondary, hostRecords)
		} else {
			prov, err = s.host.UpsertBINDRecords(ctx, domain, hostRecords)
		}
		if err != nil {
			result["status"] = "action-required"
			result["reason"] = err.Error()
			return result
		}
		_, _ = s.resources.ReplaceDNSZoneRecords(domain, stateRecords)
		s.host.InvalidateInventory()
		result["managed"] = true
		result["status"] = "managed-updated"
		result["zone_file"] = prov.ZoneFile
		result["records"] = stateRecords
		return result
	}
	var prov hostadapter.DNSProvisionResult
	var err error
	if ns.Primary != "" && ns.Secondary != "" {
		prov, err = s.host.ProvisionBINDZoneWithNameservers(ctx, domain, ns.Primary, ns.Secondary, hostRecords)
	} else {
		prov, err = s.host.ProvisionBINDZone(ctx, domain, hostRecords)
	}
	if err != nil {
		result["status"] = "action-required"
		result["reason"] = err.Error()
		result["suggested_ipv4"] = v4
		result["suggested_ipv6"] = v6
		return result
	}
	_, recErr := s.resources.RecordRealDNSZone(resources.DNSZone{Domain: domain, Records: stateRecords})
	if recErr != nil && strings.Contains(strings.ToLower(recErr.Error()), "already exists") {
		_, recErr = s.resources.ReplaceDNSZoneRecords(domain, stateRecords)
	}
	if recErr != nil {
		result["state_warning"] = recErr.Error()
	}
	s.host.InvalidateInventory()
	result["managed"] = true
	result["status"] = "managed-created"
	result["zone_file"] = prov.ZoneFile
	result["records"] = stateRecords
	return result
}

// bestHostedParentDomain returns the longest existing hosted/DNS parent for a
// hostname. This lets Create Website and Add Subdomain share the same DNS
// semantics: a child hostname belongs in the parent's authoritative zone and
// must not silently become an independent zone merely because it was entered
// through the generic website form.
func (s *Server) bestHostedParentDomain(ctx context.Context, domain string) string {
	domain = strings.ToLower(strings.Trim(strings.TrimSpace(domain), "."))
	if domain == "" {
		return ""
	}
	candidates := map[string]bool{}
	for _, site := range s.hosting.ListSites() {
		p := strings.ToLower(strings.Trim(strings.TrimSpace(site.Domain), "."))
		if p != "" && p != domain && strings.HasSuffix(domain, "."+p) {
			candidates[p] = true
		}
	}
	if s.cfg.Mock {
		for _, zone := range s.resources.ListDNSZones() {
			p := strings.ToLower(strings.Trim(strings.TrimSpace(zone.Domain), "."))
			if p != "" && p != domain && strings.HasSuffix(domain, "."+p) {
				candidates[p] = true
			}
		}
	} else {
		inv := s.host.DiscoverDNSInventory(ctx)
		for _, zone := range inv.DNSZones {
			p := strings.ToLower(strings.Trim(strings.TrimSpace(zone.Domain), "."))
			if p != "" && p != domain && strings.HasSuffix(domain, "."+p) {
				candidates[p] = true
			}
		}
	}
	best := ""
	for p := range candidates {
		if len(p) > len(best) {
			best = p
		}
	}
	return best
}

func (s *Server) autoProvisionHostedDNS(ctx context.Context, domain string) (map[string]any, string) {
	domain = strings.ToLower(strings.TrimSpace(domain))
	if parent := s.bestHostedParentDomain(ctx, domain); parent != "" {
		return s.autoProvisionSubdomainDNS(ctx, parent, domain), parent
	}
	return s.autoProvisionSiteDNS(ctx, domain), ""
}

var subdomainPrefixRx = regexp.MustCompile(`^(?i:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)$`)

func normalizeSubdomainPrefix(v string) (string, error) {
	v = strings.ToLower(strings.Trim(strings.TrimSpace(v), "."))
	if v == "" || len(v) > 63 || !subdomainPrefixRx.MatchString(v) {
		return "", errors.New("invalid subdomain name; enter one DNS label only, such as blog")
	}
	if v == "www" {
		return "", errors.New("www is reserved as the website alias; choose another subdomain name")
	}
	return v, nil
}

func subdomainRecordName(fullDomain, parentDomain string) string {
	fullDomain = strings.ToLower(strings.TrimSpace(fullDomain))
	parentDomain = strings.ToLower(strings.TrimSpace(parentDomain))
	return strings.TrimSuffix(fullDomain, "."+parentDomain)
}

func (s *Server) autoProvisionSubdomainDNS(ctx context.Context, parentDomain, fullDomain string) map[string]any {
	parentDomain = strings.ToLower(strings.TrimSpace(parentDomain))
	fullDomain = strings.ToLower(strings.TrimSpace(fullDomain))
	name := subdomainRecordName(fullDomain, parentDomain)
	result := map[string]any{"domain": fullDomain, "parent_zone": parentDomain, "record_name": name, "managed": false, "status": "external"}
	v4, v6 := s.host.PrimaryHostAddresses()
	if s.cfg.Mock && !publicAddress(v4) && !publicAddress(v6) {
		v4 = "203.0.113.10"
	}
	hostRecords := []hostadapter.DNSRecord{}
	stateRecords := []resources.DNSRecord{}
	if publicAddress(v4) {
		hostRecords = append(hostRecords, hostadapter.DNSRecord{Type: "A", Name: name, Value: v4, TTL: 3600})
		stateRecords = append(stateRecords, resources.DNSRecord{Type: "A", Name: name, Value: v4, TTL: 3600})
	}
	if publicAddress(v6) {
		hostRecords = append(hostRecords, hostadapter.DNSRecord{Type: "AAAA", Name: name, Value: v6, TTL: 3600})
		stateRecords = append(stateRecords, resources.DNSRecord{Type: "AAAA", Name: name, Value: v6, TTL: 3600})
	}
	result["required_records"] = stateRecords
	if len(hostRecords) == 0 {
		result["status"] = "action-required"
		result["reason"] = "no public server address was detected; add the subdomain DNS record at the external DNS provider"
		return result
	}
	if s.cfg.Mock {
		if !s.resources.HasDNSZone(parentDomain) {
			result["status"] = "external-parent-zone"
			result["reason"] = "parent DNS zone is not managed by Privora"
			return result
		}
		var existing []resources.DNSRecord
		for _, zone := range s.resources.ListDNSZones() {
			if zone.Domain == parentDomain {
				existing = append(existing, zone.Records...)
				break
			}
		}
		for _, rec := range stateRecords {
			keyName, keyType := strings.ToLower(rec.Name), strings.ToUpper(rec.Type)
			filtered := existing[:0]
			for _, old := range existing {
				if strings.ToLower(old.Name) == keyName && strings.ToUpper(old.Type) == keyType {
					continue
				}
				filtered = append(filtered, old)
			}
			existing = append(filtered, rec)
		}
		_, _ = s.resources.ReplaceDNSZoneRecords(parentDomain, existing)
		result["managed"] = true
		result["status"] = "managed-parent-zone"
		return result
	}
	inv := s.host.DiscoverInventory(ctx)
	parentManaged := false
	parentExists := false
	for _, z := range inv.DNSZones {
		if strings.EqualFold(z.Domain, parentDomain) {
			parentExists = true
			parentManaged = z.Managed
			break
		}
	}
	if !parentExists || !parentManaged {
		result["status"] = "external-parent-zone"
		result["reason"] = "parent DNS zone is not managed by Privora; add the required A/AAAA record at the authoritative DNS provider"
		return result
	}
	prov, err := s.host.UpsertBINDRecords(ctx, parentDomain, hostRecords)
	if err != nil {
		result["status"] = "action-required"
		result["reason"] = err.Error()
		return result
	}
	if live, err := s.host.ReadBINDZone(parentDomain); err == nil {
		_, _ = s.resources.ReplaceDNSZoneRecords(parentDomain, stateDNSRecords(live.Records))
	}
	s.host.InvalidateInventory()
	result["managed"] = true
	result["status"] = "managed-parent-zone"
	result["zone_file"] = prov.ZoneFile
	return result
}

func (s *Server) deleteSubdomainDNS(ctx context.Context, site hosting.Site) (bool, error) {
	if site.Kind != "subdomain" || strings.TrimSpace(site.ParentDomain) == "" {
		return false, nil
	}
	parent := strings.ToLower(strings.TrimSpace(site.ParentDomain))
	name := subdomainRecordName(site.Domain, parent)
	if s.cfg.Mock {
		if !s.resources.HasDNSZone(parent) {
			return false, nil
		}
		for _, zone := range s.resources.ListDNSZones() {
			if zone.Domain != parent {
				continue
			}
			rows := make([]resources.DNSRecord, 0, len(zone.Records))
			for _, rec := range zone.Records {
				if strings.EqualFold(rec.Name, name) && (strings.EqualFold(rec.Type, "A") || strings.EqualFold(rec.Type, "AAAA")) {
					continue
				}
				rows = append(rows, rec)
			}
			_, err := s.resources.ReplaceDNSZoneRecords(parent, rows)
			return true, err
		}
		return false, nil
	}
	managed := false
	for _, z := range s.host.DiscoverInventory(ctx).DNSZones {
		if strings.EqualFold(z.Domain, parent) && z.Managed {
			managed = true
			break
		}
	}
	if !managed {
		return false, nil
	}
	for _, typ := range []string{"A", "AAAA"} {
		_, err := s.host.DeleteBINDRecord(ctx, parent, hostadapter.DNSRecord{Type: typ, Name: name, TTL: 3600})
		if err != nil && !strings.Contains(strings.ToLower(err.Error()), "record not found") {
			return false, err
		}
	}
	if live, err := s.host.ReadBINDZone(parent); err == nil {
		_, _ = s.resources.ReplaceDNSZoneRecords(parent, stateDNSRecords(live.Records))
	}
	s.host.InvalidateInventory()
	return true, nil
}

func (s *Server) autoProvisionSiteSSL(ctx context.Context, site hosting.Site) map[string]any {
	domain := strings.ToLower(strings.TrimSpace(site.Domain))
	out := map[string]any{"domain": domain, "provider": "letsencrypt", "status": "pending"}
	if domain == "" || site.DocumentRoot == "" {
		out["detail"] = "website metadata incomplete"
		return out
	}
	if s.cfg.Mock {
		if cert, err := s.resources.IssueCertificate(domain); err == nil {
			out["status"] = "valid"
			out["expires_at"] = cert.ExpiresAt
			if updated, uerr := s.hosting.RecordSSL(domain, "valid"); uerr == nil {
				_ = updated
			}
		} else {
			out["detail"] = err.Error()
		}
		return out
	}
	pre := s.host.PreflightLetsEncryptDomain(ctx, domain)
	out["preflight"] = pre
	if !pre.Ready {
		_, _ = s.hosting.RecordSSL(domain, "pending")
		return out
	}
	contact := "hostmaster@" + domain
	cert, err := s.host.IssueLetsEncryptWebroot(ctx, domain, site.DocumentRoot, contact)
	if err != nil {
		out["detail"] = err.Error()
		_, _ = s.hosting.RecordSSL(domain, "pending")
		return out
	}
	if err := s.host.InstallLetsEncryptNginxTLS(ctx, domain, site.Username, site.PHPVersion, site.DocumentRoot, cert); err != nil {
		out["status"] = "failed-install"
		out["detail"] = err.Error()
		_, _ = s.hosting.RecordSSL(domain, "pending")
		return out
	}
	if _, err := s.resources.RecordRealCertificate(resources.Certificate{Domain: cert.Domain, Provider: cert.Provider, ExpiresAt: cert.ExpiresAt}); err != nil {
		out["detail"] = err.Error()
		_, _ = s.hosting.RecordSSL(domain, "pending")
		return out
	}
	_, _ = s.hosting.RecordSSL(domain, "valid")
	s.host.InvalidateInventory()
	out["status"] = "valid"
	out["expires_at"] = cert.ExpiresAt
	out["https"] = true
	out["redirect_http_to_https"] = true
	return out
}

func (s *Server) createSubdomain(w http.ResponseWriter, r *http.Request) {
	var in struct {
		ParentDomain string `json:"parent_domain"`
		Label        string `json:"label"`
		Username     string `json:"username"`
		PHPVersion   string `json:"php_version"`
		DocumentRoot string `json:"document_root"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&in); err != nil {
		writeJSON(w, 400, map[string]any{"error": "invalid JSON"})
		return
	}
	parent := strings.ToLower(strings.Trim(strings.TrimSpace(in.ParentDomain), "."))
	label, err := normalizeSubdomainPrefix(in.Label)
	if err != nil {
		writeJSON(w, 400, map[string]any{"error": err.Error()})
		return
	}
	full := label + "." + parent
	if len(full) > 253 || parent == "" || net.ParseIP(parent) != nil {
		writeJSON(w, 400, map[string]any{"error": "invalid parent domain"})
		return
	}
	var parentOwner string
	if s.cfg.Mock {
		if parentSite, ok := s.hosting.GetSite(parent); ok {
			parentOwner = parentSite.Username
		}
	} else {
		s.host.InvalidateInventory()
		if live, ok := s.liveSite(r.Context(), parent); ok {
			parentOwner = live.Username
		} else if parentSite, ok := s.hosting.GetSite(parent); ok {
			parentOwner = parentSite.Username
		}
	}
	if parentOwner == "" {
		writeJSON(w, 404, map[string]any{"error": "parent website was not found; create or adopt the parent domain before adding a subdomain"})
		return
	}
	requested := strings.ToLower(strings.TrimSpace(in.Username))
	if requested != "" && requested != parentOwner {
		writeJSON(w, 409, map[string]any{"error": "subdomain must use the same hosting owner as its parent website", "parent_owner": parentOwner})
		return
	}
	if in.PHPVersion == "" {
		in.PHPVersion = "8.4"
	}
	if err := s.preflightSiteCreate(r.Context(), full); err != nil {
		s.auditMutation(r, "subdomain.create", full, "failure")
		writeJSON(w, 409, map[string]any{"error": err.Error(), "duplicate": true})
		return
	}
	requestedRoot := filepath.Clean(strings.TrimSpace(in.DocumentRoot))
	if strings.TrimSpace(in.DocumentRoot) == "" || requestedRoot == "." {
		requestedRoot = ""
	}
	siteIn := hosting.Site{Domain: full, Username: parentOwner, PHPVersion: in.PHPVersion, DocumentRoot: requestedRoot, Kind: "subdomain", ParentDomain: parent}
	dnsResult := map[string]any{"domain": full, "parent_zone": parent, "managed": false, "status": "external"}
	sslResult := map[string]any{"domain": full, "provider": "letsencrypt", "status": "pending"}
	var site hosting.Site
	if s.cfg.Mock {
		site, err = s.hosting.CreateSite(siteIn)
		if err == nil {
			dnsResult = s.autoProvisionSubdomainDNS(r.Context(), parent, full)
			if st, _ := dnsResult["status"].(string); st != "" {
				if updated, uerr := s.hosting.RecordDNS(site.Domain, st); uerr == nil {
					site = updated
				}
			}
		}
	} else if !s.cfg.HostMutations {
		err = errors.New("real host mutations are disabled; start agent with --host-mutations after certification")
	} else {
		if _, _, ownerErr := s.resolveSiteOwner(r.Context(), full, parentOwner); ownerErr != nil {
			err = ownerErr
		} else {
			res, provisionErr := s.host.ProvisionSiteWithDocumentRoot(r.Context(), full, parentOwner, in.PHPVersion, requestedRoot)
			err = provisionErr
			if err == nil {
				siteIn.DocumentRoot = res.DocumentRoot
				s.host.InvalidateInventory()
				dnsResult = s.autoProvisionSubdomainDNS(r.Context(), parent, full)
				if st, _ := dnsResult["status"].(string); st != "" {
					siteIn.DNS = st
				}
				site, err = s.hosting.RecordProvisionedSite(siteIn)
				if err == nil {
					s.host.InvalidateInventory()
					if live, ok := s.liveSite(r.Context(), full); ok {
						site.Domain, site.Username, site.DocumentRoot = live.Domain, live.Username, live.DocumentRoot
						site.PHPVersion, site.SSL = live.PHPVersion, live.SSL
						if live.Enabled {
							site.Status = "active"
						} else {
							site.Status = "disabled"
						}
					}
				}
			}
		}
	}
	if err == nil {
		sslResult = s.autoProvisionSiteSSL(r.Context(), site)
	}
	if err != nil {
		s.auditMutation(r, "subdomain.create", full, "failure")
		writeJSON(w, 400, map[string]any{"error": err.Error(), "domain": full, "dns": dnsResult})
		return
	}
	s.auditMutation(r, "subdomain.create", full, "success")
	writeJSON(w, 201, map[string]any{"ok": true, "site": site, "parent_domain": parent, "subdomain": label, "dns": dnsResult, "ssl": sslResult})
}

func (s *Server) createSite(w http.ResponseWriter, r *http.Request) {
	var in hosting.Site
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&in); err != nil {
		writeJSON(w, 400, map[string]any{"error": "invalid JSON"})
		return
	}
	var site hosting.Site
	var err error
	autoOwner := false
	in.Domain = strings.ToLower(strings.TrimSpace(in.Domain))
	dnsResult := map[string]any{"domain": in.Domain, "managed": false, "status": "external"}
	sslResult := map[string]any{"domain": in.Domain, "provider": "letsencrypt", "status": "pending"}
	if err = s.preflightSiteCreate(r.Context(), in.Domain); err != nil {
		s.auditMutation(r, "site.create", in.Domain, "failure")
		writeJSON(w, 409, map[string]any{"error": err.Error(), "duplicate": true})
		return
	}
	if s.cfg.Mock {
		if strings.TrimSpace(in.Username) == "" {
			accounts := s.hosting.ListAccounts()
			active := []hosting.Account{}
			for _, a := range accounts {
				if a.Status == "active" {
					active = append(active, a)
				}
			}
			if len(active) == 1 {
				in.Username = active[0].Username
			} else {
				err = errors.New("mock site creation needs one unambiguous hosting owner")
			}
		}
		if err == nil {
			site, err = s.hosting.CreateSite(in)
			if err == nil {
				if parent := s.bestHostedParentDomain(r.Context(), in.Domain); parent != "" {
					dnsResult = s.autoProvisionSubdomainDNS(r.Context(), parent, in.Domain)
					if updated, uerr := s.hosting.RecordSiteClassification(site.Domain, "subdomain", parent); uerr == nil {
						site = updated
					}
				} else {
					z, zerr := s.resources.CreateDNSZone(resources.DNSZone{Domain: in.Domain})
					if zerr == nil {
						dnsResult = map[string]any{"domain": z.Domain, "managed": true, "status": "managed-created", "records": z.Records}
					}
				}
				if st, _ := dnsResult["status"].(string); st != "" {
					if updated, uerr := s.hosting.RecordDNS(site.Domain, st); uerr == nil {
						site = updated
					}
				}
			}
		}
	} else if !s.cfg.HostMutations {
		err = fmt.Errorf("real host mutations are disabled; start agent with --host-mutations after certification")
	} else {
		in.Username, autoOwner, err = s.resolveSiteOwner(r.Context(), in.Domain, in.Username)
		if err == nil {
			res, provisionErr := s.host.ProvisionSite(r.Context(), in.Domain, in.Username, in.PHPVersion)
			err = provisionErr
			if err == nil {
				in.DocumentRoot = res.DocumentRoot
				s.host.InvalidateInventory()
				var parent string
				dnsResult, parent = s.autoProvisionHostedDNS(r.Context(), in.Domain)
				if parent != "" {
					in.Kind = "subdomain"
					in.ParentDomain = parent
				}
				if st, _ := dnsResult["status"].(string); strings.HasPrefix(st, "managed-") {
					in.DNS = "managed"
				} else {
					in.DNS = st
				}
				site, err = s.hosting.RecordProvisionedSite(in)
				if err == nil {
					s.host.InvalidateInventory()
					if live, ok := s.liveSite(r.Context(), in.Domain); ok {
						site.Domain = live.Domain
						site.Username = live.Username
						site.DocumentRoot = live.DocumentRoot
						site.PHPVersion = live.PHPVersion
						site.SSL = live.SSL
						if live.Enabled {
							site.Status = "active"
						} else {
							site.Status = "disabled"
						}
					}
				}
			}
		}
	}
	if err == nil {
		sslResult = s.autoProvisionSiteSSL(r.Context(), site)
	}
	if err != nil {
		s.auditMutation(r, "site.create", in.Domain, "failure")
		writeJSON(w, 400, map[string]any{"error": err.Error(), "automatic_owner_retained": autoOwner, "username": in.Username, "dns": dnsResult})
		return
	}
	s.auditMutation(r, "site.create", site.Domain, "success")
	writeJSON(w, 201, map[string]any{"ok": true, "site": site, "automatic_owner": autoOwner, "dns": dnsResult, "ssl": sslResult, "inventory_refreshed": true})
}

func managedSubdomainDeleteFilesAllowed(domain, username, documentRoot string, stateSites []hosting.Site, liveSites []hostadapter.LiveSite) (bool, string) {
	domain = strings.ToLower(strings.TrimSpace(domain))
	username = strings.TrimSpace(username)
	cleanRoot := filepath.Clean(strings.TrimSpace(documentRoot))
	ownTree := filepath.Clean(filepath.Join("/home", username, "domains", domain))
	if documentRoot == "" || cleanRoot == ownTree || !strings.HasPrefix(cleanRoot+string(os.PathSeparator), ownTree+string(os.PathSeparator)) {
		return false, "subdomain document root is shared or outside its dedicated domain tree"
	}
	for _, other := range stateSites {
		if strings.EqualFold(other.Domain, domain) {
			continue
		}
		if strings.TrimSpace(other.DocumentRoot) != "" && filepath.Clean(other.DocumentRoot) == cleanRoot {
			return false, "subdomain document root is shared with another managed website"
		}
	}
	for _, other := range liveSites {
		if strings.EqualFold(other.Domain, domain) {
			continue
		}
		if strings.TrimSpace(other.DocumentRoot) != "" && filepath.Clean(other.DocumentRoot) == cleanRoot {
			return false, "subdomain document root is shared with another live website"
		}
	}
	return true, ""
}

func (s *Server) deleteSite(w http.ResponseWriter, r *http.Request) {
	domain := strings.ToLower(strings.TrimSpace(r.PathValue("domain")))
	var in struct {
		DeleteFiles bool `json:"delete_files"`
		DeleteDNS   bool `json:"delete_dns"`
	}
	if r.Body != nil {
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<16)).Decode(&in); err != nil && !errors.Is(err, io.EOF) {
			writeJSON(w, 400, map[string]any{"error": "invalid JSON"})
			return
		}
	}
	stateSite, stateOK := s.hosting.GetSite(domain)
	if s.cfg.Mock {
		if !stateOK {
			writeJSON(w, 404, map[string]any{"error": "site not found"})
			return
		}
		dnsDeleted := false
		if in.DeleteDNS && stateSite.Kind == "subdomain" && stateSite.ParentDomain != "" {
			var dnsErr error
			dnsDeleted, dnsErr = s.deleteSubdomainDNS(r.Context(), stateSite)
			if dnsErr != nil {
				writeJSON(w, 400, map[string]any{"error": "subdomain DNS cleanup failed: " + dnsErr.Error()})
				return
			}
		} else if in.DeleteDNS && s.resources.HasDNSZone(domain) {
			_, _ = s.resources.DeleteDNSZone(domain)
			dnsDeleted = true
		}
		_, err := s.hosting.RemoveSite(domain)
		if err != nil {
			writeJSON(w, 400, map[string]any{"error": err.Error()})
			return
		}
		s.auditMutation(r, "site.delete", domain, "success")
		writeJSON(w, 200, map[string]any{"ok": true, "domain": domain, "files_deleted": in.DeleteFiles, "dns_deleted": dnsDeleted})
		return
	}
	if !s.cfg.HostMutations {
		writeJSON(w, 403, map[string]any{"error": "real host mutations are disabled"})
		return
	}
	s.host.InvalidateInventory()
	live, liveOK := s.liveSite(r.Context(), domain)
	if !liveOK && !stateOK {
		writeJSON(w, 404, map[string]any{"error": "site not found"})
		return
	}
	if liveOK && !live.Managed {
		writeJSON(w, 409, map[string]any{"error": "website is externally managed; adopt or remove its provider configuration before deleting it from Privora"})
		return
	}
	user := stateSite.Username
	if liveOK {
		user = live.Username
	}
	effectiveDeleteFiles := in.DeleteFiles
	filesPreservedReason := ""
	documentRoot := strings.TrimSpace(stateSite.DocumentRoot)
	if liveOK && strings.TrimSpace(live.DocumentRoot) != "" {
		documentRoot = strings.TrimSpace(live.DocumentRoot)
	}
	isManagedSubdomain := stateOK && (stateSite.Kind == "subdomain" || strings.TrimSpace(stateSite.ParentDomain) != "")
	if effectiveDeleteFiles && isManagedSubdomain {
		allowed, reason := managedSubdomainDeleteFilesAllowed(domain, user, documentRoot, s.hosting.ListSites(), s.host.DiscoverInventory(r.Context()).Sites)
		if !allowed {
			effectiveDeleteFiles = false
			filesPreservedReason = reason
		}
	}
	if liveOK {
		if err := s.host.DeleteSiteWithDocumentRoot(r.Context(), domain, user, documentRoot, effectiveDeleteFiles); err != nil {
			s.auditMutation(r, "site.delete", domain, "failure")
			writeJSON(w, 400, map[string]any{"error": err.Error()})
			return
		}
	}
	dnsDeleted := false
	if in.DeleteDNS {
		if stateOK && stateSite.Kind == "subdomain" && stateSite.ParentDomain != "" {
			var dnsErr error
			dnsDeleted, dnsErr = s.deleteSubdomainDNS(r.Context(), stateSite)
			if dnsErr != nil {
				writeJSON(w, 400, map[string]any{"error": "website removed but subdomain DNS cleanup failed: " + dnsErr.Error()})
				return
			}
		} else {
			for _, z := range s.host.DiscoverInventory(r.Context()).DNSZones {
				if z.Domain == domain && z.Managed {
					if err := s.host.DeleteBINDZone(r.Context(), domain); err != nil {
						writeJSON(w, 400, map[string]any{"error": "website removed but DNS cleanup failed: " + err.Error()})
						return
					}
					dnsDeleted = true
					break
				}
			}
			if s.resources.HasDNSZone(domain) {
				_, _ = s.resources.DeleteDNSZone(domain)
			}
		}
	}
	if stateOK {
		_, _ = s.hosting.RemoveSite(domain)
	}
	s.host.InvalidateInventory()
	s.auditMutation(r, "site.delete", domain, "success")
	response := map[string]any{"ok": true, "domain": domain, "files_deleted": effectiveDeleteFiles, "dns_deleted": dnsDeleted}
	if filesPreservedReason != "" {
		response["files_preserved"] = true
		response["files_preserved_reason"] = filesPreservedReason
	}
	writeJSON(w, 200, response)
}

func (s *Server) configFiles(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, 200, map[string]any{"files": s.host.EditableConfigs()})
}
func (s *Server) configFile(w http.ResponseWriter, r *http.Request) {
	d, content, err := s.host.ReadEditableConfig(r.PathValue("id"))
	if err != nil {
		writeJSON(w, 404, map[string]any{"error": err.Error()})
		return
	}
	writeJSON(w, 200, map[string]any{"file": d, "content": content})
}
func (s *Server) writeConfigFile(w http.ResponseWriter, r *http.Request) {
	if !s.cfg.HostMutations {
		writeJSON(w, 403, map[string]any{"error": "real host mutations are disabled"})
		return
	}
	var in struct {
		Content     string `json:"content"`
		ExpectedSHA string `json:"expected_sha"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 3<<20)).Decode(&in); err != nil {
		writeJSON(w, 400, map[string]any{"error": "invalid JSON"})
		return
	}
	v, err := s.host.WriteEditableConfig(r.Context(), r.PathValue("id"), in.Content, in.ExpectedSHA)
	outcome := "success"
	if err != nil {
		outcome = "failure"
	}
	s.auditMutation(r, "config.write", r.PathValue("id"), outcome)
	if err != nil {
		writeJSON(w, 400, map[string]any{"error": err.Error()})
		return
	}
	writeJSON(w, 200, map[string]any{"ok": true, "file": v})
}

func (s *Server) nameservers(w http.ResponseWriter, r *http.Request) {
	v := s.resources.Nameservers()
	sets := s.resources.NameserverSets()
	v4, v6 := s.host.PrimaryHostAddresses()
	registrar := s.host.RegistrarStatus()
	setup := make([]hostadapter.NameserverSetupStatus, 0, len(sets))
	for _, item := range sets {
		setup = append(setup, s.host.InspectNameserverSetup(r.Context(), hostadapter.NameserverSetupConfig{
			BaseDomain: item.BaseDomain,
			Primary:    item.Primary,
			Secondary:  item.Secondary,
			IPv4:       item.IPv4,
			IPv6:       item.IPv6,
			GlueStatus: item.GlueStatus,
		}))
	}
	note := "Local A/AAAA records are created automatically for every configured nameserver set."
	if registrar.Connected {
		note += " Registry glue/delegation synchronization is available through the connected registrar adapter."
	} else {
		note += " Registrar connection required for registry glue/delegation."
	}
	writeJSON(w, 200, map[string]any{"nameservers": v, "nameserver_sets": sets, "assignments": s.resources.NameserverAssignments(), "setup_status": setup, "detected_ipv4": v4, "detected_ipv6": v6, "registrar": registrar, "registrar_note": note})
}

func (s *Server) configureRegistrar(w http.ResponseWriter, r *http.Request) {
	if !s.cfg.HostMutations {
		writeJSON(w, 403, map[string]any{"error": "real host mutations are disabled"})
		return
	}
	var in hostadapter.RegistrarConnectionConfig
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<16)).Decode(&in); err != nil {
		writeJSON(w, 400, map[string]any{"error": "invalid JSON"})
		return
	}
	if err := s.host.ConfigureRegistrarConnection(r.Context(), in); err != nil {
		s.auditMutation(r, "dns.registrar.connect", in.Provider, "failure")
		writeJSON(w, 400, map[string]any{"error": err.Error()})
		return
	}
	s.auditMutation(r, "dns.registrar.connect", in.Provider, "success")
	writeJSON(w, 200, map[string]any{"ok": true, "provider": strings.TrimSpace(in.Provider), "status": "refresh-scheduled", "detail": "Registrar connection saved. Privora Agent will refresh momentarily."})
}

func (s *Server) setNameservers(w http.ResponseWriter, r *http.Request) {
	if !s.cfg.HostMutations {
		writeJSON(w, 403, map[string]any{"error": "real host mutations are disabled"})
		return
	}
	var in resources.NameserverConfig
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<16)).Decode(&in); err != nil {
		writeJSON(w, 400, map[string]any{"error": "invalid JSON"})
		return
	}
	in.BaseDomain = strings.ToLower(strings.TrimSpace(in.BaseDomain))
	in.Primary = strings.ToLower(strings.TrimSpace(in.Primary))
	in.Secondary = strings.ToLower(strings.TrimSpace(in.Secondary))
	if in.Primary == "" {
		in.Primary = "ns1." + in.BaseDomain
	}
	if in.Secondary == "" {
		in.Secondary = "ns2." + in.BaseDomain
	}
	v4, v6 := s.host.PrimaryHostAddresses()
	if strings.TrimSpace(in.IPv4) == "" {
		in.IPv4 = v4
	}
	if strings.TrimSpace(in.IPv6) == "" {
		in.IPv6 = v6
	}
	primaryLabel := strings.TrimSuffix(in.Primary, "."+in.BaseDomain)
	secondaryLabel := strings.TrimSuffix(in.Secondary, "."+in.BaseDomain)
	recs := []hostadapter.DNSRecord{}
	if publicAddress(in.IPv4) {
		recs = append(recs, hostadapter.DNSRecord{Type: "A", Name: primaryLabel, Value: in.IPv4, TTL: 3600}, hostadapter.DNSRecord{Type: "A", Name: secondaryLabel, Value: in.IPv4, TTL: 3600})
	}
	if publicAddress(in.IPv6) {
		recs = append(recs, hostadapter.DNSRecord{Type: "AAAA", Name: primaryLabel, Value: in.IPv6, TTL: 3600}, hostadapter.DNSRecord{Type: "AAAA", Name: secondaryLabel, Value: in.IPv6, TTL: 3600})
	}
	if len(recs) == 0 {
		writeJSON(w, 400, map[string]any{"error": "no public server address is available for authoritative nameservers"})
		return
	}
	var prov hostadapter.DNSProvisionResult
	var err error
	foundZone, managedZone := false, false
	s.host.InvalidateInventory()
	for _, z := range s.host.DiscoverInventory(r.Context()).DNSZones {
		if z.Domain == in.BaseDomain {
			foundZone = true
			managedZone = z.Managed
			break
		}
	}
	if foundZone && !managedZone {
		writeJSON(w, 409, map[string]any{"error": "base-domain DNS zone is externally managed; Privora will not overwrite it"})
		return
	}
	if foundZone {
		prov, err = s.host.RewriteBINDZoneNameservers(r.Context(), in.BaseDomain, in.Primary, in.Secondary, recs)
	} else {
		prov, err = s.host.ProvisionBINDZoneWithNameservers(r.Context(), in.BaseDomain, in.Primary, in.Secondary, recs)
	}
	if err != nil {
		s.auditMutation(r, "dns.nameservers.set", in.BaseDomain, "failure")
		writeJSON(w, 400, map[string]any{"error": err.Error()})
		return
	}
	// Local glue is complete at this point. Registry glue is pushed automatically
	// when a Privora-compatible registrar adapter is connected.
	regReq := hostadapter.RegistrarGlueRequest{BaseDomain: in.BaseDomain, Primary: in.Primary, Secondary: in.Secondary, IPv4: in.IPv4, IPv6: in.IPv6, Nameservers: []string{in.Primary, in.Secondary}}
	registrar, regErr := s.host.SyncRegistrarGlue(r.Context(), regReq)
	if regErr != nil {
		in.GlueStatus = "registrar-sync-failed"
		registrar = hostadapter.RegistrarGlueResult{Connected: true, Provider: s.host.RegistrarStatus().Provider, Status: "sync-failed", Detail: regErr.Error()}
	} else if registrar.Connected {
		in.GlueStatus = "registrar-glue-synced"
	} else {
		in.GlueStatus = "local-glue-ready"
	}
	oldDefault := strings.ToLower(strings.TrimSpace(s.resources.Nameservers().BaseDomain))
	if in.Default && oldDefault != "" && oldDefault != in.BaseDomain {
		existing := s.resources.NameserverAssignments()
		preserve := map[string]bool{}
		for _, site := range s.hosting.ListSites() {
			d := strings.ToLower(strings.TrimSpace(site.Domain))
			if d != "" && site.ParentDomain == "" && site.Kind != "subdomain" {
				preserve[d] = true
			}
		}
		for _, account := range s.hosting.ListAccounts() {
			if d := strings.ToLower(strings.TrimSpace(account.PrimaryDomain)); d != "" {
				preserve[d] = true
			}
		}
		for _, zone := range s.resources.ListDNSZones() {
			if d := strings.ToLower(strings.TrimSpace(zone.Domain)); d != "" {
				preserve[d] = true
			}
		}
		delete(preserve, in.BaseDomain)
		for domain := range preserve {
			if _, ok := existing[domain]; ok {
				continue
			}
			if _, assignErr := s.resources.SetNameserverAssignment(domain, oldDefault); assignErr != nil {
				writeJSON(w, 400, map[string]any{"error": "could not preserve existing nameserver assignment for " + domain + ": " + assignErr.Error()})
				return
			}
		}
	}
	saved, err := s.resources.SetNameservers(in)
	if err == nil {
		if _, assigned := s.resources.NameserverAssignments()[in.BaseDomain]; !assigned {
			_, _ = s.resources.SetNameserverAssignment(in.BaseDomain, in.BaseDomain)
		}
	}
	if err != nil {
		writeJSON(w, 400, map[string]any{"error": err.Error()})
		return
	}
	if live, err := s.host.ReadBINDZone(in.BaseDomain); err == nil {
		_, _ = s.resources.ReplaceDNSZoneRecords(in.BaseDomain, stateDNSRecords(live.Records))
	}
	s.host.InvalidateInventory()
	s.auditMutation(r, "dns.nameservers.set", in.BaseDomain, "success")
	writeJSON(w, 200, map[string]any{"ok": true, "nameservers": saved, "zone_file": prov.ZoneFile, "local_glue_created": true, "registrar": registrar, "registrar_glue_synced": registrar.Connected && registrar.Status == "synced"})
}

func (s *Server) setNameserverAssignment(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Domain     string `json:"domain"`
		BaseDomain string `json:"base_domain"`
	}
	if r.Body != nil {
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<16)).Decode(&in); err != nil && !errors.Is(err, io.EOF) {
			writeJSON(w, 400, map[string]any{"error": "invalid JSON"})
			return
		}
	}
	in.Domain = strings.ToLower(strings.Trim(strings.TrimSpace(in.Domain), "."))
	in.BaseDomain = strings.ToLower(strings.Trim(strings.TrimSpace(in.BaseDomain), "."))
	set, err := s.resources.SetNameserverAssignment(in.Domain, in.BaseDomain)
	if err != nil {
		writeJSON(w, 400, map[string]any{"error": err.Error()})
		return
	}
	// Reconcile the zone immediately so assignment is not merely UI metadata.
	result := s.autoProvisionSiteDNS(r.Context(), in.Domain)
	if managed, _ := result["managed"].(bool); !managed {
		writeJSON(w, 409, map[string]any{"error": result["reason"], "assignment_saved": true, "domain": in.Domain, "nameservers": set, "dns": result})
		return
	}
	s.auditMutation(r, "dns.nameserver.assignment", in.Domain, "success")
	writeJSON(w, 200, map[string]any{"ok": true, "domain": in.Domain, "nameservers": set, "dns": result})
}

func (s *Server) deleteNameservers(w http.ResponseWriter, r *http.Request) {
	if !s.cfg.HostMutations {
		writeJSON(w, 403, map[string]any{"error": "real host mutations are disabled"})
		return
	}
	var in struct {
		BaseDomain string `json:"base_domain"`
		Force      bool   `json:"force"`
	}
	if r.Body != nil {
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<16)).Decode(&in); err != nil && !errors.Is(err, io.EOF) {
			writeJSON(w, 400, map[string]any{"error": "invalid JSON"})
			return
		}
	}
	in.BaseDomain = strings.ToLower(strings.TrimSpace(in.BaseDomain))
	sets := s.resources.NameserverSets()
	if len(sets) == 0 {
		writeJSON(w, 404, map[string]any{"error": "no Privora nameservers are configured"})
		return
	}
	current := resources.NameserverConfig{}
	if in.BaseDomain == "" {
		current = s.resources.Nameservers()
		in.BaseDomain = current.BaseDomain
	} else {
		for _, candidate := range sets {
			if candidate.BaseDomain == in.BaseDomain {
				current = candidate
				break
			}
		}
	}
	if current.Primary == "" || current.BaseDomain == "" {
		writeJSON(w, 404, map[string]any{"error": "requested nameserver set was not found"})
		return
	}

	s.host.InvalidateInventory()
	deps := []string{}
	for _, z := range s.host.DiscoverInventory(r.Context()).DNSZones {
		if !z.Managed || z.Domain == current.BaseDomain {
			continue
		}
		live, err := s.host.ReadBINDZone(z.Domain)
		if err != nil {
			continue
		}
		for _, rec := range live.Records {
			if strings.EqualFold(rec.Type, "NS") && rec.Name == "@" {
				target := strings.TrimSuffix(strings.ToLower(strings.TrimSpace(rec.Value)), ".")
				if target == current.Primary || target == current.Secondary {
					deps = append(deps, z.Domain)
					break
				}
			}
		}
	}
	if len(deps) > 0 && !in.Force {
		writeJSON(w, 409, map[string]any{"error": "hosted DNS zones still depend on this nameserver set", "dependent_zones": deps, "force_available": true})
		return
	}

	// Prefer another configured nameserver set when dependent zones must be
	// reassigned. This keeps branded/shared server DNS intact. If no alternate
	// set exists, fall back to per-domain ns1/ns2 hostnames.
	alternate := resources.NameserverConfig{}
	for _, candidate := range sets {
		if candidate.BaseDomain == current.BaseDomain {
			continue
		}
		if candidate.Default {
			alternate = candidate
			break
		}
		if alternate.BaseDomain == "" {
			alternate = candidate
		}
	}
	v4, v6 := s.host.PrimaryHostAddresses()
	reassigned := []string{}
	if in.Force {
		for _, domain := range deps {
			primary, secondary := alternate.Primary, alternate.Secondary
			extra := []hostadapter.DNSRecord{}
			if primary == "" || secondary == "" {
				primary, secondary = "ns1."+domain, "ns2."+domain
				if publicAddress(v4) {
					extra = append(extra, hostadapter.DNSRecord{Type: "A", Name: "ns1", Value: v4, TTL: 3600}, hostadapter.DNSRecord{Type: "A", Name: "ns2", Value: v4, TTL: 3600})
				}
				if publicAddress(v6) {
					extra = append(extra, hostadapter.DNSRecord{Type: "AAAA", Name: "ns1", Value: v6, TTL: 3600}, hostadapter.DNSRecord{Type: "AAAA", Name: "ns2", Value: v6, TTL: 3600})
				}
			}
			if _, err := s.host.RewriteBINDZoneNameservers(r.Context(), domain, primary, secondary, extra); err != nil {
				writeJSON(w, 400, map[string]any{"error": "failed to reassign dependent zone " + domain + ": " + err.Error()})
				return
			}
			reassigned = append(reassigned, domain)
		}
	}

	registrar, regErr := s.host.DeleteRegistrarGlue(r.Context(), hostadapter.RegistrarGlueRequest{BaseDomain: current.BaseDomain, Primary: current.Primary, Secondary: current.Secondary, IPv4: current.IPv4, IPv6: current.IPv6, Nameservers: []string{current.Primary, current.Secondary}})
	if regErr != nil {
		registrar = hostadapter.RegistrarGlueResult{Connected: true, Provider: s.host.RegistrarStatus().Provider, Status: "delete-failed", Detail: regErr.Error()}
	}
	baseZoneDeleted := false
	if _, siteExists := s.liveSite(r.Context(), current.BaseDomain); !siteExists {
		for _, z := range s.host.DiscoverInventory(r.Context()).DNSZones {
			if z.Domain == current.BaseDomain && z.Managed {
				if err := s.host.DeleteBINDZone(r.Context(), current.BaseDomain); err == nil {
					baseZoneDeleted = true
					if s.resources.HasDNSZone(current.BaseDomain) {
						_, _ = s.resources.DeleteDNSZone(current.BaseDomain)
					}
				}
				break
			}
		}
	}
	if _, err := s.resources.DeleteNameserverSet(current.BaseDomain); err != nil {
		writeJSON(w, 400, map[string]any{"error": err.Error()})
		return
	}
	s.host.InvalidateInventory()
	s.auditMutation(r, "dns.nameservers.delete", current.BaseDomain, "success")
	writeJSON(w, 200, map[string]any{"ok": true, "base_domain": current.BaseDomain, "deleted": []string{current.Primary, current.Secondary}, "base_zone_deleted": baseZoneDeleted, "reassigned_zones": reassigned, "reassigned_to": alternate, "registrar": registrar, "registrar_cleanup_required": !registrar.Connected, "remaining_sets": s.resources.NameserverSets()})
}

func (s *Server) phpVersions(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, 200, map[string]any{"versions": s.host.PHPVersions(r.Context()), "policy": "curated-version-allow-list"})
}

func (s *Server) phpExtensions(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, 200, map[string]any{"extensions": s.host.PHPExtensions(r.Context()), "policy": "per-runtime-live-inventory"})
}

func (s *Server) installPHPVersion(w http.ResponseWriter, r *http.Request) {
	version := strings.TrimSpace(r.PathValue("version"))
	status, restarted, err := s.host.InstallPHPVersion(r.Context(), version)
	outcome := "success"
	if err != nil {
		outcome = "failure"
	}
	s.auditMutation(r, "php.version.install", version, outcome)
	if err != nil {
		writeJSON(w, 400, map[string]any{"error": err.Error(), "version": status, "restarted_services": restarted})
		return
	}
	writeJSON(w, 200, map[string]any{"ok": true, "version": status, "restarted_services": restarted})
}

func (s *Server) removePHPVersion(w http.ResponseWriter, r *http.Request) {
	version := strings.TrimSpace(r.PathValue("version"))
	used := []string{}
	if !s.cfg.Mock {
		inv := s.host.DiscoverInventory(r.Context())
		for _, site := range inv.Sites {
			if site.PHPVersion == version {
				used = append(used, site.Domain)
			}
		}
	}
	for _, site := range s.hosting.ListSites() {
		if site.PHPVersion == version {
			found := false
			for _, d := range used {
				if d == site.Domain {
					found = true
					break
				}
			}
			if !found {
				used = append(used, site.Domain)
			}
		}
	}
	sort.Strings(used)
	if len(used) > 0 {
		writeJSON(w, 409, map[string]any{"error": "PHP version is still assigned to hosted websites; migrate them before removal", "version": version, "websites": used})
		return
	}
	status, err := s.host.RemovePHPVersion(r.Context(), version)
	outcome := "success"
	if err != nil {
		outcome = "failure"
	}
	s.auditMutation(r, "php.version.remove", version, outcome)
	if err != nil {
		writeJSON(w, 400, map[string]any{"error": err.Error(), "version": status})
		return
	}
	writeJSON(w, 200, map[string]any{"ok": true, "version": status})
}

func (s *Server) phpRuntimes(w http.ResponseWriter, r *http.Request) {
	rows := s.host.PHPRuntimes(r.Context())
	writeJSON(w, 200, map[string]any{"runtimes": rows, "host_mutations_enabled": s.cfg.HostMutations && !s.cfg.Mock})
}

func (s *Server) setSitePHP(w http.ResponseWriter, r *http.Request) {
	domain := r.PathValue("domain")
	var in struct {
		Version string `json:"version"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<16)).Decode(&in); err != nil {
		writeJSON(w, 400, map[string]any{"error": "invalid JSON"})
		return
	}
	var site hosting.Site
	var err error
	if s.cfg.Mock {
		site, err = s.hosting.SetPHP(domain, in.Version)
	} else if !s.cfg.HostMutations {
		err = fmt.Errorf("real host mutations are disabled; start agent with --host-mutations after certification")
	} else {
		current, ok := s.hosting.GetSite(domain)
		if !ok {
			if live, liveOK := s.liveSite(r.Context(), domain); liveOK {
				current = hosting.Site{Domain: live.Domain, Username: live.Username, DocumentRoot: live.DocumentRoot, PHPVersion: live.PHPVersion, SSL: live.SSL, Status: "active"}
				ok = true
			}
		}
		if !ok {
			err = fmt.Errorf("site not found on live host")
		} else {
			_, err = s.host.SwitchSitePHP(r.Context(), current.Domain, current.Username, current.PHPVersion, in.Version)
			if err == nil {
				if _, exists := s.hosting.GetSite(domain); exists {
					site, err = s.hosting.RecordPHP(domain, in.Version)
				} else {
					current.PHPVersion = in.Version
					site = current
				}
			}
		}
	}
	if err != nil {
		s.auditMutation(r, "site.php.set", domain, "failure")
		writeJSON(w, 400, map[string]any{"error": err.Error()})
		return
	}
	s.auditMutation(r, "site.php.set", domain, "success")
	writeJSON(w, 200, map[string]any{"ok": true, "site": site})
}

func (s *Server) files(w http.ResponseWriter, r *http.Request) {
	user := r.PathValue("user")
	var items any
	var err error
	if s.cfg.Mock {
		items, err = s.hosting.ListFiles(user, r.URL.Query().Get("path"))
	} else if _, ok := s.liveAccount(r.Context(), user); !ok {
		err = fmt.Errorf("account not found on live host")
	} else {
		items, err = s.host.ListAccountFiles(user, r.URL.Query().Get("path"))
	}
	if err != nil {
		writeJSON(w, 400, map[string]any{"error": err.Error()})
		return
	}
	writeJSON(w, 200, map[string]any{"files": items, "path": r.URL.Query().Get("path")})
}
func (s *Server) writeFile(w http.ResponseWriter, r *http.Request) {
	user := r.PathValue("user")
	var in struct {
		Path    string `json:"path"`
		Content string `json:"content"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 2<<20)).Decode(&in); err != nil {
		writeJSON(w, 400, map[string]any{"error": "invalid JSON"})
		return
	}
	var v any
	var err error
	if s.cfg.Mock {
		v, err = s.hosting.WriteFile(user, in.Path, in.Content)
	} else if !s.cfg.HostMutations {
		err = fmt.Errorf("real host mutations are disabled")
	} else if _, ok := s.liveAccount(r.Context(), user); !ok {
		err = fmt.Errorf("account not found on live host")
	} else {
		v, err = s.host.WriteAccountFile(user, in.Path, in.Content)
	}
	out := "success"
	if err != nil {
		out = "failure"
	}
	s.auditMutation(r, "file.write", user+":"+in.Path, out)
	if err != nil {
		writeJSON(w, 400, map[string]any{"error": err.Error()})
		return
	}
	writeJSON(w, 201, map[string]any{"ok": true, "file": v})
}

func (s *Server) requireLiveFileUser(r *http.Request, user string) error {
	if s.cfg.Mock {
		return errors.New("advanced file operation unavailable in simulation")
	}
	if !s.cfg.HostMutations && r.Method != http.MethodGet {
		return errors.New("real host mutations are disabled")
	}
	if _, ok := s.liveAccount(r.Context(), user); !ok {
		return errors.New("account not found on live host")
	}
	return nil
}
func (s *Server) readFile(w http.ResponseWriter, r *http.Request) {
	user := r.PathValue("user")
	if err := s.requireLiveFileUser(r, user); err != nil {
		writeJSON(w, 400, map[string]any{"error": err.Error()})
		return
	}
	maxBytes := int64(4 << 20)
	if r.URL.Query().Get("download") == "1" {
		maxBytes = 32 << 20
	}
	v, err := s.host.ReadAccountFile(user, r.URL.Query().Get("path"), maxBytes)
	if err != nil {
		writeJSON(w, 400, map[string]any{"error": err.Error()})
		return
	}
	writeJSON(w, 200, map[string]any{"file": map[string]any{"path": v.Path, "name": v.Name, "size": v.Size, "mode": v.Mode, "modified": v.Modified, "content": string(v.Content), "content_base64": base64.StdEncoding.EncodeToString(v.Content)}})
}
func (s *Server) mkdirFile(w http.ResponseWriter, r *http.Request) {
	user := r.PathValue("user")
	if err := s.requireLiveFileUser(r, user); err != nil {
		writeJSON(w, 400, map[string]any{"error": err.Error()})
		return
	}
	var in struct {
		Path string `json:"path"`
	}
	if json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&in) != nil {
		writeJSON(w, 400, map[string]any{"error": "invalid JSON"})
		return
	}
	v, err := s.host.CreateAccountDirectory(user, in.Path)
	s.auditFileResult(r, "file.mkdir", user+":"+in.Path, err)
	if err != nil {
		writeJSON(w, 400, map[string]any{"error": err.Error()})
		return
	}
	writeJSON(w, 201, map[string]any{"ok": true, "file": v})
}
func (s *Server) uploadFile(w http.ResponseWriter, r *http.Request) {
	user := r.PathValue("user")
	if err := s.requireLiveFileUser(r, user); err != nil {
		writeJSON(w, 400, map[string]any{"error": err.Error()})
		return
	}
	var in struct {
		Path    string `json:"path"`
		Content string `json:"content_base64"`
	}
	if json.NewDecoder(http.MaxBytesReader(w, r.Body, 46<<20)).Decode(&in) != nil {
		writeJSON(w, 400, map[string]any{"error": "invalid JSON"})
		return
	}
	b, err := base64.StdEncoding.DecodeString(in.Content)
	if err != nil {
		writeJSON(w, 400, map[string]any{"error": "invalid upload encoding"})
		return
	}
	v, err := s.host.WriteAccountBytes(user, in.Path, b)
	s.auditFileResult(r, "file.upload", user+":"+in.Path, err)
	if err != nil {
		writeJSON(w, 400, map[string]any{"error": err.Error()})
		return
	}
	writeJSON(w, 201, map[string]any{"ok": true, "file": v})
}
func (s *Server) renameFile(w http.ResponseWriter, r *http.Request) {
	user := r.PathValue("user")
	if err := s.requireLiveFileUser(r, user); err != nil {
		writeJSON(w, 400, map[string]any{"error": err.Error()})
		return
	}
	var in struct {
		From string `json:"from"`
		To   string `json:"to"`
	}
	if json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&in) != nil {
		writeJSON(w, 400, map[string]any{"error": "invalid JSON"})
		return
	}
	err := s.host.RenameAccountPath(user, in.From, in.To)
	s.auditFileResult(r, "file.rename", user+":"+in.From+"->"+in.To, err)
	if err != nil {
		writeJSON(w, 400, map[string]any{"error": err.Error()})
		return
	}
	writeJSON(w, 200, map[string]any{"ok": true})
}
func (s *Server) copyFile(w http.ResponseWriter, r *http.Request) {
	user := r.PathValue("user")
	if err := s.requireLiveFileUser(r, user); err != nil {
		writeJSON(w, 400, map[string]any{"error": err.Error()})
		return
	}
	var in struct {
		From string `json:"from"`
		To   string `json:"to"`
	}
	if json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&in) != nil {
		writeJSON(w, 400, map[string]any{"error": "invalid JSON"})
		return
	}
	err := s.host.CopyAccountPath(user, in.From, in.To)
	s.auditFileResult(r, "file.copy", user+":"+in.From+"->"+in.To, err)
	if err != nil {
		writeJSON(w, 400, map[string]any{"error": err.Error()})
		return
	}
	writeJSON(w, 200, map[string]any{"ok": true})
}
func (s *Server) deleteFile(w http.ResponseWriter, r *http.Request) {
	user := r.PathValue("user")
	if err := s.requireLiveFileUser(r, user); err != nil {
		writeJSON(w, 400, map[string]any{"error": err.Error()})
		return
	}
	var in struct {
		Path string `json:"path"`
	}
	if json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&in) != nil {
		writeJSON(w, 400, map[string]any{"error": "invalid JSON"})
		return
	}
	err := s.host.DeleteAccountPath(user, in.Path)
	s.auditFileResult(r, "file.delete", user+":"+in.Path, err)
	if err != nil {
		writeJSON(w, 400, map[string]any{"error": err.Error()})
		return
	}
	writeJSON(w, 200, map[string]any{"ok": true})
}
func (s *Server) chmodFile(w http.ResponseWriter, r *http.Request) {
	user := r.PathValue("user")
	if err := s.requireLiveFileUser(r, user); err != nil {
		writeJSON(w, 400, map[string]any{"error": err.Error()})
		return
	}
	var in struct {
		Path string `json:"path"`
		Mode string `json:"mode"`
	}
	if json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&in) != nil {
		writeJSON(w, 400, map[string]any{"error": "invalid JSON"})
		return
	}
	n, err := strconv.ParseUint(strings.TrimPrefix(strings.TrimSpace(in.Mode), "0"), 8, 32)
	if err != nil || n > 0777 {
		writeJSON(w, 400, map[string]any{"error": "mode must be an octal permission such as 0644 or 0755"})
		return
	}
	err = s.host.ChmodAccountPath(user, in.Path, os.FileMode(n))
	s.auditFileResult(r, "file.chmod", user+":"+in.Path, err)
	if err != nil {
		writeJSON(w, 400, map[string]any{"error": err.Error()})
		return
	}
	writeJSON(w, 200, map[string]any{"ok": true})
}
func (s *Server) searchFiles(w http.ResponseWriter, r *http.Request) {
	user := r.PathValue("user")
	if err := s.requireLiveFileUser(r, user); err != nil {
		writeJSON(w, 400, map[string]any{"error": err.Error()})
		return
	}
	rows, err := s.host.SearchAccountFiles(user, r.URL.Query().Get("q"), 200)
	if err != nil {
		writeJSON(w, 400, map[string]any{"error": err.Error()})
		return
	}
	writeJSON(w, 200, map[string]any{"files": rows, "query": r.URL.Query().Get("q")})
}
func (s *Server) archiveFile(w http.ResponseWriter, r *http.Request) {
	user := r.PathValue("user")
	if err := s.requireLiveFileUser(r, user); err != nil {
		writeJSON(w, 400, map[string]any{"error": err.Error()})
		return
	}
	var in struct {
		Source      string `json:"source"`
		Destination string `json:"destination"`
	}
	if json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&in) != nil {
		writeJSON(w, 400, map[string]any{"error": "invalid JSON"})
		return
	}
	v, err := s.host.CreateAccountZip(user, in.Source, in.Destination)
	s.auditFileResult(r, "file.archive", user+":"+in.Source, err)
	if err != nil {
		writeJSON(w, 400, map[string]any{"error": err.Error()})
		return
	}
	writeJSON(w, 201, map[string]any{"ok": true, "file": v})
}
func (s *Server) extractFile(w http.ResponseWriter, r *http.Request) {
	user := r.PathValue("user")
	if err := s.requireLiveFileUser(r, user); err != nil {
		writeJSON(w, 400, map[string]any{"error": err.Error()})
		return
	}
	var in struct {
		Archive     string `json:"archive"`
		Destination string `json:"destination"`
	}
	if json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&in) != nil {
		writeJSON(w, 400, map[string]any{"error": "invalid JSON"})
		return
	}
	err := s.host.ExtractAccountZip(user, in.Archive, in.Destination)
	s.auditFileResult(r, "file.extract", user+":"+in.Archive, err)
	if err != nil {
		writeJSON(w, 400, map[string]any{"error": err.Error()})
		return
	}
	writeJSON(w, 200, map[string]any{"ok": true})
}
func (s *Server) auditFileResult(r *http.Request, op, res string, err error) {
	outcome := "success"
	if err != nil {
		outcome = "failure"
	}
	s.auditMutation(r, op, res, outcome)
}
func (s *Server) accountUsage(w http.ResponseWriter, r *http.Request) {
	user := r.PathValue("user")
	if s.cfg.Mock {
		writeJSON(w, 200, map[string]any{"analytics": map[string]any{"generated_at": time.Now().UTC(), "usage": map[string]any{"disk_bytes": 104857600, "file_count": 128, "directory_count": 24, "process_count": 2, "memory_bytes": 67108864, "cpu_minutes": 12.4}, "requests": 240, "bandwidth_bytes": 5242880, "unique_visitors": 42, "http_4xx": 8, "http_5xx": 1, "access_log_period": "simulation"}})
		return
	}
	if _, ok := s.liveAccount(r.Context(), user); !ok {
		writeJSON(w, 404, map[string]any{"error": "account not found on live host"})
		return
	}
	inv := s.host.DiscoverInventory(r.Context())
	domains := []string{}
	for _, site := range inv.Sites {
		if site.Username == user {
			domains = append(domains, site.Domain)
		}
	}
	v, err := s.host.AccountAnalytics(user, domains)
	if err != nil {
		writeJSON(w, 400, map[string]any{"error": err.Error()})
		return
	}
	var limit any
	for _, x := range s.platform.ListResourceLimits() {
		if x.Owner == user {
			limit = x
			break
		}
	}
	writeJSON(w, 200, map[string]any{"analytics": v, "resource_limit": limit, "domains": domains})
}

func (s *Server) sftpAccounts(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, 200, map[string]any{"sftp_accounts": s.resources.ListSFTPAccounts()})
}
func (s *Server) createSFTPAccount(w http.ResponseWriter, r *http.Request) {
	var in resources.SFTPAccount
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<16)).Decode(&in); err != nil {
		writeJSON(w, 400, map[string]any{"error": "invalid JSON"})
		return
	}
	var v resources.SFTPAccount
	var err error
	oneTimePassword := ""
	if s.cfg.Mock {
		v, err = s.resources.CreateSFTPAccount(in)
	} else if !s.cfg.HostMutations {
		err = fmt.Errorf("real host mutations are disabled")
	} else {
		if in.Owner == "" {
			in.Owner = in.Username
		}
		if in.Username != in.Owner {
			err = fmt.Errorf("real SFTP currently binds to the hosting account owner")
		} else if !s.hosting.HasAccount(in.Owner) {
			err = fmt.Errorf("hosting account not found")
		} else {
			var result hostadapter.SFTPProvisionResult
			result, err = s.host.EnableAccountSFTPPassword(r.Context(), in.Username)
			if err == nil {
				in.Root, in.Auth, in.Status = result.Root, result.Auth, result.Status
				oneTimePassword = result.Password
				v, err = s.resources.RecordRealSFTPAccount(in)
			}
		}
	}
	out := "success"
	if err != nil {
		out = "failure"
	}
	s.auditMutation(r, "sftp.account.create", in.Username, out)
	if err != nil {
		writeJSON(w, 400, map[string]any{"error": err.Error()})
		return
	}
	resp := map[string]any{"ok": true, "sftp_account": v}
	if oneTimePassword != "" {
		resp["credentials"] = map[string]any{"username": v.Username, "password": oneTimePassword, "secret_once": true}
	}
	writeJSON(w, 201, resp)
}
func (s *Server) firewallRules(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, 200, map[string]any{"firewall_rules": s.resources.ListFirewallRules()})
}
func (s *Server) createFirewallRule(w http.ResponseWriter, r *http.Request) {
	var in resources.FirewallRule
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<16)).Decode(&in); err != nil {
		writeJSON(w, 400, map[string]any{"error": "invalid JSON"})
		return
	}
	var v resources.FirewallRule
	var err error
	simulation := s.cfg.Mock
	if s.cfg.Mock {
		v, err = s.resources.CreateFirewallRule(in)
	} else if !s.cfg.HostMutations {
		err = fmt.Errorf("real host mutations are disabled")
	} else {
		existing := s.resources.ListFirewallRules()
		rules := make([]hostadapter.FirewallRule, 0, len(existing)+1)
		for _, item := range existing {
			rules = append(rules, hostadapter.FirewallRule{Direction: item.Direction, Protocol: item.Protocol, Port: item.Port, Source: item.Source, Action: item.Action})
		}
		rules = append(rules, hostadapter.FirewallRule{Direction: in.Direction, Protocol: in.Protocol, Port: in.Port, Source: in.Source, Action: in.Action})
		_, err = s.host.ApplyNftablesRules(r.Context(), rules)
		if err == nil {
			v, err = s.resources.RecordRealFirewallRule(in)
		}
	}
	out := "success"
	if err != nil {
		out = "failure"
	}
	s.auditMutation(r, "firewall.rule.create", in.Protocol+":"+fmt.Sprint(in.Port), out)
	if err != nil {
		writeJSON(w, 400, map[string]any{"error": err.Error()})
		return
	}
	writeJSON(w, 201, map[string]any{"ok": true, "firewall_rule": v, "simulation": simulation})
}
func (s *Server) applications(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, 200, map[string]any{"applications": s.resources.ListApplications()})
}
func (s *Server) createApplication(w http.ResponseWriter, r *http.Request) {
	var in resources.Application
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<16)).Decode(&in); err != nil {
		writeJSON(w, 400, map[string]any{"error": "invalid JSON"})
		return
	}
	v, err := s.resources.CreateApplication(in)
	out := "success"
	if err != nil {
		out = "failure"
	}
	s.auditMutation(r, "application.create", in.Domain, out)
	if err != nil {
		writeJSON(w, 400, map[string]any{"error": err.Error()})
		return
	}
	writeJSON(w, 201, map[string]any{"ok": true, "application": v, "simulation": true})
}

func (s *Server) resourceSummary(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, 200, s.resources.Summary())
}
func (s *Server) databases(w http.ResponseWriter, r *http.Request) {
	if s.cfg.Mock {
		writeJSON(w, 200, map[string]any{"databases": s.resources.ListDatabases(), "source": "privora-state"})
		return
	}
	inv := s.host.DiscoverInventory(r.Context())
	meta := map[string]resources.Database{}
	for _, d := range s.resources.ListDatabases() {
		meta[d.Name] = d
	}
	out := make([]map[string]any, 0, len(inv.Databases))
	for _, d := range inv.Databases {
		m := meta[d.Name]
		owner := d.Owner
		if owner == "" {
			owner = m.Owner
		}
		out = append(out, map[string]any{"name": d.Name, "engine": d.Engine, "owner": owner, "user": m.User, "status": "live", "source": d.Source, "managed": m.Name != ""})
	}
	writeJSON(w, 200, map[string]any{"databases": out, "source": "live-host", "collected_at": inv.CollectedAt, "warnings": inv.Warnings, "diagnostics": inv.Diagnostics})
}
func (s *Server) createDatabase(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Name     string `json:"name"`
		User     string `json:"user"`
		Engine   string `json:"engine"`
		Owner    string `json:"owner"`
		Password string `json:"password,omitempty"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&req); err != nil {
		writeJSON(w, 400, map[string]any{"error": "invalid JSON"})
		return
	}
	in := resources.Database{Name: strings.TrimSpace(req.Name), User: strings.TrimSpace(req.User), Engine: strings.TrimSpace(req.Engine), Owner: strings.TrimSpace(req.Owner)}
	if in.User == "" {
		in.User = in.Name
	}
	var v resources.Database
	var err error
	var oneTimePassword string
	generatedPassword := req.Password == ""
	if s.cfg.Mock {
		v, err = s.resources.CreateDatabase(in)
		if err == nil {
			if req.Password != "" {
				oneTimePassword = req.Password
			} else {
				oneTimePassword, _ = hostadapterTestPassword()
			}
		}
	} else if !s.cfg.HostMutations {
		err = fmt.Errorf("real host mutations are disabled")
	} else {
		if in.Owner != "" {
			if _, ok := s.liveAccount(r.Context(), in.Owner); !ok {
				err = fmt.Errorf("database owner account not found on live host")
			}
		}
		if err == nil {
			var result hostadapter.DatabaseProvisionResult
			if in.Engine == "mysql" {
				result, err = s.host.ProvisionMySQL(r.Context(), in.Name, in.User, req.Password)
			} else if in.Engine == "mariadb" {
				result, err = s.host.ProvisionMariaDB(r.Context(), in.Name, in.User, req.Password)
			} else if in.Engine == "postgresql" {
				result, err = s.host.ProvisionPostgreSQL(r.Context(), in.Name, in.User, req.Password)
			} else {
				err = fmt.Errorf("unsupported database engine")
			}
			if err == nil {
				in.User = result.User
				oneTimePassword = result.Password
				v, err = s.resources.RecordRealDatabase(in)
			}
		}
	}
	out := "success"
	if err != nil {
		out = "failure"
	}
	s.auditMutation(r, "database.create", in.Name, out)
	if err != nil {
		writeJSON(w, 400, map[string]any{"error": err.Error()})
		return
	}
	resp := map[string]any{"ok": true, "database": v}
	if oneTimePassword != "" {
		resp["credentials"] = map[string]any{"user": v.User, "password": oneTimePassword, "secret_once": true, "generated": generatedPassword}
	}
	writeJSON(w, 201, resp)
}
func (s *Server) rotateDatabasePassword(w http.ResponseWriter, r *http.Request) {
	name := strings.TrimSpace(r.PathValue("name"))
	d, ok := s.resources.DatabaseByName(name)
	if !ok {
		writeJSON(w, 404, map[string]any{"error": "database is not Privora-managed"})
		return
	}
	var req struct {
		Password string `json:"password,omitempty"`
	}
	if r.Body != nil {
		dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 8192))
		if err := dec.Decode(&req); err != nil && !errors.Is(err, io.EOF) {
			writeJSON(w, 400, map[string]any{"error": "invalid JSON"})
			return
		}
	}
	if s.cfg.Mock {
		password := req.Password
		if password == "" {
			password, _ = hostadapterTestPassword()
		}
		writeJSON(w, 200, map[string]any{"ok": true, "database": d, "credentials": map[string]any{"user": d.User, "password": password, "secret_once": true, "generated": req.Password == ""}, "simulation": true})
		return
	}
	password, err := s.host.RotateDatabasePassword(r.Context(), d.Engine, d.Name, d.User, req.Password)
	outcome := "success"
	if err != nil {
		outcome = "failure"
	}
	s.auditMutation(r, "database.password.rotate", name, outcome)
	if err != nil {
		writeJSON(w, 400, map[string]any{"error": err.Error()})
		return
	}
	writeJSON(w, 200, map[string]any{"ok": true, "database": d, "credentials": map[string]any{"user": d.User, "password": password, "secret_once": true, "generated": req.Password == ""}})
}
func (s *Server) renameDatabaseUser(w http.ResponseWriter, r *http.Request) {
	name := strings.TrimSpace(r.PathValue("name"))
	d, ok := s.resources.DatabaseByName(name)
	if !ok {
		writeJSON(w, 404, map[string]any{"error": "database is not Privora-managed"})
		return
	}
	var req struct {
		User     string `json:"user"`
		Password string `json:"password,omitempty"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 8192)).Decode(&req); err != nil {
		writeJSON(w, 400, map[string]any{"error": "invalid JSON"})
		return
	}
	newUser := strings.TrimSpace(req.User)
	if newUser == "" {
		writeJSON(w, 400, map[string]any{"error": "database user is required"})
		return
	}
	var password string
	var err error
	if s.cfg.Mock {
		password = req.Password
		if password == "" {
			password, _ = hostadapterTestPassword()
		}
	} else if !s.cfg.HostMutations {
		err = errors.New("real host mutations are disabled")
	} else {
		password, err = s.host.RenameDatabaseUser(r.Context(), d.Engine, d.Name, d.User, newUser, req.Password)
	}
	var updated resources.Database
	if err == nil {
		updated, err = s.resources.UpdateDatabaseUser(name, newUser)
	}
	outcome := "success"
	if err != nil {
		outcome = "failure"
	}
	s.auditMutation(r, "database.user.rename", name+":"+d.User+"->"+newUser, outcome)
	if err != nil {
		writeJSON(w, 400, map[string]any{"error": err.Error()})
		return
	}
	writeJSON(w, 200, map[string]any{"ok": true, "database": updated, "credentials": map[string]any{"user": newUser, "password": password, "secret_once": true, "generated": req.Password == ""}})
}
func hostadapterTestPassword() (string, error) { return "mock-password-not-for-production", nil }
func (s *Server) deleteDatabase(w http.ResponseWriter, r *http.Request) {
	name := strings.TrimSpace(r.PathValue("name"))
	d, ok := s.resources.DatabaseByName(name)
	if !ok {
		writeJSON(w, 404, map[string]any{"error": "database is not Privora-managed"})
		return
	}
	confirm := r.URL.Query().Get("confirm")
	if confirm != name {
		writeJSON(w, 400, map[string]any{"error": "database deletion requires exact name confirmation"})
		return
	}
	var err error
	if !s.cfg.Mock {
		if !s.cfg.HostMutations {
			err = errors.New("real host mutations are disabled")
		} else {
			err = s.host.DeleteDatabase(r.Context(), d.Engine, d.Name, d.User)
		}
	}
	if err == nil {
		err = s.resources.RemoveDatabase(name)
	}
	outcome := "success"
	if err != nil {
		outcome = "failure"
	}
	s.auditMutation(r, "database.delete", name, outcome)
	if err != nil {
		writeJSON(w, 400, map[string]any{"error": err.Error()})
		return
	}
	writeJSON(w, 200, map[string]any{"ok": true, "deleted": name})
}

func (s *Server) managedDatabase(name string) (resources.Database, bool) {
	return s.resources.DatabaseByName(strings.TrimSpace(name))
}

func (s *Server) inspectDatabase(w http.ResponseWriter, r *http.Request) {
	d, ok := s.managedDatabase(r.PathValue("name"))
	if !ok {
		writeJSON(w, 404, map[string]any{"error": "database is not Privora-managed"})
		return
	}
	if s.cfg.Mock {
		writeJSON(w, 200, map[string]any{"database": d, "inspection": map[string]any{"engine": d.Engine, "database": d.Name, "user": d.User, "status": "simulation"}, "simulation": true})
		return
	}
	info, err := s.host.InspectDatabase(r.Context(), d.Engine, d.Name, d.User)
	if err != nil {
		writeJSON(w, 400, map[string]any{"error": err.Error()})
		return
	}
	writeJSON(w, 200, map[string]any{"database": d, "inspection": info})
}

func (s *Server) maintainDatabase(w http.ResponseWriter, r *http.Request) {
	d, ok := s.managedDatabase(r.PathValue("name"))
	if !ok {
		writeJSON(w, 404, map[string]any{"error": "database is not Privora-managed"})
		return
	}
	var in struct {
		Action string `json:"action"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 8192)).Decode(&in); err != nil {
		writeJSON(w, 400, map[string]any{"error": "invalid JSON"})
		return
	}
	if s.cfg.Mock {
		writeJSON(w, 200, map[string]any{"ok": true, "database": d.Name, "action": in.Action, "simulation": true})
		return
	}
	text, err := s.host.MaintainDatabase(r.Context(), d.Engine, d.Name, in.Action)
	outcome := "success"
	if err != nil {
		outcome = "failure"
	}
	s.auditMutation(r, "database.maintenance."+strings.ToLower(in.Action), d.Name, outcome)
	if err != nil {
		writeJSON(w, 400, map[string]any{"error": err.Error()})
		return
	}
	if len(text) > 6000 {
		text = text[len(text)-6000:]
	}
	writeJSON(w, 200, map[string]any{"ok": true, "database": d.Name, "action": strings.ToLower(in.Action), "output": strings.TrimSpace(text)})
}

func (s *Server) exportDatabase(w http.ResponseWriter, r *http.Request) {
	d, ok := s.managedDatabase(r.PathValue("name"))
	if !ok {
		writeJSON(w, 404, map[string]any{"error": "database is not Privora-managed"})
		return
	}
	if d.Owner == "" {
		writeJSON(w, 409, map[string]any{"error": "database owner is unknown; export destination cannot be safely scoped"})
		return
	}
	if s.cfg.Mock {
		writeJSON(w, 200, map[string]any{"ok": true, "simulation": true, "database": d.Name})
		return
	}
	res, err := s.host.ExportDatabase(r.Context(), d.Engine, d.Name, d.Owner)
	outcome := "success"
	if err != nil {
		outcome = "failure"
	}
	s.auditMutation(r, "database.export", d.Name, outcome)
	if err != nil {
		writeJSON(w, 400, map[string]any{"error": err.Error()})
		return
	}
	writeJSON(w, 200, map[string]any{"ok": true, "export": res})
}

func (s *Server) importDatabase(w http.ResponseWriter, r *http.Request) {
	d, ok := s.managedDatabase(r.PathValue("name"))
	if !ok {
		writeJSON(w, 404, map[string]any{"error": "database is not Privora-managed"})
		return
	}
	if d.Owner == "" {
		writeJSON(w, 409, map[string]any{"error": "database owner is unknown; import source cannot be safely scoped"})
		return
	}
	var in struct {
		SourcePath string `json:"source_path"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<16)).Decode(&in); err != nil {
		writeJSON(w, 400, map[string]any{"error": "invalid JSON"})
		return
	}
	if strings.TrimSpace(in.SourcePath) == "" {
		writeJSON(w, 400, map[string]any{"error": "source_path is required"})
		return
	}
	if s.cfg.Mock {
		writeJSON(w, 200, map[string]any{"ok": true, "simulation": true, "database": d.Name, "source_path": in.SourcePath})
		return
	}
	err := s.host.ImportDatabase(r.Context(), d.Engine, d.Name, d.Owner, in.SourcePath)
	outcome := "success"
	if err != nil {
		outcome = "failure"
	}
	s.auditMutation(r, "database.import", d.Name, outcome)
	if err != nil {
		writeJSON(w, 400, map[string]any{"error": err.Error()})
		return
	}
	writeJSON(w, 200, map[string]any{"ok": true, "database": d.Name, "source_path": in.SourcePath})
}

func stateDNSRecords(rows []hostadapter.DNSRecord) []resources.DNSRecord {
	out := make([]resources.DNSRecord, 0, len(rows))
	for _, r := range rows {
		out = append(out, resources.DNSRecord{Type: r.Type, Name: r.Name, Value: r.Value, TTL: r.TTL})
	}
	return out
}

func hostDNSRecords(rows []resources.DNSRecord) []hostadapter.DNSRecord {
	out := make([]hostadapter.DNSRecord, 0, len(rows))
	for _, r := range rows {
		out = append(out, hostadapter.DNSRecord{Type: r.Type, Name: r.Name, Value: r.Value, TTL: r.TTL})
	}
	return out
}

func longestHostedParent(domain string, roots map[string]bool) string {
	domain = strings.ToLower(strings.Trim(strings.TrimSpace(domain), "."))
	best := ""
	for root := range roots {
		root = strings.ToLower(strings.Trim(strings.TrimSpace(root), "."))
		if root == "" || root == domain || !strings.HasSuffix(domain, "."+root) {
			continue
		}
		if len(root) > len(best) {
			best = root
		}
	}
	return best
}

func zoneHasChildAddress(records []hostadapter.DNSRecord, fullDomain, parent string) bool {
	name := strings.ToLower(strings.TrimSpace(subdomainRecordName(fullDomain, parent)))
	for _, rec := range records {
		owner := strings.ToLower(strings.Trim(strings.TrimSpace(rec.Name), "."))
		typ := strings.ToUpper(strings.TrimSpace(rec.Type))
		if owner == name && (typ == "A" || typ == "AAAA" || typ == "CNAME") {
			return true
		}
	}
	return false
}

func (s *Server) dnsZones(w http.ResponseWriter, r *http.Request) {
	if s.cfg.Mock {
		writeJSON(w, 200, map[string]any{"zones": s.resources.ListDNSZones(), "source": "privora-state"})
		return
	}
	// DNS Zone Manager must not depend on unrelated host probes (database/PHP/mail).
	// Use the narrow DNS inventory so a failure elsewhere cannot collapse the zone list.
	inv := s.host.DiscoverDNSInventory(r.Context())
	meta := map[string]resources.DNSZone{}
	for _, z := range s.resources.ListDNSZones() {
		meta[z.Domain] = z
	}
	out := make([]map[string]any, 0, len(inv.DNSZones)+len(meta))
	seen := map[string]bool{}
	liveZoneByDomain := map[string]hostadapter.LiveDNSZone{}
	parentRoots := map[string]bool{}
	for _, z := range inv.DNSZones {
		liveZoneByDomain[strings.ToLower(strings.TrimSpace(z.Domain))] = z
		parentRoots[strings.ToLower(strings.TrimSpace(z.Domain))] = true
	}
	for _, ns := range s.resources.NameserverSets() {
		if d := strings.ToLower(strings.TrimSpace(ns.BaseDomain)); d != "" {
			parentRoots[d] = true
		}
	}
	for _, account := range s.hosting.ListAccounts() {
		if d := strings.ToLower(strings.TrimSpace(account.PrimaryDomain)); d != "" {
			parentRoots[d] = true
		}
	}
	for _, z := range inv.DNSZones {
		records := []resources.DNSRecord{}
		var live hostadapter.ManagedBINDZone
		var err error
		if z.Managed {
			live, err = s.host.ReadBINDZone(z.Domain)
		} else if z.ZoneFile != "" {
			live, err = s.host.ReadBINDZoneFile(z.Domain, z.ZoneFile)
		}
		if err == nil && live.Domain != "" {
			records = stateDNSRecords(live.Records)
			if z.Managed {
				_, _ = s.resources.ReplaceDNSZoneRecords(z.Domain, records)
			}
		}
		m := meta[z.Domain]
		out = append(out, map[string]any{"domain": z.Domain, "dnssec": m.DNSSEC, "records": records, "status": "live", "managed": z.Managed, "source": z.Source, "zone_file": z.ZoneFile})
		seen[z.Domain] = true
	}

	// Confirm against the running authoritative nameserver before a recorded zone
	// can be marked missing. This prevents healthy loaded zones from remaining in
	// Needs attention after an effective-file discovery miss.
	for domain, m := range meta {
		if seen[domain] {
			continue
		}
		if ok, source := s.host.HasLocalAuthoritativeDNSZone(r.Context(), domain); ok {
			records := m.Records
			managed := false
			zoneFile := ""
			if live, err := s.host.ReadBINDZone(domain); err == nil && live.Domain != "" {
				records = stateDNSRecords(live.Records)
				managed = true
				zoneFile = live.ZoneFile
				_, _ = s.resources.ReplaceDNSZoneRecords(domain, records)
			}
			out = append(out, map[string]any{"domain": domain, "dnssec": m.DNSSEC, "records": records, "status": "live", "managed": managed, "source": source, "zone_file": zoneFile, "status_reason": "Authoritative zone confirmed from the running local nameserver after inventory scan miss."})
			seen[domain] = true
			continue
		}
		out = append(out, map[string]any{"domain": domain, "dnssec": m.DNSSEC, "records": m.Records, "status": "missing", "managed": true, "source": "privora-state", "zone_file": "", "status_reason": "Recorded in Privora but no loaded authoritative BIND zone was confirmed."})
		seen[domain] = true
	}

	// Nameserver base zones are especially important: if the local server gives
	// an authoritative answer for a configured nameserver set, surface that zone
	// even when named-checkconf is unavailable or the provider hides its file.
	for _, ns := range s.resources.NameserverSets() {
		domain := strings.ToLower(strings.TrimSpace(ns.BaseDomain))
		if domain == "" || seen[domain] {
			continue
		}
		status := s.host.InspectNameserverSetup(r.Context(), hostadapter.NameserverSetupConfig{BaseDomain: ns.BaseDomain, Primary: ns.Primary, Secondary: ns.Secondary, IPv4: ns.IPv4, IPv6: ns.IPv6, GlueStatus: ns.GlueStatus})
		if !status.DNSZoneConfigured {
			continue
		}
		m := meta[domain]
		out = append(out, map[string]any{"domain": domain, "dnssec": m.DNSSEC, "records": []resources.DNSRecord{}, "status": "live", "managed": false, "source": status.DNSZoneSource, "zone_file": "", "status_reason": "Authoritative zone is loaded locally but its zone file was not discovered; shown read-only."})
		seen[domain] = true
	}

	// Last-resort reconciliation for hosted domains. Some provider/imported BIND
	// layouts are authoritative locally but do not expose their zone file through
	// named-checkconf -p. Probe the exact zone apex against localhost and surface
	// it read-only instead of silently omitting it from DNS Zone Manager.
	candidates := map[string]bool{}
	for _, site := range inv.Sites {
		if d := strings.ToLower(strings.TrimSpace(site.Domain)); d != "" {
			candidates[d] = true
		}
	}
	for _, site := range s.hosting.ListSites() {
		if d := strings.ToLower(strings.TrimSpace(site.Domain)); d != "" {
			candidates[d] = true
		}
	}
	for _, account := range s.hosting.ListAccounts() {
		if d := strings.ToLower(strings.TrimSpace(account.PrimaryDomain)); d != "" {
			candidates[d] = true
		}
	}
	for _, ns := range s.resources.NameserverSets() {
		if d := strings.ToLower(strings.TrimSpace(ns.BaseDomain)); d != "" {
			candidates[d] = true
		}
	}
	authoritativeFallbacks := 0
	knownWithoutLocalZone := 0
	for domain := range candidates {
		if seen[domain] {
			continue
		}

		// A child hostname is not an authoritative zone. If it belongs beneath a
		// hosted parent zone, surface the relationship directly instead of
		// falsely labelling the child as an unconfigured zone.
		if parent := longestHostedParent(domain, parentRoots); parent != "" {
			configured := false
			reason := "Child hostname is served from parent DNS zone " + parent + "."
			if z, ok := liveZoneByDomain[parent]; ok {
				var live hostadapter.ManagedBINDZone
				var err error
				if z.Managed {
					live, err = s.host.ReadBINDZone(parent)
				} else if z.ZoneFile != "" {
					live, err = s.host.ReadBINDZoneFile(parent, z.ZoneFile)
				}
				if err == nil && live.Domain != "" {
					configured = zoneHasChildAddress(live.Records, domain, parent)
					if !configured {
						reason = "Parent zone " + parent + " is loaded, but the child A/AAAA/CNAME record is missing. Run Repair hosted DNS."
					}
				}
			}
			status := "parent-record-missing"
			if configured {
				status = "via-parent-zone"
			}
			out = append(out, map[string]any{"domain": domain, "dnssec": false, "records": []resources.DNSRecord{}, "status": status, "managed": false, "source": "parent-zone", "zone_file": "", "parent_zone": parent, "status_reason": reason})
			seen[domain] = true
			continue
		}

		if ok, source := s.host.HasLocalAuthoritativeDNSZone(r.Context(), domain); ok {
			m := meta[domain]
			out = append(out, map[string]any{"domain": domain, "dnssec": m.DNSSEC, "records": []resources.DNSRecord{}, "status": "live", "managed": false, "source": source, "zone_file": "", "status_reason": "Authoritative zone is loaded locally but its zone file was not discoverable; shown read-only."})
			seen[domain] = true
			authoritativeFallbacks++
			continue
		}

		// DNS Zone Manager is also the operator's domain-to-zone reconciliation
		// screen. A known hosted/root domain must never disappear merely because
		// no local authoritative zone can be confirmed. Keep it visible with an
		// explicit not-configured state so the operator can create/adopt its zone.
		m := meta[domain]
		out = append(out, map[string]any{"domain": domain, "dnssec": m.DNSSEC, "records": []resources.DNSRecord{}, "status": "not-configured", "managed": false, "source": "known-hosted-domain", "zone_file": "", "status_reason": "Domain is known to Privora, but no local authoritative BIND zone was confirmed. Create a Privora zone or keep DNS external."})
		seen[domain] = true
		knownWithoutLocalZone++
	}
	if inv.Diagnostics == nil {
		inv.Diagnostics = map[string]any{}
	}
	inv.Diagnostics["dns_local_authoritative_fallbacks"] = authoritativeFallbacks
	inv.Diagnostics["dns_known_without_local_zone"] = knownWithoutLocalZone

	sort.Slice(out, func(i, j int) bool { return fmt.Sprint(out[i]["domain"]) < fmt.Sprint(out[j]["domain"]) })
	writeJSON(w, 200, map[string]any{"zones": out, "source": "reconciled-live-host", "collected_at": inv.CollectedAt, "warnings": inv.Warnings, "diagnostics": inv.Diagnostics})
}

func (s *Server) dnsZone(w http.ResponseWriter, r *http.Request) {
	domain := strings.ToLower(strings.TrimSpace(r.PathValue("domain")))
	if s.cfg.Mock {
		for _, z := range s.resources.ListDNSZones() {
			if z.Domain == domain {
				writeJSON(w, 200, map[string]any{"zone": z, "managed": true, "source": "privora-state"})
				return
			}
		}
		writeJSON(w, 404, map[string]any{"error": "DNS zone not found"})
		return
	}
	s.host.InvalidateInventory()
	for _, z := range s.host.DiscoverInventory(r.Context()).DNSZones {
		if z.Domain != domain {
			continue
		}
		if !z.Managed {
			records := []resources.DNSRecord{}
			if z.ZoneFile != "" {
				if live, err := s.host.ReadBINDZoneFile(domain, z.ZoneFile); err == nil {
					records = stateDNSRecords(live.Records)
				}
			}
			writeJSON(w, 200, map[string]any{"zone": map[string]any{"domain": domain, "records": records, "zone_file": z.ZoneFile}, "managed": false, "source": z.Source})
			return
		}
		live, err := s.host.ReadBINDZone(domain)
		if err != nil {
			writeJSON(w, 400, map[string]any{"error": err.Error()})
			return
		}
		records := stateDNSRecords(live.Records)
		state, _ := s.resources.ReplaceDNSZoneRecords(domain, records)
		writeJSON(w, 200, map[string]any{"zone": map[string]any{"domain": domain, "dnssec": state.DNSSEC, "records": records, "zone_file": live.ZoneFile}, "managed": true, "source": z.Source})
		return
	}
	writeJSON(w, 404, map[string]any{"error": "DNS zone not found"})
}

func (s *Server) createDNSZone(w http.ResponseWriter, r *http.Request) {
	var in resources.DNSZone
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&in); err != nil {
		writeJSON(w, 400, map[string]any{"error": "invalid JSON"})
		return
	}
	in.Domain = strings.ToLower(strings.TrimSpace(in.Domain))
	var v resources.DNSZone
	var err error
	if s.cfg.Mock {
		v, err = s.resources.CreateDNSZone(in)
	} else if !s.cfg.HostMutations {
		err = fmt.Errorf("real host mutations are disabled")
	} else {
		s.host.InvalidateInventory()
		for _, z := range s.host.DiscoverInventory(r.Context()).DNSZones {
			if z.Domain == in.Domain {
				err = fmt.Errorf("DNS zone already exists on live host")
				break
			}
		}
		if err == nil {
			if len(in.Records) == 0 {
				v4, v6 := s.host.PrimaryHostAddresses()
				ns := s.nameserversForDomain(in.Domain)
				hostRows, stateRows := standardSiteDNSRecords(in.Domain, v4, v6, ns.Primary == "")
				_, stateRows = ensureConfiguredNameserverGlue(in.Domain, v4, v6, ns, hostRows, stateRows)
				in.Records = stateRows
			}
			ns := s.nameserversForDomain(in.Domain)
			if ns.Primary != "" && ns.Secondary != "" {
				_, err = s.host.ProvisionBINDZoneWithNameservers(r.Context(), in.Domain, ns.Primary, ns.Secondary, hostDNSRecords(in.Records))
			} else {
				_, err = s.host.ProvisionBINDZone(r.Context(), in.Domain, hostDNSRecords(in.Records))
			}
			if err == nil {
				v, err = s.resources.RecordRealDNSZone(in)
			}
		}
	}
	outcome := "success"
	if err != nil {
		outcome = "failure"
	}
	s.auditMutation(r, "dns.zone.create", in.Domain, outcome)
	if err != nil {
		writeJSON(w, 400, map[string]any{"error": err.Error()})
		return
	}
	s.host.InvalidateInventory()
	writeJSON(w, 201, map[string]any{"ok": true, "zone": v})
}

// repairHostedDNS replays the certified DNS provisioning contract for every
// hosted website. It exists both as an operator repair and as a regression
// recovery path for sites created by older builds that allowed the web-vhost
// transaction to succeed after DNS provisioning had degraded.
func (s *Server) repairHostedDNS(w http.ResponseWriter, r *http.Request) {
	if !s.cfg.Mock && !s.cfg.HostMutations {
		writeJSON(w, 403, map[string]any{"error": "real host mutations are disabled"})
		return
	}
	type candidate struct {
		Domain string
		Site   hosting.Site
		Known  bool
	}
	byDomain := map[string]candidate{}
	for _, site := range s.hosting.ListSites() {
		d := strings.ToLower(strings.TrimSpace(site.Domain))
		if d != "" {
			byDomain[d] = candidate{Domain: d, Site: site, Known: true}
		}
	}
	if !s.cfg.Mock {
		s.host.InvalidateInventory()
		for _, live := range s.host.DiscoverDNSInventory(r.Context()).Sites {
			d := strings.ToLower(strings.TrimSpace(live.Domain))
			if d == "" {
				continue
			}
			if _, exists := byDomain[d]; !exists {
				byDomain[d] = candidate{Domain: d}
			}
		}
	}
	items := make([]candidate, 0, len(byDomain))
	for _, item := range byDomain {
		items = append(items, item)
	}
	sort.Slice(items, func(i, j int) bool {
		// Parents before children so a repaired root zone is immediately
		// available to the subdomain reconciliation that follows.
		li := strings.Count(items[i].Domain, ".")
		lj := strings.Count(items[j].Domain, ".")
		if li != lj {
			return li < lj
		}
		return items[i].Domain < items[j].Domain
	})

	results := []map[string]any{}
	repaired, actionRequired := 0, 0
	for _, item := range items {
		res, parent := s.autoProvisionHostedDNS(r.Context(), item.Domain)
		status, _ := res["status"].(string)
		managed, _ := res["managed"].(bool)
		if item.Known {
			if parent != "" {
				_, _ = s.hosting.RecordSiteClassification(item.Domain, "subdomain", parent)
			}
			recordStatus := status
			if managed {
				recordStatus = "managed"
			}
			if recordStatus != "" {
				_, _ = s.hosting.RecordDNS(item.Domain, recordStatus)
			}
		}
		if managed {
			repaired++
		} else if status == "action-required" || status == "external-parent-zone" {
			actionRequired++
		}
		row := map[string]any{"domain": item.Domain, "status": status, "managed": managed}
		if parent != "" {
			row["parent_zone"] = parent
		}
		if reason, ok := res["reason"]; ok {
			row["reason"] = reason
		}
		if zoneFile, ok := res["zone_file"]; ok {
			row["zone_file"] = zoneFile
		}
		results = append(results, row)
	}
	s.host.InvalidateInventory()
	s.auditMutation(r, "dns.hosted.repair", "all-hosted-sites", "success")
	writeJSON(w, 200, map[string]any{"ok": true, "scanned": len(items), "repaired": repaired, "action_required": actionRequired, "results": results})
}

func (s *Server) upsertDNSRecord(w http.ResponseWriter, r *http.Request) {
	domain := strings.ToLower(strings.TrimSpace(r.PathValue("domain")))
	var in resources.DNSRecord
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<16)).Decode(&in); err != nil {
		writeJSON(w, 400, map[string]any{"error": "invalid JSON"})
		return
	}
	if strings.EqualFold(strings.TrimSpace(in.Type), "NS") && strings.TrimSpace(in.Name) == "@" {
		writeJSON(w, 400, map[string]any{"error": "authoritative root NS records are managed by Nameserver Manager"})
		return
	}
	if s.cfg.Mock {
		zones := s.resources.ListDNSZones()
		var found *resources.DNSZone
		for _, z := range zones {
			if z.Domain == domain {
				zc := z
				found = &zc
				break
			}
		}
		if found == nil {
			writeJSON(w, 404, map[string]any{"error": "DNS zone not found"})
			return
		}
		key := strings.ToLower(strings.TrimSpace(in.Name)) + "|" + strings.ToUpper(strings.TrimSpace(in.Type))
		rows := []resources.DNSRecord{}
		for _, x := range found.Records {
			if strings.ToLower(strings.TrimSpace(x.Name))+"|"+strings.ToUpper(strings.TrimSpace(x.Type)) != key {
				rows = append(rows, x)
			}
		}
		rows = append(rows, in)
		v, err := s.resources.ReplaceDNSZoneRecords(domain, rows)
		if err != nil {
			writeJSON(w, 400, map[string]any{"error": err.Error()})
			return
		}
		writeJSON(w, 200, map[string]any{"ok": true, "zone": v})
		return
	}
	if !s.cfg.HostMutations {
		writeJSON(w, 403, map[string]any{"error": "real host mutations are disabled"})
		return
	}
	prov, err := s.host.UpsertBINDRecords(r.Context(), domain, []hostadapter.DNSRecord{{Type: in.Type, Name: in.Name, Value: in.Value, TTL: in.TTL}})
	if err != nil {
		s.auditMutation(r, "dns.record.upsert", domain, "failure")
		writeJSON(w, 400, map[string]any{"error": err.Error()})
		return
	}
	live, err := s.host.ReadBINDZone(domain)
	if err != nil {
		writeJSON(w, 400, map[string]any{"error": err.Error()})
		return
	}
	v, _ := s.resources.ReplaceDNSZoneRecords(domain, stateDNSRecords(live.Records))
	s.host.InvalidateInventory()
	s.auditMutation(r, "dns.record.upsert", domain+":"+in.Name+":"+in.Type, "success")
	writeJSON(w, 200, map[string]any{"ok": true, "zone": v, "zone_file": prov.ZoneFile})
}

func protectedAuthorityRecord(r resources.DNSRecord) bool {
	typ := strings.ToUpper(strings.TrimSpace(r.Type))
	name := strings.TrimSuffix(strings.ToLower(strings.TrimSpace(r.Name)), ".")
	return typ == "SOA" || (typ == "NS" && (name == "" || name == "@"))
}

func (s *Server) replaceDNSRecord(w http.ResponseWriter, r *http.Request) {
	domain := strings.ToLower(strings.TrimSpace(r.PathValue("domain")))
	var in struct {
		Original    resources.DNSRecord `json:"original"`
		Replacement resources.DNSRecord `json:"replacement"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<16)).Decode(&in); err != nil {
		writeJSON(w, 400, map[string]any{"error": "invalid JSON"})
		return
	}
	if protectedAuthorityRecord(in.Original) || protectedAuthorityRecord(in.Replacement) {
		writeJSON(w, 400, map[string]any{"error": "SOA and authoritative root NS records are protected; use Nameserver Manager for root authority"})
		return
	}
	if s.cfg.Mock {
		var found *resources.DNSZone
		for _, z := range s.resources.ListDNSZones() {
			if z.Domain == domain {
				zc := z
				found = &zc
				break
			}
		}
		if found == nil {
			writeJSON(w, 404, map[string]any{"error": "DNS zone not found"})
			return
		}
		rows := append([]resources.DNSRecord(nil), found.Records...)
		replaced := false
		for i, x := range rows {
			if !replaced && strings.EqualFold(strings.TrimSpace(x.Type), strings.TrimSpace(in.Original.Type)) && strings.EqualFold(strings.TrimSpace(x.Name), strings.TrimSpace(in.Original.Name)) && strings.EqualFold(strings.TrimSpace(x.Value), strings.TrimSpace(in.Original.Value)) {
				rows[i] = in.Replacement
				replaced = true
			}
		}
		if !replaced {
			writeJSON(w, 404, map[string]any{"error": "original DNS record not found"})
			return
		}
		v, err := s.resources.ReplaceDNSZoneRecords(domain, rows)
		if err != nil {
			writeJSON(w, 400, map[string]any{"error": err.Error()})
			return
		}
		writeJSON(w, 200, map[string]any{"ok": true, "zone": v})
		return
	}
	if !s.cfg.HostMutations {
		writeJSON(w, 403, map[string]any{"error": "real host mutations are disabled"})
		return
	}
	prov, err := s.host.ReplaceBINDRecord(r.Context(), domain, hostadapter.DNSRecord{Type: in.Original.Type, Name: in.Original.Name, Value: in.Original.Value, TTL: in.Original.TTL}, hostadapter.DNSRecord{Type: in.Replacement.Type, Name: in.Replacement.Name, Value: in.Replacement.Value, TTL: in.Replacement.TTL})
	if err != nil {
		s.auditMutation(r, "dns.record.replace", domain, "failure")
		writeJSON(w, 400, map[string]any{"error": err.Error()})
		return
	}
	live, err := s.host.ReadBINDZone(domain)
	if err != nil {
		writeJSON(w, 400, map[string]any{"error": err.Error()})
		return
	}
	v, _ := s.resources.ReplaceDNSZoneRecords(domain, stateDNSRecords(live.Records))
	s.host.InvalidateInventory()
	s.auditMutation(r, "dns.record.replace", domain+":"+in.Original.Name+":"+in.Original.Type, "success")
	writeJSON(w, 200, map[string]any{"ok": true, "zone": v, "zone_file": prov.ZoneFile})
}

func (s *Server) deleteDNSRecord(w http.ResponseWriter, r *http.Request) {
	domain := strings.ToLower(strings.TrimSpace(r.PathValue("domain")))
	var in resources.DNSRecord
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<16)).Decode(&in); err != nil {
		writeJSON(w, 400, map[string]any{"error": "invalid JSON"})
		return
	}
	if s.cfg.Mock {
		var rows []resources.DNSRecord
		found := false
		for _, z := range s.resources.ListDNSZones() {
			if z.Domain != domain {
				continue
			}
			found = true
			removed := false
			for _, x := range z.Records {
				match := strings.EqualFold(x.Type, in.Type) && strings.EqualFold(x.Name, in.Name) && (strings.TrimSpace(in.Value) == "" || strings.EqualFold(x.Value, in.Value))
				if match && !removed {
					removed = true
					continue
				}
				rows = append(rows, x)
			}
		}
		if !found {
			writeJSON(w, 404, map[string]any{"error": "DNS zone not found"})
			return
		}
		v, _ := s.resources.ReplaceDNSZoneRecords(domain, rows)
		writeJSON(w, 200, map[string]any{"ok": true, "zone": v})
		return
	}
	if !s.cfg.HostMutations {
		writeJSON(w, 403, map[string]any{"error": "real host mutations are disabled"})
		return
	}
	_, err := s.host.DeleteBINDRecord(r.Context(), domain, hostadapter.DNSRecord{Type: in.Type, Name: in.Name, Value: in.Value, TTL: in.TTL})
	if err != nil {
		s.auditMutation(r, "dns.record.delete", domain, "failure")
		writeJSON(w, 400, map[string]any{"error": err.Error()})
		return
	}
	live, _ := s.host.ReadBINDZone(domain)
	v, _ := s.resources.ReplaceDNSZoneRecords(domain, stateDNSRecords(live.Records))
	s.host.InvalidateInventory()
	s.auditMutation(r, "dns.record.delete", domain+":"+in.Name+":"+in.Type, "success")
	writeJSON(w, 200, map[string]any{"ok": true, "zone": v})
}

func (s *Server) deleteDNSZone(w http.ResponseWriter, r *http.Request) {
	domain := strings.ToLower(strings.TrimSpace(r.PathValue("domain")))
	if s.cfg.Mock {
		v, err := s.resources.DeleteDNSZone(domain)
		if err != nil {
			writeJSON(w, 404, map[string]any{"error": err.Error()})
			return
		}
		writeJSON(w, 200, map[string]any{"ok": true, "zone": v})
		return
	}
	if !s.cfg.HostMutations {
		writeJSON(w, 403, map[string]any{"error": "real host mutations are disabled"})
		return
	}
	for _, ns := range s.resources.NameserverSets() {
		if ns.BaseDomain != "" && ns.BaseDomain == domain {
			writeJSON(w, 409, map[string]any{"error": "this zone owns a configured nameserver set; delete that nameserver set first"})
			return
		}
	}
	s.host.InvalidateInventory()
	managed := false
	for _, z := range s.host.DiscoverInventory(r.Context()).DNSZones {
		if z.Domain == domain {
			if !z.Managed {
				writeJSON(w, 409, map[string]any{"error": "DNS zone is externally managed"})
				return
			}
			managed = true
			break
		}
	}
	if !managed {
		writeJSON(w, 404, map[string]any{"error": "DNS zone not found"})
		return
	}
	if err := s.host.DeleteBINDZone(r.Context(), domain); err != nil {
		s.auditMutation(r, "dns.zone.delete", domain, "failure")
		writeJSON(w, 400, map[string]any{"error": err.Error()})
		return
	}
	if s.resources.HasDNSZone(domain) {
		_, _ = s.resources.DeleteDNSZone(domain)
	}
	s.host.InvalidateInventory()
	s.auditMutation(r, "dns.zone.delete", domain, "success")
	writeJSON(w, 200, map[string]any{"ok": true, "domain": domain})
}
func (s *Server) certificates(w http.ResponseWriter, r *http.Request) {
	if s.cfg.Mock {
		writeJSON(w, 200, map[string]any{"certificates": s.resources.ListCertificates(), "source": "privora-state"})
		return
	}
	inv := s.host.DiscoverInventory(r.Context())
	out := make([]map[string]any, 0, len(inv.Certificates))
	now := time.Now().UTC()
	for _, c := range inv.Certificates {
		days := int(c.ExpiresAt.Sub(now).Hours() / 24)
		renewal := "manual"
		if c.AutoRenew {
			renewal = "automatic"
		}
		out = append(out, map[string]any{"domain": c.Domain, "provider": c.Provider, "status": c.Status, "expires_at": c.ExpiresAt, "days_remaining": days, "auto_renew": c.AutoRenew, "renewal": renewal, "active": true, "source": c.Source})
	}
	writeJSON(w, 200, map[string]any{"certificates": out, "source": "live-host", "collected_at": inv.CollectedAt, "warnings": inv.Warnings, "diagnostics": inv.Diagnostics})
}
func (s *Server) issueCertificate(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Domain string `json:"domain"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<16)).Decode(&in); err != nil {
		writeJSON(w, 400, map[string]any{"error": "invalid JSON"})
		return
	}
	var v resources.Certificate
	var err error
	if s.cfg.Mock {
		v, err = s.resources.IssueCertificate(in.Domain)
	} else if !s.cfg.HostMutations {
		err = fmt.Errorf("real host mutations are disabled")
	} else {
		site, ok := s.hosting.GetSite(in.Domain)
		if !ok {
			if live, liveOK := s.liveSite(r.Context(), in.Domain); liveOK {
				site = hosting.Site{Domain: live.Domain, Username: live.Username, DocumentRoot: live.DocumentRoot, PHPVersion: live.PHPVersion}
				ok = true
			}
		}
		if !ok {
			err = fmt.Errorf("site not found on live host for certificate domain")
		} else {
			result, issueErr := s.host.IssueLetsEncryptWebroot(r.Context(), in.Domain, site.DocumentRoot, "hostmaster@"+strings.ToLower(strings.TrimSpace(in.Domain)))
			if issueErr != nil {
				err = issueErr
			} else {
				var installErr error
				if s.host.IsManagedMailChallengeHost(in.Domain) {
					installErr = s.host.InstallLetsEncryptMailTLS(r.Context(), in.Domain, result)
				} else {
					installErr = s.host.InstallLetsEncryptNginxTLS(r.Context(), in.Domain, site.Username, site.PHPVersion, site.DocumentRoot, result)
				}
				if installErr != nil {
					err = installErr
				} else {
					v, err = s.resources.RecordRealCertificate(resources.Certificate{Domain: result.Domain, Provider: result.Provider, ExpiresAt: result.ExpiresAt})
					if err == nil {
						_, _ = s.hosting.RecordSSL(in.Domain, "valid")
						s.host.InvalidateInventory()
					}
				}
			}
		}
	}
	out := "success"
	if err != nil {
		out = "failure"
	}
	s.auditMutation(r, "ssl.issue", in.Domain, out)
	if err != nil {
		writeJSON(w, 400, map[string]any{"error": err.Error()})
		return
	}
	writeJSON(w, 201, map[string]any{"ok": true, "certificate": v})
}
func (s *Server) runAutoSSL(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Owner         string `json:"owner,omitempty"`
		Domain        string `json:"domain,omitempty"`
		PreflightOnly bool   `json:"preflight_only,omitempty"`
	}
	if r.Body != nil {
		_ = json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<16)).Decode(&in)
	}
	in.Domain = strings.ToLower(strings.TrimSpace(in.Domain))
	inv := s.host.DiscoverInventory(r.Context())
	sites := inv.Sites
	certs := map[string]hostadapter.LiveCertificate{}
	for _, c := range inv.Certificates {
		certs[strings.ToLower(c.Domain)] = c
	}
	type result struct {
		Domain string `json:"domain"`
		Status string `json:"status"`
		Detail string `json:"detail"`
	}
	out := []result{}
	issued := 0
	ready := 0
	skipped := 0
	pending := 0
	blocked := 0
	failed := 0
	scanned := 0
	for _, site := range sites {
		if in.Owner != "" && site.Username != in.Owner {
			continue
		}
		if in.Domain != "" && !strings.EqualFold(site.Domain, in.Domain) {
			continue
		}
		scanned++
		if c, ok := certs[strings.ToLower(site.Domain)]; ok && c.ExpiresAt.After(time.Now().UTC().Add(30*24*time.Hour)) {
			skipped++
			out = append(out, result{site.Domain, "valid", c.ExpiresAt.Format(time.RFC3339)})
			continue
		}
		if s.cfg.Mock {
			_, err := s.resources.IssueCertificate(site.Domain)
			if err != nil {
				failed++
				out = append(out, result{site.Domain, "failed", err.Error()})
			} else {
				issued++
				out = append(out, result{site.Domain, "issued", "mock certificate"})
			}
			continue
		}
		if !s.cfg.HostMutations {
			failed++
			out = append(out, result{site.Domain, "failed", "real host mutations are disabled"})
			continue
		}
		pre := s.host.PreflightLetsEncryptDomain(r.Context(), site.Domain)
		if !pre.Ready {
			pending++
			out = append(out, result{site.Domain, "pending", pre.Detail})
			continue
		}
		httpPre := s.host.PreflightLetsEncryptHTTP01(r.Context(), site.Domain, site.DocumentRoot)
		if !httpPre.Ready {
			blocked++
			out = append(out, result{site.Domain, "blocked", httpPre.Detail})
			continue
		}
		if in.PreflightOnly {
			ready++
			out = append(out, result{site.Domain, "ready", httpPre.Status + ": " + httpPre.Detail})
			continue
		}
		acme, err := s.host.IssueLetsEncryptWebroot(r.Context(), site.Domain, site.DocumentRoot, "hostmaster@"+strings.ToLower(site.Domain))
		if err != nil {
			failed++
			out = append(out, result{site.Domain, "failed", err.Error()})
			continue
		}
		if s.host.IsManagedMailChallengeHost(site.Domain) {
			err = s.host.InstallLetsEncryptMailTLS(r.Context(), site.Domain, acme)
		} else {
			err = s.host.InstallLetsEncryptNginxTLS(r.Context(), site.Domain, site.Username, site.PHPVersion, site.DocumentRoot, acme)
		}
		if err != nil {
			failed++
			out = append(out, result{site.Domain, "failed", err.Error()})
			continue
		}
		if _, err = s.resources.RecordRealCertificate(resources.Certificate{Domain: acme.Domain, Provider: acme.Provider, ExpiresAt: acme.ExpiresAt}); err != nil {
			failed++
			out = append(out, result{site.Domain, "failed", err.Error()})
			continue
		}
		_, _ = s.hosting.RecordSSL(site.Domain, "valid")
		s.host.InvalidateInventory()
		issued++
		out = append(out, result{site.Domain, "issued", acme.ExpiresAt.Format(time.RFC3339)})
	}
	outcome := "success"
	if failed > 0 {
		outcome = "partial"
	}
	target := in.Domain
	if target == "" {
		target = in.Owner
	}
	s.auditMutation(r, "ssl.autossl", target, outcome)
	writeJSON(w, 200, map[string]any{"ok": failed == 0 && blocked == 0, "scanned": scanned, "ready": ready, "issued": issued, "skipped": skipped, "pending": pending, "blocked": blocked, "failed": failed, "preflight_only": in.PreflightOnly, "results": out})
}

func (s *Server) certificateSite(ctx context.Context, domain string) (hosting.Site, bool) {
	domain = strings.ToLower(strings.TrimSpace(domain))
	site, ok := s.hosting.GetSite(domain)
	if ok {
		return site, true
	}
	if live, yes := s.liveSite(ctx, domain); yes {
		return hosting.Site{Domain: live.Domain, Username: live.Username, DocumentRoot: live.DocumentRoot, PHPVersion: live.PHPVersion}, true
	}
	return hosting.Site{}, false
}

func (s *Server) inspectCertificate(w http.ResponseWriter, r *http.Request) {
	domain := strings.ToLower(strings.TrimSpace(r.PathValue("domain")))
	if s.cfg.Mock {
		writeJSON(w, 200, map[string]any{"domain": domain, "simulation": true})
		return
	}
	info, err := s.host.InspectCertificate(r.Context(), domain)
	if err != nil {
		writeJSON(w, 404, map[string]any{"error": err.Error()})
		return
	}
	writeJSON(w, 200, map[string]any{"certificate": info})
}

func (s *Server) generateCertificateCSR(w http.ResponseWriter, r *http.Request) {
	domain := strings.ToLower(strings.TrimSpace(r.PathValue("domain")))
	if s.cfg.Mock {
		writeJSON(w, 200, map[string]any{"domain": domain, "simulation": true})
		return
	}
	res, err := s.host.GenerateCSR(r.Context(), domain)
	outcome := "success"
	if err != nil {
		outcome = "failure"
	}
	s.auditMutation(r, "ssl.csr.generate", domain, outcome)
	if err != nil {
		writeJSON(w, 400, map[string]any{"error": err.Error()})
		return
	}
	writeJSON(w, 200, map[string]any{"ok": true, "csr": res})
}

func (s *Server) installCustomCertificate(w http.ResponseWriter, r *http.Request) {
	domain := strings.ToLower(strings.TrimSpace(r.PathValue("domain")))
	site, ok := s.certificateSite(r.Context(), domain)
	if !ok {
		writeJSON(w, 404, map[string]any{"error": "hosted website not found"})
		return
	}
	var in struct {
		Certificate string `json:"certificate"`
		PrivateKey  string `json:"private_key"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 768<<10)).Decode(&in); err != nil {
		writeJSON(w, 400, map[string]any{"error": "invalid JSON"})
		return
	}
	if s.cfg.Mock {
		writeJSON(w, 200, map[string]any{"ok": true, "simulation": true, "domain": domain})
		return
	}
	res, err := s.host.InstallCustomCertificate(r.Context(), domain, site.Username, site.PHPVersion, site.DocumentRoot, in.Certificate, in.PrivateKey)
	outcome := "success"
	if err != nil {
		outcome = "failure"
	}
	s.auditMutation(r, "ssl.custom.install", domain, outcome)
	if err != nil {
		writeJSON(w, 400, map[string]any{"error": err.Error()})
		return
	}
	cert, err := s.resources.RecordRealCertificate(resources.Certificate{Domain: res.Domain, Provider: "custom", ExpiresAt: res.ExpiresAt})
	if err != nil {
		writeJSON(w, 500, map[string]any{"error": err.Error()})
		return
	}
	_, _ = s.hosting.RecordSSL(domain, "valid")
	s.host.InvalidateInventory()
	writeJSON(w, 200, map[string]any{"ok": true, "certificate": cert})
}

func (s *Server) revokeCertificate(w http.ResponseWriter, r *http.Request) {
	domain := strings.ToLower(strings.TrimSpace(r.PathValue("domain")))
	site, ok := s.certificateSite(r.Context(), domain)
	if !ok {
		writeJSON(w, 404, map[string]any{"error": "hosted website not found"})
		return
	}
	if s.cfg.Mock {
		_ = s.resources.RemoveCertificate(domain)
		writeJSON(w, 200, map[string]any{"ok": true, "simulation": true})
		return
	}
	if err := s.host.RevokeLetsEncryptCertificate(r.Context(), domain); err != nil {
		s.auditMutation(r, "ssl.revoke", domain, "failure")
		writeJSON(w, 400, map[string]any{"error": err.Error()})
		return
	}
	if _, err := s.host.ProvisionSite(r.Context(), site.Domain, site.Username, site.PHPVersion); err != nil {
		s.auditMutation(r, "ssl.revoke", domain, "failure-http-restore")
		writeJSON(w, 500, map[string]any{"error": "certificate revoked but HTTP-only vhost restoration failed: " + err.Error()})
		return
	}
	_ = s.resources.RemoveCertificate(domain)
	_, _ = s.hosting.RecordSSL(domain, "none")
	s.host.InvalidateInventory()
	s.auditMutation(r, "ssl.revoke", domain, "success")
	writeJSON(w, 200, map[string]any{"ok": true, "domain": domain, "https_disabled": true})
}

func (s *Server) backups(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, 200, map[string]any{"backups": s.resources.ListBackups()})
}
func (s *Server) createBackup(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Scope       string `json:"scope"`
		Resource    string `json:"resource"`
		Destination string `json:"destination"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<16)).Decode(&in); err != nil {
		writeJSON(w, 400, map[string]any{"error": "invalid JSON"})
		return
	}
	var v resources.Backup
	var err error
	if s.cfg.Mock {
		v, err = s.resources.CreateBackup(in.Scope, in.Resource, in.Destination)
	} else if !s.cfg.HostMutations {
		err = fmt.Errorf("real host mutations are disabled")
	} else if in.Destination != "" && in.Destination != "local" {
		err = fmt.Errorf("only certified local backups are enabled in this gate")
	} else {
		var source string
		switch in.Scope {
		case "account":
			if live, ok := s.liveAccount(r.Context(), in.Resource); ok {
				source = live.Home
			}
		case "site":
			if live, ok := s.liveSite(r.Context(), in.Resource); ok {
				source = filepath.Dir(live.DocumentRoot)
			}
		default:
			err = fmt.Errorf("real local backup supports account or site scope")
		}
		if err == nil && source == "" {
			err = fmt.Errorf("backup resource not found")
		}
		if err == nil {
			root := s.cfg.BackupRoot
			if root == "" {
				root = "/var/backups/privora-panel"
			}
			name := strings.NewReplacer("/", "_", "\\", "_", "..", "_").Replace(in.Resource)
			dst := filepath.Join(root, name+"-"+time.Now().UTC().Format("20060102T150405Z")+".tar.zst")
			var br hostadapter.BackupResult
			br, err = s.host.CreateLocalBackup(r.Context(), source, dst)
			if err == nil {
				v, err = s.resources.RecordRealBackup(in.Scope, in.Resource, br.Path, br.SHA256, uint64(br.Size))
			}
		}
	}
	out := "success"
	if err != nil {
		out = "failure"
	}
	s.auditMutation(r, "backup.create", in.Resource, out)
	if err != nil {
		writeJSON(w, 400, map[string]any{"error": err.Error()})
		return
	}
	writeJSON(w, 201, map[string]any{"ok": true, "backup": v})
}
func (s *Server) restoreBackup(w http.ResponseWriter, r *http.Request) {
	id := strings.TrimSpace(r.PathValue("id"))
	b, ok := s.resources.BackupByID(id)
	if !ok {
		writeJSON(w, 404, map[string]any{"error": "backup not found"})
		return
	}
	var in struct {
		ConfirmResource string `json:"confirm_resource"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<16)).Decode(&in); err != nil {
		writeJSON(w, 400, map[string]any{"error": "invalid JSON"})
		return
	}
	if in.ConfirmResource != b.Resource {
		writeJSON(w, 400, map[string]any{"error": "type the exact backup resource to confirm restore"})
		return
	}
	if s.cfg.Mock {
		writeJSON(w, 200, map[string]any{"ok": true, "backup": b, "simulation": true, "message": "mock restore verified; no host files changed"})
		return
	}
	if !s.cfg.HostMutations {
		writeJSON(w, 403, map[string]any{"error": "real host mutations are disabled"})
		return
	}
	if b.Scope != "site" {
		writeJSON(w, 400, map[string]any{"error": "real restore is currently certified for site backups only; account/server restore remains gated"})
		return
	}
	live, ok := s.liveSite(r.Context(), b.Resource)
	if !ok {
		writeJSON(w, 404, map[string]any{"error": "site restore target not found on live host"})
		return
	}
	target := filepath.Dir(live.DocumentRoot)
	result, err := s.host.RestoreLocalBackup(r.Context(), b.Destination, b.SHA256, target)
	outcome := "success"
	if err != nil {
		outcome = "failure"
	}
	s.auditMutation(r, "backup.restore", b.Resource, outcome)
	if err != nil {
		writeJSON(w, 400, map[string]any{"error": err.Error()})
		return
	}
	writeJSON(w, 200, map[string]any{"ok": true, "backup": b, "restore": result})
}

func (s *Server) mailboxes(w http.ResponseWriter, r *http.Request) {
	if s.cfg.Mock {
		writeJSON(w, 200, map[string]any{"mailboxes": s.resources.ListMailboxes(), "source": "privora-state"})
		return
	}
	inv := s.host.DiscoverInventory(r.Context())
	meta := map[string]resources.Mailbox{}
	for _, m := range s.resources.ListMailboxes() {
		meta[strings.ToLower(m.Address)] = m
	}
	out := make([]map[string]any, 0, len(inv.Mailboxes))
	for _, live := range inv.Mailboxes {
		m := meta[strings.ToLower(live.Address)]
		quota := m.QuotaMB
		if quota == 0 {
			quota = 1024
		}
		out = append(out, map[string]any{"address": live.Address, "domain": live.Domain, "quota_mb": quota, "status": "live", "source": live.Source})
	}
	writeJSON(w, 200, map[string]any{"mailboxes": out, "source": "live-host", "collected_at": inv.CollectedAt, "warnings": inv.Warnings, "diagnostics": inv.Diagnostics})
}
func (s *Server) createMailbox(w http.ResponseWriter, r *http.Request) {
	var request struct {
		Address  string `json:"address"`
		QuotaMB  int    `json:"quota_mb"`
		Password string `json:"password"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<16)).Decode(&request); err != nil {
		writeJSON(w, 400, map[string]any{"error": "invalid JSON"})
		return
	}
	if len(request.Password) < 12 || len(request.Password) > 128 || strings.ContainsAny(request.Password, "\x00\r\n") {
		writeJSON(w, 400, map[string]any{"error": "mailbox password must be 12-128 characters and contain no control line breaks"})
		return
	}
	in := resources.Mailbox{Address: request.Address, QuotaMB: request.QuotaMB}
	var v resources.Mailbox
	var err error
	oneTimePassword := ""
	if s.cfg.Mock {
		v, err = s.resources.CreateMailbox(in)
	} else if !s.cfg.HostMutations {
		err = fmt.Errorf("real host mutations are disabled")
	} else {
		parts := strings.Split(strings.ToLower(strings.TrimSpace(in.Address)), "@")
		ownedDomain := false
		if len(parts) == 2 {
			for _, site := range s.host.DiscoverInventory(r.Context()).Sites {
				if site.Domain == parts[1] {
					ownedDomain = true
					break
				}
			}
		}
		if !ownedDomain {
			err = fmt.Errorf("mailbox domain is not attached to a Privora site")
		} else {
			var result hostadapter.MailboxProvisionResult
			result, err = s.host.ProvisionMailboxWithPassword(r.Context(), in.Address, in.QuotaMB, request.Password)
			if err == nil {
				in.Address, in.Domain, in.QuotaMB, in.Status = result.Address, result.Domain, result.QuotaMB, result.Status
				oneTimePassword = result.Password
				v, err = s.resources.RecordRealMailbox(in)
			}
		}
	}
	out := "success"
	if err != nil {
		out = "failure"
	}
	s.auditMutation(r, "mailbox.create", in.Address, out)
	if err != nil {
		writeJSON(w, 400, map[string]any{"error": err.Error()})
		return
	}
	resp := map[string]any{"ok": true, "mailbox": v}
	if oneTimePassword != "" {
		resp["credentials"] = map[string]any{"address": v.Address, "password": oneTimePassword, "secret_once": true}
	}
	writeJSON(w, 201, resp)
}
func (s *Server) updateMailbox(w http.ResponseWriter, r *http.Request) {
	address := strings.ToLower(strings.TrimSpace(r.PathValue("address")))
	var in struct {
		QuotaMB  int    `json:"quota_mb"`
		Password string `json:"password"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<16)).Decode(&in); err != nil {
		writeJSON(w, 400, map[string]any{"error": "invalid JSON"})
		return
	}
	var v resources.Mailbox
	var err error
	if s.cfg.Mock {
		v, err = s.resources.UpdateMailboxMetadata(address, in.QuotaMB)
	} else if !s.cfg.HostMutations {
		err = fmt.Errorf("real host mutations are disabled")
	} else {
		parts := strings.Split(address, "@")
		ownedDomain := false
		if len(parts) == 2 {
			for _, site := range s.host.DiscoverInventory(r.Context()).Sites {
				if strings.EqualFold(site.Domain, parts[1]) {
					ownedDomain = true
					break
				}
			}
		}
		if !ownedDomain {
			err = fmt.Errorf("mailbox domain is not attached to a Privora site")
		} else {
			var updated hostadapter.MailboxProvisionResult
			updated, err = s.host.UpdateMailbox(r.Context(), address, in.QuotaMB, in.Password)
			if err == nil {
				v, err = s.resources.UpdateMailboxMetadata(updated.Address, updated.QuotaMB)
			}
		}
	}
	outcome := "success"
	if err != nil {
		outcome = "failure"
	}
	s.auditMutation(r, "mailbox.update", address, outcome)
	if err != nil {
		writeJSON(w, 400, map[string]any{"error": err.Error()})
		return
	}
	writeJSON(w, 200, map[string]any{"ok": true, "mailbox": v, "password_changed": in.Password != ""})
}

func (s *Server) deleteMailbox(w http.ResponseWriter, r *http.Request) {
	address := strings.ToLower(strings.TrimSpace(r.PathValue("address")))
	var err error
	if s.cfg.Mock {
		err = s.resources.RemoveMailbox(address)
	} else if !s.cfg.HostMutations {
		err = fmt.Errorf("real host mutations are disabled")
	} else {
		parts := strings.Split(address, "@")
		ownedDomain := false
		if len(parts) == 2 {
			for _, site := range s.host.DiscoverInventory(r.Context()).Sites {
				if strings.EqualFold(site.Domain, parts[1]) {
					ownedDomain = true
					break
				}
			}
		}
		if !ownedDomain {
			err = fmt.Errorf("mailbox domain is not attached to a Privora site")
		} else if err = s.host.DeleteMailbox(r.Context(), address); err == nil {
			err = s.resources.ForgetMailbox(address)
		}
	}
	outcome := "success"
	if err != nil {
		outcome = "failure"
	}
	s.auditMutation(r, "mailbox.delete", address, outcome)
	if err != nil {
		writeJSON(w, 400, map[string]any{"error": err.Error()})
		return
	}
	writeJSON(w, 200, map[string]any{"ok": true, "address": address, "status": "deleted"})
}

func (s *Server) resellers(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, 200, map[string]any{"resellers": s.resources.ListResellers()})
}
func (s *Server) createReseller(w http.ResponseWriter, r *http.Request) {
	var in resources.Reseller
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<16)).Decode(&in); err != nil {
		writeJSON(w, 400, map[string]any{"error": "invalid JSON"})
		return
	}
	v, err := s.resources.CreateReseller(in)
	out := "success"
	if err != nil {
		out = "failure"
	}
	s.auditMutation(r, "reseller.create", in.Name, out)
	if err != nil {
		writeJSON(w, 400, map[string]any{"error": err.Error()})
		return
	}
	writeJSON(w, 201, map[string]any{"ok": true, "reseller": v})
}
func (s *Server) updateReseller(w http.ResponseWriter, r *http.Request) {
	name := strings.ToLower(strings.TrimSpace(r.PathValue("name")))
	var in resources.Reseller
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&in); err != nil {
		writeJSON(w, 400, map[string]any{"error": "invalid JSON"})
		return
	}
	v, err := s.resources.UpdateReseller(name, in)
	resultAudit(s, r, "reseller.update", name, err)
	if err != nil {
		writeJSON(w, 400, map[string]any{"error": err.Error()})
		return
	}
	writeJSON(w, 200, map[string]any{"ok": true, "reseller": v})
}
func (s *Server) deleteReseller(w http.ResponseWriter, r *http.Request) {
	name := strings.ToLower(strings.TrimSpace(r.PathValue("name")))
	for _, a := range s.hosting.ListAccounts() {
		if a.Reseller == name {
			writeJSON(w, 409, map[string]any{"error": "reseller still owns hosting accounts", "account": a.Username})
			return
		}
	}
	err := s.resources.DeleteReseller(name)
	resultAudit(s, r, "reseller.delete", name, err)
	if err != nil {
		writeJSON(w, 400, map[string]any{"error": err.Error()})
		return
	}
	writeJSON(w, 200, map[string]any{"ok": true, "name": name})
}

func (s *Server) nodes(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, 200, map[string]any{"nodes": s.resources.ListNodes()})
}
func (s *Server) createNode(w http.ResponseWriter, r *http.Request) {
	var in resources.Node
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<16)).Decode(&in); err != nil {
		writeJSON(w, 400, map[string]any{"error": "invalid JSON"})
		return
	}
	v, err := s.resources.CreateNode(in)
	out := "success"
	if err != nil {
		out = "failure"
	}
	s.auditMutation(r, "fleet.node.enroll", in.Name, out)
	if err != nil {
		writeJSON(w, 400, map[string]any{"error": err.Error()})
		return
	}
	writeJSON(w, 201, map[string]any{"ok": true, "node": v, "simulation": true})
}
func (s *Server) instances(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, 200, map[string]any{"instances": s.resources.ListInstances()})
}
func (s *Server) createInstance(w http.ResponseWriter, r *http.Request) {
	var in resources.Instance
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<16)).Decode(&in); err != nil {
		writeJSON(w, 400, map[string]any{"error": "invalid JSON"})
		return
	}
	v, err := s.resources.CreateInstance(in)
	out := "success"
	if err != nil {
		out = "failure"
	}
	s.auditMutation(r, "cloud.instance.create", in.Provider+":"+in.Region, out)
	if err != nil {
		writeJSON(w, 400, map[string]any{"error": err.Error()})
		return
	}
	writeJSON(w, 201, map[string]any{"ok": true, "instance": v, "simulation": true})
}
func (s *Server) workloads(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, 200, map[string]any{"workloads": s.resources.ListWorkloads()})
}
func (s *Server) createWorkload(w http.ResponseWriter, r *http.Request) {
	var in resources.Workload
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<16)).Decode(&in); err != nil {
		writeJSON(w, 400, map[string]any{"error": "invalid JSON"})
		return
	}
	v, err := s.resources.CreateWorkload(in)
	out := "success"
	if err != nil {
		out = "failure"
	}
	s.auditMutation(r, "fabric.workload.place", in.Name, out)
	if err != nil {
		writeJSON(w, 400, map[string]any{"error": err.Error()})
		return
	}
	writeJSON(w, 201, map[string]any{"ok": true, "workload": v, "simulation": true})
}

func (s *Server) automations(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, 200, map[string]any{"automations": s.resources.ListAutomations()})
}
func (s *Server) automationProvision(w http.ResponseWriter, r *http.Request) {
	if !s.cfg.Mock {
		writeJSON(w, 501, map[string]any{"error": "billing/provider-backed automation is not enabled in this build"})
		return
	}
	var in struct {
		Customer   string `json:"customer"`
		Username   string `json:"username"`
		Domain     string `json:"domain"`
		Package    string `json:"package"`
		PHPVersion string `json:"php_version"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&in); err != nil {
		writeJSON(w, 400, map[string]any{"error": "invalid JSON"})
		return
	}
	if in.PHPVersion == "" {
		in.PHPVersion = "8.4"
	}
	steps := []string{}
	a, err := s.hosting.CreateAccount(hosting.Account{Username: in.Username, PrimaryDomain: in.Domain, Package: in.Package})
	if err != nil {
		s.auditMutation(r, "automation.provision", in.Domain, "failure")
		_, _ = s.resources.RecordAutomation(in.Customer, in.Domain, in.Package, "failed", append(steps, "account: "+err.Error()))
		writeJSON(w, 400, map[string]any{"error": err.Error(), "steps": steps})
		return
	}
	steps = append(steps, "account-created:"+a.Username)
	site, err := s.hosting.CreateSite(hosting.Site{Domain: in.Domain, Username: in.Username, PHPVersion: in.PHPVersion})
	if err != nil {
		s.auditMutation(r, "automation.provision", in.Domain, "failure")
		_, _ = s.resources.RecordAutomation(in.Customer, in.Domain, in.Package, "partial", append(steps, "site: "+err.Error()))
		writeJSON(w, 400, map[string]any{"error": err.Error(), "steps": steps})
		return
	}
	steps = append(steps, "site-created:"+site.Domain)
	if _, err := s.resources.CreateDNSZone(resources.DNSZone{Domain: in.Domain}); err == nil {
		steps = append(steps, "dns-zone-created")
	} else {
		steps = append(steps, "dns-zone-skipped:"+err.Error())
	}
	if _, err := s.resources.IssueCertificate(in.Domain); err == nil {
		steps = append(steps, "certificate-issued")
	} else {
		steps = append(steps, "certificate-failed:"+err.Error())
	}
	run, _ := s.resources.RecordAutomation(in.Customer, in.Domain, in.Package, "simulated-complete", steps)
	s.auditMutation(r, "automation.provision", in.Domain, "success")
	writeJSON(w, 201, map[string]any{"ok": true, "simulation": true, "run": run, "account": a, "site": site})
}

func (s *Server) verifyBillingLedger(w http.ResponseWriter, _ *http.Request) {
	if s.ledgerErr != nil || s.ledger == nil {
		err := s.ledgerErr
		if err == nil {
			err = fmt.Errorf("billing ledger unavailable")
		}
		writeJSON(w, 500, map[string]any{"ok": false, "error": err.Error()})
		return
	}
	if err := s.ledger.Verify(); err != nil {
		writeJSON(w, 409, map[string]any{"ok": false, "valid": false, "error": err.Error()})
		return
	}
	writeJSON(w, 200, map[string]any{"ok": true, "valid": true, "hash_chained": true, "double_entry": true})
}

func (s *Server) postBillingTransaction(w http.ResponseWriter, r *http.Request) {
	if s.ledgerErr != nil || s.ledger == nil {
		err := s.ledgerErr
		if err == nil {
			err = fmt.Errorf("billing ledger unavailable")
		}
		writeJSON(w, 500, map[string]any{"error": err.Error()})
		return
	}
	var in billingledger.Transaction
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&in); err != nil {
		writeJSON(w, 400, map[string]any{"error": "invalid JSON"})
		return
	}
	tx, err := s.ledger.Post(in)
	out := "success"
	if err != nil {
		out = "failure"
	}
	s.auditMutation(r, "billing.ledger.post", in.IdempotencyKey, out)
	if err != nil {
		writeJSON(w, 400, map[string]any{"error": err.Error()})
		return
	}
	writeJSON(w, 201, map[string]any{"ok": true, "transaction": tx, "payment_provider": "not-connected", "double_entry": true, "hash_chained": true})
}

func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("Content-Security-Policy", "default-src 'none'; frame-ancestors 'none'")
		next.ServeHTTP(w, r)
	})
}

var _ = fmt.Sprintf
var _ = regexp.MustCompile
