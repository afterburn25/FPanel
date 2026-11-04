package platform

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"
)

var ownerRx = regexp.MustCompile(`^[a-z][a-z0-9_]{2,23}$`)
var domainRx = regexp.MustCompile(`^(?i:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+)$`)
var safeNameRx = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9_.:@/-]{0,190}$`)
var cronFieldRx = regexp.MustCompile(`^[0-9*/?,\-]+$`)

// 0.19 — Cron/task scheduling.
type CronJob struct {
	ID        string    `json:"id"`
	Owner     string    `json:"owner"`
	Schedule  string    `json:"schedule"`
	Command   string    `json:"command"`
	Enabled   bool      `json:"enabled"`
	Status    string    `json:"status"`
	LastRun   time.Time `json:"last_run,omitempty"`
	NextRun   time.Time `json:"next_run,omitempty"`
	CreatedAt time.Time `json:"created_at"`
}

// 0.20–0.25 — Application installers and deployment records.
type Deployment struct {
	ID         string    `json:"id"`
	Kind       string    `json:"kind"`
	Domain     string    `json:"domain"`
	Owner      string    `json:"owner"`
	Repository string    `json:"repository,omitempty"`
	Branch     string    `json:"branch,omitempty"`
	Runtime    string    `json:"runtime"`
	Status     string    `json:"status"`
	Steps      []string  `json:"steps"`
	CreatedAt  time.Time `json:"created_at"`
}

type AppTemplate struct {
	Slug          string   `json:"slug"`
	Name          string   `json:"name"`
	Category      string   `json:"category"`
	Kind          string   `json:"kind"`
	Runtime       string   `json:"runtime"`
	Database      string   `json:"database,omitempty"`
	ReleasePolicy string   `json:"release_policy"`
	Description   string   `json:"description"`
	Requirements  []string `json:"requirements"`
	InstallSteps  []string `json:"install_steps"`
}

type AppInstall struct {
	ID            string    `json:"id"`
	Template      string    `json:"template"`
	Name          string    `json:"name"`
	Version       string    `json:"version,omitempty"`
	Domain        string    `json:"domain"`
	Owner         string    `json:"owner"`
	Path          string    `json:"path"`
	Target        string    `json:"target,omitempty"`
	Database      string    `json:"database,omitempty"`
	DatabaseName  string    `json:"database_name,omitempty"`
	DatabaseUser  string    `json:"database_user,omitempty"`
	Runtime       string    `json:"runtime"`
	BootstrapMode string    `json:"bootstrap_mode,omitempty"`
	Status        string    `json:"status"`
	Steps         []string  `json:"steps"`
	CreatedAt     time.Time `json:"created_at"`
	UpdatedAt     time.Time `json:"updated_at,omitempty"`
}

// 0.26–0.29 — Mail foundation, authentication and reputation.
type MailDomain struct {
	Domain        string    `json:"domain"`
	Owner         string    `json:"owner"`
	DKIM          bool      `json:"dkim"`
	SPF           bool      `json:"spf"`
	DMARC         string    `json:"dmarc"`
	Webmail       bool      `json:"webmail"`
	OutboundLimit int       `json:"outbound_limit_per_hour,omitempty"` // legacy state only; not advertised as enforced
	MailHost      string    `json:"mail_host,omitempty"`
	TLSReady      bool      `json:"tls_ready,omitempty"`
	DNSReady      bool      `json:"dns_ready,omitempty"`
	Detail        string    `json:"detail,omitempty"`
	Status        string    `json:"status"`
	CreatedAt     time.Time `json:"created_at"`
}

type MailAlias struct {
	Address     string    `json:"address"`
	Destination string    `json:"destination"`
	Owner       string    `json:"owner"`
	Status      string    `json:"status"`
	CreatedAt   time.Time `json:"created_at"`
}

type ReputationCheck struct {
	ID        string    `json:"id"`
	Target    string    `json:"target"`
	Score     int       `json:"score"`
	Status    string    `json:"status"`
	Signals   []string  `json:"signals"`
	CheckedAt time.Time `json:"checked_at"`
}

// 0.31–0.35 — Host and account security controls.
type Ban struct {
	ID        string    `json:"id"`
	Service   string    `json:"service"`
	Source    string    `json:"source"`
	Reason    string    `json:"reason"`
	Status    string    `json:"status"`
	ExpiresAt time.Time `json:"expires_at"`
	CreatedAt time.Time `json:"created_at"`
}

type MalwareScan struct {
	ID          string    `json:"id"`
	Scope       string    `json:"scope"`
	Target      string    `json:"target"`
	Status      string    `json:"status"`
	Findings    int       `json:"findings"`
	Quarantined int       `json:"quarantined"`
	StartedAt   time.Time `json:"started_at"`
	FinishedAt  time.Time `json:"finished_at"`
}

type IntegrityCheck struct {
	ID        string    `json:"id"`
	Scope     string    `json:"scope"`
	Target    string    `json:"target"`
	Files     int       `json:"files"`
	Changed   int       `json:"changed"`
	Status    string    `json:"status"`
	CheckedAt time.Time `json:"checked_at"`
}

type SSHPolicy struct {
	Port         int       `json:"port"`
	RootLogin    bool      `json:"root_login"`
	PasswordAuth bool      `json:"password_auth"`
	KeyOnly      bool      `json:"key_only"`
	AllowedCIDRs []string  `json:"allowed_cidrs"`
	UpdatedAt    time.Time `json:"updated_at"`
}

type SecurityFinding struct {
	ID       string `json:"id"`
	Severity string `json:"severity"`
	Title    string `json:"title"`
	Detail   string `json:"detail"`
	Status   string `json:"status"`
}

// 0.36–0.39 — Logs, monitoring and alerts.
type MetricSample struct {
	ID         string    `json:"id"`
	CPU        float64   `json:"cpu_percent"`
	Memory     float64   `json:"memory_percent"`
	Disk       float64   `json:"disk_percent"`
	Load       float64   `json:"load_1"`
	MailQueue  int       `json:"mail_queue"`
	PHPBusy    int       `json:"php_busy_workers"`
	CapturedAt time.Time `json:"captured_at"`
}

type AlertRule struct {
	ID        string    `json:"id"`
	Name      string    `json:"name"`
	Metric    string    `json:"metric"`
	Operator  string    `json:"operator"`
	Threshold float64   `json:"threshold"`
	WindowMin int       `json:"window_minutes"`
	Severity  string    `json:"severity"`
	Enabled   bool      `json:"enabled"`
	CreatedAt time.Time `json:"created_at"`
}

type Incident struct {
	ID        string    `json:"id"`
	RuleID    string    `json:"rule_id"`
	Title     string    `json:"title"`
	Severity  string    `json:"severity"`
	Status    string    `json:"status"`
	Detail    string    `json:"detail"`
	CreatedAt time.Time `json:"created_at"`
}

// 0.40–0.49 — Updates, resources, process/storage/network and reseller controls.
type UpdatePolicy struct {
	Channel             string    `json:"channel"`
	SecurityAuto        bool      `json:"security_auto"`
	PackageAuto         bool      `json:"package_auto"`
	MajorVersionsManual bool      `json:"major_versions_manual"`
	AutoReboot          bool      `json:"auto_reboot"`
	RebootWindow        string    `json:"reboot_window"`
	UpdatedAt           time.Time `json:"updated_at"`
}

type ResourceLimit struct {
	Owner       string    `json:"owner"`
	CPUPercent  int       `json:"cpu_percent"`
	MemoryMB    int       `json:"memory_mb"`
	PIDs        int       `json:"pids"`
	IOWeight    int       `json:"io_weight"`
	DiskGB      int       `json:"disk_gb"`
	BandwidthGB int       `json:"bandwidth_gb"`
	UpdatedAt   time.Time `json:"updated_at"`
}

type ProcessInfo struct {
	PID     int     `json:"pid"`
	User    string  `json:"user"`
	CPU     float64 `json:"cpu_percent"`
	Memory  float64 `json:"memory_percent"`
	Command string  `json:"command"`
	Status  string  `json:"status"`
}

type StorageVolume struct {
	Name       string `json:"name"`
	Mount      string `json:"mount"`
	Filesystem string `json:"filesystem"`
	SizeGB     int    `json:"size_gb"`
	UsedGB     int    `json:"used_gb"`
	Health     string `json:"health"`
}

type NetworkInterface struct {
	Name      string   `json:"name"`
	Addresses []string `json:"addresses"`
	State     string   `json:"state"`
	RXBytes   uint64   `json:"rx_bytes"`
	TXBytes   uint64   `json:"tx_bytes"`
}

type ResellerBrand struct {
	Reseller    string    `json:"reseller"`
	Company     string    `json:"company"`
	LogoURL     string    `json:"logo_url"`
	Accent      string    `json:"accent"`
	SupportURL  string    `json:"support_url"`
	Nameservers []string  `json:"nameservers"`
	UpdatedAt   time.Time `json:"updated_at"`
}

// 0.50–0.59 — Delegation, migrations and cluster resources.
type Delegate struct {
	ID          string    `json:"id"`
	Owner       string    `json:"owner"`
	Username    string    `json:"username"`
	Role        string    `json:"role"`
	Permissions []string  `json:"permissions"`
	Status      string    `json:"status"`
	CreatedAt   time.Time `json:"created_at"`
}

type Migration struct {
	ID          string    `json:"id"`
	Source      string    `json:"source"`
	SourceType  string    `json:"source_type"`
	Account     string    `json:"account"`
	Destination string    `json:"destination"`
	Status      string    `json:"status"`
	Steps       []string  `json:"steps"`
	CreatedAt   time.Time `json:"created_at"`
}

type ClusterResource struct {
	ID        string    `json:"id"`
	Kind      string    `json:"kind"`
	Name      string    `json:"name"`
	Nodes     []string  `json:"nodes"`
	Mode      string    `json:"mode"`
	Status    string    `json:"status"`
	CreatedAt time.Time `json:"created_at"`
}

// 0.60–0.69 — HA, provisioning, provider/API contracts.
type LoadBalancer struct {
	ID        string    `json:"id"`
	Name      string    `json:"name"`
	Region    string    `json:"region"`
	Backends  []string  `json:"backends"`
	Algorithm string    `json:"algorithm"`
	Status    string    `json:"status"`
	CreatedAt time.Time `json:"created_at"`
}

type ProvisionProfile struct {
	ID        string    `json:"id"`
	Name      string    `json:"name"`
	OS        string    `json:"os"`
	Role      string    `json:"role"`
	Packages  []string  `json:"packages"`
	Hardening string    `json:"hardening"`
	CreatedAt time.Time `json:"created_at"`
}

type APIKey struct {
	ID           string    `json:"id"`
	Name         string    `json:"name"`
	Prefix       string    `json:"prefix"`
	Scopes       []string  `json:"scopes"`
	Owner        string    `json:"owner,omitempty"`
	AllowedCIDRs []string  `json:"allowed_cidrs,omitempty"`
	Status       string    `json:"status"`
	SecretDigest string    `json:"secret_digest,omitempty"`
	CreatedAt    time.Time `json:"created_at"`
	ExpiresAt    time.Time `json:"expires_at,omitempty"`
	LastUsedAt   time.Time `json:"last_used_at,omitempty"`
	LastUsedIP   string    `json:"last_used_ip,omitempty"`
}

type Webhook struct {
	ID        string    `json:"id"`
	URL       string    `json:"url"`
	Events    []string  `json:"events"`
	Status    string    `json:"status"`
	CreatedAt time.Time `json:"created_at"`
}

// 0.70–0.79 — Extensions, billing and notification workflow contracts.
type Plugin struct {
	ID        string    `json:"id"`
	Name      string    `json:"name"`
	Version   string    `json:"version"`
	Type      string    `json:"type"`
	Status    string    `json:"status"`
	CreatedAt time.Time `json:"created_at"`
}

type Invoice struct {
	ID          string    `json:"id"`
	Customer    string    `json:"customer"`
	AmountCents int       `json:"amount_cents"`
	Currency    string    `json:"currency"`
	Status      string    `json:"status"`
	DueAt       time.Time `json:"due_at"`
	CreatedAt   time.Time `json:"created_at"`
}

type Notification struct {
	ID        string    `json:"id"`
	Channel   string    `json:"channel"`
	Recipient string    `json:"recipient"`
	Subject   string    `json:"subject"`
	Status    string    `json:"status"`
	CreatedAt time.Time `json:"created_at"`
}

// 0.80–0.89 — diagnostics, repair, config history, secrets and signed updates.
type Diagnostic struct {
	ID             string    `json:"id"`
	Scope          string    `json:"scope"`
	Summary        string    `json:"summary"`
	Severity       string    `json:"severity"`
	Recommendation string    `json:"recommendation"`
	CreatedAt      time.Time `json:"created_at"`
}

type RepairRun struct {
	ID        string    `json:"id"`
	Resource  string    `json:"resource"`
	Action    string    `json:"action"`
	Snapshot  string    `json:"snapshot"`
	Status    string    `json:"status"`
	Steps     []string  `json:"steps"`
	CreatedAt time.Time `json:"created_at"`
}

type ConfigRevision struct {
	ID        string    `json:"id"`
	Resource  string    `json:"resource"`
	Version   int       `json:"version"`
	Digest    string    `json:"digest"`
	Status    string    `json:"status"`
	CreatedAt time.Time `json:"created_at"`
}

type SecretRef struct {
	ID        string    `json:"id"`
	Name      string    `json:"name"`
	Type      string    `json:"type"`
	KeyID     string    `json:"key_id"`
	Status    string    `json:"status"`
	CreatedAt time.Time `json:"created_at"`
}

type SignedRelease struct {
	Version   string    `json:"version"`
	Channel   string    `json:"channel"`
	Digest    string    `json:"digest"`
	Signature string    `json:"signature"`
	Status    string    `json:"status"`
	CreatedAt time.Time `json:"created_at"`
}

// 0.90–0.99 — portability, performance, staging, isolation and certification.
type ExportBundle struct {
	ID        string    `json:"id"`
	Account   string    `json:"account"`
	Format    string    `json:"format"`
	Encrypted bool      `json:"encrypted"`
	Status    string    `json:"status"`
	CreatedAt time.Time `json:"created_at"`
}

type PerformanceRecommendation struct {
	ID        string `json:"id"`
	Resource  string `json:"resource"`
	Current   string `json:"current"`
	Suggested string `json:"suggested"`
	Impact    string `json:"impact"`
	Status    string `json:"status"`
}

type StagingEnvironment struct {
	ID               string    `json:"id"`
	ProductionDomain string    `json:"production_domain"`
	StagingDomain    string    `json:"staging_domain"`
	Owner            string    `json:"owner"`
	Status           string    `json:"status"`
	CreatedAt        time.Time `json:"created_at"`
}

type IsolationProfile struct {
	Owner           string    `json:"owner"`
	Namespaces      bool      `json:"namespaces"`
	Cgroups         bool      `json:"cgroups"`
	PrivateTmp      bool      `json:"private_tmp"`
	NoNewPrivileges bool      `json:"no_new_privileges"`
	Status          string    `json:"status"`
	UpdatedAt       time.Time `json:"updated_at"`
}

// 5.0.0-dev.6 — account-scoped Privora Panel (PPanel) controls. These are durable
// control-plane records. Host application remains adapter/certification-gated.
type AccountControl struct {
	ID        string    `json:"id"`
	Owner     string    `json:"owner"`
	Kind      string    `json:"kind"`
	Domain    string    `json:"domain,omitempty"`
	Name      string    `json:"name"`
	Value     string    `json:"value"`
	Status    string    `json:"status"`
	CreatedAt time.Time `json:"created_at"`
}

type CertificationGate struct {
	ID        string    `json:"id"`
	Name      string    `json:"name"`
	Status    string    `json:"status"`
	Evidence  []string  `json:"evidence"`
	Blockers  []string  `json:"blockers"`
	UpdatedAt time.Time `json:"updated_at"`
}

// 1.0–5.0 — explicit maturity state. These records never imply a real backend.
type HorizonState struct {
	Major         int       `json:"major"`
	Name          string    `json:"name"`
	Contract      string    `json:"contract"`
	Backend       string    `json:"backend"`
	Certification string    `json:"certification"`
	Blockers      []string  `json:"blockers"`
	UpdatedAt     time.Time `json:"updated_at"`
}

type State struct {
	CronJobs        map[string]CronJob                   `json:"cron_jobs"`
	Deployments     map[string]Deployment                `json:"deployments"`
	AppInstalls     map[string]AppInstall                `json:"app_installs"`
	MailDomains     map[string]MailDomain                `json:"mail_domains"`
	MailAliases     map[string]MailAlias                 `json:"mail_aliases"`
	Reputation      map[string]ReputationCheck           `json:"reputation"`
	Bans            map[string]Ban                       `json:"bans"`
	MalwareScans    map[string]MalwareScan               `json:"malware_scans"`
	IntegrityChecks map[string]IntegrityCheck            `json:"integrity_checks"`
	SSHPolicy       SSHPolicy                            `json:"ssh_policy"`
	Findings        map[string]SecurityFinding           `json:"findings"`
	Metrics         []MetricSample                       `json:"metrics"`
	AlertRules      map[string]AlertRule                 `json:"alert_rules"`
	Incidents       map[string]Incident                  `json:"incidents"`
	UpdatePolicy    UpdatePolicy                         `json:"update_policy"`
	ResourceLimits  map[string]ResourceLimit             `json:"resource_limits"`
	Brands          map[string]ResellerBrand             `json:"brands"`
	Delegates       map[string]Delegate                  `json:"delegates"`
	Migrations      map[string]Migration                 `json:"migrations"`
	Clusters        map[string]ClusterResource           `json:"clusters"`
	LoadBalancers   map[string]LoadBalancer              `json:"load_balancers"`
	Profiles        map[string]ProvisionProfile          `json:"profiles"`
	APIKeys         map[string]APIKey                    `json:"api_keys"`
	Webhooks        map[string]Webhook                   `json:"webhooks"`
	Plugins         map[string]Plugin                    `json:"plugins"`
	Invoices        map[string]Invoice                   `json:"invoices"`
	Notifications   map[string]Notification              `json:"notifications"`
	Diagnostics     map[string]Diagnostic                `json:"diagnostics"`
	Repairs         map[string]RepairRun                 `json:"repairs"`
	Revisions       map[string]ConfigRevision            `json:"revisions"`
	Secrets         map[string]SecretRef                 `json:"secrets"`
	Releases        map[string]SignedRelease             `json:"releases"`
	Exports         map[string]ExportBundle              `json:"exports"`
	Recommendations map[string]PerformanceRecommendation `json:"recommendations"`
	Staging         map[string]StagingEnvironment        `json:"staging"`
	Isolation       map[string]IsolationProfile          `json:"isolation"`
	AccountControls map[string]AccountControl            `json:"account_controls"`
	Certification   map[string]CertificationGate         `json:"certification"`
	MailFilters     map[string]MailFilter                `json:"mail_filters"`
	BackupPolicies  map[string]BackupPolicy              `json:"backup_policies"`
	SitePolicies    map[string]SitePolicy                `json:"site_policies"`
	DNSTemplates    map[string]DNSTemplate               `json:"dns_templates"`
	ReadinessRuns   map[string]ReadinessRun              `json:"readiness_runs"`
	Horizons        map[int]HorizonState                 `json:"horizons"`
}

type Manager struct {
	mu    sync.Mutex
	path  string
	mock  bool
	state State
}

func New(path string, mock bool) *Manager {
	m := &Manager{path: path, mock: mock}
	m.ensure()
	_ = m.load()
	m.seedDefaults()
	return m
}

func (m *Manager) ensure() {
	if m.state.CronJobs == nil {
		m.state.CronJobs = map[string]CronJob{}
	}
	if m.state.Deployments == nil {
		m.state.Deployments = map[string]Deployment{}
	}
	if m.state.AppInstalls == nil {
		m.state.AppInstalls = map[string]AppInstall{}
	}
	if m.state.MailDomains == nil {
		m.state.MailDomains = map[string]MailDomain{}
	}
	if m.state.MailAliases == nil {
		m.state.MailAliases = map[string]MailAlias{}
	}
	if m.state.Reputation == nil {
		m.state.Reputation = map[string]ReputationCheck{}
	}
	if m.state.Bans == nil {
		m.state.Bans = map[string]Ban{}
	}
	if m.state.MalwareScans == nil {
		m.state.MalwareScans = map[string]MalwareScan{}
	}
	if m.state.IntegrityChecks == nil {
		m.state.IntegrityChecks = map[string]IntegrityCheck{}
	}
	if m.state.Findings == nil {
		m.state.Findings = map[string]SecurityFinding{}
	}
	if m.state.AlertRules == nil {
		m.state.AlertRules = map[string]AlertRule{}
	}
	if m.state.Incidents == nil {
		m.state.Incidents = map[string]Incident{}
	}
	if m.state.ResourceLimits == nil {
		m.state.ResourceLimits = map[string]ResourceLimit{}
	}
	if m.state.Brands == nil {
		m.state.Brands = map[string]ResellerBrand{}
	}
	if m.state.Delegates == nil {
		m.state.Delegates = map[string]Delegate{}
	}
	if m.state.Migrations == nil {
		m.state.Migrations = map[string]Migration{}
	}
	if m.state.Clusters == nil {
		m.state.Clusters = map[string]ClusterResource{}
	}
	if m.state.LoadBalancers == nil {
		m.state.LoadBalancers = map[string]LoadBalancer{}
	}
	if m.state.Profiles == nil {
		m.state.Profiles = map[string]ProvisionProfile{}
	}
	if m.state.APIKeys == nil {
		m.state.APIKeys = map[string]APIKey{}
	}
	if m.state.Webhooks == nil {
		m.state.Webhooks = map[string]Webhook{}
	}
	if m.state.Plugins == nil {
		m.state.Plugins = map[string]Plugin{}
	}
	if m.state.Invoices == nil {
		m.state.Invoices = map[string]Invoice{}
	}
	if m.state.Notifications == nil {
		m.state.Notifications = map[string]Notification{}
	}
	if m.state.Diagnostics == nil {
		m.state.Diagnostics = map[string]Diagnostic{}
	}
	if m.state.Repairs == nil {
		m.state.Repairs = map[string]RepairRun{}
	}
	if m.state.Revisions == nil {
		m.state.Revisions = map[string]ConfigRevision{}
	}
	if m.state.Secrets == nil {
		m.state.Secrets = map[string]SecretRef{}
	}
	if m.state.Releases == nil {
		m.state.Releases = map[string]SignedRelease{}
	}
	if m.state.Exports == nil {
		m.state.Exports = map[string]ExportBundle{}
	}
	if m.state.Recommendations == nil {
		m.state.Recommendations = map[string]PerformanceRecommendation{}
	}
	if m.state.Staging == nil {
		m.state.Staging = map[string]StagingEnvironment{}
	}
	if m.state.Isolation == nil {
		m.state.Isolation = map[string]IsolationProfile{}
	}
	if m.state.AccountControls == nil {
		m.state.AccountControls = map[string]AccountControl{}
	}
	if m.state.Certification == nil {
		m.state.Certification = map[string]CertificationGate{}
	}
	if m.state.MailFilters == nil {
		m.state.MailFilters = map[string]MailFilter{}
	}
	if m.state.BackupPolicies == nil {
		m.state.BackupPolicies = map[string]BackupPolicy{}
	}
	if m.state.SitePolicies == nil {
		m.state.SitePolicies = map[string]SitePolicy{}
	}
	if m.state.DNSTemplates == nil {
		m.state.DNSTemplates = map[string]DNSTemplate{}
	}
	if m.state.ReadinessRuns == nil {
		m.state.ReadinessRuns = map[string]ReadinessRun{}
	}
	if m.state.Horizons == nil {
		m.state.Horizons = map[int]HorizonState{}
	}
}

func (m *Manager) load() error {
	b, err := os.ReadFile(m.path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	if err := json.Unmarshal(b, &m.state); err != nil {
		return err
	}
	m.ensure()
	return nil
}

func (m *Manager) save() error {
	if err := os.MkdirAll(filepath.Dir(m.path), 0750); err != nil {
		return err
	}
	b, err := json.MarshalIndent(m.state, "", "  ")
	if err != nil {
		return err
	}
	tmp := m.path + ".tmp"
	if err := os.WriteFile(tmp, b, 0640); err != nil {
		return err
	}
	return os.Rename(tmp, m.path)
}

func makeID(prefix string) string {
	b := make([]byte, 6)
	_, _ = rand.Read(b)
	return prefix + "_" + hex.EncodeToString(b)
}

func validOwner(v string) bool { return ownerRx.MatchString(strings.TrimSpace(v)) }
func validDomain(v string) bool {
	return len(v) <= 253 && domainRx.MatchString(v) && net.ParseIP(v) == nil
}
func validEmail(v string) bool {
	at := strings.LastIndex(v, "@")
	return at > 0 && at < len(v)-1 && len(v) <= 254 && validDomain(v[at+1:])
}
func validCIDR(v string) bool { _, _, err := net.ParseCIDR(v); return err == nil }
func validCron(v string) bool {
	fields := strings.Fields(v)
	if len(fields) != 5 {
		return false
	}
	for _, f := range fields {
		if !cronFieldRx.MatchString(f) {
			return false
		}
	}
	return true
}
func validSafeText(v string, max int) bool {
	v = strings.TrimSpace(v)
	return v != "" && len(v) <= max && !strings.ContainsAny(v, "\x00\r\n")
}
func cloneStrings(v []string) []string { return append([]string(nil), v...) }

func (m *Manager) seedDefaults() {
	m.mu.Lock()
	defer m.mu.Unlock()
	changed := false
	if m.state.SSHPolicy.Port == 0 {
		m.state.SSHPolicy = SSHPolicy{Port: 22, RootLogin: false, PasswordAuth: false, KeyOnly: true, AllowedCIDRs: []string{"0.0.0.0/0"}, UpdatedAt: time.Now().UTC()}
		changed = true
	}
	if m.state.UpdatePolicy.Channel == "" {
		m.state.UpdatePolicy = UpdatePolicy{Channel: "stable", SecurityAuto: true, PackageAuto: true, MajorVersionsManual: true, AutoReboot: false, RebootWindow: "Sun 03:00", UpdatedAt: time.Now().UTC()}
		changed = true
	}
	if len(m.state.Horizons) == 0 {
		now := time.Now().UTC()
		m.state.Horizons[1] = HorizonState{Major: 1, Name: "Privora Panel/PCC single-server", Contract: "real-host-adapter-gate-v2", Backend: "live-certified-linux-user-suspend-account-files-local-backup-nginx-parser", Certification: "blocked", Blockers: []string{"live writable quota/cgroup certification", "PHP-FPM daemon/site transaction certification", "live MariaDB/PostgreSQL/DNS/ACME/mail/nftables/SFTP dependencies and certification", "full cPanel import/restore", "security/load/failure certification"}, UpdatedAt: now}
		m.state.Horizons[2] = HorizonState{Major: 2, Name: "Multi-server platform", Contract: "durable-mtls-fleet-core-certified", Backend: "tls13-mtls-node-registry-rotation-revocation-persistent-replay-typed-executor", Certification: "blocked", Blockers: []string{"production CA custody and enrollment bootstrap", "real remote convergence adapters", "network partition/fleet update certification"}, UpdatedAt: now}
		m.state.Horizons[3] = HorizonState{Major: 3, Name: "Hosting cloud", Contract: "durable-provider-vault-core-certified", Backend: "durable-idempotent-lifecycle-aes256gcm-secret-vault", Certification: "blocked", Blockers: []string{"real provider API adapters", "operational credential injection/rotation", "signed node bootstrap", "provider teardown/cost/failure certification"}, UpdatedAt: now}
		m.state.Horizons[4] = HorizonState{Major: 4, Name: "Automation platform", Contract: "durable-order-ledger-core-certified", Backend: "persistent-compensating-orders-hash-chained-double-entry-ledger", Certification: "blocked", Blockers: []string{"payment provider adapters", "verified payment webhooks", "subscription/refund/suspension workflows", "commercial retry/reconciliation certification"}, UpdatedAt: now}
		m.state.Horizons[5] = HorizonState{Major: 5, Name: "Distributed hosting fabric", Contract: "durable-placement-safety-core-certified", Backend: "persistent-placement-majority-observation-fencing-route-plan", Certification: "blocked", Blockers: []string{"real replication engine", "deployed distributed consensus/fencing authority", "live DNS/load-balancer traffic routing", "cross-region secrets/state", "chaos/failover certification"}, UpdatedAt: now}
		changed = true
	}
	if changed {
		_ = m.save()
	}
}

func (m *Manager) ListCronJobs() []CronJob {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]CronJob, 0, len(m.state.CronJobs))
	for _, v := range m.state.CronJobs {
		out = append(out, v)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].CreatedAt.Before(out[j].CreatedAt) })
	return out
}
func (m *Manager) RemoveCronJob(id string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	id = strings.TrimSpace(id)
	if _, ok := m.state.CronJobs[id]; !ok {
		return errors.New("cron job not found")
	}
	delete(m.state.CronJobs, id)
	return m.save()
}

func (m *Manager) CreateCronJob(v CronJob) (CronJob, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if !validOwner(v.Owner) || !validCron(v.Schedule) || !validSafeText(v.Command, 1000) {
		return v, errors.New("invalid cron job")
	}
	if strings.ContainsAny(v.Command, "\x00\r\n") {
		return v, errors.New("invalid cron command")
	}
	v.ID = makeID("cron")
	v.Enabled = true
	v.Status = "scheduled"
	v.CreatedAt = time.Now().UTC()
	v.NextRun = v.CreatedAt.Add(time.Hour)
	m.state.CronJobs[v.ID] = v
	return v, m.save()
}
func (m *Manager) RunCron(id string) (CronJob, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	v, ok := m.state.CronJobs[id]
	if !ok {
		return v, errors.New("cron job not found")
	}
	if !m.mock {
		return v, errors.New("real cron execution backend is not enabled")
	}
	now := time.Now().UTC()
	v.LastRun = now
	v.NextRun = now.Add(time.Hour)
	v.Status = "simulated-success"
	m.state.CronJobs[id] = v
	return v, m.save()
}

func AppCatalog() []AppTemplate {
	commonPublish := []string{"validate-owned-domain", "resolve-latest-compatible-release", "verify-official-source", "stage-private-release", "validate-runtime-requirements", "atomic-publish", "health-check", "rollback-on-failure"}
	withDB := func(extra ...string) []string {
		out := []string{"provision-database-and-user"}
		out = append(out, extra...)
		out = append(out, commonPublish...)
		return out
	}
	return []AppTemplate{
		{Slug: "wordpress", Name: "WordPress", Category: "CMS", Kind: "php", Runtime: "php8.4", Database: "mariadb", ReleasePolicy: "latest-compatible", Description: "Popular publishing and website CMS with themes and plugins.", Requirements: []string{"php-fpm", "mariadb", "curl", "gd", "intl", "mbstring", "mysqli", "zip"}, InstallSteps: withDB("render-wp-config", "generate-application-secrets")},
		{Slug: "joomla", Name: "Joomla", Category: "CMS", Kind: "php", Runtime: "php8.4", Database: "mariadb", ReleasePolicy: "latest-compatible", Description: "Flexible content management system for sites, portals and intranets.", Requirements: []string{"php-fpm", "mariadb", "curl", "gd", "intl", "mbstring", "xml", "zip"}, InstallSteps: withDB("render-joomla-config")},
		{Slug: "drupal", Name: "Drupal", Category: "CMS", Kind: "php", Runtime: "php8.4", Database: "mariadb", ReleasePolicy: "latest-compatible", Description: "Structured-content CMS for complex and highly configurable websites.", Requirements: []string{"php-fpm", "composer", "mariadb", "gd", "intl", "mbstring", "pdo", "xml"}, InstallSteps: withDB("composer-install", "render-drupal-settings")},
		{Slug: "grav", Name: "Grav", Category: "CMS", Kind: "php", Runtime: "php8.4", ReleasePolicy: "latest-compatible", Description: "Fast flat-file CMS that does not require a database.", Requirements: []string{"php-fpm", "curl", "gd", "mbstring", "yaml", "zip"}, InstallSteps: append([]string{"prepare-writable-cache-and-logs"}, commonPublish...)},
		{Slug: "phpbb", Name: "phpBB", Category: "Community", Kind: "php", Runtime: "php8.4", Database: "mariadb", ReleasePolicy: "latest-compatible", Description: "Classic discussion forum and community platform.", Requirements: []string{"php-fpm", "mariadb", "gd", "intl", "mbstring", "xml"}, InstallSteps: withDB("render-phpbb-config")},
		{Slug: "prestashop", Name: "PrestaShop", Category: "E-commerce", Kind: "php", Runtime: "php8.4", Database: "mariadb", ReleasePolicy: "latest-compatible", Description: "Self-hosted e-commerce storefront and catalog platform.", Requirements: []string{"php-fpm", "mariadb", "curl", "gd", "intl", "mbstring", "zip"}, InstallSteps: withDB("generate-shop-secrets", "render-prestashop-config")},
		{Slug: "nextcloud", Name: "Nextcloud", Category: "Collaboration", Kind: "php", Runtime: "php8.4", Database: "mariadb", ReleasePolicy: "latest-compatible", Description: "Private file sync, collaboration and productivity suite.", Requirements: []string{"php-fpm", "mariadb", "curl", "gd", "intl", "mbstring", "zip", "redis-recommended"}, InstallSteps: withDB("prepare-data-directory", "render-nextcloud-config", "configure-background-job-intent")},
		{Slug: "moodle", Name: "Moodle", Category: "Learning", Kind: "php", Runtime: "php8.4", Database: "mariadb", ReleasePolicy: "latest-compatible", Description: "Learning-management system for courses, training and education.", Requirements: []string{"php-fpm", "mariadb", "curl", "gd", "intl", "mbstring", "xml", "zip"}, InstallSteps: withDB("prepare-moodledata-directory", "render-moodle-config", "configure-cron-intent")},
		{Slug: "matomo", Name: "Matomo", Category: "Analytics", Kind: "php", Runtime: "php8.4", Database: "mariadb", ReleasePolicy: "latest-compatible", Description: "Self-hosted web analytics platform.", Requirements: []string{"php-fpm", "mariadb", "curl", "gd", "mbstring", "pdo", "zip"}, InstallSteps: withDB("render-matomo-config", "configure-archiver-cron-intent")},
		{Slug: "laravel", Name: "Laravel", Category: "Framework", Kind: "php", Runtime: "php8.4", Database: "mariadb", ReleasePolicy: "latest-compatible", Description: "Modern PHP application framework with Composer, queues and scheduler support.", Requirements: []string{"php-fpm", "composer", "pdo", "mbstring", "openssl"}, InstallSteps: withDB("composer-create-project", "generate-app-key", "storage-link", "scheduler-and-queue-intent")},
	}
}

func appTemplate(slug string) (AppTemplate, bool) {
	slug = strings.ToLower(strings.TrimSpace(slug))
	for _, t := range AppCatalog() {
		if t.Slug == slug {
			return t, true
		}
	}
	return AppTemplate{}, false
}

func validInstallPath(v string) bool {
	if v == "" || v == "." {
		return true
	}
	if len(v) > 180 || filepath.IsAbs(v) || strings.Contains(v, "\\") || strings.ContainsAny(v, "\x00\r\n") {
		return false
	}
	clean := filepath.Clean(v)
	if clean == "." {
		return true
	}
	return clean == v && clean != ".." && !strings.HasPrefix(clean, "../") && !strings.Contains(clean, "/../")
}

func (m *Manager) ListAppInstalls() []AppInstall {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]AppInstall, 0, len(m.state.AppInstalls))
	for _, v := range m.state.AppInstalls {
		v.Steps = cloneStrings(v.Steps)
		out = append(out, v)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].CreatedAt.Before(out[j].CreatedAt) })
	return out
}

func (m *Manager) CreateAppInstall(v AppInstall) (AppInstall, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	v.Template = strings.ToLower(strings.TrimSpace(v.Template))
	v.Domain = strings.ToLower(strings.TrimSpace(v.Domain))
	v.Owner = strings.ToLower(strings.TrimSpace(v.Owner))
	v.Path = strings.TrimSpace(v.Path)
	if v.Path == "" {
		v.Path = "."
	}
	t, ok := appTemplate(v.Template)
	if !ok || !validDomain(v.Domain) || !validOwner(v.Owner) || !validInstallPath(v.Path) {
		return v, errors.New("invalid application install request")
	}
	if v.Database == "" {
		v.Database = t.Database
	}
	if t.Database == "" && v.Database != "" {
		return v, errors.New("selected application does not require a database")
	}
	if t.Database != "" && !map[string]bool{"mysql": true, "mariadb": true, "postgresql": true}[v.Database] {
		return v, errors.New("invalid application database engine")
	}
	if v.Runtime == "" {
		v.Runtime = t.Runtime
	}
	if !validSafeText(v.Runtime, 64) {
		return v, errors.New("invalid application runtime")
	}
	v.ID = makeID("install")
	v.Name = t.Name
	v.Status = "install-plan-ready-adapter-gated"
	v.Steps = cloneStrings(t.InstallSteps)
	v.CreatedAt = time.Now().UTC()
	m.state.AppInstalls[v.ID] = v
	return v, m.save()
}

func (m *Manager) RemoveAppInstall(id string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	id = strings.TrimSpace(id)
	if _, ok := m.state.AppInstalls[id]; !ok {
		return errors.New("application install not found")
	}
	delete(m.state.AppInstalls, id)
	return m.save()
}

func (m *Manager) UpdateAppInstall(id, status, version, target, databaseName, databaseUser, bootstrapMode string) (AppInstall, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	v, ok := m.state.AppInstalls[id]
	if !ok {
		return v, errors.New("application install not found")
	}
	if !validSafeText(status, 96) || !validSafeText(version, 64) || !validSafeText(bootstrapMode, 64) {
		return v, errors.New("invalid application install status")
	}
	v.Status = status
	v.Version = version
	v.Target = target
	v.DatabaseName = databaseName
	v.DatabaseUser = databaseUser
	v.BootstrapMode = bootstrapMode
	v.UpdatedAt = time.Now().UTC()
	m.state.AppInstalls[id] = v
	return v, m.save()
}

func (m *Manager) ListDeployments() []Deployment {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]Deployment, 0, len(m.state.Deployments))
	for _, v := range m.state.Deployments {
		out = append(out, v)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].CreatedAt.Before(out[j].CreatedAt) })
	return out
}
func (m *Manager) RemoveDeployment(id string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	id = strings.TrimSpace(id)
	if _, ok := m.state.Deployments[id]; !ok {
		return errors.New("deployment not found")
	}
	delete(m.state.Deployments, id)
	return m.save()
}

func (m *Manager) CreateDeployment(v Deployment) (Deployment, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	allowed := map[string]bool{"laravel": true, "wordpress": true, "node": true, "python": true, "git": true}
	if !allowed[v.Kind] || !validDomain(v.Domain) || !validOwner(v.Owner) || !validSafeText(v.Runtime, 64) {
		return v, errors.New("invalid deployment")
	}
	if v.Repository != "" && (!strings.HasPrefix(v.Repository, "https://") && !strings.HasPrefix(v.Repository, "git@")) {
		return v, errors.New("repository must use https or git ssh form")
	}
	if v.Branch == "" {
		v.Branch = "main"
	}
	if len(v.Branch) > 120 || strings.ContainsAny(v.Branch, "\x00\r\n ") {
		return v, errors.New("invalid branch")
	}
	v.ID = makeID("deploy")
	v.Status = "simulated-ready"
	v.CreatedAt = time.Now().UTC()
	v.Steps = []string{"validate-input", "prepare-release-directory", "resolve-runtime", "render-service-config", "health-check", "atomic-release-intent"}
	if v.Kind == "laravel" {
		v.Steps = append(v.Steps, "composer-install", "env-key", "storage-link", "scheduler-and-queue-intent")
	}
	if v.Kind == "wordpress" {
		v.Steps = append(v.Steps, "database-bind", "wp-config-intent", "core-install-intent")
	}
	if v.Kind == "node" {
		v.Steps = append(v.Steps, "npm-install", "systemd-unit-intent", "nginx-proxy-intent")
	}
	if v.Kind == "python" {
		v.Steps = append(v.Steps, "venv-create", "pip-install", "app-server-unit-intent")
	}
	m.state.Deployments[v.ID] = v
	return v, m.save()
}

func (m *Manager) ListMailDomains() []MailDomain {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]MailDomain, 0, len(m.state.MailDomains))
	for _, v := range m.state.MailDomains {
		out = append(out, v)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Domain < out[j].Domain })
	return out
}
func (m *Manager) CreateMailDomain(v MailDomain) (MailDomain, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if !validDomain(v.Domain) || !validOwner(v.Owner) {
		return v, errors.New("invalid mail domain")
	}
	if _, ok := m.state.MailDomains[v.Domain]; ok {
		return v, errors.New("mail domain already exists")
	}
	if v.DMARC == "" {
		v.DMARC = "quarantine"
	}
	if !map[string]bool{"none": true, "quarantine": true, "reject": true}[v.DMARC] {
		return v, errors.New("invalid DMARC policy")
	}
	if v.OutboundLimit <= 0 {
		v.OutboundLimit = 250
	}
	v.DKIM = true
	v.SPF = true
	v.Webmail = true
	v.Status = "simulated-configured"
	v.CreatedAt = time.Now().UTC()
	m.state.MailDomains[v.Domain] = v
	return v, m.save()
}
func (m *Manager) RecordRealMailDomain(v MailDomain) (MailDomain, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if !validDomain(v.Domain) || !validOwner(v.Owner) {
		return v, errors.New("invalid mail domain")
	}
	if v.CreatedAt.IsZero() {
		v.CreatedAt = time.Now().UTC()
	}
	m.state.MailDomains[v.Domain] = v
	return v, m.save()
}

func (m *Manager) DeleteMailDomain(domain string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	domain = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(domain)), ".")
	if !validDomain(domain) {
		return errors.New("invalid mail domain")
	}
	if _, ok := m.state.MailDomains[domain]; !ok {
		return errors.New("mail domain not found")
	}
	delete(m.state.MailDomains, domain)
	return m.save()
}

func (m *Manager) ListMailAliases() []MailAlias {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]MailAlias, 0, len(m.state.MailAliases))
	for _, v := range m.state.MailAliases {
		out = append(out, v)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Address < out[j].Address })
	return out
}
func (m *Manager) CreateMailAlias(v MailAlias) (MailAlias, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if !validEmail(v.Address) || !validEmail(v.Destination) || !validOwner(v.Owner) {
		return v, errors.New("invalid mail alias")
	}
	v.Status = "simulated-active"
	v.CreatedAt = time.Now().UTC()
	m.state.MailAliases[v.Address] = v
	return v, m.save()
}
func (m *Manager) RecordRealMailAlias(v MailAlias) (MailAlias, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if !validEmail(v.Address) || !validEmail(v.Destination) || !validOwner(v.Owner) {
		return v, errors.New("invalid mail alias")
	}
	if v.CreatedAt.IsZero() {
		v.CreatedAt = time.Now().UTC()
	}
	m.state.MailAliases[v.Address] = v
	return v, m.save()
}

func (m *Manager) UpdateMailAlias(address, destination string) (MailAlias, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	address = strings.ToLower(strings.TrimSpace(address))
	destination = strings.ToLower(strings.TrimSpace(destination))
	v, ok := m.state.MailAliases[address]
	if !ok {
		return MailAlias{}, errors.New("mail alias is not Privora-managed")
	}
	if !validEmail(address) || !validEmail(destination) {
		return MailAlias{}, errors.New("invalid mail alias")
	}
	v.Destination = destination
	if v.Status == "" {
		v.Status = "active-real"
	}
	m.state.MailAliases[address] = v
	return v, m.save()
}

func (m *Manager) DeleteMailAlias(address string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	address = strings.ToLower(strings.TrimSpace(address))
	if _, ok := m.state.MailAliases[address]; !ok {
		return errors.New("mail alias is not Privora-managed")
	}
	delete(m.state.MailAliases, address)
	return m.save()
}

func (m *Manager) ListReputation() []ReputationCheck {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]ReputationCheck, 0, len(m.state.Reputation))
	for _, v := range m.state.Reputation {
		out = append(out, v)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].CheckedAt.After(out[j].CheckedAt) })
	return out
}
func (m *Manager) CheckReputation(target string) (ReputationCheck, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	target = strings.TrimSpace(target)
	if !validDomain(target) && net.ParseIP(target) == nil {
		return ReputationCheck{}, errors.New("invalid reputation target")
	}
	v := ReputationCheck{ID: makeID("rep"), Target: target, Score: 92, Status: "simulated-good", Signals: []string{"SPF present", "DKIM enabled", "DMARC policy configured", "No simulated blocklist hit"}, CheckedAt: time.Now().UTC()}
	m.state.Reputation[v.ID] = v
	return v, m.save()
}

func (m *Manager) ListBans() []Ban {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]Ban, 0, len(m.state.Bans))
	for _, v := range m.state.Bans {
		out = append(out, v)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].CreatedAt.After(out[j].CreatedAt) })
	return out
}
func (m *Manager) CreateBan(v Ban) (Ban, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if !map[string]bool{"ssh": true, "panel": true, "smtp": true, "imap": true, "webmail": true, "wordpress": true}[v.Service] {
		return v, errors.New("invalid protected service")
	}
	if net.ParseIP(v.Source) == nil {
		return v, errors.New("invalid source IP")
	}
	if !validSafeText(v.Reason, 200) {
		v.Reason = "rate threshold exceeded"
	}
	v.ID = makeID("ban")
	v.Status = "simulated-blocked"
	v.CreatedAt = time.Now().UTC()
	if v.ExpiresAt.IsZero() {
		v.ExpiresAt = v.CreatedAt.Add(time.Hour)
	}
	m.state.Bans[v.ID] = v
	return v, m.save()
}
func (m *Manager) ListMalwareScans() []MalwareScan {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]MalwareScan, 0, len(m.state.MalwareScans))
	for _, v := range m.state.MalwareScans {
		out = append(out, v)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].StartedAt.After(out[j].StartedAt) })
	return out
}
func (m *Manager) StartMalwareScan(scope, target string) (MalwareScan, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if !map[string]bool{"account": true, "site": true, "server": true}[scope] || !validSafeText(target, 253) {
		return MalwareScan{}, errors.New("invalid malware scan")
	}
	now := time.Now().UTC()
	v := MalwareScan{ID: makeID("scan"), Scope: scope, Target: target, Status: "simulated-clean", Findings: 0, Quarantined: 0, StartedAt: now, FinishedAt: now.Add(2 * time.Second)}
	m.state.MalwareScans[v.ID] = v
	return v, m.save()
}
func (m *Manager) ListIntegrityChecks() []IntegrityCheck {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]IntegrityCheck, 0, len(m.state.IntegrityChecks))
	for _, v := range m.state.IntegrityChecks {
		out = append(out, v)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].CheckedAt.After(out[j].CheckedAt) })
	return out
}
func (m *Manager) RunIntegrityCheck(scope, target string) (IntegrityCheck, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if !map[string]bool{"system": true, "account": true, "site": true}[scope] || !validSafeText(target, 253) {
		return IntegrityCheck{}, errors.New("invalid integrity check")
	}
	v := IntegrityCheck{ID: makeID("fim"), Scope: scope, Target: target, Files: 1842, Changed: 0, Status: "simulated-pass", CheckedAt: time.Now().UTC()}
	m.state.IntegrityChecks[v.ID] = v
	return v, m.save()
}
func (m *Manager) GetSSHPolicy() SSHPolicy {
	m.mu.Lock()
	defer m.mu.Unlock()
	v := m.state.SSHPolicy
	v.AllowedCIDRs = cloneStrings(v.AllowedCIDRs)
	return v
}
func (m *Manager) SetSSHPolicy(v SSHPolicy) (SSHPolicy, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if v.Port < 1 || v.Port > 65535 {
		return v, errors.New("invalid SSH port")
	}
	for _, c := range v.AllowedCIDRs {
		if !validCIDR(c) {
			return v, fmt.Errorf("invalid CIDR %q", c)
		}
	}
	if v.RootLogin && v.PasswordAuth {
		return v, errors.New("root password login may not be enabled")
	}
	v.KeyOnly = !v.PasswordAuth
	v.UpdatedAt = time.Now().UTC()
	m.state.SSHPolicy = v
	return v, m.save()
}
func (m *Manager) SecurityPosture() map[string]any {
	m.mu.Lock()
	defer m.mu.Unlock()
	score := 100
	findings := []SecurityFinding{}
	if m.state.SSHPolicy.RootLogin {
		score -= 20
		findings = append(findings, SecurityFinding{ID: "ssh-root", Severity: "high", Title: "SSH root login enabled", Detail: "Disable direct root login and use sudo with audited accounts.", Status: "open"})
	}
	if m.state.SSHPolicy.PasswordAuth {
		score -= 15
		findings = append(findings, SecurityFinding{ID: "ssh-password", Severity: "medium", Title: "SSH password authentication enabled", Detail: "Prefer public-key authentication.", Status: "open"})
	}
	if len(m.state.Bans) > 20 {
		score -= 5
	}
	if score < 0 {
		score = 0
	}
	return map[string]any{"score": score, "findings": findings, "controls": []string{"privilege-separated agent", "RBAC", "CSRF", "account-scoped customer routes", "audit log", "typed mutations", "path validation"}}
}

func (m *Manager) ListMetrics() []MetricSample {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := append([]MetricSample(nil), m.state.Metrics...)
	return out
}
func (m *Manager) CaptureMetric(v MetricSample) (MetricSample, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if v.CPU < 0 || v.CPU > 100 || v.Memory < 0 || v.Memory > 100 || v.Disk < 0 || v.Disk > 100 {
		return v, errors.New("invalid metric sample")
	}
	v.ID = makeID("metric")
	v.CapturedAt = time.Now().UTC()
	m.state.Metrics = append(m.state.Metrics, v)
	if len(m.state.Metrics) > 1000 {
		m.state.Metrics = m.state.Metrics[len(m.state.Metrics)-1000:]
	}
	return v, m.save()
}
func (m *Manager) ListAlertRules() []AlertRule {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]AlertRule, 0, len(m.state.AlertRules))
	for _, v := range m.state.AlertRules {
		out = append(out, v)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].CreatedAt.Before(out[j].CreatedAt) })
	return out
}
func (m *Manager) CreateAlertRule(v AlertRule) (AlertRule, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	metrics := map[string]bool{"cpu": true, "memory": true, "disk": true, "load": true, "mail_queue": true, "php_busy": true}
	if !metrics[v.Metric] || !map[string]bool{">": true, ">=": true, "<": true, "<=": true}[v.Operator] || v.Threshold < 0 || v.WindowMin < 1 || v.WindowMin > 1440 {
		return v, errors.New("invalid alert rule")
	}
	if !map[string]bool{"info": true, "warning": true, "critical": true}[v.Severity] {
		v.Severity = "warning"
	}
	if v.Name == "" {
		v.Name = v.Metric + " threshold"
	}
	v.ID = makeID("alert")
	v.Enabled = true
	v.CreatedAt = time.Now().UTC()
	m.state.AlertRules[v.ID] = v
	return v, m.save()
}
func (m *Manager) ListIncidents() []Incident {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]Incident, 0, len(m.state.Incidents))
	for _, v := range m.state.Incidents {
		out = append(out, v)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].CreatedAt.After(out[j].CreatedAt) })
	return out
}

func (m *Manager) GetUpdatePolicy() UpdatePolicy {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.state.UpdatePolicy
}
func (m *Manager) SetUpdatePolicy(v UpdatePolicy) (UpdatePolicy, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if !map[string]bool{"stable": true, "early-access": true, "developer": true}[v.Channel] {
		return v, errors.New("invalid update channel")
	}
	if !regexp.MustCompile(`^[A-Za-z]{3} [0-2][0-9]:[0-5][0-9]$`).MatchString(v.RebootWindow) {
		return v, errors.New("invalid reboot window")
	}
	v.UpdatedAt = time.Now().UTC()
	m.state.UpdatePolicy = v
	return v, m.save()
}
func (m *Manager) ListResourceLimits() []ResourceLimit {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]ResourceLimit, 0, len(m.state.ResourceLimits))
	for _, v := range m.state.ResourceLimits {
		out = append(out, v)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Owner < out[j].Owner })
	return out
}
func (m *Manager) SetResourceLimit(v ResourceLimit) (ResourceLimit, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if !validOwner(v.Owner) || v.CPUPercent < 1 || v.CPUPercent > 800 || v.MemoryMB < 128 || v.PIDs < 16 || v.IOWeight < 1 || v.IOWeight > 10000 || v.DiskGB < 1 || v.BandwidthGB < 1 {
		return v, errors.New("invalid resource limit")
	}
	v.UpdatedAt = time.Now().UTC()
	m.state.ResourceLimits[v.Owner] = v
	return v, m.save()
}
func (m *Manager) MockProcesses() []ProcessInfo {
	return []ProcessInfo{{PID: 1201, User: "www-data", CPU: 1.7, Memory: 0.8, Command: "nginx: worker", Status: "running"}, {PID: 1220, User: "acmeweb", CPU: 4.2, Memory: 2.1, Command: "php-fpm: pool acmeweb", Status: "running"}, {PID: 1402, User: "mysql", CPU: 2.4, Memory: 6.8, Command: "mariadbd", Status: "running"}}
}
func (m *Manager) MockStorage() []StorageVolume {
	return []StorageVolume{{Name: "nvme0n1p2", Mount: "/", Filesystem: "ext4", SizeGB: 160, UsedGB: 62, Health: "good"}, {Name: "backup0", Mount: "/srv/backups", Filesystem: "xfs", SizeGB: 500, UsedGB: 118, Health: "good"}}
}
func (m *Manager) MockNetwork() []NetworkInterface {
	return []NetworkInterface{{Name: "eth0", Addresses: []string{"203.0.113.10/24", "2001:db8::10/64"}, State: "up", RXBytes: 982341234, TXBytes: 441208774}, {Name: "lo", Addresses: []string{"127.0.0.1/8", "::1/128"}, State: "up", RXBytes: 1244432, TXBytes: 1244432}}
}
func (m *Manager) ListBrands() []ResellerBrand {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]ResellerBrand, 0, len(m.state.Brands))
	for _, v := range m.state.Brands {
		v.Nameservers = cloneStrings(v.Nameservers)
		out = append(out, v)
	}
	return out
}
func (m *Manager) SetBrand(v ResellerBrand) (ResellerBrand, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if !validSafeText(v.Reseller, 64) || !validSafeText(v.Company, 120) {
		return v, errors.New("invalid reseller brand")
	}
	if v.Accent != "" && !regexp.MustCompile(`^#[0-9A-Fa-f]{6}$`).MatchString(v.Accent) {
		return v, errors.New("invalid accent")
	}
	for _, n := range v.Nameservers {
		if !validDomain(n) {
			return v, errors.New("invalid nameserver")
		}
	}
	v.UpdatedAt = time.Now().UTC()
	m.state.Brands[v.Reseller] = v
	return v, m.save()
}

func (m *Manager) ListDelegates() []Delegate {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]Delegate, 0, len(m.state.Delegates))
	for _, v := range m.state.Delegates {
		v.Permissions = cloneStrings(v.Permissions)
		out = append(out, v)
	}
	return out
}
func (m *Manager) CreateDelegate(v Delegate) (Delegate, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if !validOwner(v.Owner) || !validSafeText(v.Username, 64) || !map[string]bool{"developer": true, "database": true, "email": true, "billing": true, "read-only": true}[v.Role] {
		return v, errors.New("invalid delegate")
	}
	v.ID = makeID("delegate")
	v.Status = "active"
	v.CreatedAt = time.Now().UTC()
	m.state.Delegates[v.ID] = v
	return v, m.save()
}
func (m *Manager) ListMigrations() []Migration {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]Migration, 0, len(m.state.Migrations))
	for _, v := range m.state.Migrations {
		v.Steps = cloneStrings(v.Steps)
		out = append(out, v)
	}
	return out
}
func (m *Manager) RecordRealMigration(v Migration, steps []string) (Migration, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.mock {
		return v, errors.New("real migration recorder is disabled in mock mode")
	}
	if v.SourceType != "cpanel" || !validOwner(v.Account) || !validSafeText(v.Source, 255) || !validSafeText(v.Destination, 255) {
		return v, errors.New("invalid real migration")
	}
	v.ID = makeID("migration")
	v.Status = "staged-real"
	v.Steps = cloneStrings(steps)
	v.CreatedAt = time.Now().UTC()
	m.state.Migrations[v.ID] = v
	return v, m.save()
}

func (m *Manager) CreateMigration(v Migration) (Migration, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if !map[string]bool{"privora": true, "cpanel": true, "directadmin": true, "plesk": true, "generic": true}[v.SourceType] || !validOwner(v.Account) || !validSafeText(v.Source, 255) || !validSafeText(v.Destination, 255) {
		return v, errors.New("invalid migration")
	}
	v.ID = makeID("migration")
	v.Status = "simulated-ready"
	v.Steps = []string{"inventory-source", "preflight-destination", "initial-files-sync", "database-export-import", "mail-dns-ssl-map", "delta-sync", "validation", "cutover-plan"}
	v.CreatedAt = time.Now().UTC()
	m.state.Migrations[v.ID] = v
	return v, m.save()
}
func (m *Manager) ListClusters() []ClusterResource {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]ClusterResource, 0, len(m.state.Clusters))
	for _, v := range m.state.Clusters {
		v.Nodes = cloneStrings(v.Nodes)
		out = append(out, v)
	}
	return out
}
func (m *Manager) CreateCluster(v ClusterResource) (ClusterResource, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if !map[string]bool{"dns": true, "backup": true, "database": true, "mail": true}[v.Kind] || !validSafeText(v.Name, 120) || len(v.Nodes) < 1 {
		return v, errors.New("invalid cluster resource")
	}
	v.ID = makeID("cluster")
	v.Status = "simulation-contract"
	v.CreatedAt = time.Now().UTC()
	m.state.Clusters[v.ID] = v
	return v, m.save()
}

func (m *Manager) ListLoadBalancers() []LoadBalancer {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]LoadBalancer, 0, len(m.state.LoadBalancers))
	for _, v := range m.state.LoadBalancers {
		v.Backends = cloneStrings(v.Backends)
		out = append(out, v)
	}
	return out
}
func (m *Manager) CreateLoadBalancer(v LoadBalancer) (LoadBalancer, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if !validSafeText(v.Name, 120) || !validSafeText(v.Region, 80) || len(v.Backends) < 1 || !map[string]bool{"round-robin": true, "least-connections": true, "weighted": true}[v.Algorithm] {
		return v, errors.New("invalid load balancer")
	}
	v.ID = makeID("lb")
	v.Status = "simulation-contract"
	v.CreatedAt = time.Now().UTC()
	m.state.LoadBalancers[v.ID] = v
	return v, m.save()
}
func (m *Manager) ListProfiles() []ProvisionProfile {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]ProvisionProfile, 0, len(m.state.Profiles))
	for _, v := range m.state.Profiles {
		v.Packages = cloneStrings(v.Packages)
		out = append(out, v)
	}
	return out
}
func (m *Manager) CreateProfile(v ProvisionProfile) (ProvisionProfile, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if !map[string]bool{"ubuntu-lts": true, "debian-stable": true, "almalinux": true, "rocky": true}[v.OS] || !map[string]bool{"full-hosting": true, "web": true, "database": true, "mail": true, "dns": true, "backup": true}[v.Role] || !validSafeText(v.Name, 120) {
		return v, errors.New("invalid provision profile")
	}
	v.ID = makeID("profile")
	v.CreatedAt = time.Now().UTC()
	m.state.Profiles[v.ID] = v
	return v, m.save()
}
func (m *Manager) ListAPIKeys() []APIKey {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]APIKey, 0, len(m.state.APIKeys))
	for _, v := range m.state.APIKeys {
		v.Scopes = cloneStrings(v.Scopes)
		v.SecretDigest = ""
		out = append(out, v)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].CreatedAt.Before(out[j].CreatedAt) })
	return out
}
func (m *Manager) CreateAPIKey(v APIKey) (APIKey, string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if !validSafeText(v.Name, 100) || len(v.Scopes) < 1 {
		return v, "", errors.New("invalid API key")
	}
	allowed := map[string]bool{
		"health.read": true, "accounts.read": true, "accounts.write": true, "sites.read": true, "sites.write": true, "resources.read": true,
		"backups.read": true, "backups.write": true, "dns.read": true, "dns.write": true, "ssl.read": true, "ssl.write": true,
		"mail.read": true, "mail.write": true, "monitoring.read": true, "security.read": true, "databases.read": true, "databases.write": true,
	}
	for _, scope := range v.Scopes {
		if !allowed[scope] {
			return v, "", fmt.Errorf("unsupported API scope %q", scope)
		}
	}
	if v.Owner != "" && !ownerRx.MatchString(v.Owner) {
		return v, "", errors.New("invalid API key owner")
	}
	if err := validateCIDRs(v.AllowedCIDRs); err != nil {
		return v, "", err
	}
	if !v.ExpiresAt.IsZero() && v.ExpiresAt.Before(time.Now().UTC().Add(5*time.Minute)) {
		return v, "", errors.New("API key expiration must be in the future")
	}
	raw := make([]byte, 24)
	_, _ = rand.Read(raw)
	tokenBody := hex.EncodeToString(raw)
	v.ID = makeID("key")
	v.Prefix = tokenBody[:8]
	secret := "prv_" + v.Prefix + "_" + tokenBody[8:]
	d := sha256.Sum256([]byte(secret))
	v.SecretDigest = hex.EncodeToString(d[:])
	v.Status = "active"
	v.CreatedAt = time.Now().UTC()
	v.LastUsedAt = time.Time{}
	v.LastUsedIP = ""
	m.state.APIKeys[v.ID] = v
	public := v
	public.SecretDigest = ""
	return public, secret, m.save()
}
func ipAllowedByCIDRs(ip string, cidrs []string) bool {
	if len(cidrs) == 0 {
		return true
	}
	parsed := net.ParseIP(strings.TrimSpace(ip))
	if parsed == nil {
		return false
	}
	for _, raw := range cidrs {
		_, n, err := net.ParseCIDR(raw)
		if err == nil && n.Contains(parsed) {
			return true
		}
	}
	return false
}
func (m *Manager) VerifyAPIKeyForIP(secret, ip string) (APIKey, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if !strings.HasPrefix(secret, "prv_") {
		return APIKey{}, false
	}
	d := sha256.Sum256([]byte(secret))
	got := hex.EncodeToString(d[:])
	now := time.Now().UTC()
	for id, v := range m.state.APIKeys {
		if v.Status != "active" || v.SecretDigest == "" {
			continue
		}
		if !v.ExpiresAt.IsZero() && now.After(v.ExpiresAt) {
			v.Status = "expired"
			m.state.APIKeys[id] = v
			continue
		}
		if subtle.ConstantTimeCompare([]byte(got), []byte(v.SecretDigest)) == 1 {
			if !ipAllowedByCIDRs(ip, v.AllowedCIDRs) {
				return APIKey{}, false
			}
			v.LastUsedAt = now
			v.LastUsedIP = ip
			m.state.APIKeys[id] = v
			_ = m.save()
			v.SecretDigest = ""
			v.Scopes = cloneStrings(v.Scopes)
			v.AllowedCIDRs = cloneStrings(v.AllowedCIDRs)
			return v, true
		}
	}
	return APIKey{}, false
}
func (m *Manager) VerifyAPIKey(secret string) (APIKey, bool) { return m.VerifyAPIKeyForIP(secret, "") }
func (m *Manager) RevokeAPIKey(id string) (APIKey, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	v, ok := m.state.APIKeys[id]
	if !ok {
		return APIKey{}, errors.New("API key not found")
	}
	v.Status = "revoked"
	m.state.APIKeys[id] = v
	pub := v
	pub.SecretDigest = ""
	return pub, m.save()
}
func (m *Manager) RotateAPIKey(id string) (APIKey, string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	v, ok := m.state.APIKeys[id]
	if !ok {
		return APIKey{}, "", errors.New("API key not found")
	}
	raw := make([]byte, 24)
	_, _ = rand.Read(raw)
	tokenBody := hex.EncodeToString(raw)
	v.Prefix = tokenBody[:8]
	secret := "prv_" + v.Prefix + "_" + tokenBody[8:]
	d := sha256.Sum256([]byte(secret))
	v.SecretDigest = hex.EncodeToString(d[:])
	v.Status = "active"
	v.LastUsedAt = time.Time{}
	v.LastUsedIP = ""
	m.state.APIKeys[id] = v
	pub := v
	pub.SecretDigest = ""
	return pub, secret, m.save()
}
func (m *Manager) ListWebhooks() []Webhook {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]Webhook, 0, len(m.state.Webhooks))
	for _, v := range m.state.Webhooks {
		v.Events = cloneStrings(v.Events)
		out = append(out, v)
	}
	return out
}
func (m *Manager) CreateWebhook(v Webhook) (Webhook, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if !strings.HasPrefix(v.URL, "https://") || len(v.Events) < 1 {
		return v, errors.New("webhook must use https and at least one event")
	}
	v.ID = makeID("hook")
	v.Status = "active-contract"
	v.CreatedAt = time.Now().UTC()
	m.state.Webhooks[v.ID] = v
	return v, m.save()
}

func (m *Manager) ListPlugins() []Plugin {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]Plugin, 0, len(m.state.Plugins))
	for _, v := range m.state.Plugins {
		out = append(out, v)
	}
	return out
}
func (m *Manager) InstallPlugin(v Plugin) (Plugin, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if !validSafeText(v.Name, 120) || !regexp.MustCompile(`^\d+\.\d+\.\d+$`).MatchString(v.Version) || !map[string]bool{"backup": true, "dns": true, "billing": true, "security": true, "app": true, "provider": true}[v.Type] {
		return v, errors.New("invalid plugin")
	}
	v.ID = makeID("plugin")
	v.Status = "registered-contract"
	v.CreatedAt = time.Now().UTC()
	m.state.Plugins[v.ID] = v
	return v, m.save()
}
func (m *Manager) ListInvoices() []Invoice {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]Invoice, 0, len(m.state.Invoices))
	for _, v := range m.state.Invoices {
		out = append(out, v)
	}
	return out
}
func (m *Manager) CreateInvoice(v Invoice) (Invoice, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if !validEmail(v.Customer) || v.AmountCents < 1 || !map[string]bool{"USD": true, "EUR": true, "GBP": true}[v.Currency] {
		return v, errors.New("invalid invoice")
	}
	v.ID = makeID("inv")
	v.Status = "draft-simulation"
	v.CreatedAt = time.Now().UTC()
	if v.DueAt.IsZero() {
		v.DueAt = v.CreatedAt.Add(14 * 24 * time.Hour)
	}
	m.state.Invoices[v.ID] = v
	return v, m.save()
}
func (m *Manager) ListNotifications() []Notification {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]Notification, 0, len(m.state.Notifications))
	for _, v := range m.state.Notifications {
		out = append(out, v)
	}
	return out
}
func (m *Manager) CreateNotification(v Notification) (Notification, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if !map[string]bool{"email": true, "webhook": true, "slack": true, "discord": true}[v.Channel] || !validSafeText(v.Recipient, 255) || !validSafeText(v.Subject, 200) {
		return v, errors.New("invalid notification")
	}
	v.ID = makeID("notice")
	v.Status = "queued-simulation"
	v.CreatedAt = time.Now().UTC()
	m.state.Notifications[v.ID] = v
	return v, m.save()
}

func (m *Manager) ListDiagnostics() []Diagnostic {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]Diagnostic, 0, len(m.state.Diagnostics))
	for _, v := range m.state.Diagnostics {
		out = append(out, v)
	}
	return out
}
func (m *Manager) RunDiagnostic(scope string) (Diagnostic, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if !map[string]bool{"server": true, "php": true, "database": true, "mail": true, "dns": true, "site": true}[scope] {
		return Diagnostic{}, errors.New("invalid diagnostic scope")
	}
	v := Diagnostic{ID: makeID("diag"), Scope: scope, Summary: "Development telemetry indicates healthy capacity.", Severity: "info", Recommendation: "Keep production adapters gated until integration certification passes.", CreatedAt: time.Now().UTC()}
	m.state.Diagnostics[v.ID] = v
	return v, m.save()
}
func (m *Manager) ListRepairs() []RepairRun {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]RepairRun, 0, len(m.state.Repairs))
	for _, v := range m.state.Repairs {
		v.Steps = cloneStrings(v.Steps)
		out = append(out, v)
	}
	return out
}
func (m *Manager) RunRepair(resource, action string) (RepairRun, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if !validSafeText(resource, 160) || !map[string]bool{"restore-config": true, "reload": true, "rollback": true, "clear-cache": true}[action] {
		return RepairRun{}, errors.New("invalid repair")
	}
	v := RepairRun{ID: makeID("repair"), Resource: resource, Action: action, Snapshot: makeID("snapshot"), Status: "simulated-rolled-forward", Steps: []string{"capture-before-state", "validate-proposed-action", "apply-to-simulation", "health-check", "retain-rollback-point"}, CreatedAt: time.Now().UTC()}
	m.state.Repairs[v.ID] = v
	return v, m.save()
}
func (m *Manager) ListRevisions() []ConfigRevision {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]ConfigRevision, 0, len(m.state.Revisions))
	for _, v := range m.state.Revisions {
		out = append(out, v)
	}
	return out
}
func (m *Manager) CreateRevision(resource, digest string) (ConfigRevision, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if !validSafeText(resource, 160) || !regexp.MustCompile(`^[a-f0-9]{64}$`).MatchString(digest) {
		return ConfigRevision{}, errors.New("invalid config revision")
	}
	version := 1
	for _, x := range m.state.Revisions {
		if x.Resource == resource && x.Version >= version {
			version = x.Version + 1
		}
	}
	v := ConfigRevision{ID: makeID("rev"), Resource: resource, Version: version, Digest: digest, Status: "sealed", CreatedAt: time.Now().UTC()}
	m.state.Revisions[v.ID] = v
	return v, m.save()
}
func (m *Manager) ListSecrets() []SecretRef {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]SecretRef, 0, len(m.state.Secrets))
	for _, v := range m.state.Secrets {
		out = append(out, v)
	}
	return out
}
func (m *Manager) CreateSecretRef(name, typ string) (SecretRef, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if !validSafeText(name, 120) || !map[string]bool{"database": true, "smtp": true, "api": true, "cloud": true, "backup": true, "certificate": true}[typ] {
		return SecretRef{}, errors.New("invalid secret reference")
	}
	v := SecretRef{ID: makeID("secret"), Name: name, Type: typ, KeyID: makeID("dek"), Status: "reference-only-no-secret-material", CreatedAt: time.Now().UTC()}
	m.state.Secrets[v.ID] = v
	return v, m.save()
}
func (m *Manager) ListReleases() []SignedRelease {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]SignedRelease, 0, len(m.state.Releases))
	for _, v := range m.state.Releases {
		out = append(out, v)
	}
	return out
}
func (m *Manager) AddSignedRelease(v SignedRelease) (SignedRelease, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if !regexp.MustCompile(`^\d+\.\d+\.\d+(?:-[a-z0-9.-]+)?$`).MatchString(v.Version) || !map[string]bool{"stable": true, "early-access": true, "developer": true}[v.Channel] || !regexp.MustCompile(`^[a-f0-9]{64}$`).MatchString(v.Digest) || !validSafeText(v.Signature, 512) {
		return v, errors.New("invalid signed release")
	}
	v.Status = "signature-recorded-not-cryptographically-verified"
	v.CreatedAt = time.Now().UTC()
	m.state.Releases[v.Version] = v
	return v, m.save()
}

func (m *Manager) ListExports() []ExportBundle {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]ExportBundle, 0, len(m.state.Exports))
	for _, v := range m.state.Exports {
		out = append(out, v)
	}
	return out
}
func (m *Manager) CreateExport(account string, encrypted bool) (ExportBundle, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if !validOwner(account) {
		return ExportBundle{}, errors.New("invalid account")
	}
	v := ExportBundle{ID: makeID("export"), Account: account, Format: "privora-account-v1", Encrypted: encrypted, Status: "simulated-ready", CreatedAt: time.Now().UTC()}
	m.state.Exports[v.ID] = v
	return v, m.save()
}
func (m *Manager) ListRecommendations() []PerformanceRecommendation {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]PerformanceRecommendation, 0, len(m.state.Recommendations))
	for _, v := range m.state.Recommendations {
		out = append(out, v)
	}
	return out
}
func (m *Manager) CreateRecommendation(resource, current, suggested, impact string) (PerformanceRecommendation, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if !validSafeText(resource, 160) || !validSafeText(current, 240) || !validSafeText(suggested, 240) || !validSafeText(impact, 240) {
		return PerformanceRecommendation{}, errors.New("invalid recommendation")
	}
	v := PerformanceRecommendation{ID: makeID("perf"), Resource: resource, Current: current, Suggested: suggested, Impact: impact, Status: "advisory"}
	m.state.Recommendations[v.ID] = v
	return v, m.save()
}
func (m *Manager) ListStaging() []StagingEnvironment {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]StagingEnvironment, 0, len(m.state.Staging))
	for _, v := range m.state.Staging {
		out = append(out, v)
	}
	return out
}
func (m *Manager) CreateStaging(v StagingEnvironment) (StagingEnvironment, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if !validDomain(v.ProductionDomain) || !validDomain(v.StagingDomain) || v.ProductionDomain == v.StagingDomain || !validOwner(v.Owner) {
		return v, errors.New("invalid staging environment")
	}
	v.ID = makeID("stage")
	v.Status = "simulated-clone-ready"
	v.CreatedAt = time.Now().UTC()
	m.state.Staging[v.ID] = v
	return v, m.save()
}
func (m *Manager) ListIsolation() []IsolationProfile {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]IsolationProfile, 0, len(m.state.Isolation))
	for _, v := range m.state.Isolation {
		out = append(out, v)
	}
	return out
}
func (m *Manager) SetIsolation(v IsolationProfile) (IsolationProfile, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if !validOwner(v.Owner) {
		return v, errors.New("invalid isolation owner")
	}
	v.Status = "policy-recorded-host-adapter-gated"
	v.UpdatedAt = time.Now().UTC()
	m.state.Isolation[v.Owner] = v
	return v, m.save()
}
func (m *Manager) ListAccountControls() []AccountControl {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]AccountControl, 0, len(m.state.AccountControls))
	for _, v := range m.state.AccountControls {
		out = append(out, v)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Kind == out[j].Kind {
			return out[i].CreatedAt.Before(out[j].CreatedAt)
		}
		return out[i].Kind < out[j].Kind
	})
	return out
}

func validAccountControl(v AccountControl) error {
	if !validOwner(v.Owner) {
		return errors.New("invalid account owner")
	}
	allowed := map[string]bool{
		"redirect": true, "error_page": true, "mime_type": true,
		"directory_privacy": true, "hotlink": true, "ip_block": true,
		"ssh_key": true, "autoresponder": true, "spam_policy": true,
		"php_setting": true, "php_extension": true, "restore_request": true,
	}
	if !allowed[v.Kind] {
		return errors.New("unsupported account control kind")
	}
	if v.Domain != "" && !validDomain(v.Domain) {
		return errors.New("invalid control domain")
	}
	requiresDomain := map[string]bool{
		"redirect": true, "error_page": true, "directory_privacy": true,
		"hotlink": true, "autoresponder": true, "spam_policy": true,
		"php_setting": true, "php_extension": true,
	}
	if requiresDomain[v.Kind] && v.Domain == "" {
		return errors.New("domain is required for this control")
	}
	if len(strings.TrimSpace(v.Name)) == 0 || len(v.Name) > 512 || len(v.Value) > 8192 || strings.ContainsAny(v.Name, "\x00\r\n") || strings.ContainsAny(v.Value, "\x00\r") {
		return errors.New("invalid account control value")
	}
	switch v.Kind {
	case "redirect":
		if !strings.HasPrefix(v.Name, "/") || strings.Contains(v.Name, "..") || strings.ContainsAny(v.Name, "?#") {
			return errors.New("invalid redirect source path")
		}
		if !(strings.HasPrefix(v.Value, "https://") || strings.HasPrefix(v.Value, "http://") || strings.HasPrefix(v.Value, "/")) || strings.Contains(strings.ToLower(v.Value), "javascript:") {
			return errors.New("invalid redirect target")
		}
	case "error_page":
		if !map[string]bool{"400": true, "401": true, "403": true, "404": true, "410": true, "429": true, "500": true, "502": true, "503": true}[v.Name] {
			return errors.New("unsupported error page code")
		}
		if !strings.HasPrefix(v.Value, "/") || strings.Contains(v.Value, "..") {
			return errors.New("invalid error page path")
		}
	case "mime_type":
		if !regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9.+_-]{0,31}$`).MatchString(v.Name) || !regexp.MustCompile(`^[a-zA-Z0-9.+_-]+/[a-zA-Z0-9.+_-]+$`).MatchString(v.Value) {
			return errors.New("invalid MIME mapping")
		}
	case "directory_privacy":
		if strings.HasPrefix(v.Name, "/") || strings.Contains(v.Name, "..") || v.Value != "enabled" && v.Value != "disabled" {
			return errors.New("invalid directory privacy policy")
		}
	case "hotlink":
		if v.Name != "images" || v.Value != "enabled" && v.Value != "disabled" {
			return errors.New("invalid hotlink policy")
		}
	case "ip_block":
		if net.ParseIP(v.Name) == nil {
			if _, _, err := net.ParseCIDR(v.Name); err != nil {
				return errors.New("invalid IP/CIDR")
			}
		}
	case "ssh_key":
		if !regexp.MustCompile(`^[A-Za-z0-9_.-]{1,64}$`).MatchString(v.Name) || !(strings.HasPrefix(v.Value, "ssh-ed25519 ") || strings.HasPrefix(v.Value, "ssh-rsa ") || strings.HasPrefix(v.Value, "ecdsa-sha2-")) {
			return errors.New("invalid SSH public key")
		}
	case "autoresponder":
		parts := strings.Split(v.Name, "@")
		if len(parts) != 2 || parts[0] == "" || !strings.EqualFold(parts[1], v.Domain) || len(v.Value) < 1 {
			return errors.New("invalid autoresponder")
		}
	case "spam_policy":
		if !map[string]bool{"normal": true, "aggressive": true, "lenient": true, "disabled": true}[v.Name] || !map[string]bool{"quarantine": true, "reject": true, "deliver": true}[v.Value] {
			return errors.New("invalid spam policy")
		}
	case "php_setting":
		if !map[string]bool{"memory_limit": true, "upload_max_filesize": true, "post_max_size": true, "max_execution_time": true, "max_input_vars": true, "display_errors": true, "opcache.enable": true}[v.Name] || !regexp.MustCompile(`^[A-Za-z0-9._-]{1,32}$`).MatchString(v.Value) {
			return errors.New("invalid PHP setting")
		}
	case "php_extension":
		if !regexp.MustCompile(`^[a-z0-9_]{2,32}$`).MatchString(v.Name) || v.Value != "enabled" && v.Value != "disabled" {
			return errors.New("invalid PHP extension policy")
		}
	case "restore_request":
		if !regexp.MustCompile(`^[A-Za-z0-9_.-]{3,128}$`).MatchString(v.Name) || !map[string]bool{"files": true, "database": true, "site": true, "account": true}[v.Value] {
			return errors.New("invalid restore request")
		}
	}
	return nil
}

func (m *Manager) CreateAccountControl(v AccountControl) (AccountControl, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	v.Owner = strings.ToLower(strings.TrimSpace(v.Owner))
	v.Domain = strings.ToLower(strings.TrimSpace(v.Domain))
	v.Kind = strings.ToLower(strings.TrimSpace(v.Kind))
	v.Name = strings.TrimSpace(v.Name)
	v.Value = strings.TrimSpace(v.Value)
	if err := validAccountControl(v); err != nil {
		return v, err
	}
	v.ID = makeID("ctl")
	v.Status = "policy-recorded-host-adapter-gated"
	v.CreatedAt = time.Now().UTC()
	m.state.AccountControls[v.ID] = v
	return v, m.save()
}

func (m *Manager) ListCertification() []CertificationGate {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]CertificationGate, 0, len(m.state.Certification))
	for _, v := range m.state.Certification {
		v.Evidence = cloneStrings(v.Evidence)
		v.Blockers = cloneStrings(v.Blockers)
		out = append(out, v)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}
func (m *Manager) RecordCertification(v CertificationGate) (CertificationGate, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if !validSafeText(v.Name, 180) || !map[string]bool{"pass": true, "fail": true, "blocked": true}[v.Status] {
		return v, errors.New("invalid certification gate")
	}
	if v.ID == "" {
		v.ID = makeID("cert")
	}
	v.UpdatedAt = time.Now().UTC()
	m.state.Certification[v.ID] = v
	return v, m.save()
}
func (m *Manager) ListHorizons() []HorizonState {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]HorizonState, 0, len(m.state.Horizons))
	for _, v := range m.state.Horizons {
		v.Blockers = cloneStrings(v.Blockers)
		out = append(out, v)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Major < out[j].Major })
	return out
}

func (m *Manager) Summary() map[string]int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return map[string]int{
		"cron_jobs": len(m.state.CronJobs), "deployments": len(m.state.Deployments), "app_installs": len(m.state.AppInstalls), "mail_domains": len(m.state.MailDomains), "mail_aliases": len(m.state.MailAliases), "reputation_checks": len(m.state.Reputation), "bans": len(m.state.Bans), "malware_scans": len(m.state.MalwareScans), "integrity_checks": len(m.state.IntegrityChecks), "metrics": len(m.state.Metrics), "alert_rules": len(m.state.AlertRules), "incidents": len(m.state.Incidents), "resource_limits": len(m.state.ResourceLimits), "delegates": len(m.state.Delegates), "migrations": len(m.state.Migrations), "clusters": len(m.state.Clusters), "load_balancers": len(m.state.LoadBalancers), "profiles": len(m.state.Profiles), "api_keys": len(m.state.APIKeys), "webhooks": len(m.state.Webhooks), "plugins": len(m.state.Plugins), "invoices": len(m.state.Invoices), "notifications": len(m.state.Notifications), "diagnostics": len(m.state.Diagnostics), "repairs": len(m.state.Repairs), "revisions": len(m.state.Revisions), "secrets": len(m.state.Secrets), "releases": len(m.state.Releases), "exports": len(m.state.Exports), "recommendations": len(m.state.Recommendations), "staging": len(m.state.Staging), "isolation": len(m.state.Isolation), "account_controls": len(m.state.AccountControls), "certification": len(m.state.Certification),
	}
}

func (m *Manager) String() string {
	return fmt.Sprintf("platform(%d cron,%d deployments,%d migrations)", len(m.state.CronJobs), len(m.state.Deployments), len(m.state.Migrations))
}

// Deliberately retained to force compile-time awareness that simulation behavior is a build property.
func (m *Manager) IsMock() bool { return m.mock }
func SafeName(v string) bool    { return safeNameRx.MatchString(v) }
