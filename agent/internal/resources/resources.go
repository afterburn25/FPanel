package resources

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"
)

var domainRx = regexp.MustCompile(`^(?i:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+)$`)
var nameRx = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9_.-]{1,62}$`)

type SFTPAccount struct {
	Username  string    `json:"username"`
	Owner     string    `json:"owner"`
	Root      string    `json:"root"`
	Auth      string    `json:"auth"`
	Status    string    `json:"status"`
	CreatedAt time.Time `json:"created_at"`
}
type FirewallRule struct {
	ID        string    `json:"id"`
	Direction string    `json:"direction"`
	Protocol  string    `json:"protocol"`
	Port      int       `json:"port"`
	Source    string    `json:"source"`
	Action    string    `json:"action"`
	Status    string    `json:"status"`
	CreatedAt time.Time `json:"created_at"`
}
type Application struct {
	ID        string    `json:"id"`
	Type      string    `json:"type"`
	Domain    string    `json:"domain"`
	Owner     string    `json:"owner"`
	Runtime   string    `json:"runtime"`
	Status    string    `json:"status"`
	CreatedAt time.Time `json:"created_at"`
}
type Database struct {
	Name      string    `json:"name"`
	User      string    `json:"user,omitempty"`
	Engine    string    `json:"engine"`
	Owner     string    `json:"owner"`
	Status    string    `json:"status"`
	CreatedAt time.Time `json:"created_at"`
}
type DNSRecord struct {
	Type  string `json:"type"`
	Name  string `json:"name"`
	Value string `json:"value"`
	TTL   int    `json:"ttl"`
}
type DNSZone struct {
	Domain    string      `json:"domain"`
	DNSSEC    bool        `json:"dnssec"`
	Records   []DNSRecord `json:"records"`
	CreatedAt time.Time   `json:"created_at"`
}
type NameserverConfig struct {
	BaseDomain string    `json:"base_domain"`
	Primary    string    `json:"primary"`
	Secondary  string    `json:"secondary"`
	IPv4       string    `json:"ipv4,omitempty"`
	IPv6       string    `json:"ipv6,omitempty"`
	GlueStatus string    `json:"glue_status"`
	Default    bool      `json:"default,omitempty"`
	UpdatedAt  time.Time `json:"updated_at"`
}
type Certificate struct {
	Domain    string    `json:"domain"`
	Provider  string    `json:"provider"`
	Status    string    `json:"status"`
	AutoRenew bool      `json:"auto_renew"`
	ExpiresAt time.Time `json:"expires_at"`
	CreatedAt time.Time `json:"created_at"`
}
type Backup struct {
	ID          string    `json:"id"`
	Scope       string    `json:"scope"`
	Resource    string    `json:"resource"`
	Status      string    `json:"status"`
	Destination string    `json:"destination"`
	SHA256      string    `json:"sha256,omitempty"`
	SizeBytes   uint64    `json:"size_bytes"`
	PolicyID    string    `json:"policy_id,omitempty"`
	VerifiedAt  time.Time `json:"verified_at,omitempty"`
	CreatedAt   time.Time `json:"created_at"`
}
type Mailbox struct {
	Address   string    `json:"address"`
	Domain    string    `json:"domain"`
	QuotaMB   int       `json:"quota_mb"`
	Status    string    `json:"status"`
	CreatedAt time.Time `json:"created_at"`
}
type Reseller struct {
	Name            string    `json:"name"`
	Company         string    `json:"company"`
	MaxAccounts     int       `json:"max_accounts"`
	DiskGB          int       `json:"disk_gb,omitempty"`
	BandwidthGB     int       `json:"bandwidth_gb,omitempty"`
	AllowedPackages []string  `json:"allowed_packages,omitempty"`
	AllowedFeatures []string  `json:"allowed_feature_lists,omitempty"`
	DNSAllowed      bool      `json:"dns_allowed"`
	SSLAllowed      bool      `json:"ssl_allowed"`
	NameserverBases []string  `json:"nameserver_bases,omitempty"`
	Status          string    `json:"status"`
	CreatedAt       time.Time `json:"created_at"`
	UpdatedAt       time.Time `json:"updated_at,omitempty"`
}
type Node struct {
	ID        string    `json:"id"`
	Name      string    `json:"name"`
	Role      string    `json:"role"`
	Region    string    `json:"region"`
	Endpoint  string    `json:"endpoint"`
	Status    string    `json:"status"`
	CreatedAt time.Time `json:"created_at"`
}
type Instance struct {
	ID        string    `json:"id"`
	Provider  string    `json:"provider"`
	Region    string    `json:"region"`
	Size      string    `json:"size"`
	Image     string    `json:"image"`
	Status    string    `json:"status"`
	CreatedAt time.Time `json:"created_at"`
}
type AutomationRun struct {
	ID        string    `json:"id"`
	Customer  string    `json:"customer"`
	Domain    string    `json:"domain"`
	Package   string    `json:"package"`
	Status    string    `json:"status"`
	Steps     []string  `json:"steps"`
	CreatedAt time.Time `json:"created_at"`
}
type Workload struct {
	ID              string    `json:"id"`
	Name            string    `json:"name"`
	Type            string    `json:"type"`
	Region          string    `json:"region"`
	DesiredReplicas int       `json:"desired_replicas"`
	Status          string    `json:"status"`
	CreatedAt       time.Time `json:"created_at"`
}

type State struct {
	SFTPAccounts  map[string]SFTPAccount   `json:"sftp_accounts"`
	FirewallRules map[string]FirewallRule  `json:"firewall_rules"`
	Applications  map[string]Application   `json:"applications"`
	Databases     map[string]Database      `json:"databases"`
	DNSZones      map[string]DNSZone       `json:"dns_zones"`
	Certificates  map[string]Certificate   `json:"certificates"`
	Backups       map[string]Backup        `json:"backups"`
	Mailboxes     map[string]Mailbox       `json:"mailboxes"`
	Resellers     map[string]Reseller      `json:"resellers"`
	Nodes         map[string]Node          `json:"nodes"`
	Instances     map[string]Instance      `json:"instances"`
	Workloads     map[string]Workload      `json:"workloads"`
	Automations   map[string]AutomationRun `json:"automations"`
	// Nameservers is retained as a compatibility mirror of the default set.
	Nameservers           NameserverConfig            `json:"nameservers"`
	NameserverSets        map[string]NameserverConfig `json:"nameserver_sets,omitempty"`
	DefaultNameserverBase string                      `json:"default_nameserver_base,omitempty"`
	// NameserverAssignments explicitly maps a hosted root domain to the branded
	// nameserver set it should publish. Never infer this from the hosted domain
	// name: example.org may intentionally use ns1/ns2.example.com.
	NameserverAssignments map[string]string `json:"nameserver_assignments,omitempty"`
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
	return m
}
func (m *Manager) ensure() {
	if m.state.SFTPAccounts == nil {
		m.state.SFTPAccounts = map[string]SFTPAccount{}
	}
	if m.state.FirewallRules == nil {
		m.state.FirewallRules = map[string]FirewallRule{}
	}
	if m.state.Applications == nil {
		m.state.Applications = map[string]Application{}
	}
	if m.state.Databases == nil {
		m.state.Databases = map[string]Database{}
	}
	if m.state.DNSZones == nil {
		m.state.DNSZones = map[string]DNSZone{}
	}
	if m.state.Certificates == nil {
		m.state.Certificates = map[string]Certificate{}
	}
	if m.state.Backups == nil {
		m.state.Backups = map[string]Backup{}
	}
	if m.state.Mailboxes == nil {
		m.state.Mailboxes = map[string]Mailbox{}
	}
	if m.state.Resellers == nil {
		m.state.Resellers = map[string]Reseller{}
	}
	if m.state.Nodes == nil {
		m.state.Nodes = map[string]Node{}
	}
	if m.state.Instances == nil {
		m.state.Instances = map[string]Instance{}
	}
	if m.state.Workloads == nil {
		m.state.Workloads = map[string]Workload{}
	}
	if m.state.Automations == nil {
		m.state.Automations = map[string]AutomationRun{}
	}
	if m.state.NameserverSets == nil {
		m.state.NameserverSets = map[string]NameserverConfig{}
	}
	if m.state.NameserverAssignments == nil {
		m.state.NameserverAssignments = map[string]string{}
	}
	// One-time in-memory migration from the legacy single nameserver pair.
	if m.state.Nameservers.BaseDomain != "" {
		base := strings.ToLower(strings.TrimSpace(m.state.Nameservers.BaseDomain))
		if _, ok := m.state.NameserverSets[base]; !ok {
			v := m.state.Nameservers
			v.BaseDomain = base
			m.state.NameserverSets[base] = v
		}
		if m.state.DefaultNameserverBase == "" {
			m.state.DefaultNameserverBase = base
		}
	}
	if m.state.DefaultNameserverBase == "" && len(m.state.NameserverSets) > 0 {
		keys := make([]string, 0, len(m.state.NameserverSets))
		for k := range m.state.NameserverSets {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		m.state.DefaultNameserverBase = keys[0]
	}
	for k, v := range m.state.NameserverSets {
		v.Default = k == m.state.DefaultNameserverBase
		m.state.NameserverSets[k] = v
	}
	if v, ok := m.state.NameserverSets[m.state.DefaultNameserverBase]; ok {
		m.state.Nameservers = v
	} else if len(m.state.NameserverSets) == 0 {
		m.state.Nameservers = NameserverConfig{}
	}
}
func (m *Manager) load() error {
	b, err := os.ReadFile(m.path)
	if errors.Is(err, os.ErrNotExist) {
		m.ensure()
		return nil
	}
	if err != nil {
		return err
	}
	if err = json.Unmarshal(b, &m.state); err != nil {
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
	if err = os.WriteFile(tmp, b, 0640); err != nil {
		return err
	}
	return os.Rename(tmp, m.path)
}
func id(prefix string) string {
	b := make([]byte, 5)
	_, _ = rand.Read(b)
	return prefix + "_" + hex.EncodeToString(b)
}
func validDomain(s string) bool { return len(s) <= 253 && domainRx.MatchString(s) }
func validName(s string) bool   { return nameRx.MatchString(s) }

func (m *Manager) ListSFTPAccounts() []SFTPAccount {
	m.mu.Lock()
	defer m.mu.Unlock()
	a := make([]SFTPAccount, 0, len(m.state.SFTPAccounts))
	for _, v := range m.state.SFTPAccounts {
		a = append(a, v)
	}
	sort.Slice(a, func(i, j int) bool { return a[i].Username < a[j].Username })
	return a
}
func (m *Manager) RemoveSFTPAccount(username string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	username = strings.ToLower(strings.TrimSpace(username))
	if _, ok := m.state.SFTPAccounts[username]; !ok {
		return errors.New("SFTP account is not Privora-managed")
	}
	delete(m.state.SFTPAccounts, username)
	return m.save()
}

func (m *Manager) RecordRealSFTPAccount(v SFTPAccount) (SFTPAccount, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.mock {
		return v, errors.New("real SFTP recorder is disabled in mock mode")
	}
	if !validName(v.Username) || !validName(v.Owner) {
		return v, errors.New("invalid SFTP account")
	}
	if v.Username != v.Owner {
		return v, errors.New("real SFTP currently binds to the hosting account owner")
	}
	if strings.TrimSpace(v.Root) == "" || strings.Contains(v.Root, "..") || !strings.HasPrefix(v.Root, "/home/") {
		return v, errors.New("invalid SFTP root")
	}
	if _, ok := m.state.SFTPAccounts[v.Username]; ok {
		return v, errors.New("SFTP account already exists")
	}
	v.Auth = "password"
	v.Status = "provisioned-real"
	v.CreatedAt = time.Now().UTC()
	m.state.SFTPAccounts[v.Username] = v
	return v, m.save()
}

func (m *Manager) CreateSFTPAccount(v SFTPAccount) (SFTPAccount, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if !m.mock {
		return v, errors.New("real SFTP backend is not certified")
	}
	if !validName(v.Username) || !validName(v.Owner) {
		return v, errors.New("invalid SFTP account")
	}
	if strings.TrimSpace(v.Root) == "" || strings.Contains(v.Root, "..") || !strings.HasPrefix(v.Root, "/home/") {
		return v, errors.New("invalid SFTP root")
	}
	if _, ok := m.state.SFTPAccounts[v.Username]; ok {
		return v, errors.New("SFTP account already exists")
	}
	if v.Auth == "" {
		v.Auth = "ssh-key"
	}
	if v.Auth != "ssh-key" && v.Auth != "password" {
		return v, errors.New("invalid SFTP auth mode")
	}
	v.Status = "active"
	v.CreatedAt = time.Now().UTC()
	m.state.SFTPAccounts[v.Username] = v
	return v, m.save()
}
func (m *Manager) ListFirewallRules() []FirewallRule {
	m.mu.Lock()
	defer m.mu.Unlock()
	a := make([]FirewallRule, 0, len(m.state.FirewallRules))
	for _, v := range m.state.FirewallRules {
		a = append(a, v)
	}
	sort.Slice(a, func(i, j int) bool { return a[i].CreatedAt.Before(a[j].CreatedAt) })
	return a
}
func (m *Manager) RecordRealFirewallRule(v FirewallRule) (FirewallRule, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.mock {
		return v, errors.New("real firewall recorder is disabled in mock mode")
	}
	if v.Direction != "inbound" && v.Direction != "outbound" {
		return v, errors.New("invalid firewall direction")
	}
	if v.Protocol != "tcp" && v.Protocol != "udp" {
		return v, errors.New("invalid firewall protocol")
	}
	if v.Port < 1 || v.Port > 65535 {
		return v, errors.New("invalid firewall port")
	}
	if v.Action != "allow" && v.Action != "deny" {
		return v, errors.New("invalid firewall action")
	}
	if strings.TrimSpace(v.Source) == "" {
		v.Source = "0.0.0.0/0"
	}
	v.ID = id("fw")
	v.Status = "applied-real"
	v.CreatedAt = time.Now().UTC()
	m.state.FirewallRules[v.ID] = v
	return v, m.save()
}

func (m *Manager) CreateFirewallRule(v FirewallRule) (FirewallRule, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if !m.mock {
		return v, errors.New("host firewall backend is not enabled in this build")
	}
	if v.Direction != "inbound" && v.Direction != "outbound" {
		return v, errors.New("invalid firewall direction")
	}
	if v.Protocol != "tcp" && v.Protocol != "udp" {
		return v, errors.New("invalid firewall protocol")
	}
	if v.Port < 1 || v.Port > 65535 {
		return v, errors.New("invalid firewall port")
	}
	if v.Action != "allow" && v.Action != "deny" {
		return v, errors.New("invalid firewall action")
	}
	if strings.TrimSpace(v.Source) == "" {
		v.Source = "0.0.0.0/0"
	}
	v.ID = id("fw")
	v.Status = "simulated-active"
	v.CreatedAt = time.Now().UTC()
	m.state.FirewallRules[v.ID] = v
	return v, m.save()
}
func (m *Manager) ListApplications() []Application {
	m.mu.Lock()
	defer m.mu.Unlock()
	a := make([]Application, 0, len(m.state.Applications))
	for _, v := range m.state.Applications {
		a = append(a, v)
	}
	sort.Slice(a, func(i, j int) bool { return a[i].Domain < a[j].Domain })
	return a
}
func (m *Manager) RemoveApplication(id string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	id = strings.TrimSpace(id)
	if _, ok := m.state.Applications[id]; !ok {
		return errors.New("application record not found")
	}
	delete(m.state.Applications, id)
	return m.save()
}

func (m *Manager) CreateApplication(v Application) (Application, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if !m.mock {
		return v, errors.New("application deployment backend is not enabled in this build")
	}
	if v.Type != "laravel" && v.Type != "wordpress" && v.Type != "node" && v.Type != "python" {
		return v, errors.New("unsupported application type")
	}
	if !validDomain(v.Domain) || !validName(v.Owner) {
		return v, errors.New("invalid application target")
	}
	if v.Runtime == "" {
		if v.Type == "laravel" || v.Type == "wordpress" {
			v.Runtime = "php8.4"
		} else if v.Type == "node" {
			v.Runtime = "node22"
		} else {
			v.Runtime = "python3"
		}
	}
	v.ID = id("app")
	v.Status = "simulated-ready"
	v.CreatedAt = time.Now().UTC()
	m.state.Applications[v.ID] = v
	return v, m.save()
}

func (m *Manager) ListDatabases() []Database {
	m.mu.Lock()
	defer m.mu.Unlock()
	a := make([]Database, 0, len(m.state.Databases))
	for _, v := range m.state.Databases {
		a = append(a, v)
	}
	sort.Slice(a, func(i, j int) bool { return a[i].Name < a[j].Name })
	return a
}
func (m *Manager) DatabaseByName(name string) (Database, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	v, ok := m.state.Databases[strings.TrimSpace(name)]
	return v, ok
}
func (m *Manager) RemoveDatabase(name string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	name = strings.TrimSpace(name)
	if _, ok := m.state.Databases[name]; !ok {
		return errors.New("database is not Privora-managed")
	}
	delete(m.state.Databases, name)
	return m.save()
}
func (m *Manager) UpdateDatabaseUser(name, user string) (Database, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	name = strings.TrimSpace(name)
	user = strings.TrimSpace(user)
	v, ok := m.state.Databases[name]
	if !ok {
		return Database{}, errors.New("database is not Privora-managed")
	}
	if !validName(user) {
		return Database{}, errors.New("invalid database user")
	}
	for dbName, row := range m.state.Databases {
		if dbName != name && row.User == user {
			return Database{}, errors.New("database user is already assigned to another Privora-managed database")
		}
	}
	v.User = user
	m.state.Databases[name] = v
	return v, m.save()
}
func (m *Manager) CreateDatabase(v Database) (Database, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if !m.mock {
		return v, errors.New("real database backend is not certified")
	}
	v.Name = strings.TrimSpace(v.Name)
	if !validName(v.Name) {
		return v, errors.New("invalid database name")
	}
	if v.Engine != "mysql" && v.Engine != "mariadb" && v.Engine != "postgresql" {
		return v, errors.New("unsupported database engine")
	}
	if !validName(v.Owner) {
		return v, errors.New("invalid database owner")
	}
	if _, ok := m.state.Databases[v.Name]; ok {
		return v, errors.New("database already exists")
	}
	v.Status = "ready"
	v.CreatedAt = time.Now().UTC()
	m.state.Databases[v.Name] = v
	return v, m.save()
}
func (m *Manager) RecordRealDatabase(v Database) (Database, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.mock {
		return v, errors.New("real database recorder is disabled in mock mode")
	}
	v.Name = strings.TrimSpace(v.Name)
	if !validName(v.Name) || !validName(v.User) || !validName(v.Owner) {
		return v, errors.New("invalid database metadata")
	}
	if v.Engine != "mysql" && v.Engine != "mariadb" && v.Engine != "postgresql" {
		return v, errors.New("unsupported database engine")
	}
	if _, ok := m.state.Databases[v.Name]; ok {
		return v, errors.New("database already exists")
	}
	v.Status = "provisioned-real"
	v.CreatedAt = time.Now().UTC()
	m.state.Databases[v.Name] = v
	return v, m.save()
}

func (m *Manager) ListDNSZones() []DNSZone {
	m.mu.Lock()
	defer m.mu.Unlock()
	a := make([]DNSZone, 0, len(m.state.DNSZones))
	for _, v := range m.state.DNSZones {
		a = append(a, v)
	}
	sort.Slice(a, func(i, j int) bool { return a[i].Domain < a[j].Domain })
	return a
}
func (m *Manager) HasDNSZone(domain string) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	domain = strings.ToLower(strings.TrimSpace(domain))
	_, ok := m.state.DNSZones[domain]
	return ok
}

func (m *Manager) RecordRealDNSZone(v DNSZone) (DNSZone, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.mock {
		return v, errors.New("real DNS recorder is disabled in mock mode")
	}
	v.Domain = strings.ToLower(strings.TrimSpace(v.Domain))
	if !validDomain(v.Domain) {
		return v, errors.New("invalid DNS zone domain")
	}
	if _, ok := m.state.DNSZones[v.Domain]; ok {
		return v, errors.New("DNS zone already exists")
	}
	v.CreatedAt = time.Now().UTC()
	m.state.DNSZones[v.Domain] = v
	return v, m.save()
}

func (m *Manager) CreateDNSZone(v DNSZone) (DNSZone, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if !m.mock {
		return v, errors.New("real DNS backend is not certified")
	}
	v.Domain = strings.ToLower(strings.TrimSpace(v.Domain))
	if !validDomain(v.Domain) {
		return v, errors.New("invalid DNS zone domain")
	}
	if _, ok := m.state.DNSZones[v.Domain]; ok {
		return v, errors.New("DNS zone already exists")
	}
	if len(v.Records) == 0 {
		v.Records = []DNSRecord{{Type: "A", Name: "@", Value: "203.0.113.10", TTL: 3600}, {Type: "CNAME", Name: "www", Value: v.Domain + ".", TTL: 3600}}
	}
	v.CreatedAt = time.Now().UTC()
	m.state.DNSZones[v.Domain] = v
	return v, m.save()
}
func (m *Manager) ListCertificates() []Certificate {
	m.mu.Lock()
	defer m.mu.Unlock()
	a := make([]Certificate, 0, len(m.state.Certificates))
	for _, v := range m.state.Certificates {
		a = append(a, v)
	}
	sort.Slice(a, func(i, j int) bool { return a[i].Domain < a[j].Domain })
	return a
}
func (m *Manager) RecordRealCertificate(v Certificate) (Certificate, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.mock {
		return Certificate{}, errors.New("real certificate recorder is disabled in mock mode")
	}
	v.Domain = strings.ToLower(strings.TrimSpace(v.Domain))
	if !validDomain(v.Domain) {
		return Certificate{}, errors.New("invalid certificate domain")
	}
	if v.Provider == "" {
		v.Provider = "letsencrypt"
	}
	if v.ExpiresAt.IsZero() {
		return Certificate{}, errors.New("certificate expiry required")
	}
	v.Status = "valid-real"
	v.AutoRenew = true
	v.CreatedAt = time.Now().UTC()
	m.state.Certificates[v.Domain] = v
	return v, m.save()
}

func (m *Manager) RemoveCertificate(domain string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	domain = strings.ToLower(strings.TrimSpace(domain))
	if _, ok := m.state.Certificates[domain]; !ok {
		return errors.New("certificate not found")
	}
	delete(m.state.Certificates, domain)
	return m.save()
}

func (m *Manager) IssueCertificate(domain string) (Certificate, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if !m.mock {
		return Certificate{}, errors.New("real ACME backend is not certified")
	}
	domain = strings.ToLower(strings.TrimSpace(domain))
	if !validDomain(domain) {
		return Certificate{}, errors.New("invalid certificate domain")
	}
	v := Certificate{Domain: domain, Provider: "letsencrypt", Status: "valid", AutoRenew: true, ExpiresAt: time.Now().UTC().Add(90 * 24 * time.Hour), CreatedAt: time.Now().UTC()}
	m.state.Certificates[domain] = v
	return v, m.save()
}
func (m *Manager) ListBackups() []Backup {
	m.mu.Lock()
	defer m.mu.Unlock()
	a := make([]Backup, 0, len(m.state.Backups))
	for _, v := range m.state.Backups {
		a = append(a, v)
	}
	sort.Slice(a, func(i, j int) bool { return a[i].CreatedAt.After(a[j].CreatedAt) })
	return a
}
func (m *Manager) BackupByID(id string) (Backup, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	v, ok := m.state.Backups[id]
	return v, ok
}
func (m *Manager) CreateBackup(scope, res, dest string) (Backup, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if !m.mock {
		return Backup{}, errors.New("real backup recording must use certified backup adapter")
	}
	if scope != "account" && scope != "site" && scope != "server" {
		return Backup{}, errors.New("invalid backup scope")
	}
	if strings.TrimSpace(res) == "" {
		return Backup{}, errors.New("backup resource required")
	}
	if dest == "" {
		dest = "local"
	}
	v := Backup{ID: id("bkp"), Scope: scope, Resource: res, Destination: dest, Status: "verified", SizeBytes: 1048576 * uint64(12+len(m.state.Backups)*3), CreatedAt: time.Now().UTC()}
	m.state.Backups[v.ID] = v
	return v, m.save()
}
func (m *Manager) RecordRealBackup(scope, res, dest, sha256sum string, size uint64) (Backup, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.mock {
		return Backup{}, errors.New("real backup recorder is disabled in mock mode")
	}
	if scope != "account" && scope != "site" {
		return Backup{}, errors.New("real local backup supports account or site scope")
	}
	if strings.TrimSpace(res) == "" || strings.TrimSpace(dest) == "" {
		return Backup{}, errors.New("backup resource and destination required")
	}
	sha256sum = strings.ToLower(strings.TrimSpace(sha256sum))
	if !regexp.MustCompile(`^[a-f0-9]{64}$`).MatchString(sha256sum) {
		return Backup{}, errors.New("backup SHA-256 is required")
	}
	v := Backup{ID: id("bkp"), Scope: scope, Resource: res, Destination: dest, SHA256: strings.ToLower(strings.TrimSpace(sha256sum)), Status: "verified-real-local", SizeBytes: size, CreatedAt: time.Now().UTC()}
	m.state.Backups[v.ID] = v
	return v, m.save()
}

func (m *Manager) RecordScheduledBackup(scope, res, dest, sha256sum string, size uint64, policyID string) (Backup, error) {
	v, err := m.RecordRealBackup(scope, res, dest, sha256sum, size)
	if err != nil {
		return Backup{}, err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	v.PolicyID = strings.TrimSpace(policyID)
	m.state.Backups[v.ID] = v
	return v, m.save()
}

func (m *Manager) MarkBackupVerified(id string, at time.Time) (Backup, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	v, ok := m.state.Backups[id]
	if !ok {
		return Backup{}, errors.New("backup not found")
	}
	v.VerifiedAt = at.UTC()
	v.Status = "verified-real-local"
	m.state.Backups[id] = v
	return v, m.save()
}

func (m *Manager) DeleteBackupRecord(id string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.state.Backups[id]; !ok {
		return errors.New("backup not found")
	}
	delete(m.state.Backups, id)
	return m.save()
}

func (m *Manager) ListMailboxes() []Mailbox {
	m.mu.Lock()
	defer m.mu.Unlock()
	a := make([]Mailbox, 0, len(m.state.Mailboxes))
	for _, v := range m.state.Mailboxes {
		a = append(a, v)
	}
	sort.Slice(a, func(i, j int) bool { return a[i].Address < a[j].Address })
	return a
}
func (m *Manager) RecordRealMailbox(v Mailbox) (Mailbox, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.mock {
		return v, errors.New("real mailbox recorder is disabled in mock mode")
	}
	v.Address = strings.ToLower(strings.TrimSpace(v.Address))
	parts := strings.Split(v.Address, "@")
	if len(parts) != 2 || parts[0] == "" || !validDomain(parts[1]) {
		return v, errors.New("invalid mailbox address")
	}
	v.Domain = parts[1]
	if v.QuotaMB <= 0 {
		v.QuotaMB = 1024
	}
	if _, ok := m.state.Mailboxes[v.Address]; ok {
		return v, errors.New("mailbox already exists")
	}
	v.Status = "provisioned-real"
	v.CreatedAt = time.Now().UTC()
	m.state.Mailboxes[v.Address] = v
	return v, m.save()
}

func (m *Manager) UpdateMailboxMetadata(address string, quotaMB int) (Mailbox, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	address = strings.ToLower(strings.TrimSpace(address))
	parts := strings.Split(address, "@")
	if len(parts) != 2 || parts[0] == "" || !validDomain(parts[1]) {
		return Mailbox{}, errors.New("invalid mailbox address")
	}
	if quotaMB <= 0 {
		return Mailbox{}, errors.New("mailbox quota must be greater than zero")
	}
	v, ok := m.state.Mailboxes[address]
	if !ok {
		v = Mailbox{Address: address, Domain: parts[1], Status: "provisioned-real", CreatedAt: time.Now().UTC()}
	}
	v.Domain = parts[1]
	v.QuotaMB = quotaMB
	if v.Status == "" {
		v.Status = "provisioned-real"
	}
	m.state.Mailboxes[address] = v
	return v, m.save()
}

func (m *Manager) ForgetMailbox(address string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	address = strings.ToLower(strings.TrimSpace(address))
	if _, ok := m.state.Mailboxes[address]; !ok {
		return nil
	}
	delete(m.state.Mailboxes, address)
	return m.save()
}

func (m *Manager) RemoveMailbox(address string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	address = strings.ToLower(strings.TrimSpace(address))
	if _, ok := m.state.Mailboxes[address]; !ok {
		return errors.New("mailbox is not Privora-managed")
	}
	delete(m.state.Mailboxes, address)
	return m.save()
}

func (m *Manager) CreateMailbox(v Mailbox) (Mailbox, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if !m.mock {
		return v, errors.New("real mail backend is not certified")
	}
	v.Address = strings.ToLower(strings.TrimSpace(v.Address))
	parts := strings.Split(v.Address, "@")
	if len(parts) != 2 || parts[0] == "" || !validDomain(parts[1]) {
		return v, errors.New("invalid mailbox address")
	}
	v.Domain = parts[1]
	if v.QuotaMB <= 0 {
		v.QuotaMB = 1024
	}
	v.Status = "active"
	v.CreatedAt = time.Now().UTC()
	m.state.Mailboxes[v.Address] = v
	return v, m.save()
}

func uniqueSafeNames(values []string) []string {
	seen := map[string]bool{}
	out := []string{}
	for _, raw := range values {
		v := strings.TrimSpace(raw)
		if v == "" || len(v) > 64 || strings.ContainsAny(v, "\x00\r\n") || seen[v] {
			continue
		}
		seen[v] = true
		out = append(out, v)
	}
	sort.Strings(out)
	return out
}
func uniqueDomains(values []string) []string {
	seen := map[string]bool{}
	out := []string{}
	for _, raw := range values {
		v := strings.ToLower(strings.TrimSpace(raw))
		if v == "" || !validDomain(v) || seen[v] {
			continue
		}
		seen[v] = true
		out = append(out, v)
	}
	sort.Strings(out)
	return out
}

func (m *Manager) GetReseller(name string) (Reseller, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	v, ok := m.state.Resellers[strings.ToLower(strings.TrimSpace(name))]
	return v, ok
}
func (m *Manager) UpdateReseller(name string, in Reseller) (Reseller, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	name = strings.ToLower(strings.TrimSpace(name))
	v, ok := m.state.Resellers[name]
	if !ok {
		return v, errors.New("reseller not found")
	}
	if strings.TrimSpace(in.Company) != "" {
		if len(in.Company) > 120 {
			return v, errors.New("invalid reseller company")
		}
		v.Company = strings.TrimSpace(in.Company)
	}
	if in.MaxAccounts > 0 {
		if in.MaxAccounts > 100000 {
			return v, errors.New("invalid reseller account limit")
		}
		v.MaxAccounts = in.MaxAccounts
	}
	if in.DiskGB >= 0 {
		v.DiskGB = in.DiskGB
	}
	if in.BandwidthGB >= 0 {
		v.BandwidthGB = in.BandwidthGB
	}
	if in.AllowedPackages != nil {
		v.AllowedPackages = uniqueSafeNames(in.AllowedPackages)
	}
	if in.AllowedFeatures != nil {
		v.AllowedFeatures = uniqueSafeNames(in.AllowedFeatures)
	}
	if in.NameserverBases != nil {
		v.NameserverBases = uniqueDomains(in.NameserverBases)
	}
	v.DNSAllowed = in.DNSAllowed
	v.SSLAllowed = in.SSLAllowed
	if in.Status != "" {
		st := strings.ToLower(strings.TrimSpace(in.Status))
		if st != "active" && st != "suspended" {
			return v, errors.New("invalid reseller status")
		}
		v.Status = st
	}
	v.UpdatedAt = time.Now().UTC()
	m.state.Resellers[name] = v
	return v, m.save()
}
func (m *Manager) DeleteReseller(name string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	name = strings.ToLower(strings.TrimSpace(name))
	if _, ok := m.state.Resellers[name]; !ok {
		return errors.New("reseller not found")
	}
	delete(m.state.Resellers, name)
	return m.save()
}

func (m *Manager) ListResellers() []Reseller {
	m.mu.Lock()
	defer m.mu.Unlock()
	a := make([]Reseller, 0, len(m.state.Resellers))
	for _, v := range m.state.Resellers {
		a = append(a, v)
	}
	sort.Slice(a, func(i, j int) bool { return a[i].Name < a[j].Name })
	return a
}
func (m *Manager) CreateReseller(v Reseller) (Reseller, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if !validName(v.Name) {
		return v, errors.New("invalid reseller name")
	}
	if v.MaxAccounts <= 0 || v.MaxAccounts > 100000 {
		return v, errors.New("invalid reseller account limit")
	}
	v.Name = strings.ToLower(strings.TrimSpace(v.Name))
	if strings.TrimSpace(v.Company) == "" || len(v.Company) > 120 {
		return v, errors.New("invalid reseller company")
	}
	if v.DiskGB < 0 || v.BandwidthGB < 0 {
		return v, errors.New("invalid reseller allocation")
	}
	v.AllowedPackages = uniqueSafeNames(v.AllowedPackages)
	v.AllowedFeatures = uniqueSafeNames(v.AllowedFeatures)
	v.NameserverBases = uniqueDomains(v.NameserverBases)
	v.Status = "active"
	v.CreatedAt = time.Now().UTC()
	v.UpdatedAt = v.CreatedAt
	m.state.Resellers[v.Name] = v
	return v, m.save()
}
func (m *Manager) ListNodes() []Node {
	m.mu.Lock()
	defer m.mu.Unlock()
	a := make([]Node, 0, len(m.state.Nodes))
	for _, v := range m.state.Nodes {
		a = append(a, v)
	}
	sort.Slice(a, func(i, j int) bool { return a[i].Name < a[j].Name })
	return a
}
func (m *Manager) CreateNode(v Node) (Node, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if !m.mock {
		return v, errors.New("remote node enrollment requires the future mTLS backend")
	}
	if !validName(v.Name) {
		return v, errors.New("invalid node name")
	}
	if v.Role == "" || v.Region == "" {
		return v, errors.New("node role and region are required")
	}
	v.ID = id("node")
	v.Status = "simulated-healthy"
	v.CreatedAt = time.Now().UTC()
	m.state.Nodes[v.ID] = v
	return v, m.save()
}
func (m *Manager) ListInstances() []Instance {
	m.mu.Lock()
	defer m.mu.Unlock()
	a := make([]Instance, 0, len(m.state.Instances))
	for _, v := range m.state.Instances {
		a = append(a, v)
	}
	sort.Slice(a, func(i, j int) bool { return a[i].CreatedAt.After(a[j].CreatedAt) })
	return a
}
func (m *Manager) CreateInstance(v Instance) (Instance, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if !m.mock {
		return v, errors.New("cloud provisioning requires a configured provider adapter")
	}
	if v.Provider != "mock" {
		return v, errors.New("only mock provider is enabled in this build")
	}
	if v.Region == "" || v.Size == "" || v.Image == "" {
		return v, errors.New("region, size and image are required")
	}
	v.ID = id("vm")
	v.Status = "simulated-running"
	v.CreatedAt = time.Now().UTC()
	m.state.Instances[v.ID] = v
	return v, m.save()
}
func (m *Manager) ListAutomations() []AutomationRun {
	m.mu.Lock()
	defer m.mu.Unlock()
	a := make([]AutomationRun, 0, len(m.state.Automations))
	for _, v := range m.state.Automations {
		a = append(a, v)
	}
	sort.Slice(a, func(i, j int) bool { return a[i].CreatedAt.After(a[j].CreatedAt) })
	return a
}
func (m *Manager) RecordAutomation(customer, domain, pkg, status string, steps []string) (AutomationRun, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if strings.TrimSpace(customer) == "" || !validDomain(domain) || strings.TrimSpace(pkg) == "" {
		return AutomationRun{}, errors.New("invalid automation request")
	}
	v := AutomationRun{ID: id("auto"), Customer: customer, Domain: domain, Package: pkg, Status: status, Steps: steps, CreatedAt: time.Now().UTC()}
	m.state.Automations[v.ID] = v
	return v, m.save()
}

func (m *Manager) ListWorkloads() []Workload {
	m.mu.Lock()
	defer m.mu.Unlock()
	a := make([]Workload, 0, len(m.state.Workloads))
	for _, v := range m.state.Workloads {
		a = append(a, v)
	}
	sort.Slice(a, func(i, j int) bool { return a[i].Name < a[j].Name })
	return a
}
func (m *Manager) CreateWorkload(v Workload) (Workload, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if !m.mock {
		return v, errors.New("distributed placement is simulation-only in this build")
	}
	if !validName(v.Name) {
		return v, errors.New("invalid workload name")
	}
	if v.Type != "web" && v.Type != "database" && v.Type != "mail" && v.Type != "dns" {
		return v, errors.New("unsupported workload type")
	}
	if v.DesiredReplicas < 1 || v.DesiredReplicas > 1000 {
		return v, errors.New("invalid replica count")
	}
	if v.Region == "" {
		return v, errors.New("region is required")
	}
	v.ID = id("wrk")
	v.Status = "simulated-placed"
	v.CreatedAt = time.Now().UTC()
	m.state.Workloads[v.ID] = v
	return v, m.save()
}
func (m *Manager) Summary() map[string]int {
	return map[string]int{"sftp_accounts": len(m.state.SFTPAccounts), "firewall_rules": len(m.state.FirewallRules), "applications": len(m.state.Applications), "databases": len(m.state.Databases), "dns_zones": len(m.state.DNSZones), "certificates": len(m.state.Certificates), "backups": len(m.state.Backups), "mailboxes": len(m.state.Mailboxes), "resellers": len(m.state.Resellers), "nodes": len(m.state.Nodes), "instances": len(m.state.Instances), "workloads": len(m.state.Workloads)}
}
func (m *Manager) String() string { return fmt.Sprintf("resources(%d)", len(m.state.Databases)) }

func (m *Manager) DeleteDNSZone(domain string) (DNSZone, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	domain = strings.ToLower(strings.TrimSpace(domain))
	if !domainRx.MatchString(domain) {
		return DNSZone{}, errors.New("invalid domain")
	}
	v, ok := m.state.DNSZones[domain]
	if !ok {
		return DNSZone{}, errors.New("DNS zone not found")
	}
	delete(m.state.DNSZones, domain)
	return v, m.save()
}

func (m *Manager) Nameservers() NameserverConfig {
	m.mu.Lock()
	defer m.mu.Unlock()
	if v, ok := m.state.NameserverSets[m.state.DefaultNameserverBase]; ok {
		v.Default = true
		return v
	}
	return m.state.Nameservers
}

func (m *Manager) NameserverSets() []NameserverConfig {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]NameserverConfig, 0, len(m.state.NameserverSets))
	for base, v := range m.state.NameserverSets {
		v.Default = base == m.state.DefaultNameserverBase
		out = append(out, v)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Default != out[j].Default {
			return out[i].Default
		}
		return out[i].BaseDomain < out[j].BaseDomain
	})
	return out
}

func (m *Manager) NameserverAssignments() map[string]string {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make(map[string]string, len(m.state.NameserverAssignments))
	for domain, base := range m.state.NameserverAssignments {
		out[domain] = base
	}
	return out
}

func (m *Manager) NameserverSet(baseDomain string) (NameserverConfig, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	baseDomain = strings.ToLower(strings.Trim(strings.TrimSpace(baseDomain), "."))
	v, ok := m.state.NameserverSets[baseDomain]
	if ok {
		v.Default = baseDomain == m.state.DefaultNameserverBase
	}
	return v, ok
}

func (m *Manager) AssignedNameservers(domain string) (NameserverConfig, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	domain = strings.ToLower(strings.Trim(strings.TrimSpace(domain), "."))
	base := strings.ToLower(strings.Trim(strings.TrimSpace(m.state.NameserverAssignments[domain]), "."))
	if base == "" {
		return NameserverConfig{}, false
	}
	v, ok := m.state.NameserverSets[base]
	if !ok {
		return NameserverConfig{}, false
	}
	v.Default = base == m.state.DefaultNameserverBase
	return v, true
}

func (m *Manager) SetNameserverAssignment(domain, baseDomain string) (NameserverConfig, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	domain = strings.ToLower(strings.Trim(strings.TrimSpace(domain), "."))
	baseDomain = strings.ToLower(strings.Trim(strings.TrimSpace(baseDomain), "."))
	if !domainRx.MatchString(domain) {
		return NameserverConfig{}, errors.New("invalid hosted domain")
	}
	if baseDomain == "" {
		delete(m.state.NameserverAssignments, domain)
		if err := m.save(); err != nil {
			return NameserverConfig{}, err
		}
		if v, ok := m.state.NameserverSets[m.state.DefaultNameserverBase]; ok {
			v.Default = true
			return v, nil
		}
		return NameserverConfig{}, nil
	}
	v, ok := m.state.NameserverSets[baseDomain]
	if !ok {
		return NameserverConfig{}, errors.New("nameserver set not found")
	}
	if m.state.NameserverAssignments == nil {
		m.state.NameserverAssignments = map[string]string{}
	}
	m.state.NameserverAssignments[domain] = baseDomain
	if err := m.save(); err != nil {
		return NameserverConfig{}, err
	}
	v.Default = baseDomain == m.state.DefaultNameserverBase
	return v, nil
}

func (m *Manager) SetNameservers(v NameserverConfig) (NameserverConfig, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	v.BaseDomain = strings.ToLower(strings.TrimSpace(v.BaseDomain))
	v.Primary = strings.ToLower(strings.TrimSpace(v.Primary))
	v.Secondary = strings.ToLower(strings.TrimSpace(v.Secondary))
	if !domainRx.MatchString(v.BaseDomain) || !domainRx.MatchString(v.Primary) || !domainRx.MatchString(v.Secondary) {
		return NameserverConfig{}, errors.New("invalid nameserver domain")
	}
	if v.Primary == v.Secondary {
		return NameserverConfig{}, errors.New("primary and secondary nameservers must differ")
	}
	if !strings.HasSuffix(v.Primary, "."+v.BaseDomain) || !strings.HasSuffix(v.Secondary, "."+v.BaseDomain) {
		return NameserverConfig{}, errors.New("nameservers must be children of the base domain")
	}
	v.UpdatedAt = time.Now().UTC()
	if strings.TrimSpace(v.GlueStatus) == "" {
		v.GlueStatus = "local-glue-ready"
	}
	if m.state.NameserverSets == nil {
		m.state.NameserverSets = map[string]NameserverConfig{}
	}
	_, existed := m.state.NameserverSets[v.BaseDomain]
	makeDefault := v.Default || m.state.DefaultNameserverBase == "" || (existed && m.state.DefaultNameserverBase == v.BaseDomain)
	if makeDefault {
		m.state.DefaultNameserverBase = v.BaseDomain
	}
	v.Default = m.state.DefaultNameserverBase == v.BaseDomain
	m.state.NameserverSets[v.BaseDomain] = v
	for k, item := range m.state.NameserverSets {
		item.Default = k == m.state.DefaultNameserverBase
		m.state.NameserverSets[k] = item
	}
	if def, ok := m.state.NameserverSets[m.state.DefaultNameserverBase]; ok {
		m.state.Nameservers = def
	}
	return v, m.save()
}

func (m *Manager) DeleteNameserverSet(baseDomain string) (NameserverConfig, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	baseDomain = strings.ToLower(strings.TrimSpace(baseDomain))
	if !domainRx.MatchString(baseDomain) {
		return NameserverConfig{}, errors.New("invalid base domain")
	}
	old, ok := m.state.NameserverSets[baseDomain]
	if !ok {
		return NameserverConfig{}, errors.New("nameserver set not found")
	}
	delete(m.state.NameserverSets, baseDomain)
	for domain, assigned := range m.state.NameserverAssignments {
		if assigned == baseDomain {
			delete(m.state.NameserverAssignments, domain)
		}
	}
	if m.state.DefaultNameserverBase == baseDomain {
		m.state.DefaultNameserverBase = ""
		keys := make([]string, 0, len(m.state.NameserverSets))
		for k := range m.state.NameserverSets {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		if len(keys) > 0 {
			m.state.DefaultNameserverBase = keys[0]
		}
	}
	for k, item := range m.state.NameserverSets {
		item.Default = k == m.state.DefaultNameserverBase
		m.state.NameserverSets[k] = item
	}
	if def, ok := m.state.NameserverSets[m.state.DefaultNameserverBase]; ok {
		m.state.Nameservers = def
	} else {
		m.state.Nameservers = NameserverConfig{}
	}
	return old, m.save()
}

// ReplaceDNSZoneRecords updates Privora's durable record view after a certified
// live BIND mutation. It does not itself touch the host DNS service.
func (m *Manager) ReplaceDNSZoneRecords(domain string, records []DNSRecord) (DNSZone, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	domain = strings.ToLower(strings.TrimSpace(domain))
	if !domainRx.MatchString(domain) {
		return DNSZone{}, errors.New("invalid DNS zone domain")
	}
	v, ok := m.state.DNSZones[domain]
	if !ok {
		v = DNSZone{Domain: domain, CreatedAt: time.Now().UTC()}
	}
	v.Records = append([]DNSRecord(nil), records...)
	m.state.DNSZones[domain] = v
	return v, m.save()
}
