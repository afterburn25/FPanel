package hosting

import (
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

var userRx = regexp.MustCompile(`^[a-z][a-z0-9_]{2,23}$`)
var domainRx = regexp.MustCompile(`^(?i:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+)$`)
var phpRx = regexp.MustCompile(`^8\.[2-5]$`)

type Account struct {
	Username      string    `json:"username"`
	PrimaryDomain string    `json:"primary_domain"`
	Package       string    `json:"package"`
	Status        string    `json:"status"`
	Owner         string    `json:"owner,omitempty"`
	Reseller      string    `json:"reseller,omitempty"`
	Notes         string    `json:"notes,omitempty"`
	ShellPolicy   string    `json:"shell_policy,omitempty"`
	CreatedAt     time.Time `json:"created_at"`
	UpdatedAt     time.Time `json:"updated_at,omitempty"`
}

type AccountUpdate struct {
	PrimaryDomain *string `json:"primary_domain,omitempty"`
	Owner         *string `json:"owner,omitempty"`
	Reseller      *string `json:"reseller,omitempty"`
	Notes         *string `json:"notes,omitempty"`
	ShellPolicy   *string `json:"shell_policy,omitempty"`
}
type Site struct {
	Domain       string    `json:"domain"`
	Username     string    `json:"username"`
	DocumentRoot string    `json:"document_root"`
	PHPVersion   string    `json:"php_version"`
	SSL          string    `json:"ssl"`
	DNS          string    `json:"dns"`
	Status       string    `json:"status"`
	StatusReason string    `json:"status_reason,omitempty"`
	Kind         string    `json:"kind,omitempty"`
	ParentDomain string    `json:"parent_domain,omitempty"`
	CreatedAt    time.Time `json:"created_at"`
}
type State struct {
	Accounts map[string]Account `json:"accounts"`
	Sites    map[string]Site    `json:"sites"`
}
type Manager struct {
	mu        sync.Mutex
	statePath string
	root      string
	mock      bool
	state     State
}

func New(statePath, root string, mock bool) *Manager {
	m := &Manager{statePath: statePath, root: root, mock: mock, state: State{Accounts: map[string]Account{}, Sites: map[string]Site{}}}
	_ = m.load()
	return m
}
func (m *Manager) load() error {
	b, err := os.ReadFile(m.statePath)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	if err = json.Unmarshal(b, &m.state); err != nil {
		return err
	}
	if m.state.Accounts == nil {
		m.state.Accounts = map[string]Account{}
	}
	if m.state.Sites == nil {
		m.state.Sites = map[string]Site{}
	}
	return nil
}
func (m *Manager) save() error {
	if err := os.MkdirAll(filepath.Dir(m.statePath), 0750); err != nil {
		return err
	}
	b, err := json.MarshalIndent(m.state, "", "  ")
	if err != nil {
		return err
	}
	tmp := m.statePath + ".tmp"
	if err = os.WriteFile(tmp, b, 0640); err != nil {
		return err
	}
	return os.Rename(tmp, m.statePath)
}
func validateUser(v string) error {
	if !userRx.MatchString(v) {
		return errors.New("invalid hosting username")
	}
	return nil
}
func validateDomain(v string) error {
	if len(v) > 253 || !domainRx.MatchString(v) || net.ParseIP(v) != nil {
		return errors.New("invalid domain")
	}
	return nil
}
func validatePHP(v string) error {
	if !phpRx.MatchString(v) {
		return errors.New("unsupported PHP version")
	}
	return nil
}
func (m *Manager) ListAccounts() []Account {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]Account, 0, len(m.state.Accounts))
	for _, a := range m.state.Accounts {
		out = append(out, a)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Username < out[j].Username })
	return out
}
func (m *Manager) ListSites() []Site {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]Site, 0, len(m.state.Sites))
	for _, s := range m.state.Sites {
		out = append(out, s)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Domain < out[j].Domain })
	return out
}
func (m *Manager) prepareAccount(a Account) (Account, error) {
	a.Username = strings.ToLower(strings.TrimSpace(a.Username))
	a.PrimaryDomain = strings.ToLower(strings.TrimSpace(a.PrimaryDomain))
	if err := validateUser(a.Username); err != nil {
		return Account{}, err
	}
	if err := validateDomain(a.PrimaryDomain); err != nil {
		return Account{}, err
	}
	if _, ok := m.state.Accounts[a.Username]; ok {
		return Account{}, errors.New("account already exists")
	}
	if a.Package == "" {
		a.Package = "Starter"
	}
	a.Status = "active"
	if a.Owner == "" {
		a.Owner = "root"
	}
	if a.ShellPolicy == "" {
		a.ShellPolicy = "none"
	}
	a.CreatedAt = time.Now().UTC()
	a.UpdatedAt = a.CreatedAt
	return a, nil
}

// RecordProvisionedAccount records a real account only after the privileged host
// adapter has successfully created the operating-system account.
func (m *Manager) RecordProvisionedAccount(a Account) (Account, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.mock {
		return Account{}, errors.New("real account recorder is disabled in mock mode")
	}
	var err error
	a, err = m.prepareAccount(a)
	if err != nil {
		return Account{}, err
	}
	m.state.Accounts[a.Username] = a
	return a, m.save()
}

// AdoptDiscoveredAccount records an account that already exists on the host.
// This never creates or changes the operating-system user and therefore is safe
// for installer reconciliation and third-party hosting environments.
func (m *Manager) AdoptDiscoveredAccount(a Account) (Account, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	a.Username = strings.ToLower(strings.TrimSpace(a.Username))
	a.PrimaryDomain = strings.ToLower(strings.TrimSpace(a.PrimaryDomain))
	if err := validateUser(a.Username); err != nil {
		return Account{}, err
	}
	if a.PrimaryDomain != "" {
		if err := validateDomain(a.PrimaryDomain); err != nil {
			return Account{}, err
		}
	}
	if current, ok := m.state.Accounts[a.Username]; ok {
		if current.PrimaryDomain == "" && a.PrimaryDomain != "" {
			current.PrimaryDomain = a.PrimaryDomain
		}
		if current.Package == "" {
			current.Package = "Detected"
		}
		if a.Status != "" {
			current.Status = a.Status
		}
		m.state.Accounts[a.Username] = current
		return current, m.save()
	}
	if a.Package == "" {
		a.Package = "Detected"
	}
	if a.Status == "" {
		a.Status = "active"
	}
	if a.CreatedAt.IsZero() {
		a.CreatedAt = time.Now().UTC()
	}
	if a.Owner == "" {
		a.Owner = "root"
	}
	if a.ShellPolicy == "" {
		a.ShellPolicy = "none"
	}
	if a.UpdatedAt.IsZero() {
		a.UpdatedAt = a.CreatedAt
	}
	m.state.Accounts[a.Username] = a
	return a, m.save()
}

// AdoptDiscoveredSite records existing live-host metadata without modifying the
// web server or filesystem. Unknown PHP versions are retained as discovered.
func (m *Manager) AdoptDiscoveredSite(s Site) (Site, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	s.Domain = strings.ToLower(strings.TrimSpace(s.Domain))
	s.Username = strings.ToLower(strings.TrimSpace(s.Username))
	if err := validateDomain(s.Domain); err != nil {
		return Site{}, err
	}
	if err := validateUser(s.Username); err != nil {
		return Site{}, err
	}
	if _, ok := m.state.Accounts[s.Username]; !ok {
		return Site{}, errors.New("account not found")
	}
	if s.Status == "" {
		s.Status = "active"
	}
	if s.SSL == "" {
		s.SSL = "unknown"
	}
	if s.PHPVersion == "" {
		s.PHPVersion = "unknown"
	}
	if s.CreatedAt.IsZero() {
		s.CreatedAt = time.Now().UTC()
	}
	if current, ok := m.state.Sites[s.Domain]; ok && !current.CreatedAt.IsZero() {
		s.CreatedAt = current.CreatedAt
	}
	m.state.Sites[s.Domain] = s
	return s, m.save()
}

func (m *Manager) CreateAccount(a Account) (Account, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if !m.mock {
		return Account{}, errors.New("direct real-host account mutation disabled; use certified host adapter")
	}
	var err error
	a, err = m.prepareAccount(a)
	if err != nil {
		return Account{}, err
	}
	m.state.Accounts[a.Username] = a
	home := filepath.Join(m.root, "home", a.Username)
	if err := os.MkdirAll(filepath.Join(home, "public_html"), 0750); err != nil {
		return Account{}, err
	}
	return a, m.save()
}
func (m *Manager) SetAccountPackage(user, packageName string) (Account, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	user = strings.ToLower(strings.TrimSpace(user))
	packageName = strings.TrimSpace(packageName)
	if err := validateUser(user); err != nil {
		return Account{}, err
	}
	if packageName == "" || len(packageName) > 64 || strings.ContainsAny(packageName, "\x00\r\n") {
		return Account{}, errors.New("invalid package")
	}
	a, ok := m.state.Accounts[user]
	if !ok {
		return Account{}, errors.New("account not found")
	}
	a.Package = packageName
	a.UpdatedAt = time.Now().UTC()
	m.state.Accounts[user] = a
	return a, m.save()
}

func (m *Manager) SetAccountStatus(user, status string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := validateUser(user); err != nil {
		return err
	}
	a, ok := m.state.Accounts[user]
	if !ok {
		return errors.New("account not found")
	}
	if status != "active" && status != "suspended" {
		return errors.New("invalid account status")
	}
	a.Status = status
	a.UpdatedAt = time.Now().UTC()
	m.state.Accounts[user] = a
	return m.save()
}

func (m *Manager) GetAccount(user string) (Account, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	user = strings.ToLower(strings.TrimSpace(user))
	a, ok := m.state.Accounts[user]
	return a, ok
}

func validAccountOwner(v string) bool {
	v = strings.TrimSpace(v)
	if v == "" {
		return true
	}
	return len(v) <= 64 && regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.@ -]{0,63}$`).MatchString(v)
}

func validShellPolicy(v string) bool {
	switch v {
	case "none", "restricted", "ssh":
		return true
	}
	return false
}

func (m *Manager) UpdateAccount(user string, in AccountUpdate) (Account, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	user = strings.ToLower(strings.TrimSpace(user))
	if err := validateUser(user); err != nil {
		return Account{}, err
	}
	a, ok := m.state.Accounts[user]
	if !ok {
		return Account{}, errors.New("account not found")
	}
	if in.PrimaryDomain != nil {
		d := strings.ToLower(strings.TrimSpace(*in.PrimaryDomain))
		if d != "" {
			if err := validateDomain(d); err != nil {
				return Account{}, err
			}
		}
		a.PrimaryDomain = d
	}
	if in.Owner != nil {
		v := strings.TrimSpace(*in.Owner)
		if !validAccountOwner(v) {
			return Account{}, errors.New("invalid account owner")
		}
		if v == "" {
			v = "root"
		}
		a.Owner = v
	}
	if in.Reseller != nil {
		v := strings.ToLower(strings.TrimSpace(*in.Reseller))
		if v != "" && !userRx.MatchString(v) {
			return Account{}, errors.New("invalid reseller")
		}
		a.Reseller = v
	}
	if in.Notes != nil {
		v := strings.TrimSpace(*in.Notes)
		if len(v) > 4096 || strings.ContainsRune(v, '\x00') {
			return Account{}, errors.New("account notes exceed safety limit")
		}
		a.Notes = v
	}
	if in.ShellPolicy != nil {
		v := strings.ToLower(strings.TrimSpace(*in.ShellPolicy))
		if !validShellPolicy(v) {
			return Account{}, errors.New("invalid shell policy")
		}
		a.ShellPolicy = v
	}
	a.UpdatedAt = time.Now().UTC()
	m.state.Accounts[user] = a
	return a, m.save()
}

func (m *Manager) prepareSite(s Site) (Site, error) {
	s.Domain = strings.ToLower(strings.TrimSpace(s.Domain))
	if err := validateDomain(s.Domain); err != nil {
		return Site{}, err
	}
	if err := validateUser(s.Username); err != nil {
		return Site{}, err
	}
	if err := validatePHP(s.PHPVersion); err != nil {
		return Site{}, err
	}
	if _, ok := m.state.Accounts[s.Username]; !ok {
		return Site{}, errors.New("account not found")
	}
	if _, ok := m.state.Sites[s.Domain]; ok {
		return Site{}, errors.New("site already exists")
	}
	defaultRoot := filepath.Join("/home", s.Username, "domains", s.Domain, "public")
	requestedRoot := strings.TrimSpace(s.DocumentRoot)
	if requestedRoot == "" {
		s.DocumentRoot = defaultRoot
	} else {
		cleanRoot := filepath.Clean(requestedRoot)
		allowedBase := filepath.Clean(filepath.Join("/home", s.Username, "domains"))
		if !filepath.IsAbs(cleanRoot) || cleanRoot == allowedBase || !strings.HasPrefix(cleanRoot+string(os.PathSeparator), allowedBase+string(os.PathSeparator)) {
			return Site{}, errors.New("document root must stay inside the hosting account domains directory")
		}
		s.DocumentRoot = cleanRoot
	}
	s.SSL = "pending"
	s.Status = "active"
	s.CreatedAt = time.Now().UTC()
	return s, nil
}

func (m *Manager) RecordProvisionedSite(s Site) (Site, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.mock {
		return Site{}, errors.New("real site recorder is disabled in mock mode")
	}
	var err error
	s, err = m.prepareSite(s)
	if err != nil {
		return Site{}, err
	}
	m.state.Sites[s.Domain] = s
	return s, m.save()
}

func (m *Manager) RecordDNS(domain, status string) (Site, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	domain = strings.ToLower(strings.TrimSpace(domain))
	if err := validateDomain(domain); err != nil {
		return Site{}, err
	}
	s, ok := m.state.Sites[domain]
	if !ok {
		return Site{}, errors.New("site not found")
	}
	s.DNS = strings.TrimSpace(status)
	m.state.Sites[domain] = s
	return s, m.save()
}

// RecordSiteClassification updates only the logical site relationship used by
// DNS and UI reconciliation. It never mutates the web server or filesystem.
func (m *Manager) RecordSiteClassification(domain, kind, parentDomain string) (Site, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	domain = strings.ToLower(strings.TrimSpace(domain))
	parentDomain = strings.ToLower(strings.TrimSpace(parentDomain))
	if err := validateDomain(domain); err != nil {
		return Site{}, err
	}
	s, ok := m.state.Sites[domain]
	if !ok {
		return Site{}, errors.New("site not found")
	}
	if parentDomain != "" {
		if err := validateDomain(parentDomain); err != nil {
			return Site{}, err
		}
		if domain == parentDomain || !strings.HasSuffix(domain, "."+parentDomain) {
			return Site{}, errors.New("invalid parent domain for site")
		}
		kind = "subdomain"
	} else if kind == "subdomain" {
		return Site{}, errors.New("subdomain classification requires parent domain")
	}
	if kind == "" {
		kind = "website"
	}
	s.Kind = kind
	s.ParentDomain = parentDomain
	m.state.Sites[domain] = s
	return s, m.save()
}

func (m *Manager) RecordSSL(domain, status string) (Site, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	domain = strings.ToLower(strings.TrimSpace(domain))
	if err := validateDomain(domain); err != nil {
		return Site{}, err
	}
	s, ok := m.state.Sites[domain]
	if !ok {
		return Site{}, errors.New("site not found")
	}
	status = strings.TrimSpace(status)
	if status == "" {
		status = "pending"
	}
	s.SSL = status
	m.state.Sites[domain] = s
	return s, m.save()
}

func (m *Manager) RecordPHP(domain, version string) (Site, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.mock {
		return Site{}, errors.New("real PHP recorder is disabled in mock mode")
	}
	domain = strings.ToLower(strings.TrimSpace(domain))
	if err := validateDomain(domain); err != nil {
		return Site{}, err
	}
	if err := validatePHP(version); err != nil {
		return Site{}, err
	}
	s, ok := m.state.Sites[domain]
	if !ok {
		return Site{}, errors.New("site not found")
	}
	s.PHPVersion = version
	m.state.Sites[domain] = s
	return s, m.save()
}

func (m *Manager) HasAccount(username string) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	_, ok := m.state.Accounts[strings.TrimSpace(username)]
	return ok
}

func (m *Manager) GetSite(domain string) (Site, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	s, ok := m.state.Sites[strings.ToLower(strings.TrimSpace(domain))]
	return s, ok
}

func (m *Manager) CreateSite(s Site) (Site, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if !m.mock {
		return Site{}, errors.New("direct real-host site mutation disabled; use certified host adapter")
	}
	var err error
	s, err = m.prepareSite(s)
	if err != nil {
		return Site{}, err
	}
	m.state.Sites[s.Domain] = s
	root := filepath.Join(m.root, strings.TrimPrefix(filepath.Clean(s.DocumentRoot), string(os.PathSeparator)))
	if !strings.HasPrefix(filepath.Clean(root)+string(os.PathSeparator), filepath.Clean(m.root)+string(os.PathSeparator)) {
		return Site{}, errors.New("unsafe document root")
	}
	_, statErr := os.Stat(root)
	rootExisted := statErr == nil
	if statErr != nil && !errors.Is(statErr, os.ErrNotExist) {
		return Site{}, statErr
	}
	if err := os.MkdirAll(root, 0750); err != nil {
		return Site{}, err
	}
	if !rootExisted {
		html := fmt.Sprintf("<!doctype html><title>%s</title><h1>%s is managed by Privora Panel</h1>\n", s.Domain, s.Domain)
		if err := os.WriteFile(filepath.Join(root, "index.html"), []byte(html), 0640); err != nil {
			return Site{}, err
		}
	}
	if err := m.writeNginx(s); err != nil {
		return Site{}, err
	}
	return s, m.save()
}
func (m *Manager) SetPHP(domain, version string) (Site, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if !m.mock {
		return Site{}, errors.New("direct real-host PHP mutation disabled; use certified host adapter")
	}
	domain = strings.ToLower(strings.TrimSpace(domain))
	if err := validateDomain(domain); err != nil {
		return Site{}, err
	}
	if err := validatePHP(version); err != nil {
		return Site{}, err
	}
	s, ok := m.state.Sites[domain]
	if !ok {
		return Site{}, errors.New("site not found")
	}
	s.PHPVersion = version
	m.state.Sites[domain] = s
	if m.mock {
		if err := m.writeNginx(s); err != nil {
			return Site{}, err
		}
	}
	return s, m.save()
}
func (m *Manager) writeNginx(s Site) error {
	cfgdir := filepath.Join(m.root, "etc", "nginx", "sites-available")
	if err := os.MkdirAll(cfgdir, 0750); err != nil {
		return err
	}
	realRoot := filepath.Join(m.root, strings.TrimPrefix(filepath.Clean(s.DocumentRoot), string(os.PathSeparator)))
	body := fmt.Sprintf("server {\n  listen 80;\n  server_name %s;\n  root %s;\n  index index.php index.html;\n  location / { try_files $uri $uri/ /index.php?$query_string; }\n  location ~ \\.php$ { include fastcgi_params; fastcgi_param SCRIPT_FILENAME $document_root$fastcgi_script_name; fastcgi_pass unix:/run/php/php%s-fpm.sock; }\n}\n", s.Domain, realRoot, s.PHPVersion)
	return os.WriteFile(filepath.Join(cfgdir, s.Domain+".conf"), []byte(body), 0640)
}

type FileEntry struct {
	Name     string    `json:"name"`
	Path     string    `json:"path"`
	Type     string    `json:"type"`
	Size     int64     `json:"size"`
	Mode     string    `json:"mode"`
	Modified time.Time `json:"modified"`
}

func safeRelative(v string) (string, error) {
	v = strings.TrimSpace(v)
	if v == "" || v == "." {
		return ".", nil
	}
	if filepath.IsAbs(v) {
		return "", errors.New("absolute paths are not allowed")
	}
	clean := filepath.Clean(v)
	if clean == ".." || strings.HasPrefix(clean, ".."+string(os.PathSeparator)) {
		return "", errors.New("path traversal rejected")
	}
	return clean, nil
}
func (m *Manager) ListFiles(user, rel string) ([]FileEntry, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if !m.mock {
		return nil, errors.New("host file backend is not enabled in this build")
	}
	if err := validateUser(user); err != nil {
		return nil, err
	}
	if _, ok := m.state.Accounts[user]; !ok {
		return nil, errors.New("account not found")
	}
	clean, err := safeRelative(rel)
	if err != nil {
		return nil, err
	}
	base := filepath.Join(m.root, "home", user)
	target := filepath.Join(base, clean)
	if !strings.HasPrefix(filepath.Clean(target), filepath.Clean(base)+string(os.PathSeparator)) && filepath.Clean(target) != filepath.Clean(base) {
		return nil, errors.New("unsafe file path")
	}
	ents, err := os.ReadDir(target)
	if err != nil {
		return nil, err
	}
	out := make([]FileEntry, 0, len(ents))
	for _, e := range ents {
		info, err := e.Info()
		if err != nil {
			continue
		}
		typ := "file"
		if e.IsDir() {
			typ = "directory"
		}
		p := filepath.Join(clean, e.Name())
		if clean == "." {
			p = e.Name()
		}
		out = append(out, FileEntry{Name: e.Name(), Path: p, Type: typ, Size: info.Size(), Mode: info.Mode().Perm().String(), Modified: info.ModTime().UTC()})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Type != out[j].Type {
			return out[i].Type == "directory"
		}
		return out[i].Name < out[j].Name
	})
	return out, nil
}
func (m *Manager) WriteFile(user, rel, content string) (FileEntry, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if !m.mock {
		return FileEntry{}, errors.New("host file backend is not enabled in this build")
	}
	if err := validateUser(user); err != nil {
		return FileEntry{}, err
	}
	if _, ok := m.state.Accounts[user]; !ok {
		return FileEntry{}, errors.New("account not found")
	}
	if len(content) > 1<<20 {
		return FileEntry{}, errors.New("file exceeds development write limit")
	}
	clean, err := safeRelative(rel)
	if err != nil || clean == "." {
		return FileEntry{}, errors.New("invalid file path")
	}
	base := filepath.Join(m.root, "home", user)
	target := filepath.Join(base, clean)
	if !strings.HasPrefix(filepath.Clean(target), filepath.Clean(base)+string(os.PathSeparator)) {
		return FileEntry{}, errors.New("unsafe file path")
	}
	if err := os.MkdirAll(filepath.Dir(target), 0750); err != nil {
		return FileEntry{}, err
	}
	if err := os.WriteFile(target, []byte(content), 0640); err != nil {
		return FileEntry{}, err
	}
	info, err := os.Stat(target)
	if err != nil {
		return FileEntry{}, err
	}
	return FileEntry{Name: filepath.Base(clean), Path: clean, Type: "file", Size: info.Size(), Mode: info.Mode().Perm().String(), Modified: info.ModTime().UTC()}, nil
}

// RemoveAccount removes Privora's durable account registration after the live
// host identity and owned sites have been cleaned up. Suspended-state gating is
// enforced by the API before this method is called.
func (m *Manager) RemoveAccount(username string) (Account, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	username = strings.ToLower(strings.TrimSpace(username))
	if err := validateUser(username); err != nil {
		return Account{}, err
	}
	a, ok := m.state.Accounts[username]
	if !ok {
		return Account{}, errors.New("account not found")
	}
	for _, site := range m.state.Sites {
		if site.Username == username {
			return Account{}, errors.New("account still owns websites")
		}
	}
	delete(m.state.Accounts, username)
	return a, m.save()
}

// RemoveSite removes only Privora's site registration. Live host mutation is
// performed by the certified host adapter before this method is called.
func (m *Manager) RemoveSite(domain string) (Site, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	domain = strings.ToLower(strings.TrimSpace(domain))
	if err := validateDomain(domain); err != nil {
		return Site{}, err
	}
	s, ok := m.state.Sites[domain]
	if !ok {
		return Site{}, errors.New("site not found")
	}
	delete(m.state.Sites, domain)
	return s, m.save()
}
