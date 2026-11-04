package hostadapter

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
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
	"time"
)

var (
	userRE  = regexp.MustCompile(`^[a-z][a-z0-9_-]{2,31}$`)
	labelRE = regexp.MustCompile(`^[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?$`)
	phpRE   = regexp.MustCompile(`^8\.[2-5]$`)
)

type Capability struct {
	Name       string `json:"name"`
	Available  bool   `json:"available"`
	Certified  bool   `json:"certified"`
	Dependency string `json:"dependency,omitempty"`
	Detail     string `json:"detail"`
}

type Config struct {
	AllowMutations       bool
	NginxSitesAvailable  string
	NginxSitesEnabled    string
	PHPFPMPoolDir        string
	AccountHomeBase      string
	CommandTimeout       time.Duration
	CertificationPath    string
	CertificationMode    bool // test-only bootstrap mode; not exposed by agent CLI
	DNSZoneDir           string
	DNSIndexPath         string
	DNSService           string
	ACMEConfigDir        string
	NftablesPath         string
	MailStateDir         string
	MailRoot             string
	MailUser             string
	MailAuthGroup        string
	SSHDConfigPath       string
	SFTPGroup            string
	CgroupRoot           string
	UpdaterPath          string
	UpdateUploadInbox    string
	UpdateUploadStaging  string
	UpdateAuthRoot       string
	UpdateStateRoot      string
	UpdateVerifierPath   string
	ReleasePublicKey     string
	AppManifestPath      string
	AppManifestSigPath   string
	AppManifestPublicKey string
	AppStagingRoot       string
	PasswdPath           string
	ShadowPath           string
	HTTPClient           *http.Client // test/cert injection; nil uses hardened default client
	RegistrarProvider    string
	RegistrarAdapterURL  string
	RegistrarToken       string
	AgentEnvPath         string
	PhpMyAdminRoot       string
	PanelNginxConfig     string
	PhpMyAdminFPMConfig  string
	NginxLogDir          string
	DovecotPrivoraConfig string
	RspamdDKIMConfig     string
	RspamdDKIMDir        string
	MailTLSDir           string
}

type Adapter struct {
	cfg               Config
	certified         map[string]bool
	evidenceOK        bool
	inventoryMu       sync.Mutex
	inventoryCache    HostInventory
	inventoryCachedAt time.Time
}

func New(cfg Config) *Adapter {
	if cfg.NginxSitesAvailable == "" {
		cfg.NginxSitesAvailable = "/etc/nginx/sites-available"
	}
	if cfg.NginxSitesEnabled == "" {
		cfg.NginxSitesEnabled = "/etc/nginx/sites-enabled"
	}
	if cfg.PHPFPMPoolDir == "" {
		cfg.PHPFPMPoolDir = "/etc/php"
	}
	if cfg.NginxLogDir == "" {
		cfg.NginxLogDir = "/var/log/nginx"
	}
	if cfg.AccountHomeBase == "" {
		cfg.AccountHomeBase = "/home"
	}
	if cfg.DNSZoneDir == "" {
		if _, err := os.Stat("/etc/bind"); err == nil {
			cfg.DNSZoneDir = "/etc/bind/privora-zones"
		} else {
			cfg.DNSZoneDir = "/etc/named/privora-zones"
		}
	}
	if cfg.DNSIndexPath == "" {
		if _, err := os.Stat("/etc/bind"); err == nil {
			cfg.DNSIndexPath = "/etc/bind/privora-zones.conf"
		} else {
			cfg.DNSIndexPath = "/etc/named/privora-zones.conf"
		}
	}
	if cfg.DNSService == "" {
		if _, err := os.Stat("/etc/bind"); err == nil {
			cfg.DNSService = "bind9"
		} else {
			cfg.DNSService = "named"
		}
	}
	if cfg.CommandTimeout == 0 {
		cfg.CommandTimeout = 15 * time.Second
	}
	if cfg.UpdaterPath == "" {
		cfg.UpdaterPath = "/usr/local/sbin/privora-update"
	}
	if cfg.UpdateUploadInbox == "" {
		cfg.UpdateUploadInbox = "/var/lib/privora-panel/web/update-uploads"
	}
	if cfg.UpdateUploadStaging == "" {
		cfg.UpdateUploadStaging = "/var/lib/privora-panel/update-upload-staging"
	}
	if cfg.UpdateAuthRoot == "" {
		cfg.UpdateAuthRoot = "/run/privora-panel/update-auth"
	}
	if cfg.UpdateStateRoot == "" {
		cfg.UpdateStateRoot = "/var/lib/privora-panel/update-transactions"
	}
	if cfg.UpdateVerifierPath == "" {
		cfg.UpdateVerifierPath = "/opt/privora-panel/scripts/verify-upload-update.py"
	}
	if cfg.ReleasePublicKey == "" {
		cfg.ReleasePublicKey = "/opt/privora-panel/install/release-public-key.pem"
	}
	if cfg.AppManifestPath == "" {
		cfg.AppManifestPath = "/etc/privora-panel/apps/releases.json"
	}
	if cfg.AppManifestSigPath == "" {
		cfg.AppManifestSigPath = cfg.AppManifestPath + ".sig"
	}
	if cfg.AppManifestPublicKey == "" {
		cfg.AppManifestPublicKey = "/etc/privora-panel/apps/app-release-public-key.pem"
	}
	if cfg.AppStagingRoot == "" {
		cfg.AppStagingRoot = "/var/lib/privora-panel/app-staging"
	}
	if cfg.AgentEnvPath == "" {
		cfg.AgentEnvPath = "/etc/privora-panel/agent.env"
	}
	if cfg.PasswdPath == "" {
		cfg.PasswdPath = "/etc/passwd"
	}
	if cfg.ShadowPath == "" {
		cfg.ShadowPath = "/etc/shadow"
	}
	if cfg.PhpMyAdminRoot == "" {
		cfg.PhpMyAdminRoot = "/usr/share/phpmyadmin"
	}
	if cfg.PanelNginxConfig == "" {
		if _, err := os.Stat("/etc/nginx/sites-available"); err == nil {
			cfg.PanelNginxConfig = "/etc/nginx/sites-available/privora-panel.conf"
		} else {
			cfg.PanelNginxConfig = "/etc/nginx/conf.d/privora-panel.conf"
		}
	}
	if cfg.PhpMyAdminFPMConfig == "" {
		if _, err := os.Stat("/etc/php/8.4/fpm/pool.d"); err == nil {
			cfg.PhpMyAdminFPMConfig = "/etc/php/8.4/fpm/pool.d/privora-phpmyadmin.conf"
		} else {
			cfg.PhpMyAdminFPMConfig = "/etc/php-fpm.d/privora-phpmyadmin.conf"
		}
	}
	a := &Adapter{cfg: cfg, certified: map[string]bool{}}
	a.loadCertification()
	return a
}

type CertificationEvidence struct {
	Profile           string   `json:"profile"`
	Status            string   `json:"status"`
	MachineIDHash     string   `json:"machine_id_sha256"`
	CertifiedAdapters []string `json:"certified_adapters"`
}

func machineIDHash() string {
	b, err := os.ReadFile("/etc/machine-id")
	if err != nil || len(bytes.TrimSpace(b)) == 0 {
		b = []byte(os.Getenv("HOSTNAME"))
	}
	h := sha256.Sum256(bytes.TrimSpace(b))
	return hex.EncodeToString(h[:])
}

func (a *Adapter) loadCertification() {
	if a.cfg.CertificationPath == "" {
		return
	}
	b, err := os.ReadFile(a.cfg.CertificationPath)
	if err != nil {
		return
	}
	var e CertificationEvidence
	if json.Unmarshal(b, &e) != nil {
		return
	}
	if e.Profile != "privora-panel-host-adapter-certification-v1" || e.Status != "PASS" || e.MachineIDHash != machineIDHash() {
		return
	}
	for _, name := range e.CertifiedAdapters {
		a.certified[name] = true
	}
	a.evidenceOK = true
}
func (a *Adapter) certifiedFor(name string) bool {
	return a.cfg.CertificationMode || (a.evidenceOK && a.certified[name])
}
func (a *Adapter) requireCertified(name string) error {
	if !a.certifiedFor(name) {
		return fmt.Errorf("host adapter %s is not certified for this machine", name)
	}
	return nil
}

func commandExists(name string) (string, bool) { p, err := exec.LookPath(name); return p, err == nil }

// mysqlFamilyAvailable distinguishes Oracle/MySQL Server from MariaDB even when
// MariaDB provides a mysql compatibility client. This prevents the UI from
// advertising both engines when only MariaDB is actually installed.
func mysqlFamilyAvailable(engine string) (bool, string) {
	mysqlPath, mysqlOK := commandExists("mysql")
	mariaPath, mariaOK := commandExists("mariadb")
	versionText := ""
	if mysqlOK {
		if b, err := exec.Command(mysqlPath, "--version").CombinedOutput(); err == nil {
			versionText = strings.ToLower(string(b))
		}
	}
	isMaria := mariaOK || strings.Contains(versionText, "mariadb")
	switch engine {
	case "mariadb":
		if isMaria {
			if mariaOK {
				return true, mariaPath
			}
			return true, mysqlPath + " (MariaDB compatibility client)"
		}
		return false, "MariaDB server/client not installed"
	case "mysql":
		if mysqlOK && !isMaria {
			return true, mysqlPath
		}
		if mysqlOK && isMaria {
			return false, "mysql command belongs to MariaDB; Oracle/MySQL Server is not installed"
		}
		return false, "MySQL client/server not installed"
	default:
		return false, "unsupported SQL family"
	}
}
func validUser(v string) bool { return userRE.MatchString(v) }
func validDomain(v string) bool {
	v = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(v)), ".")
	if len(v) < 3 || len(v) > 253 || !strings.Contains(v, ".") || net.ParseIP(v) != nil {
		return false
	}
	for _, p := range strings.Split(v, ".") {
		if !labelRE.MatchString(p) {
			return false
		}
	}
	return true
}

// PrimaryHostAddresses returns the best locally assigned addresses for default
// website/DNS provisioning. Public/global addresses are preferred; RFC1918/ULA
// addresses are retained only as a fallback so NAT/private hosts can return
// explicit manual-DNS guidance instead of inventing a public address.
func (a *Adapter) PrimaryHostAddresses() (string, string) {
	type candidate struct {
		value  string
		public bool
	}
	var v4s, v6s []candidate
	ifaces, err := net.Interfaces()
	if err != nil {
		return "", ""
	}
	for _, iface := range ifaces {
		if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 {
			continue
		}
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}
		for _, addr := range addrs {
			raw := addr.String()
			if i := strings.IndexByte(raw, '/'); i >= 0 {
				raw = raw[:i]
			}
			ip := net.ParseIP(strings.TrimSpace(raw))
			if ip == nil || ip.IsLoopback() || ip.IsLinkLocalUnicast() {
				continue
			}
			pub := ip.IsGlobalUnicast() && !ip.IsPrivate()
			if x := ip.To4(); x != nil {
				v4s = append(v4s, candidate{x.String(), pub})
			} else if ip.To16() != nil {
				v6s = append(v6s, candidate{ip.String(), pub})
			}
		}
	}
	pick := func(xs []candidate) string {
		for _, x := range xs {
			if x.public {
				return x.value
			}
		}
		if len(xs) > 0 {
			return xs[0].value
		}
		return ""
	}
	return pick(v4s), pick(v6s)
}

func (a *Adapter) Probe() []Capability {
	probes := []struct{ name, dep string }{
		{"linux-users", "useradd"}, {"filesystem-quota", "setquota"}, {"cgroup-v2", "cgroup.controllers"}, {"nginx", "nginx"},
		{"php-fpm", "php-fpm8.4"}, {"mysql", "mysql"}, {"mariadb", "mariadb"}, {"postgresql", "psql"},
		{"authoritative-dns", "named-checkzone"}, {"acme", "certbot"}, {"nftables", "nft"},
		{"postfix", "postconf"}, {"dovecot", "doveconf"}, {"rspamd", "rspamadm"}, {"openssh-sftp", "sshd"}, {"privora-updater", "privora-update"}, {"app-installer", "openssl"},
		{"phpmyadmin", "phpmyadmin-package"}, {"webmail", "roundcube"}, {"fail2ban", "fail2ban-client"}, {"modsecurity", "modsecurity-crs"}, {"clamav", "clamscan"}, {"backup-zstd", "zstd"}, {"backup-rsync", "rsync"},
		{"dns-cluster", "rndc"}, {"migration-rsync", "rsync"}, {"migration-ssh", "ssh"}, {"monitoring-journal", "journalctl"}, {"system-network", "ip"}, {"system-storage", "lsblk"},
	}
	out := make([]Capability, 0, len(probes))
	for _, p := range probes {
		path, ok := commandExists(p.dep)
		detail := "dependency not installed"
		if ok {
			detail = path
		}
		if p.name == "mysql" || p.name == "mariadb" {
			ok, detail = mysqlFamilyAvailable(p.name)
		}
		certified := a.certifiedFor(p.name)
		switch p.name {
		case "cgroup-v2":
			root := a.cfg.CgroupRoot
			if root == "" {
				root = "/sys/fs/cgroup"
			}
			controllers := filepath.Join(root, "cgroup.controllers")
			if st, err := os.Stat(controllers); err == nil && st.Mode().IsRegular() {
				ok = true
				detail = controllers
				if f, err := os.OpenFile(filepath.Join(root, ".privora-write-probe"), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600); err == nil {
					f.Close()
					_ = os.Remove(filepath.Join(root, ".privora-write-probe"))
				} else {
					detail += "; hierarchy not writable"
				}
			}
		case "webmail":
			ok, certified, detail = a.webmailCapability()
		case "phpmyadmin":
			ok, certified, detail = a.phpMyAdminCapability()
		case "php-fpm":
			if _, err := os.Stat("/etc/php/8.4"); err == nil {
				ok = true
				detail = "/etc/php/8.4 detected; daemon binary not certified"
			}
		}
		out = append(out, Capability{Name: p.name, Available: ok, Certified: certified, Dependency: p.dep, Detail: detail})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

func (a *Adapter) phpMyAdminCapability() (bool, bool, string) {
	index := filepath.Join(a.cfg.PhpMyAdminRoot, "index.php")
	st, err := os.Stat(index)
	if err != nil || !st.Mode().IsRegular() {
		return false, false, "phpMyAdmin package files not installed"
	}
	nginxRaw, nerr := os.ReadFile(a.cfg.PanelNginxConfig)
	fpmRaw, ferr := os.ReadFile(a.cfg.PhpMyAdminFPMConfig)
	routeOK := nerr == nil && bytes.Contains(nginxRaw, []byte("location /phpmyadmin/")) && bytes.Contains(nginxRaw, []byte("/_privora_phpmyadmin_auth"))
	poolOK := ferr == nil && bytes.Contains(fpmRaw, []byte("[privora-phpmyadmin]")) && bytes.Contains(fpmRaw, []byte("privora-phpmyadmin.sock"))
	if !routeOK || !poolOK {
		missing := []string{}
		if !routeOK {
			missing = append(missing, "Privora Nginx auth route")
		}
		if !poolOK {
			missing = append(missing, "dedicated PHP-FPM pool")
		}
		return true, false, index + "; missing " + strings.Join(missing, " + ")
	}
	return true, true, index + "; launch=/phpmyadmin/; panel-session-gated"
}

func (a *Adapter) run(ctx context.Context, name string, args ...string) (string, error) {
	if name == "runuser" && !a.cfg.CertificationMode {
		userName, command, commandArgs, err := parseRunuserInvocation(args)
		if err != nil {
			return "", err
		}
		return runIsolatedUserCommand(ctx, "privora-user-command", a.cfg.CommandTimeout, userName, command, commandArgs, "", "")
	}
	cctx, cancel := context.WithTimeout(ctx, a.cfg.CommandTimeout)
	defer cancel()
	cmd := exec.CommandContext(cctx, name, args...)
	var out, stderr bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return out.String(), fmt.Errorf("%s %v: %w: %s", name, args, err, strings.TrimSpace(stderr.String()))
	}
	return out.String(), nil
}

func (a *Adapter) SetLinuxUserPassword(ctx context.Context, username, password string) error {
	if !a.cfg.AllowMutations {
		return errors.New("host mutations disabled")
	}
	if err := a.requireCertified("linux-users"); err != nil {
		return err
	}
	if !validUser(username) {
		return errors.New("invalid username")
	}
	if len(password) < 12 || len(password) > 1024 || strings.ContainsAny(password, "\x00\r\n") {
		return errors.New("password must be 12-1024 characters without line breaks")
	}
	if _, ok := commandExists("chpasswd"); !ok {
		return errors.New("chpasswd not installed")
	}
	if _, err := a.run(ctx, "id", username); err != nil {
		return errors.New("user not found")
	}
	_, err := a.runInput(ctx, username+":"+password+"\n", "chpasswd")
	return err
}

func (a *Adapter) SetLinuxUserShellPolicy(ctx context.Context, username, policy string) (string, error) {
	if !a.cfg.AllowMutations {
		return "", errors.New("host mutations disabled")
	}
	if err := a.requireCertified("linux-users"); err != nil {
		return "", err
	}
	if !validUser(username) {
		return "", errors.New("invalid username")
	}
	policy = strings.ToLower(strings.TrimSpace(policy))
	shells := map[string]string{"none": "/usr/sbin/nologin", "restricted": "/bin/rbash", "ssh": "/bin/bash"}
	shell, ok := shells[policy]
	if !ok {
		return "", errors.New("unsupported shell policy")
	}
	if st, err := os.Stat(shell); err != nil || !st.Mode().IsRegular() {
		if policy == "restricted" {
			shell = "/bin/bash"
		} else {
			return "", fmt.Errorf("shell unavailable: %s", shell)
		}
	}
	if _, ok := commandExists("usermod"); !ok {
		return "", errors.New("usermod not installed")
	}
	if _, err := a.run(ctx, "id", username); err != nil {
		return "", errors.New("user not found")
	}
	if _, err := a.run(ctx, "usermod", "--shell", shell, username); err != nil {
		return "", err
	}
	return shell, nil
}

func (a *Adapter) CreateLinuxUser(ctx context.Context, username string) error {
	if !a.cfg.AllowMutations {
		return errors.New("host mutations disabled")
	}
	if err := a.requireCertified("linux-users"); err != nil {
		return err
	}
	if !validUser(username) {
		return errors.New("invalid username")
	}
	if _, ok := commandExists("useradd"); !ok {
		return errors.New("useradd not installed")
	}
	if _, err := a.run(ctx, "id", username); err == nil {
		return errors.New("user already exists")
	}
	home := filepath.Join(a.cfg.AccountHomeBase, username)
	if !strings.HasPrefix(filepath.Clean(home), filepath.Clean(a.cfg.AccountHomeBase)+string(os.PathSeparator)) {
		return errors.New("unsafe home path")
	}
	_, err := a.run(ctx, "useradd", "--create-home", "--home-dir", home, "--shell", "/usr/sbin/nologin", username)
	return err
}

func (a *Adapter) DeleteLinuxUser(ctx context.Context, username string) error {
	if !a.cfg.AllowMutations {
		return errors.New("host mutations disabled")
	}
	if err := a.requireCertified("linux-users"); err != nil {
		return err
	}
	if !validUser(username) {
		return errors.New("invalid username")
	}
	if _, ok := commandExists("userdel"); !ok {
		return errors.New("userdel not installed")
	}
	home := filepath.Join(a.cfg.AccountHomeBase, username)
	base := filepath.Clean(a.cfg.AccountHomeBase) + string(os.PathSeparator)
	if !strings.HasPrefix(filepath.Clean(home), base) {
		return errors.New("unsafe home path")
	}
	// The account home is deliberately root-owned for OpenSSH chroot safety,
	// so userdel --remove correctly refuses to remove it. Delete only the OS
	// identity first, then remove the already validated account tree ourselves.
	if _, err := a.run(ctx, "userdel", username); err != nil {
		return err
	}
	if err := os.RemoveAll(home); err != nil {
		return fmt.Errorf("remove account home: %w", err)
	}
	mailSpool := filepath.Join("/var/mail", username)
	if st, err := os.Lstat(mailSpool); err == nil && st.Mode().IsRegular() {
		_ = os.Remove(mailSpool)
	}
	return nil
}

func panelShortcutPort(name string, fallback int) int {
	v := strings.TrimSpace(os.Getenv(name))
	if v == "" {
		return fallback
	}
	p, err := strconv.Atoi(v)
	if err != nil || p < 1 || p > 65535 {
		return fallback
	}
	return p
}

func panelShortcutLocations() string {
	pcc := panelShortcutPort("PRIVORA_ADMIN_PANEL_PORT", 8443)
	ppanel := panelShortcutPort("PRIVORA_HOSTING_PANEL_PORT", 2443)
	if pcc == ppanel {
		pcc, ppanel = 8443, 2443
	}
	return fmt.Sprintf(`    # Privora Panel PCC/PPanel convenience aliases
    location = /pcc { return 302 https://$host:%d/; }
    location = /pcc/ { return 302 https://$host:%d/; }
    location = /ppanel { return 302 https://$host:%d/; }
    location = /ppanel/ { return 302 https://$host:%d/; }
`, pcc, pcc, ppanel, ppanel)
}

func RenderNginxSite(domain, username, phpVersion, docRoot string) (string, error) {
	if !validDomain(domain) || !validUser(username) || !phpRE.MatchString(phpVersion) {
		return "", errors.New("invalid site input")
	}
	cleanRoot := filepath.Clean(docRoot)
	expected := filepath.Join("/home", username) + string(os.PathSeparator)
	if !strings.HasPrefix(cleanRoot, expected) {
		return "", errors.New("document root outside account home")
	}
	socket := fmt.Sprintf("/run/php/php%s-fpm-%s.sock", phpVersion, username)
	return fmt.Sprintf(`server {
    listen 80;
    listen [::]:80;
    server_name %s;
    root %s;
    index index.php index.html;
    access_log /var/log/nginx/%s.access.log;
    error_log /var/log/nginx/%s.error.log;
    # ACME HTTP-01 must bypass the hidden-file deny rule below.
    location ^~ /.well-known/acme-challenge/ { try_files $uri =404; }
%s    location / { try_files $uri $uri/ /index.php?$query_string; }
    location ~ \.php$ {
        include /etc/nginx/fastcgi_params;
        fastcgi_param SCRIPT_FILENAME $document_root$fastcgi_script_name;
        fastcgi_pass unix:%s;
    }
    location ~ /\. { deny all; }
}
`, domain, cleanRoot, domain, domain, panelShortcutLocations(), socket), nil
}

func RenderNginxSiteTLS(domain, username, phpVersion, docRoot, fullchain, privkey string) (string, error) {
	if !validDomain(domain) || !validUser(username) || !phpRE.MatchString(phpVersion) {
		return "", errors.New("invalid site input")
	}
	cleanRoot := filepath.Clean(docRoot)
	expected := filepath.Join("/home", username) + string(os.PathSeparator)
	if !strings.HasPrefix(cleanRoot, expected) {
		return "", errors.New("document root outside account home")
	}
	fullchain = filepath.Clean(fullchain)
	privkey = filepath.Clean(privkey)
	if !strings.HasPrefix(fullchain, "/etc/letsencrypt/") || !strings.HasPrefix(privkey, "/etc/letsencrypt/") {
		return "", errors.New("certificate path outside Let's Encrypt configuration")
	}
	socket := fmt.Sprintf("/run/php/php%s-fpm-%s.sock", phpVersion, username)
	return fmt.Sprintf(`server {
    listen 80;
    listen [::]:80;
    server_name %s;
    root %s;
    location ^~ /.well-known/acme-challenge/ { try_files $uri =404; }
%s    location / { return 301 https://$host$request_uri; }
}
server {
    listen 443 ssl http2;
    listen [::]:443 ssl http2;
    server_name %s;
    root %s;
    index index.php index.html;
    access_log /var/log/nginx/%s.access.log;
    error_log /var/log/nginx/%s.error.log;
    ssl_certificate %s;
    ssl_certificate_key %s;
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_session_cache shared:SSL:10m;
    ssl_session_timeout 1d;
%s    location / { try_files $uri $uri/ /index.php?$query_string; }
    location ~ \.php$ {
        include /etc/nginx/fastcgi_params;
        fastcgi_param SCRIPT_FILENAME $document_root$fastcgi_script_name;
        fastcgi_pass unix:%s;
    }
    location ~ /\. { deny all; }
}
`, domain, cleanRoot, panelShortcutLocations(), domain, cleanRoot, domain, domain, fullchain, privkey, panelShortcutLocations(), socket), nil
}

func RenderPHPFPMPool(username, phpVersion string) (string, error) {
	if !validUser(username) || !phpRE.MatchString(phpVersion) {
		return "", errors.New("invalid pool input")
	}
	return fmt.Sprintf(`[%s]
user = %s
group = %s
listen = /run/php/php%s-fpm-%s.sock
listen.owner = www-data
listen.group = www-data
pm = ondemand
pm.max_children = 10
pm.process_idle_timeout = 10s
php_admin_value[open_basedir] = /home/%s/:/tmp/
php_admin_value[upload_tmp_dir] = /home/%s/tmp
php_admin_value[session.save_path] = /home/%s/tmp
`, username, username, username, phpVersion, username, username, username, username), nil
}

func (a *Adapter) ValidateNginxConfig(ctx context.Context, fullConfigPath, prefix string) error {
	if _, ok := commandExists("nginx"); !ok {
		return errors.New("nginx not installed")
	}
	args := []string{"-t", "-c", fullConfigPath}
	if prefix != "" {
		args = append(args, "-p", prefix)
	}
	_, err := a.run(ctx, "nginx", args...)
	return err
}

func AtomicWrite(path string, data []byte, mode os.FileMode) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0750); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, ".privora-*.tmp")
	if err != nil {
		return err
	}
	name := tmp.Name()
	defer os.Remove(name)
	if err := tmp.Chmod(mode); err != nil {
		tmp.Close()
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(name, path)
}

// SetLinuxUserLocked changes only the account password-lock state. It does not
// enable an interactive shell. Hosting suspension still needs the web/mail
// service layers to enforce their own suspension policy before 1.0 promotion.
func (a *Adapter) SetLinuxUserLocked(ctx context.Context, username string, locked bool) error {
	if !a.cfg.AllowMutations {
		return errors.New("host mutations disabled")
	}
	if err := a.requireCertified("linux-users"); err != nil {
		return err
	}
	if !validUser(username) {
		return errors.New("invalid username")
	}
	if _, ok := commandExists("usermod"); !ok {
		return errors.New("usermod not installed")
	}
	if _, err := a.run(ctx, "id", username); err != nil {
		return errors.New("user not found")
	}
	arg := "--unlock"
	if locked {
		arg = "--lock"
	}
	_, err := a.run(ctx, "usermod", arg, username)
	return err
}

// SetLinuxUserSuspended applies an account-expiry gate that is reversible even
// when the hosting account intentionally has no password yet. It leaves the
// configured nologin shell unchanged.
func (a *Adapter) SetLinuxUserSuspended(ctx context.Context, username string, suspended bool) error {
	if !a.cfg.AllowMutations {
		return errors.New("host mutations disabled")
	}
	if err := a.requireCertified("linux-users"); err != nil {
		return err
	}
	if !validUser(username) {
		return errors.New("invalid username")
	}
	if _, ok := commandExists("usermod"); !ok {
		return errors.New("usermod not installed")
	}
	if _, err := a.run(ctx, "id", username); err != nil {
		return errors.New("user not found")
	}
	date := ""
	if suspended {
		date = "1"
	}
	_, err := a.run(ctx, "usermod", "--expiredate", date, username)
	return err
}
