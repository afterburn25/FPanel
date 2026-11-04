package hostadapter

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"syscall"
	"time"
)

type MailQueueEntry struct {
	QueueID     string   `json:"queue_id"`
	QueueName   string   `json:"queue_name"`
	ArrivalTime int64    `json:"arrival_time"`
	MessageSize int64    `json:"message_size"`
	Sender      string   `json:"sender"`
	Recipients  []string `json:"recipients"`
	DelayReason string   `json:"delay_reason,omitempty"`
}
type MailDeliveryEvent struct {
	Time      string `json:"time"`
	QueueID   string `json:"queue_id,omitempty"`
	Status    string `json:"status"`
	Sender    string `json:"sender,omitempty"`
	Recipient string `json:"recipient,omitempty"`
	Relay     string `json:"relay,omitempty"`
	Detail    string `json:"detail"`
}

var postfixQueueIDRE = regexp.MustCompile(`^[A-Fa-f0-9]{5,32}$`)

func (a *Adapter) runPostfixQueueTool(ctx context.Context, tool string, args ...string) (string, error) {
	if a.cfg.CertificationMode {
		return a.run(ctx, tool, args...)
	}
	path, ok := commandExists(tool)
	if !ok {
		return "", fmt.Errorf("%s not installed", tool)
	}
	switch tool {
	case "postqueue":
		if len(args) != 1 || (args[0] != "-j" && args[0] != "-f" && args[0] != "-p") {
			return "", errors.New("unsupported postqueue operation")
		}
	case "postsuper":
		if len(args) != 2 || (args[0] != "-r" && args[0] != "-d") || !postfixQueueIDRE.MatchString(strings.TrimSpace(args[1])) {
			return "", errors.New("unsupported postsuper operation")
		}
	default:
		return "", errors.New("unsupported Postfix queue tool")
	}
	return runIsolatedRootCommand(ctx, "privora-postfix-queue", 2*time.Minute, path, args, map[string]bool{})
}

func (a *Adapter) MailQueue(ctx context.Context) ([]MailQueueEntry, error) {
	if err := a.requireCertified("postfix"); err != nil {
		return nil, err
	}
	if _, ok := commandExists("postqueue"); !ok {
		return nil, errors.New("postqueue not installed")
	}
	out, err := a.runPostfixQueueTool(ctx, "postqueue", "-j")
	if err != nil {
		return nil, err
	}
	rows := []MailQueueEntry{}
	sc := bufio.NewScanner(strings.NewReader(out))
	for sc.Scan() {
		var raw struct {
			QueueName   string `json:"queue_name"`
			QueueID     string `json:"queue_id"`
			ArrivalTime int64  `json:"arrival_time"`
			MessageSize int64  `json:"message_size"`
			Sender      string `json:"sender"`
			Recipients  []struct {
				Address     string `json:"address"`
				DelayReason string `json:"delay_reason"`
			} `json:"recipients"`
		}
		if json.Unmarshal(sc.Bytes(), &raw) != nil {
			continue
		}
		e := MailQueueEntry{QueueID: raw.QueueID, QueueName: raw.QueueName, ArrivalTime: raw.ArrivalTime, MessageSize: raw.MessageSize, Sender: raw.Sender}
		for _, r := range raw.Recipients {
			e.Recipients = append(e.Recipients, r.Address)
			if e.DelayReason == "" {
				e.DelayReason = r.DelayReason
			}
		}
		rows = append(rows, e)
	}
	return rows, sc.Err()
}
func (a *Adapter) RetryMailQueue(ctx context.Context, id string) error {
	if !a.cfg.AllowMutations {
		return errors.New("host mutations disabled")
	}
	if err := a.requireCertified("postfix"); err != nil {
		return err
	}
	id = strings.TrimSpace(id)
	if !postfixQueueIDRE.MatchString(id) {
		return errors.New("invalid Postfix queue id")
	}
	if _, err := a.runPostfixQueueTool(ctx, "postsuper", "-r", id); err != nil {
		return err
	}
	_, err := a.runPostfixQueueTool(ctx, "postqueue", "-f")
	return err
}
func (a *Adapter) DeleteMailQueue(ctx context.Context, id string) error {
	if !a.cfg.AllowMutations {
		return errors.New("host mutations disabled")
	}
	if err := a.requireCertified("postfix"); err != nil {
		return err
	}
	id = strings.TrimSpace(id)
	if !postfixQueueIDRE.MatchString(id) {
		return errors.New("invalid Postfix queue id")
	}
	_, err := a.runPostfixQueueTool(ctx, "postsuper", "-d", id)
	return err
}
func (a *Adapter) MailDeliveryEvents(ctx context.Context, query string, limit int) ([]MailDeliveryEvent, error) {
	if err := a.requireCertified("postfix"); err != nil {
		return nil, err
	}
	if limit < 1 || limit > 500 {
		limit = 200
	}
	path := "/var/log/mail.log"
	if _, err := os.Stat(path); err != nil {
		path = "/var/log/maillog"
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	// Delivery tracing should inspect the newest log data, not the oldest bytes
	// of a large log. Read at most the trailing 16 MiB.
	if st, statErr := f.Stat(); statErr == nil && st.Size() > 16<<20 {
		_, _ = f.Seek(-(16 << 20), io.SeekEnd)
	}
	b, err := io.ReadAll(io.LimitReader(f, 16<<20))
	if err != nil {
		return nil, err
	}
	lines := strings.Split(string(b), "\n")
	q := strings.ToLower(strings.TrimSpace(query))
	out := []MailDeliveryEvent{}
	reID := regexp.MustCompile(`\b([A-F0-9]{5,32}):`)
	reFrom := regexp.MustCompile(`from=<([^>]*)>`)
	reTo := regexp.MustCompile(`to=<([^>]*)>`)
	reStatus := regexp.MustCompile(`status=([a-zA-Z]+)`)
	reRelay := regexp.MustCompile(`relay=([^, ]+)`)
	for i := len(lines) - 1; i >= 0 && len(out) < limit; i-- {
		line := strings.TrimSpace(lines[i])
		if line == "" || (!strings.Contains(line, "postfix/") && !strings.Contains(line, "postfix[")) {
			continue
		}
		if q != "" && !strings.Contains(strings.ToLower(line), q) {
			continue
		}
		e := MailDeliveryEvent{Detail: line, Status: "info"}
		if len(line) >= 15 {
			e.Time = line[:15]
		}
		if m := reID.FindStringSubmatch(line); len(m) > 1 {
			e.QueueID = m[1]
		}
		if m := reFrom.FindStringSubmatch(line); len(m) > 1 {
			e.Sender = m[1]
		}
		if m := reTo.FindStringSubmatch(line); len(m) > 1 {
			e.Recipient = m[1]
		}
		if m := reStatus.FindStringSubmatch(line); len(m) > 1 {
			e.Status = strings.ToLower(m[1])
		}
		if m := reRelay.FindStringSubmatch(line); len(m) > 1 {
			e.Relay = m[1]
		}
		out = append(out, e)
	}
	return out, nil
}

type SieveFilter struct {
	ID, Name, Field, Operator, Value, Action, Destination string
	Enabled                                               bool
}

func sieveQuote(v string) string {
	return `"` + strings.ReplaceAll(strings.ReplaceAll(v, `\`, `\\`), `"`, `\"`) + `"`
}
func RenderSieve(filters []SieveFilter) (string, error) {
	var b strings.Builder
	b.WriteString("require [\"fileinto\", \"regex\"];\n# Managed by Privora Panel.\n")
	for _, f := range filters {
		if !f.Enabled {
			continue
		}
		if !map[string]bool{"from": true, "to": true, "subject": true, "size": true}[f.Field] || !map[string]bool{"contains": true, "is": true, "matches": true, "over": true, "under": true}[f.Operator] || !map[string]bool{"keep": true, "discard": true, "fileinto": true, "redirect": true}[f.Action] {
			return "", errors.New("invalid sieve filter")
		}
		test := ""
		if f.Field == "size" {
			n, err := strconv.Atoi(f.Value)
			if err != nil || n < 1 {
				return "", errors.New("invalid size filter")
			}
			op := ":over"
			if f.Operator == "under" {
				op = ":under"
			}
			test = fmt.Sprintf("size %s %dK", op, n)
		} else if f.Field == "from" || f.Field == "to" {
			header := "From"
			if f.Field == "to" {
				header = "To"
			}
			test = fmt.Sprintf("address :%s %s %s", f.Operator, sieveQuote(header), sieveQuote(f.Value))
		} else {
			test = fmt.Sprintf("header :%s \"Subject\" %s", f.Operator, sieveQuote(f.Value))
		}
		b.WriteString("# " + strings.ReplaceAll(f.Name, "\n", " ") + "\nif " + test + " {\n")
		switch f.Action {
		case "keep":
			b.WriteString("  keep;\n")
		case "discard":
			b.WriteString("  discard;\n")
		case "fileinto":
			b.WriteString("  fileinto " + sieveQuote(f.Destination) + ";\n")
		case "redirect":
			b.WriteString("  redirect " + sieveQuote(f.Destination) + ";\n")
		}
		b.WriteString("  stop;\n}\n")
	}
	return b.String(), nil
}
func (a *Adapter) ApplyMailboxSieve(ctx context.Context, address string, filters []SieveFilter) (string, error) {
	if !a.cfg.AllowMutations {
		return "", errors.New("host mutations disabled")
	}
	if err := a.requireCertified("dovecot"); err != nil {
		return "", err
	}
	parts := strings.Split(strings.ToLower(strings.TrimSpace(address)), "@")
	if len(parts) != 2 || !mailLocalRE.MatchString(parts[0]) || !validDomain(parts[1]) {
		return "", errors.New("invalid mailbox")
	}
	if _, ok := commandExists("sievec"); !ok {
		return "", errors.New("Dovecot Pigeonhole/sievec is not installed")
	}
	text, err := RenderSieve(filters)
	if err != nil {
		return "", err
	}
	root := a.cfg.MailRoot
	if root == "" {
		root = "/var/vmail"
	}
	home := filepath.Join(root, parts[1], parts[0])
	homeInfo, err := os.Stat(home)
	if err != nil || !homeInfo.IsDir() {
		return "", errors.New("mailbox home not found")
	}
	uid, gid := -1, -1
	if sys, ok := homeInfo.Sys().(*syscall.Stat_t); ok {
		uid, gid = int(sys.Uid), int(sys.Gid)
	}
	dir := filepath.Join(home, "sieve")
	if err := os.MkdirAll(dir, 0750); err != nil {
		return "", err
	}
	if uid >= 0 {
		_ = os.Chown(dir, uid, gid)
	}
	src := filepath.Join(dir, "privora.sieve")
	tmp := src + ".tmp"
	if err := os.WriteFile(tmp, []byte(text), 0640); err != nil {
		return "", err
	}
	if uid >= 0 {
		_ = os.Chown(tmp, uid, gid)
	}
	if _, err := a.run(ctx, "sievec", tmp); err != nil {
		_ = os.Remove(tmp)
		return "", err
	}
	compiledTmp := tmp + ".svbin"
	compiled := src + ".svbin"
	if err := os.Rename(tmp, src); err != nil {
		return "", err
	}
	if uid >= 0 {
		_ = os.Chown(src, uid, gid)
	}
	if _, err := os.Stat(compiledTmp); err == nil {
		_ = os.Rename(compiledTmp, compiled)
		if uid >= 0 {
			_ = os.Chown(compiled, uid, gid)
		}
	}
	active := filepath.Join(home, ".dovecot.sieve")
	_ = os.Remove(active)
	if err := os.Symlink(src, active); err != nil {
		return "", err
	}
	return src, nil
}

type BackupVerification struct {
	Path       string    `json:"path"`
	SHA256     string    `json:"sha256"`
	Size       int64     `json:"size_bytes"`
	Entries    int       `json:"entries"`
	Status     string    `json:"status"`
	VerifiedAt time.Time `json:"verified_at"`
}

func (a *Adapter) VerifyLocalBackup(ctx context.Context, path, expected string) (BackupVerification, error) {
	if err := a.requireCertified("local-backup"); err != nil {
		return BackupVerification{}, err
	}
	path = filepath.Clean(path)
	if !filepath.IsAbs(path) || !strings.HasSuffix(path, ".tar.zst") {
		return BackupVerification{}, errors.New("invalid backup path")
	}
	f, err := os.Open(path)
	if err != nil {
		return BackupVerification{}, err
	}
	h := sha256.New()
	n, err := io.Copy(h, f)
	_ = f.Close()
	if err != nil {
		return BackupVerification{}, err
	}
	sum := hex.EncodeToString(h.Sum(nil))
	if expected != "" && sum != expected {
		return BackupVerification{}, errors.New("backup checksum mismatch")
	}
	out, err := a.run(ctx, "tar", "--use-compress-program=zstd", "-tf", path)
	if err != nil {
		return BackupVerification{}, err
	}
	entries := 0
	for _, line := range strings.Split(out, "\n") {
		if strings.TrimSpace(line) != "" {
			entries++
		}
	}
	return BackupVerification{Path: path, SHA256: sum, Size: n, Entries: entries, Status: "verified", VerifiedAt: time.Now().UTC()}, nil
}

type LiveMetrics struct {
	CPUPercent     float64   `json:"cpu_percent"`
	MemoryPercent  float64   `json:"memory_percent"`
	DiskPercent    float64   `json:"disk_percent"`
	Load1          float64   `json:"load_1"`
	MailQueue      int       `json:"mail_queue"`
	PHPBusy        int       `json:"php_busy_workers"`
	NginxActive    bool      `json:"nginx_active"`
	DatabaseActive bool      `json:"database_active"`
	CapturedAt     time.Time `json:"captured_at"`
}

func readCPUStat() (idle, total uint64, err error) {
	b, e := os.ReadFile("/proc/stat")
	if e != nil {
		return 0, 0, e
	}
	f := strings.Fields(strings.SplitN(string(b), "\n", 2)[0])
	if len(f) < 5 {
		return 0, 0, errors.New("invalid proc stat")
	}
	for i := 1; i < len(f); i++ {
		v, _ := strconv.ParseUint(f[i], 10, 64)
		total += v
		if i == 4 || i == 5 {
			idle += v
		}
	}
	return
}
func serviceActiveV7(ctx context.Context, name string) bool {
	cctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	return exec.CommandContext(cctx, "systemctl", "is-active", "--quiet", name).Run() == nil
}
func (a *Adapter) CollectLiveMetrics(ctx context.Context) (LiveMetrics, error) {
	var v LiveMetrics
	i1, t1, e := readCPUStat()
	if e == nil {
		time.Sleep(120 * time.Millisecond)
		i2, t2, _ := readCPUStat()
		dt := float64(t2 - t1)
		if dt > 0 {
			v.CPUPercent = 100 * (1 - float64(i2-i1)/dt)
		}
	}
	mem, _ := os.ReadFile("/proc/meminfo")
	vals := map[string]float64{}
	for _, l := range strings.Split(string(mem), "\n") {
		p := strings.Fields(l)
		if len(p) >= 2 {
			n, _ := strconv.ParseFloat(p[1], 64)
			vals[strings.TrimSuffix(p[0], ":")] = n
		}
	}
	if vals["MemTotal"] > 0 {
		v.MemoryPercent = 100 * (1 - vals["MemAvailable"]/vals["MemTotal"])
	}
	var st syscall.Statfs_t
	if syscall.Statfs("/", &st) == nil && st.Blocks > 0 {
		v.DiskPercent = 100 * (1 - float64(st.Bavail)/float64(st.Blocks))
	}
	if b, err := os.ReadFile("/proc/loadavg"); err == nil {
		fmt.Sscanf(string(b), "%f", &v.Load1)
	}
	if a.certifiedFor("postfix") {
		if q, err := a.MailQueue(ctx); err == nil {
			v.MailQueue = len(q)
		}
	}
	v.NginxActive = serviceActiveV7(ctx, "nginx")
	v.DatabaseActive = serviceActiveV7(ctx, "mariadb") || serviceActiveV7(ctx, "mysql") || serviceActiveV7(ctx, "postgresql")
	v.CapturedAt = time.Now().UTC()
	return v, nil
}

type SecurityAdvice struct {
	ID       string `json:"id"`
	Severity string `json:"severity"`
	Title    string `json:"title"`
	Detail   string `json:"detail"`
	Fix      string `json:"fix,omitempty"`
	Status   string `json:"status"`
}

func (a *Adapter) SecurityAdvice(ctx context.Context) []SecurityAdvice {
	out := []SecurityAdvice{}
	if serviceActiveV7(ctx, "nftables") {
		out = append(out, SecurityAdvice{ID: "firewall", Severity: "info", Title: "Firewall active", Detail: "nftables is active.", Status: "pass"})
	} else {
		out = append(out, SecurityAdvice{ID: "firewall", Severity: "critical", Title: "Firewall inactive", Detail: "nftables is installed/certified but not active.", Fix: "firewall-enable", Status: "action-required"})
	}
	if _, ok := commandExists("fail2ban-client"); ok && !serviceActiveV7(ctx, "fail2ban") {
		out = append(out, SecurityAdvice{ID: "fail2ban", Severity: "warning", Title: "Brute-force defense inactive", Detail: "fail2ban is installed but its service is not active.", Fix: "fail2ban-enable", Status: "action-required"})
	}
	if _, ok := commandExists("doveconf"); ok {
		if txt, err := a.run(ctx, "doveconf", "-n", "passdb", "userdb"); err == nil {
			low := strings.ToLower(txt)
			if !strings.Contains(low, "driver = passwd-file") || strings.Contains(low, "driver = pam") {
				out = append(out, SecurityAdvice{ID: "mail-auth", Severity: "critical", Title: "Virtual mail authentication drift", Detail: "Dovecot is not exclusively using Privora passwd-file authentication.", Fix: "mail-auth", Status: "action-required"})
			}
		}
	}
	if _, ok := commandExists("sshd"); ok {
		if txt, err := a.run(ctx, "sshd", "-T"); err == nil {
			low := strings.ToLower(txt)
			hasKey := hasAdministrativeSSHKeyV7()
			if strings.Contains(low, "passwordauthentication yes") {
				f := SecurityAdvice{ID: "ssh-password", Severity: "warning", Title: "SSH password authentication enabled", Detail: "Key-only SSH reduces brute-force exposure.", Status: "action-required"}
				if hasKey {
					f.Fix = "ssh-key-only"
				} else {
					f.Detail += " Add an administrative SSH key before disabling password authentication."
				}
				out = append(out, f)
			}
			if strings.Contains(low, "permitrootlogin yes") {
				f := SecurityAdvice{ID: "ssh-root", Severity: "critical", Title: "Direct SSH root login enabled", Detail: "Disable direct root SSH login after confirming an administrative key path.", Status: "action-required"}
				if hasKey {
					f.Fix = "ssh-disable-root"
				} else {
					f.Detail += " No administrative authorized_keys entry is currently available, so automatic repair is withheld."
				}
				out = append(out, f)
			}
		}
	}
	if st, err := os.Stat("/opt/privora-panel"); err == nil && st.Mode().Perm()&0001 == 0 {
		out = append(out, SecurityAdvice{ID: "panel-traverse", Severity: "critical", Title: "Panel root blocks Nginx traversal", Detail: "Nginx cannot traverse /opt/privora-panel.", Fix: "panel-permissions", Status: "action-required"})
	}
	return out
}
func hasAdministrativeSSHKeyV7() bool {
	paths := []string{"/root/.ssh/authorized_keys"}
	if entries, err := os.ReadDir("/home"); err == nil {
		for _, e := range entries {
			if e.IsDir() {
				paths = append(paths, filepath.Join("/home", e.Name(), ".ssh", "authorized_keys"))
			}
		}
	}
	for _, path := range paths {
		b, err := os.ReadFile(path)
		if err != nil {
			continue
		}
		for _, line := range strings.Split(string(b), "\n") {
			line = strings.TrimSpace(line)
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}
			if strings.Contains(line, "ssh-") || strings.Contains(line, "ecdsa-") || strings.Contains(line, "sk-") {
				return true
			}
		}
	}
	return false
}

func (a *Adapter) ApplySecurityFix(ctx context.Context, fix string) error {
	if !a.cfg.AllowMutations {
		return errors.New("host mutations disabled")
	}
	switch fix {
	case "panel-permissions":
		return a.RepairPanelPermissions(ctx)
	case "mail-auth":
		return a.ReconcileMailAuthentication(ctx)
	case "firewall-enable":
		if err := a.requireCertified("nftables"); err != nil {
			return err
		}
		if _, ok := commandExists("nft"); !ok {
			return errors.New("nftables is not installed")
		}
		_, err := a.run(ctx, "systemctl", "enable", "--now", "nftables")
		return err
	case "fail2ban-enable":
		if _, ok := commandExists("fail2ban-client"); !ok {
			return errors.New("fail2ban is not installed")
		}
		_, err := a.run(ctx, "systemctl", "enable", "--now", "fail2ban")
		return err
	case "ssh-key-only", "ssh-disable-root":
		if !hasAdministrativeSSHKeyV7() {
			return errors.New("refusing SSH lockout-risk change: no administrative authorized_keys entry was found")
		}
		if err := a.requireCertified("openssh-sftp"); err != nil {
			return err
		}
		dir := "/etc/ssh/sshd_config.d"
		if err := os.MkdirAll(dir, 0755); err != nil {
			return err
		}
		path := filepath.Join(dir, "99-privora-hardening.conf")
		old, _ := os.ReadFile(path)
		text := string(old)
		set := func(k, v string) {
			re := regexp.MustCompile(`(?mi)^\s*` + regexp.QuoteMeta(k) + `\s+.*$`)
			if re.MatchString(text) {
				text = re.ReplaceAllString(text, k+" "+v)
			} else {
				text += "\n" + k + " " + v + "\n"
			}
		}
		if fix == "ssh-key-only" {
			set("PasswordAuthentication", "no")
			set("KbdInteractiveAuthentication", "no")
		}
		if fix == "ssh-disable-root" {
			set("PermitRootLogin", "prohibit-password")
		}
		if err := AtomicWrite(path, []byte(text), 0644); err != nil {
			return err
		}
		if _, err := a.run(ctx, "sshd", "-t"); err != nil {
			if len(old) > 0 {
				_ = AtomicWrite(path, old, 0644)
			} else {
				_ = os.Remove(path)
			}
			return err
		}
		_, err := a.run(ctx, "systemctl", "reload", "ssh")
		if err != nil {
			_, err = a.run(ctx, "systemctl", "reload", "sshd")
		}
		return err
	default:
		return errors.New("unsupported security repair")
	}
}

func (a *Adapter) RepairPanelPermissions(ctx context.Context) error {
	if !a.cfg.AllowMutations {
		return errors.New("host mutations disabled")
	}
	if err := os.Chmod("/opt/privora-panel", 0755); err != nil {
		return err
	}
	version := "/opt/privora-panel/VERSION"
	if _, err := os.Stat(version); err == nil {
		gid := -1
		if out, e := exec.Command("getent", "group", "privora-panel").Output(); e == nil {
			f := strings.Split(strings.TrimSpace(string(out)), ":")
			if len(f) > 2 {
				gid, _ = strconv.Atoi(f[2])
			}
		}
		_ = os.Chown(version, 0, gid)
		_ = os.Chmod(version, 0640)
	}
	if _, err := a.run(ctx, "nginx", "-t"); err != nil {
		return err
	}
	_, err := a.run(ctx, "systemctl", "reload", "nginx")
	return err
}
