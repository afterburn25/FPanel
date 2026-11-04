package hostadapter

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"
)

var mailLocalRE = regexp.MustCompile(`^[a-z0-9][a-z0-9._+-]{0,63}$`)

type MailboxProvisionResult struct {
	Address  string `json:"address"`
	Domain   string `json:"domain"`
	Maildir  string `json:"maildir"`
	QuotaMB  int    `json:"quota_mb"`
	Password string `json:"password"` // returned once; never persist plaintext
	Status   string `json:"status"`
}

func (a *Adapter) ProvisionMailbox(ctx context.Context, address string, quotaMB int) (MailboxProvisionResult, error) {
	return a.provisionMailbox(ctx, address, quotaMB, "")
}

// ProvisionMailboxWithPassword provisions a mailbox using the operator-supplied secret.
// The plaintext password is used only for hashing and is never written to Privora state.
func (a *Adapter) ProvisionMailboxWithPassword(ctx context.Context, address string, quotaMB int, password string) (MailboxProvisionResult, error) {
	if err := validateMailboxPassword(password); err != nil {
		return MailboxProvisionResult{}, err
	}
	return a.provisionMailbox(ctx, address, quotaMB, password)
}

func (a *Adapter) provisionMailbox(ctx context.Context, address string, quotaMB int, password string) (MailboxProvisionResult, error) {
	if !a.cfg.AllowMutations {
		return MailboxProvisionResult{}, errors.New("host mutations disabled")
	}
	if err := a.requireCertified("postfix"); err != nil {
		return MailboxProvisionResult{}, err
	}
	if err := a.requireCertified("dovecot"); err != nil {
		return MailboxProvisionResult{}, err
	}
	address = strings.ToLower(strings.TrimSpace(address))
	parts := strings.Split(address, "@")
	if len(parts) != 2 || !mailLocalRE.MatchString(parts[0]) || !validDomain(parts[1]) {
		return MailboxProvisionResult{}, errors.New("invalid mailbox address")
	}
	if quotaMB <= 0 {
		quotaMB = 1024
	}
	if quotaMB > 102400 {
		return MailboxProvisionResult{}, errors.New("mailbox quota exceeds safety limit")
	}
	for _, cmd := range []string{"postmap", "openssl", "systemctl"} {
		if _, ok := commandExists(cmd); !ok {
			return MailboxProvisionResult{}, fmt.Errorf("%s not installed", cmd)
		}
	}
	uid, gid, err := a.EnsureMailFoundation(ctx)
	if err != nil {
		return MailboxProvisionResult{}, err
	}
	stateDir := a.cfg.MailStateDir
	if stateDir == "" {
		stateDir = "/etc/privora-mail"
	}
	mailRoot := a.cfg.MailRoot
	if mailRoot == "" {
		mailRoot = "/var/vmail"
	}
	if err := os.MkdirAll(stateDir, 0750); err != nil {
		return MailboxProvisionResult{}, err
	}
	domainsPath := filepath.Join(stateDir, "virtual_domains")
	mailboxesPath := filepath.Join(stateDir, "virtual_mailboxes")
	usersPath := filepath.Join(stateDir, "dovecot_users")
	oldDomains, domainsHad := readIfExists(domainsPath)
	oldMailboxes, mailboxesHad := readIfExists(mailboxesPath)
	oldUsers, usersHad := readIfExists(usersPath)
	if mapContainsKey(string(oldMailboxes), address) || mapContainsKey(string(oldUsers), address) {
		return MailboxProvisionResult{}, errors.New("mailbox already exists")
	}
	generatedPassword := password == ""
	if generatedPassword {
		password, err = randomPassword(32)
		if err != nil {
			return MailboxProvisionResult{}, err
		}
	} else if err := validateMailboxPassword(password); err != nil {
		return MailboxProvisionResult{}, err
	}
	hashOut, err := a.runInput(ctx, password+"\n", "openssl", "passwd", "-6", "-stdin")
	if err != nil {
		return MailboxProvisionResult{}, fmt.Errorf("hash mailbox password: %w", err)
	}
	hash := strings.TrimSpace(hashOut)
	if !strings.HasPrefix(hash, "$6$") {
		return MailboxProvisionResult{}, errors.New("unexpected password hash format")
	}
	local, domain := parts[0], parts[1]
	home := filepath.Join(mailRoot, domain, local)
	maildir := filepath.Join(home, "Maildir")
	if err := createMaildir(maildir, uid, gid); err != nil {
		return MailboxProvisionResult{}, err
	}
	createdHome := true
	rollback := func() {
		restoreFile(domainsPath, oldDomains, domainsHad, 0640)
		restoreFile(mailboxesPath, oldMailboxes, mailboxesHad, 0640)
		restoreFile(usersPath, oldUsers, usersHad, 0640)
		if domainsHad {
			_, _ = a.run(ctx, "postmap", domainsPath)
		}
		if mailboxesHad {
			_, _ = a.run(ctx, "postmap", mailboxesPath)
		}
		if createdHome {
			_ = os.RemoveAll(home)
		}
	}
	domains := upsertMapLine(string(oldDomains), domain, "OK")
	mailboxes := upsertMapLine(string(oldMailboxes), address, filepath.ToSlash(filepath.Join(domain, local, "Maildir"))+"/")
	dovecotLine := fmt.Sprintf("%s:{SHA512-CRYPT}%s:%d:%d::%s::userdb_mail=maildir:%s userdb_quota_rule=*:storage=%dM", address, hash, uid, gid, home, maildir, quotaMB)
	users := upsertPasswdLine(string(oldUsers), address, dovecotLine)
	if err := AtomicWrite(domainsPath, []byte(domains), 0640); err != nil {
		rollback()
		return MailboxProvisionResult{}, err
	}
	if err := AtomicWrite(mailboxesPath, []byte(mailboxes), 0640); err != nil {
		rollback()
		return MailboxProvisionResult{}, err
	}
	if err := AtomicWrite(usersPath, []byte(users), 0640); err != nil {
		rollback()
		return MailboxProvisionResult{}, err
	}
	if err := a.secureMailAuthState(stateDir); err != nil {
		rollback()
		return MailboxProvisionResult{}, err
	}
	if _, err := a.run(ctx, "postmap", domainsPath); err != nil {
		rollback()
		return MailboxProvisionResult{}, fmt.Errorf("compile virtual domains: %w", err)
	}
	if _, err := a.run(ctx, "postmap", mailboxesPath); err != nil {
		rollback()
		return MailboxProvisionResult{}, fmt.Errorf("compile virtual mailboxes: %w", err)
	}
	if err := a.ReconcileMailAuthentication(ctx); err != nil {
		rollback()
		return MailboxProvisionResult{}, fmt.Errorf("reconcile virtual-mail authentication: %w", err)
	}
	if err := a.certifyMailboxPassword(ctx, address, password); err != nil {
		rollback()
		return MailboxProvisionResult{}, err
	}
	createdHome = false
	returnedPassword := ""
	if generatedPassword {
		returnedPassword = password
	}
	return MailboxProvisionResult{Address: address, Domain: domain, Maildir: maildir, QuotaMB: quotaMB, Password: returnedPassword, Status: "provisioned-real"}, nil
}

func mapContainsKey(text, key string) bool {
	for _, line := range strings.Split(text, "\n") {
		trim := strings.TrimSpace(line)
		if trim == "" {
			continue
		}
		first := strings.Fields(trim)[0]
		if strings.SplitN(first, ":", 2)[0] == key {
			return true
		}
	}
	return false
}
func upsertMapLine(text, key, value string) string {
	lines := []string{}
	found := false
	for _, line := range strings.Split(text, "\n") {
		if strings.TrimSpace(line) == "" {
			continue
		}
		f := strings.Fields(line)
		if len(f) > 0 && f[0] == key {
			lines = append(lines, key+" "+value)
			found = true
		} else {
			lines = append(lines, line)
		}
	}
	if !found {
		lines = append(lines, key+" "+value)
	}
	return strings.Join(lines, "\n") + "\n"
}

func upsertPasswdLine(text, key, fullLine string) string {
	lines := []string{}
	found := false
	for _, line := range strings.Split(text, "\n") {
		trim := strings.TrimSpace(line)
		if trim == "" {
			continue
		}
		first := strings.Fields(trim)[0]
		if strings.SplitN(first, ":", 2)[0] == key {
			lines = append(lines, fullLine)
			found = true
		} else {
			lines = append(lines, line)
		}
	}
	if !found {
		lines = append(lines, fullLine)
	}
	return strings.Join(lines, "\n") + "\n"
}
func createMaildir(root string, uid, gid int) error {
	for _, p := range []string{root, filepath.Join(root, "cur"), filepath.Join(root, "new"), filepath.Join(root, "tmp")} {
		if err := os.MkdirAll(p, 0700); err != nil {
			return err
		}
		if err := os.Chown(p, uid, gid); err != nil {
			return err
		}
	}
	return nil
}

func validateMailboxPassword(password string) error {
	if len(password) < 12 {
		return errors.New("mailbox password must be at least 12 characters")
	}
	if len(password) > 128 {
		return errors.New("mailbox password exceeds 128 characters")
	}
	if strings.ContainsAny(password, "\x00\r\n") {
		return errors.New("mailbox password contains unsupported control characters")
	}
	return nil
}

var mailboxQuotaRuleRE = regexp.MustCompile(`userdb_quota_rule=\*:storage=[0-9]+M`)

// UpdateMailbox changes quota and optionally the password without renaming the
// mailbox or touching its Maildir. A blank password preserves the current hash.
func (a *Adapter) UpdateMailbox(ctx context.Context, address string, quotaMB int, password string) (MailboxProvisionResult, error) {
	if !a.cfg.AllowMutations {
		return MailboxProvisionResult{}, errors.New("host mutations disabled")
	}
	if err := a.requireCertified("dovecot"); err != nil {
		return MailboxProvisionResult{}, err
	}
	address = strings.ToLower(strings.TrimSpace(address))
	parts := strings.Split(address, "@")
	if len(parts) != 2 || !mailLocalRE.MatchString(parts[0]) || !validDomain(parts[1]) {
		return MailboxProvisionResult{}, errors.New("invalid mailbox address")
	}
	if quotaMB <= 0 {
		return MailboxProvisionResult{}, errors.New("mailbox quota must be greater than zero")
	}
	if quotaMB > 102400 {
		return MailboxProvisionResult{}, errors.New("mailbox quota exceeds safety limit")
	}
	if password != "" {
		if err := validateMailboxPassword(password); err != nil {
			return MailboxProvisionResult{}, err
		}
		if _, ok := commandExists("openssl"); !ok {
			return MailboxProvisionResult{}, errors.New("openssl not installed")
		}
	}
	if _, ok := commandExists("systemctl"); !ok {
		return MailboxProvisionResult{}, errors.New("systemctl not installed")
	}
	stateDir := a.cfg.MailStateDir
	if stateDir == "" {
		stateDir = "/etc/privora-mail"
	}
	usersPath := filepath.Join(stateDir, "dovecot_users")
	oldUsers, usersHad := readIfExists(usersPath)
	if !usersHad || !mapContainsKey(string(oldUsers), address) {
		return MailboxProvisionResult{}, errors.New("mailbox is not present in the Privora-managed authentication map")
	}
	lines := strings.Split(string(oldUsers), "\n")
	found := false
	for i, line := range lines {
		trim := strings.TrimSpace(line)
		if trim == "" {
			continue
		}
		first := strings.Fields(trim)[0]
		if strings.SplitN(first, ":", 2)[0] != address {
			continue
		}
		found = true
		updated := line
		if password != "" {
			hashOut, err := a.runInput(ctx, password+"\n", "openssl", "passwd", "-6", "-stdin")
			if err != nil {
				return MailboxProvisionResult{}, fmt.Errorf("hash mailbox password: %w", err)
			}
			hash := strings.TrimSpace(hashOut)
			if !strings.HasPrefix(hash, "$6$") {
				return MailboxProvisionResult{}, errors.New("unexpected password hash format")
			}
			fields := strings.SplitN(updated, ":", 3)
			if len(fields) != 3 {
				return MailboxProvisionResult{}, errors.New("managed mailbox authentication record is malformed")
			}
			updated = fields[0] + ":{SHA512-CRYPT}" + hash + ":" + fields[2]
		}
		quota := fmt.Sprintf("userdb_quota_rule=*:storage=%dM", quotaMB)
		if mailboxQuotaRuleRE.MatchString(updated) {
			updated = mailboxQuotaRuleRE.ReplaceAllString(updated, quota)
		} else {
			updated = strings.TrimRight(updated, " \t") + " " + quota
		}
		lines[i] = updated
		break
	}
	if !found {
		return MailboxProvisionResult{}, errors.New("managed mailbox authentication record not found")
	}
	next := strings.TrimRight(strings.Join(lines, "\n"), "\n") + "\n"
	if err := AtomicWrite(usersPath, []byte(next), 0640); err != nil {
		return MailboxProvisionResult{}, err
	}
	if err := a.secureMailAuthState(stateDir); err != nil {
		restoreFile(usersPath, oldUsers, usersHad, 0640)
		_ = a.secureMailAuthState(stateDir)
		return MailboxProvisionResult{}, err
	}
	rollback := func() {
		restoreFile(usersPath, oldUsers, usersHad, 0640)
		_, _ = a.run(ctx, "systemctl", "reload", "dovecot")
	}
	if err := a.ReconcileMailAuthentication(ctx); err != nil {
		rollback()
		return MailboxProvisionResult{}, fmt.Errorf("reconcile virtual-mail authentication: %w", err)
	}
	if password != "" {
		if err := a.certifyMailboxPassword(ctx, address, password); err != nil {
			rollback()
			return MailboxProvisionResult{}, err
		}
	}
	mailRoot := a.cfg.MailRoot
	if mailRoot == "" {
		mailRoot = "/var/vmail"
	}
	maildir := filepath.Join(mailRoot, parts[1], parts[0], "Maildir")
	return MailboxProvisionResult{Address: address, Domain: parts[1], Maildir: maildir, QuotaMB: quotaMB, Status: "provisioned-real"}, nil
}

// DeleteMailbox removes one Privora-managed virtual mailbox while preserving the
// domain-level mail route. The map files and Maildir are changed transactionally:
// configuration is rewritten/validated first and the Maildir is staged aside so
// it can be restored if Postfix/Dovecot reload fails.
func (a *Adapter) DeleteMailbox(ctx context.Context, address string) error {
	if !a.cfg.AllowMutations {
		return errors.New("host mutations disabled")
	}
	if err := a.requireCertified("postfix"); err != nil {
		return err
	}
	if err := a.requireCertified("dovecot"); err != nil {
		return err
	}
	address = strings.ToLower(strings.TrimSpace(address))
	parts := strings.Split(address, "@")
	if len(parts) != 2 || !mailLocalRE.MatchString(parts[0]) || !validDomain(parts[1]) {
		return errors.New("invalid mailbox address")
	}
	for _, cmd := range []string{"postmap", "systemctl"} {
		if _, ok := commandExists(cmd); !ok {
			return fmt.Errorf("%s not installed", cmd)
		}
	}
	stateDir := a.cfg.MailStateDir
	if stateDir == "" {
		stateDir = "/etc/privora-mail"
	}
	mailRoot := a.cfg.MailRoot
	if mailRoot == "" {
		mailRoot = "/var/vmail"
	}
	mailboxesPath := filepath.Join(stateDir, "virtual_mailboxes")
	usersPath := filepath.Join(stateDir, "dovecot_users")
	oldMailboxes, mailboxesHad := readIfExists(mailboxesPath)
	oldUsers, usersHad := readIfExists(usersPath)
	if !mapContainsKey(string(oldMailboxes), address) || !mapContainsKey(string(oldUsers), address) {
		return errors.New("mailbox is not present in the Privora-managed mail maps")
	}
	local, domain := parts[0], parts[1]
	home := filepath.Join(mailRoot, domain, local)
	rootClean := filepath.Clean(mailRoot)
	homeClean := filepath.Clean(home)
	rel, err := filepath.Rel(rootClean, homeClean)
	if err != nil || rel == "." || strings.HasPrefix(rel, ".."+string(os.PathSeparator)) || rel == ".." {
		return errors.New("refusing unsafe mailbox storage path")
	}
	quarantine := homeClean + ".privora-delete-" + strconv.FormatInt(time.Now().UTC().UnixNano(), 10)
	moved := false
	if _, err := os.Lstat(homeClean); err == nil {
		if err := os.Rename(homeClean, quarantine); err != nil {
			return fmt.Errorf("stage mailbox data for deletion: %w", err)
		}
		moved = true
	} else if !os.IsNotExist(err) {
		return fmt.Errorf("inspect mailbox storage: %w", err)
	}
	rollback := func() {
		restoreFile(mailboxesPath, oldMailboxes, mailboxesHad, 0640)
		restoreFile(usersPath, oldUsers, usersHad, 0640)
		if mailboxesHad {
			_, _ = a.run(ctx, "postmap", mailboxesPath)
		}
		if moved {
			_ = os.Rename(quarantine, homeClean)
		}
		_, _ = a.run(ctx, "systemctl", "reload", "postfix")
		_, _ = a.run(ctx, "systemctl", "reload", "dovecot")
	}
	mailboxes := removeMapLine(string(oldMailboxes), address)
	users := removeMapLine(string(oldUsers), address)
	if err := AtomicWrite(mailboxesPath, []byte(mailboxes), 0640); err != nil {
		rollback()
		return err
	}
	if err := AtomicWrite(usersPath, []byte(users), 0640); err != nil {
		rollback()
		return err
	}
	if err := a.secureMailAuthState(stateDir); err != nil {
		rollback()
		return err
	}
	if _, err := a.run(ctx, "postmap", mailboxesPath); err != nil {
		rollback()
		return fmt.Errorf("compile virtual mailboxes: %w", err)
	}
	if err := a.ReconcileMailAuthentication(ctx); err != nil {
		rollback()
		return fmt.Errorf("reconcile virtual-mail authentication: %w", err)
	}
	if moved {
		if err := os.RemoveAll(quarantine); err != nil {
			return fmt.Errorf("mailbox maps were removed but staged mailbox data cleanup failed: %w", err)
		}
	}
	return nil
}

func removeMapLine(text, key string) string {
	lines := []string{}
	for _, line := range strings.Split(text, "\n") {
		if strings.TrimSpace(line) == "" {
			continue
		}
		trim := strings.TrimSpace(line)
		first := strings.Fields(trim)[0]
		if strings.SplitN(first, ":", 2)[0] == key {
			continue
		}
		lines = append(lines, line)
	}
	if len(lines) == 0 {
		return ""
	}
	return strings.Join(lines, "\n") + "\n"
}
