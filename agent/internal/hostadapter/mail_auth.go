package hostadapter

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// Privora virtual mailboxes are deliberately not Linux login accounts. Dovecot
// must authenticate full email addresses against the Privora passwd-file and
// must never silently fall back to PAM/system passwd for managed mailboxes.
func (a *Adapter) mailAuthGroupName() string {
	if strings.TrimSpace(a.cfg.MailAuthGroup) != "" {
		return strings.TrimSpace(a.cfg.MailAuthGroup)
	}
	return "privora-panel"
}

func (a *Adapter) mailAuthGroupGID() (int, error) {
	g, err := user.LookupGroup(a.mailAuthGroupName())
	if err != nil {
		if a.cfg.CertificationMode {
			return os.Getegid(), nil
		}
		return 0, fmt.Errorf("resolve Privora mail-auth group %s: %w", a.mailAuthGroupName(), err)
	}
	gid, err := strconv.Atoi(g.Gid)
	if err != nil {
		return 0, fmt.Errorf("parse Privora mail-auth group gid: %w", err)
	}
	return gid, nil
}

func (a *Adapter) secureMailAuthState(state string) error {
	gid, err := a.mailAuthGroupGID()
	if err != nil {
		return err
	}
	owner := os.Geteuid() // root in production; current test uid under certification.
	if err := os.MkdirAll(state, 0750); err != nil {
		return err
	}
	if err := os.Chown(state, owner, gid); err != nil {
		return fmt.Errorf("secure mail state owner: %w", err)
	}
	if err := os.Chmod(state, 0750); err != nil {
		return fmt.Errorf("secure mail state mode: %w", err)
	}
	for _, name := range []string{"dovecot_users", "virtual_mailboxes", "virtual_domains", "virtual_aliases"} {
		p := filepath.Join(state, name)
		if _, err := os.Stat(p); errors.Is(err, os.ErrNotExist) {
			if err := AtomicWrite(p, []byte(""), 0640); err != nil {
				return err
			}
		} else if err != nil {
			return err
		}
		if err := os.Chown(p, owner, gid); err != nil {
			return fmt.Errorf("secure %s owner: %w", p, err)
		}
		if err := os.Chmod(p, 0640); err != nil {
			return fmt.Errorf("secure %s mode: %w", p, err)
		}
	}
	return nil
}

func dovecotAuthPaths(dovecotCfg string) (authMain, authPrivora, authAccess string) {
	dir := filepath.Dir(dovecotCfg)
	return filepath.Join(dir, "10-auth.conf"), filepath.Join(dir, "auth-privora.conf.ext"), filepath.Join(dir, "99-privora-mail-auth-access.conf")
}

func renderPrivoraAuthInclude(state string) string {
	users := filepath.Join(state, "dovecot_users")
	return fmt.Sprintf(`# Privora-managed virtual mailbox authentication.
# Full-address logins are mandatory; do not replace with PAM/system passwd.
passdb {
  driver = passwd-file
  args = scheme=SHA512-CRYPT username_format=%%u %s
}
userdb {
  driver = passwd-file
  args = username_format=%%u %s
}
`, users, users)
}

func renderPrivoraAuthAccess(group string) string {
	return fmt.Sprintf(`# Privora-managed Dovecot authentication worker access.
# The password database remains root:%s 0640 and is never world-readable.
service auth {
  user = $default_internal_user
  group = %s
  unix_listener /var/spool/postfix/private/auth {
    mode = 0660
    user = postfix
    group = postfix
  }
}
service auth-worker {
  user = $default_internal_user
  group = %s
}
`, group, group, group)
}

func rewriteDovecotAuthSelection(in string) string {
	lines := strings.Split(in, "\n")
	out := make([]string, 0, len(lines)+2)
	privoraSeen := false
	for _, line := range lines {
		trim := strings.TrimSpace(line)
		if trim != "" && !strings.HasPrefix(trim, "#") {
			fields := strings.Fields(trim)
			if len(fields) >= 2 && (fields[0] == "!include" || fields[0] == "!include_try") {
				base := filepath.Base(fields[1])
				switch base {
				case "auth-system.conf.ext":
					out = append(out, "# Privora disabled system authentication: "+trim)
					continue
				case "auth-privora.conf.ext":
					if !privoraSeen {
						out = append(out, "!include auth-privora.conf.ext")
						privoraSeen = true
					}
					continue
				}
			}
		}
		out = append(out, line)
	}
	if !privoraSeen {
		out = append(out, "", "# Privora virtual mailbox authentication", "!include auth-privora.conf.ext")
	}
	return strings.TrimRight(strings.Join(out, "\n"), "\n") + "\n"
}

func validatePrivoraDovecotAuthSummary(summary string) error {
	lower := strings.ToLower(summary)
	if strings.Count(lower, "driver = passwd-file") < 2 {
		return errors.New("effective Dovecot passdb/userdb are not both passwd-file")
	}
	if strings.Contains(lower, "driver = pam") {
		return errors.New("effective Dovecot configuration still contains PAM passdb")
	}
	for _, line := range strings.Split(lower, "\n") {
		if strings.TrimSpace(line) == "driver = passwd" {
			return errors.New("effective Dovecot configuration still contains system passwd userdb")
		}
	}
	return nil
}

func (a *Adapter) ensurePrivoraDovecotAuthConfig(ctx context.Context) (func(), error) {
	state, _, dovecotCfg, _, _, _ := a.mailPaths()
	if err := a.secureMailAuthState(state); err != nil {
		return func() {}, err
	}
	authMain, authPrivora, authAccess := dovecotAuthPaths(dovecotCfg)
	mainOld, mainHad := readIfExists(authMain)
	privOld, privHad := readIfExists(authPrivora)
	accessOld, accessHad := readIfExists(authAccess)
	rollback := func() {
		restoreFile(authMain, mainOld, mainHad, 0644)
		restoreFile(authPrivora, privOld, privHad, 0644)
		restoreFile(authAccess, accessOld, accessHad, 0644)
	}
	if !mainHad {
		return rollback, fmt.Errorf("Dovecot auth selector missing: %s", authMain)
	}
	if err := AtomicWrite(authPrivora, []byte(renderPrivoraAuthInclude(state)), 0644); err != nil {
		rollback()
		return rollback, err
	}
	if err := AtomicWrite(authAccess, []byte(renderPrivoraAuthAccess(a.mailAuthGroupName())), 0644); err != nil {
		rollback()
		return rollback, err
	}
	if err := AtomicWrite(authMain, []byte(rewriteDovecotAuthSelection(string(mainOld))), 0644); err != nil {
		rollback()
		return rollback, err
	}
	summary, err := a.run(ctx, "doveconf", "-n", "passdb", "userdb")
	if err != nil {
		rollback()
		return rollback, fmt.Errorf("validate Dovecot virtual authentication: %w", err)
	}
	if err := validatePrivoraDovecotAuthSummary(summary); err != nil {
		rollback()
		return rollback, err
	}
	if _, err := a.run(ctx, "doveconf", "-n"); err != nil {
		rollback()
		return rollback, fmt.Errorf("validate Dovecot configuration: %w", err)
	}
	return rollback, nil
}

func (a *Adapter) postfixConfigSnapshot(ctx context.Context) (func(), error) {
	dir, err := a.run(ctx, "postconf", "-h", "config_directory")
	if err != nil {
		return func() {}, err
	}
	dir = strings.TrimSpace(dir)
	if dir == "" {
		dir = "/etc/postfix"
	}
	main := filepath.Join(dir, "main.cf")
	master := filepath.Join(dir, "master.cf")
	mainOld, mainHad := readIfExists(main)
	masterOld, masterHad := readIfExists(master)
	return func() {
		restoreFile(main, mainOld, mainHad, 0644)
		restoreFile(master, masterOld, masterHad, 0644)
	}, nil
}

func (a *Adapter) ensurePostfixDovecotSASL(ctx context.Context) error {
	params := map[string]string{
		"smtpd_sasl_type":             "dovecot",
		"smtpd_sasl_path":             "private/auth",
		"smtpd_sasl_auth_enable":      "yes",
		"smtpd_sasl_security_options": "noanonymous",
		"smtpd_tls_auth_only":         "yes",
		"smtpd_relay_restrictions":    "permit_mynetworks, permit_sasl_authenticated, reject_unauth_destination",
	}
	for k, v := range params {
		if _, err := a.run(ctx, "postconf", "-e", k+" = "+v); err != nil {
			return err
		}
	}
	masters := [][]string{
		{"-M", "submission/inet=submission inet n - y - - smtpd"},
		{"-P", "submission/inet/syslog_name=postfix/submission"},
		{"-P", "submission/inet/smtpd_tls_security_level=encrypt"},
		{"-P", "submission/inet/smtpd_sasl_auth_enable=yes"},
		{"-P", "submission/inet/smtpd_sasl_type=dovecot"},
		{"-P", "submission/inet/smtpd_sasl_path=private/auth"},
		{"-P", "submission/inet/smtpd_client_restrictions=permit_sasl_authenticated,reject"},
		{"-P", "submission/inet/smtpd_relay_restrictions=permit_sasl_authenticated,reject"},
		{"-M", "submissions/inet=submissions inet n - y - - smtpd"},
		{"-P", "submissions/inet/syslog_name=postfix/submissions"},
		{"-P", "submissions/inet/smtpd_tls_wrappermode=yes"},
		{"-P", "submissions/inet/smtpd_tls_security_level=encrypt"},
		{"-P", "submissions/inet/smtpd_sasl_auth_enable=yes"},
		{"-P", "submissions/inet/smtpd_sasl_type=dovecot"},
		{"-P", "submissions/inet/smtpd_sasl_path=private/auth"},
		{"-P", "submissions/inet/smtpd_client_restrictions=permit_sasl_authenticated,reject"},
		{"-P", "submissions/inet/smtpd_relay_restrictions=permit_sasl_authenticated,reject"},
	}
	for _, args := range masters {
		if _, err := a.run(ctx, "postconf", args...); err != nil {
			return err
		}
	}
	return nil
}

func (a *Adapter) validatePostfixDovecotSASL(ctx context.Context) error {
	for key, want := range map[string]string{"smtpd_sasl_type": "dovecot", "smtpd_sasl_path": "private/auth", "smtpd_sasl_auth_enable": "yes"} {
		got, err := a.run(ctx, "postconf", "-h", key)
		if err != nil || !strings.EqualFold(strings.TrimSpace(got), want) {
			return fmt.Errorf("Postfix %s is not %s", key, want)
		}
	}
	for _, key := range []string{"submission/inet/smtpd_sasl_auth_enable", "submissions/inet/smtpd_sasl_auth_enable"} {
		got, err := a.run(ctx, "postconf", "-P", key)
		if err != nil || !strings.Contains(strings.ToLower(got), "yes") {
			return fmt.Errorf("Postfix submission AUTH is not enabled for %s", key)
		}
	}
	return nil
}

func firstPrivoraMailbox(path string) string {
	b, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	for _, line := range strings.Split(string(b), "\n") {
		trim := strings.TrimSpace(line)
		if trim == "" || strings.HasPrefix(trim, "#") {
			continue
		}
		first := strings.Fields(trim)[0]
		name := strings.SplitN(first, ":", 2)[0]
		if validEmailAddress(name) {
			return name
		}
	}
	return ""
}

// ReconcileMailAuthentication is idempotent and is the authoritative repair path
// used after mailbox mutations and by mail-service reconciliation.
func (a *Adapter) ReconcileMailAuthentication(ctx context.Context) error {
	if !a.cfg.AllowMutations {
		return errors.New("host mutations disabled")
	}
	for _, cap := range []string{"postfix", "dovecot"} {
		if err := a.requireCertified(cap); err != nil {
			return err
		}
	}
	for _, cmd := range []string{"doveconf", "doveadm", "postconf", "postfix", "systemctl"} {
		if _, ok := commandExists(cmd); !ok {
			return fmt.Errorf("%s not installed", cmd)
		}
	}
	postfixRollback, err := a.postfixConfigSnapshot(ctx)
	if err != nil {
		return err
	}
	dovecotRollback, err := a.ensurePrivoraDovecotAuthConfig(ctx)
	if err != nil {
		return err
	}
	rollback := func() {
		dovecotRollback()
		postfixRollback()
		_, _ = a.run(context.Background(), "systemctl", "restart", "dovecot")
		_, _ = a.run(context.Background(), "systemctl", "restart", "postfix")
	}
	if err := a.ensurePostfixDovecotSASL(ctx); err != nil {
		rollback()
		return err
	}
	if err := a.validatePostfixDovecotSASL(ctx); err != nil {
		rollback()
		return err
	}
	if err := a.validatePostfixCheck(ctx); err != nil {
		rollback()
		return fmt.Errorf("validate Postfix mail authentication: %w", err)
	}
	for _, svc := range []string{"dovecot", "postfix"} {
		if _, err := a.run(ctx, "systemctl", "restart", svc); err != nil {
			rollback()
			return fmt.Errorf("restart %s after mail-auth reconcile: %w", svc, err)
		}
		if _, err := a.run(ctx, "systemctl", "is-active", "--quiet", svc); err != nil {
			rollback()
			return fmt.Errorf("%s is not active after mail-auth reconcile", svc)
		}
	}
	state, _, _, _, _, _ := a.mailPaths()
	if known := firstPrivoraMailbox(filepath.Join(state, "dovecot_users")); known != "" {
		if _, err := a.run(ctx, "doveadm", "user", known); err != nil {
			rollback()
			return fmt.Errorf("Dovecot cannot resolve managed mailbox %s after reconcile", known)
		}
	}
	return nil
}

// validatePostfixCheck runs Postfix's own configuration validator outside the
// long-running Agent sandbox. `postfix check` invokes postsuper, which must be
// able to perform Postfix-owned uid transitions. The Agent intentionally keeps
// NoNewPrivileges=true and RestrictSUIDSGID=true, so this one fixed operation is
// delegated to Privora's short-lived root maintenance unit instead of weakening
// the Agent service. Certification mode stays hermetic and uses the injected
// runner.
func (a *Adapter) validatePostfixCheck(ctx context.Context) error {
	if a.cfg.CertificationMode {
		_, err := a.run(ctx, "postfix", "check")
		return err
	}
	postfix, ok := commandExists("postfix")
	if !ok {
		return errors.New("postfix not installed")
	}
	_, err := runIsolatedRootCommand(ctx, "privora-postfix-check", 2*time.Minute, postfix, []string{"check"}, map[string]bool{})
	return err
}

// certifyMailboxPassword exercises the real Dovecot passdb without placing the
// plaintext password in argv or logs. doveadm prompts on stdin when password is omitted.
func (a *Adapter) certifyMailboxPassword(ctx context.Context, address, password string) error {
	if password == "" {
		return nil
	}
	out, err := a.runInput(ctx, password+"\n", "doveadm", "auth", "test", "-x", "service=imap", address)
	if err != nil || !strings.Contains(strings.ToLower(out), "auth succeeded") {
		return errors.New("Dovecot mailbox authentication certification failed")
	}
	return nil
}
