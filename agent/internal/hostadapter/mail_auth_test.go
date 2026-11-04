package hostadapter

import (
	"context"
	"os"
	"os/user"
	"path/filepath"
	"strings"
	"testing"
)

func TestRewriteDovecotAuthSelectionDisablesSystemBackend(t *testing.T) {
	in := `disable_plaintext_auth = yes
!include auth-system.conf.ext
#!include auth-sql.conf.ext
`
	out := rewriteDovecotAuthSelection(in)
	if strings.Contains(out, "\n!include auth-system.conf.ext\n") {
		t.Fatal("system authentication include remained active")
	}
	if strings.Count(out, "!include auth-privora.conf.ext") != 1 {
		t.Fatalf("Privora auth include not installed exactly once: %s", out)
	}
	out2 := rewriteDovecotAuthSelection(out)
	if out2 != out {
		t.Fatal("Dovecot auth selection rewrite is not idempotent")
	}
}

func TestValidatePrivoraDovecotAuthSummaryRejectsSystemBackends(t *testing.T) {
	good := "passdb {\n driver = passwd-file\n}\nuserdb {\n driver = passwd-file\n}\n"
	if err := validatePrivoraDovecotAuthSummary(good); err != nil {
		t.Fatal(err)
	}
	if err := validatePrivoraDovecotAuthSummary(good + "passdb {\n driver = pam\n}\n"); err == nil {
		t.Fatal("PAM backend was not rejected")
	}
	if err := validatePrivoraDovecotAuthSummary(good + "userdb {\n driver = passwd\n}\n"); err == nil {
		t.Fatal("system passwd backend was not rejected")
	}
}

func TestMailboxPasswordResetReconcilesVirtualAuthAndKeepsSecretOutOfArgv(t *testing.T) {
	current, err := user.Current()
	if err != nil {
		t.Skip(err)
	}
	tmp := t.TempDir()
	bin := filepath.Join(tmp, "bin")
	state := filepath.Join(tmp, "etc", "privora-mail")
	mailRoot := filepath.Join(tmp, "vmail")
	dovecotDir := filepath.Join(tmp, "dovecot")
	postfixDir := filepath.Join(tmp, "postfix")
	for _, d := range []string{bin, dovecotDir, postfixDir} {
		if err := os.MkdirAll(d, 0755); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(dovecotDir, "10-auth.conf"), []byte("!include auth-system.conf.ext\n"), 0644); err != nil {
		t.Fatal(err)
	}
	for _, f := range []string{"main.cf", "master.cf"} {
		if err := os.WriteFile(filepath.Join(postfixDir, f), []byte("# test\n"), 0644); err != nil {
			t.Fatal(err)
		}
	}
	argvLog := filepath.Join(tmp, "doveadm-argv.log")
	openssl := `#!/bin/sh
read p
case "$p" in
  FirstPassword123!) echo '$6$first$hash1' ;;
  SecondPassword456!) echo '$6$second$hash2' ;;
  *) echo '$6$other$hash3' ;;
esac
`
	postconf := `#!/bin/sh
if [ "$1" = "-h" ] && [ "$2" = "config_directory" ]; then echo "$POSTFIX_DIR"; exit 0; fi
if [ "$1" = "-h" ] && [ "$2" = "smtpd_sasl_type" ]; then echo dovecot; exit 0; fi
if [ "$1" = "-h" ] && [ "$2" = "smtpd_sasl_path" ]; then echo private/auth; exit 0; fi
if [ "$1" = "-h" ] && [ "$2" = "smtpd_sasl_auth_enable" ]; then echo yes; exit 0; fi
if [ "$1" = "-P" ] && [ "$#" -eq 2 ]; then echo "$2=yes"; exit 0; fi
exit 0
`
	doveconf := `#!/bin/sh
if [ "$1" = "-n" ] && [ "$2" = "passdb" ]; then cat <<'OUT'
passdb {
 driver = passwd-file
}
userdb {
 driver = passwd-file
}
OUT
fi
exit 0
`
	doveadm := `#!/bin/sh
printf '%s\n' "$*" >> "$DOVEADM_ARGV_LOG"
if [ "$1" = "auth" ] && [ "$2" = "test" ]; then
  IFS= read -r secret
  [ -n "$secret" ] || exit 2
  echo "passdb: admin@example.test auth succeeded"
  exit 0
fi
if [ "$1" = "user" ]; then
  echo 'uid=997 gid=987 home=/var/vmail/example.test/admin mail=maildir:/var/vmail/example.test/admin/Maildir quota_rule=*:storage=2048M'
  exit 0
fi
exit 0
`
	for name, body := range map[string]string{
		"openssl": openssl, "postconf": postconf, "doveconf": doveconf, "doveadm": doveadm,
		"postmap": "#!/bin/sh\nexit 0\n", "postfix": "#!/bin/sh\nexit 0\n", "systemctl": "#!/bin/sh\nexit 0\n",
	} {
		if err := os.WriteFile(filepath.Join(bin, name), []byte(body), 0755); err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv("POSTFIX_DIR", postfixDir)
	t.Setenv("DOVEADM_ARGV_LOG", argvLog)
	t.Setenv("PATH", bin+":"+os.Getenv("PATH"))
	a := New(Config{AllowMutations: true, CertificationMode: true, MailUser: current.Username, MailStateDir: state, MailRoot: mailRoot, DovecotPrivoraConfig: filepath.Join(dovecotDir, "99-privora-mail.conf")})
	if _, err := a.ProvisionMailboxWithPassword(context.Background(), "admin@example.test", 2048, "FirstPassword123!"); err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadFile(filepath.Join(state, "dovecot_users"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := a.UpdateMailbox(context.Background(), "admin@example.test", 4096, "SecondPassword456!"); err != nil {
		t.Fatal(err)
	}
	after, err := os.ReadFile(filepath.Join(state, "dovecot_users"))
	if err != nil {
		t.Fatal(err)
	}
	if string(before) == string(after) || !strings.Contains(string(after), "$6$second$hash2") {
		t.Fatalf("password hash was not replaced safely: %s", after)
	}
	if !strings.Contains(string(after), "userdb_mail=maildir:") || !strings.Contains(string(after), "userdb_quota_rule=*:storage=4096M") {
		t.Fatalf("Maildir/quota fields were not preserved: %s", after)
	}
	info, err := os.Stat(filepath.Join(state, "dovecot_users"))
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0640 {
		t.Fatalf("dovecot_users mode is %o, want 0640", info.Mode().Perm())
	}
	argv, _ := os.ReadFile(argvLog)
	if strings.Contains(string(argv), "FirstPassword123!") || strings.Contains(string(argv), "SecondPassword456!") {
		t.Fatal("plaintext mailbox password leaked into doveadm argv")
	}
	main, _ := os.ReadFile(filepath.Join(dovecotDir, "10-auth.conf"))
	if strings.Contains(string(main), "\n!include auth-system.conf.ext\n") || !strings.Contains(string(main), "!include auth-privora.conf.ext") {
		t.Fatalf("effective Dovecot auth selection is wrong: %s", main)
	}
}
