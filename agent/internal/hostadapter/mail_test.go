package hostadapter

import (
	"context"
	"os"
	"os/user"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestMailboxControlledStack(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("unix helper test")
	}
	current, err := user.Current()
	if err != nil {
		t.Skip(err)
	}
	tmp := t.TempDir()
	bin := filepath.Join(tmp, "bin")
	_ = os.MkdirAll(bin, 0755)
	logPath := filepath.Join(tmp, "mail.log")
	openssl := `#!/bin/sh
printf '$6$privora$controlledhash\n'
`
	passthrough := `#!/bin/sh
printf '%s %s\n' "$(basename "$0")" "$*" >> "$MAIL_LOG"
exit 0
`
	postfixDir := filepath.Join(tmp, "postfix")
	if err := os.MkdirAll(postfixDir, 0755); err != nil {
		t.Fatal(err)
	}
	for _, f := range []string{"main.cf", "master.cf"} {
		if err := os.WriteFile(filepath.Join(postfixDir, f), []byte("# test\n"), 0644); err != nil {
			t.Fatal(err)
		}
	}
	dovecotDir := filepath.Join(tmp, "dovecot")
	if err := os.MkdirAll(dovecotDir, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dovecotDir, "10-auth.conf"), []byte("!include auth-system.conf.ext\n"), 0644); err != nil {
		t.Fatal(err)
	}
	postconf := `#!/bin/sh
if [ "$1" = "-h" ] && [ "$2" = "config_directory" ]; then printf '%s\n' "$POSTFIX_DIR"; exit 0; fi
if [ "$1" = "-h" ] && [ "$2" = "smtpd_sasl_type" ]; then echo dovecot; exit 0; fi
if [ "$1" = "-h" ] && [ "$2" = "smtpd_sasl_path" ]; then echo private/auth; exit 0; fi
if [ "$1" = "-h" ] && [ "$2" = "smtpd_sasl_auth_enable" ]; then echo yes; exit 0; fi
if [ "$1" = "-P" ] && [ "$#" -eq 2 ]; then echo "$2=yes"; exit 0; fi
exit 0
`
	doveconf := `#!/bin/sh
if [ "$1" = "-n" ] && [ "$2" = "passdb" ]; then cat <<'EOF'
passdb {
  driver = passwd-file
}
userdb {
  driver = passwd-file
}
EOF
fi
exit 0
`
	doveadm := `#!/bin/sh
if [ "$1" = "auth" ] && [ "$2" = "test" ]; then cat >/dev/null; echo "passdb: admin@example.test auth succeeded"; exit 0; fi
if [ "$1" = "user" ]; then echo "uid=1000 gid=1000 home=/mail mail=maildir:/mail/Maildir"; exit 0; fi
exit 0
`
	for name, body := range map[string]string{"openssl": openssl, "postmap": passthrough, "systemctl": passthrough, "postfix": passthrough, "postconf": postconf, "doveconf": doveconf, "doveadm": doveadm} {
		if err := os.WriteFile(filepath.Join(bin, name), []byte(body), 0755); err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv("MAIL_LOG", logPath)
	t.Setenv("POSTFIX_DIR", postfixDir)
	t.Setenv("PATH", bin+":"+os.Getenv("PATH"))
	a := New(Config{AllowMutations: true, CertificationMode: true, MailUser: current.Username, MailStateDir: filepath.Join(tmp, "etc"), MailRoot: filepath.Join(tmp, "mail"), DovecotPrivoraConfig: filepath.Join(dovecotDir, "99-privora-mail.conf")})
	got, err := a.ProvisionMailbox(context.Background(), "Admin@example.test", 2048)
	if err != nil {
		t.Fatal(err)
	}
	if got.Address != "admin@example.test" || got.Password == "" || got.QuotaMB != 2048 {
		t.Fatalf("unexpected result %+v", got)
	}
	b, err := os.ReadFile(filepath.Join(tmp, "etc", "virtual_mailboxes"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(b), "admin@example.test example.test/admin/Maildir/") {
		t.Fatalf("bad map: %s", b)
	}
	if _, err := os.Stat(filepath.Join(tmp, "mail", "example.test", "admin", "Maildir", "new")); err != nil {
		t.Fatal(err)
	}
}
func TestMailboxRejectsUnsafeAddress(t *testing.T) {
	a := New(Config{AllowMutations: true, CertificationMode: true})
	if _, err := a.ProvisionMailbox(context.Background(), "bad/box@example.test", 100); err == nil {
		t.Fatal("expected rejection")
	}
}

func TestDeleteMailboxControlledStack(t *testing.T) {
	tmp := t.TempDir()
	stateDir := filepath.Join(tmp, "etc", "mail")
	mailRoot := filepath.Join(tmp, "vmail")
	if err := os.MkdirAll(stateDir, 0750); err != nil {
		t.Fatal(err)
	}
	address := "admin@example.test"
	if err := os.WriteFile(filepath.Join(stateDir, "virtual_mailboxes"), []byte(address+" example.test/admin/Maildir/\n"), 0640); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(stateDir, "dovecot_users"), []byte(address+" {SHA512-CRYPT}$6$x:y\n"), 0640); err != nil {
		t.Fatal(err)
	}
	home := filepath.Join(mailRoot, "example.test", "admin")
	if err := os.MkdirAll(filepath.Join(home, "Maildir"), 0700); err != nil {
		t.Fatal(err)
	}
	bin := filepath.Join(tmp, "bin")
	if err := os.MkdirAll(bin, 0755); err != nil {
		t.Fatal(err)
	}
	postfixDir := filepath.Join(tmp, "postfix")
	if err := os.MkdirAll(postfixDir, 0755); err != nil {
		t.Fatal(err)
	}
	for _, f := range []string{"main.cf", "master.cf"} {
		if err := os.WriteFile(filepath.Join(postfixDir, f), []byte("# test\n"), 0644); err != nil {
			t.Fatal(err)
		}
	}
	dovecotDir := filepath.Join(tmp, "dovecot")
	if err := os.MkdirAll(dovecotDir, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dovecotDir, "10-auth.conf"), []byte("!include auth-system.conf.ext\n"), 0644); err != nil {
		t.Fatal(err)
	}
	postconf := `#!/bin/sh
if [ "$1" = "-h" ] && [ "$2" = "config_directory" ]; then echo "$POSTFIX_DIR"; exit 0; fi
if [ "$1" = "-h" ] && [ "$2" = "smtpd_sasl_type" ]; then echo dovecot; exit 0; fi
if [ "$1" = "-h" ] && [ "$2" = "smtpd_sasl_path" ]; then echo private/auth; exit 0; fi
if [ "$1" = "-h" ] && [ "$2" = "smtpd_sasl_auth_enable" ]; then echo yes; exit 0; fi
if [ "$1" = "-P" ] && [ "$#" -eq 2 ]; then echo "$2=yes"; exit 0; fi
exit 0
`
	doveconf := `#!/bin/sh
if [ "$1" = "-n" ] && [ "$2" = "passdb" ]; then printf 'passdb {\n driver = passwd-file\n}\nuserdb {\n driver = passwd-file\n}\n'; fi
exit 0
`
	for name, body := range map[string]string{"postmap": "#!/bin/sh\nexit 0\n", "systemctl": "#!/bin/sh\nexit 0\n", "postfix": "#!/bin/sh\nexit 0\n", "postconf": postconf, "doveconf": doveconf, "doveadm": "#!/bin/sh\nexit 0\n"} {
		if err := os.WriteFile(filepath.Join(bin, name), []byte(body), 0755); err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv("POSTFIX_DIR", postfixDir)
	t.Setenv("PATH", bin+":"+os.Getenv("PATH"))
	a := New(Config{AllowMutations: true, CertificationMode: true, MailStateDir: stateDir, MailRoot: mailRoot, DovecotPrivoraConfig: filepath.Join(dovecotDir, "99-privora-mail.conf")})
	if err := a.DeleteMailbox(context.Background(), address); err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(filepath.Join(stateDir, "virtual_mailboxes"))
	if strings.Contains(string(b), address) {
		t.Fatalf("mailbox remained in map: %s", b)
	}
	b, _ = os.ReadFile(filepath.Join(stateDir, "dovecot_users"))
	if strings.Contains(string(b), address) {
		t.Fatalf("mailbox remained in users: %s", b)
	}
	if _, err := os.Stat(home); !os.IsNotExist(err) {
		t.Fatalf("mailbox home still exists: %v", err)
	}
}
