package hostadapter

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func fakeClient(t *testing.T, name, body string) string {
	t.Helper()
	d := t.TempDir()
	p := filepath.Join(d, name)
	if err := os.WriteFile(p, []byte("#!/bin/sh\n"+body+"\n"), 0755); err != nil {
		t.Fatal(err)
	}
	return d
}
func TestMariaDBProvisionUsesStdinAndReturnsOneTimeSecret(t *testing.T) {
	d := fakeClient(t, "mariadb", `input=$(cat); case "$input" in SELECT*) exit 0;; *) echo "$input" > "`+filepath.Join(t.TempDir(), "sql")+`"; exit 0;; esac`)
	old := os.Getenv("PATH")
	t.Setenv("PATH", d+":"+old)
	a := New(Config{AllowMutations: true, CertificationMode: true})
	r, err := a.ProvisionMariaDB(context.Background(), "acct_app", "acct_user", "")
	if err != nil {
		t.Fatal(err)
	}
	if r.Status != "provisioned-real" || len(r.Password) != 32 {
		t.Fatalf("%+v", r)
	}
	if strings.ContainsAny(r.Password, "' ") {
		t.Fatal("unsafe generated password")
	}
}
func TestDatabaseProvisionRejectsInjection(t *testing.T) {
	a := New(Config{AllowMutations: true, CertificationMode: true})
	if _, err := a.ProvisionMariaDB(context.Background(), "bad;drop", "user", ""); err == nil {
		t.Fatal("unsafe identifier accepted")
	}
}
func TestPostgresProvisionWithFakeRunuser(t *testing.T) {
	dir := t.TempDir()
	psql := filepath.Join(dir, "psql")
	runuser := filepath.Join(dir, "runuser")
	os.WriteFile(psql, []byte("#!/bin/sh\ncat >/dev/null\nexit 0\n"), 0755)
	os.WriteFile(runuser, []byte("#!/bin/sh\nwhile [ \"$1\" != \"--\" ]; do shift; done; shift; exec \"$@\"\n"), 0755)
	t.Setenv("PATH", dir+":"+os.Getenv("PATH"))
	a := New(Config{AllowMutations: true, CertificationMode: true})
	r, err := a.ProvisionPostgreSQL(context.Background(), "acct_pg", "acct_pguser", "")
	if err != nil {
		t.Fatal(err)
	}
	if r.Engine != "postgresql" || len(r.Password) != 32 {
		t.Fatalf("%+v", r)
	}
}

func TestDatabaseProvisionAcceptsOperatorPassword(t *testing.T) {
	dir := t.TempDir()
	log := filepath.Join(dir, "sql.log")
	client := filepath.Join(dir, "mariadb")
	body := "#!/bin/sh\ninput=$(cat)\ncase \"$input\" in SELECT*) exit 0;; *) printf '%s' \"$input\" > \"" + log + "\"; exit 0;; esac\n"
	if err := os.WriteFile(client, []byte(body), 0755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir+":"+os.Getenv("PATH"))
	a := New(Config{AllowMutations: true, CertificationMode: true})
	want := "Chosen-Database-Pass-2026!"
	r, err := a.ProvisionMariaDB(context.Background(), "acct_manual", "acct_manual_user", want)
	if err != nil {
		t.Fatal(err)
	}
	if r.Password != want {
		t.Fatalf("password mismatch: %q", r.Password)
	}
	got, err := os.ReadFile(log)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(got), "IDENTIFIED BY '"+want+"'") {
		t.Fatalf("operator password not used: %s", got)
	}
}

func TestDatabasePasswordRejectsWeakOperatorSecret(t *testing.T) {
	a := New(Config{AllowMutations: true, CertificationMode: true})
	if _, err := a.ProvisionMariaDB(context.Background(), "acct_weak", "acct_weak_user", "short"); err == nil || !strings.Contains(err.Error(), "12-128") {
		t.Fatalf("weak password accepted: %v", err)
	}
}

func TestRenameMariaDBUserUsesNewPassword(t *testing.T) {
	dir := t.TempDir()
	log := filepath.Join(dir, "sql.log")
	client := filepath.Join(dir, "mariadb")
	body := "#!/bin/sh\ninput=$(cat)\ncase \"$input\" in SELECT*) exit 0;; *) printf '%s' \"$input\" > \"" + log + "\"; exit 0;; esac\n"
	if err := os.WriteFile(client, []byte(body), 0755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir+":"+os.Getenv("PATH"))
	a := New(Config{AllowMutations: true, CertificationMode: true})
	password, err := a.RenameDatabaseUser(context.Background(), "mariadb", "acct_db", "acct_old", "acct_new", "")
	if err != nil {
		t.Fatal(err)
	}
	if len(password) != 32 {
		t.Fatalf("expected generated replacement password, got %q", password)
	}
	got, err := os.ReadFile(log)
	if err != nil {
		t.Fatal(err)
	}
	text := string(got)
	if !strings.Contains(text, "RENAME USER 'acct_old'@'localhost' TO 'acct_new'@'localhost'") || !strings.Contains(text, "ALTER USER 'acct_new'@'localhost' IDENTIFIED BY") {
		t.Fatalf("rename SQL missing: %s", text)
	}
}
