package hostadapter

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestParseRunuserInvocationRejectsRootAndFlags(t *testing.T) {
	userName, command, args, err := parseRunuserInvocation([]string{"-u", "postgres", "--", "psql", "-Atqc", "SELECT 1"})
	if err != nil {
		t.Fatal(err)
	}
	if userName != "postgres" || command != "psql" || len(args) != 2 || args[0] != "-Atqc" {
		t.Fatalf("unexpected parse: user=%q command=%q args=%v", userName, command, args)
	}
	if _, _, _, err := parseRunuserInvocation([]string{"-u", "root", "--", "id"}); err == nil {
		t.Fatal("root target must be rejected")
	}
	if _, _, _, err := parseRunuserInvocation([]string{"--shell", "/bin/sh", "postgres"}); err == nil {
		t.Fatal("arbitrary runuser flags must be rejected")
	}
}

func TestIsolatedUserCommandUsesTransientTargetUser(t *testing.T) {
	dir := t.TempDir()
	argsLog := filepath.Join(dir, "args.log")
	stdinLog := filepath.Join(dir, "stdin.log")
	systemdRun := filepath.Join(dir, "systemd-run")
	psql := filepath.Join(dir, "psql")
	if err := os.WriteFile(systemdRun, []byte("#!/bin/sh\nprintf '%s\\n' \"$@\" > \"$PRIVORA_TEST_ARGS\"\ncat > \"$PRIVORA_TEST_STDIN\"\nprintf ok\n"), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(psql, []byte("#!/bin/sh\nexit 0\n"), 0755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir+":"+os.Getenv("PATH"))
	t.Setenv("PRIVORA_TEST_ARGS", argsLog)
	t.Setenv("PRIVORA_TEST_STDIN", stdinLog)

	out, err := runIsolatedUserCommand(context.Background(), "privora-test-user", time.Second, "postgres", "psql", []string{"--no-psqlrc", "-Atqc", "SELECT 1"}, "secret-input\n", "")
	if err != nil {
		t.Fatal(err)
	}
	if strings.TrimSpace(out) != "ok" {
		t.Fatalf("unexpected output %q", out)
	}
	b, err := os.ReadFile(argsLog)
	if err != nil {
		t.Fatal(err)
	}
	got := string(b)
	for _, want := range []string{"--wait", "--collect", "--pipe", "--property=User=postgres", "--property=NoNewPrivileges=yes", psql, "--no-psqlrc", "-Atqc", "SELECT 1"} {
		if !strings.Contains(got, want) {
			t.Fatalf("systemd-run invocation missing %q:\n%s", want, got)
		}
	}
	in, err := os.ReadFile(stdinLog)
	if err != nil {
		t.Fatal(err)
	}
	if string(in) != "secret-input\n" {
		t.Fatalf("stdin was not preserved: %q", string(in))
	}
}

func TestPostfixQueueToolDelegatesAndValidates(t *testing.T) {
	dir := t.TempDir()
	argsLog := filepath.Join(dir, "args.log")
	stdinLog := filepath.Join(dir, "stdin.log")
	if err := os.WriteFile(filepath.Join(dir, "systemd-run"), []byte("#!/bin/sh\nprintf '%s\\n' \"$@\" > \"$PRIVORA_TEST_ARGS\"\ncat > \"$PRIVORA_TEST_STDIN\"\n"), 0755); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"postqueue", "postsuper"} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte("#!/bin/sh\nexit 0\n"), 0755); err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv("PATH", dir+":"+os.Getenv("PATH"))
	t.Setenv("PRIVORA_TEST_ARGS", argsLog)
	t.Setenv("PRIVORA_TEST_STDIN", stdinLog)
	a := &Adapter{cfg: Config{CommandTimeout: time.Second}}
	if _, err := a.runPostfixQueueTool(context.Background(), "postsuper", "-d", "ABCDEF1234"); err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(argsLog)
	got := string(b)
	if !strings.Contains(got, "--property=User=root") || !strings.Contains(got, "--property=NoNewPrivileges=no") || !strings.Contains(got, filepath.Join(dir, "postsuper")) {
		t.Fatalf("postsuper was not isolated correctly:\n%s", got)
	}
	if _, err := a.runPostfixQueueTool(context.Background(), "postsuper", "-d", "bad/id"); err == nil {
		t.Fatal("invalid queue id must fail closed")
	}
	if _, err := a.runPostfixQueueTool(context.Background(), "postqueue", "--arbitrary"); err == nil {
		t.Fatal("unsupported postqueue flag must fail closed")
	}
}
