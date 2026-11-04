package hostadapter

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestConfigureRegistrarConnectionPersistsWithoutLeakingToken(t *testing.T) {
	bin := t.TempDir()
	if err := os.WriteFile(filepath.Join(bin, "systemd-run"), []byte("#!/bin/sh\nexit 0\n"), 0755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", bin+":"+os.Getenv("PATH"))
	root := t.TempDir()
	env := filepath.Join(root, "agent.env")
	if err := os.WriteFile(env, []byte("PRIVORA_AGENT_TOKEN=keep\nPRIVORA_REGISTRAR_PROVIDER=\nPRIVORA_REGISTRAR_ADAPTER_URL=\nPRIVORA_REGISTRAR_TOKEN=\n"), 0600); err != nil {
		t.Fatal(err)
	}
	a := New(Config{AllowMutations: true, AgentEnvPath: env})
	if err := a.ConfigureRegistrarConnection(context.Background(), RegistrarConnectionConfig{Provider: "Example Registrar", AdapterURL: "https://adapter.example.test", Token: "very-secret"}); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(env)
	if err != nil {
		t.Fatal(err)
	}
	text := string(b)
	for _, want := range []string{`PRIVORA_AGENT_TOKEN=keep`, `PRIVORA_REGISTRAR_PROVIDER="Example Registrar"`, `PRIVORA_REGISTRAR_ADAPTER_URL="https://adapter.example.test"`, `PRIVORA_REGISTRAR_TOKEN="very-secret"`} {
		if !strings.Contains(text, want) {
			t.Fatalf("missing %q in %s", want, text)
		}
	}
}
