package runner

import (
	"bytes"
	"context"
	"fmt"
	"os/exec"
	"sync"
)

type Runner interface {
	Run(ctx context.Context, name string, args ...string) (string, error)
}

type ExecRunner struct{}

func (ExecRunner) Run(ctx context.Context, name string, args ...string) (string, error) {
	cmd := exec.CommandContext(ctx, name, args...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	err := cmd.Run()
	if err != nil {
		return stdout.String(), fmt.Errorf("%w: %s", err, stderr.String())
	}
	return stdout.String(), nil
}

type MockRunner struct {
	mu     sync.Mutex
	States map[string]string
}

func NewMockRunner() *MockRunner {
	return &MockRunner{States: map[string]string{
		"nginx": "active", "php8.4-fpm": "active", "mariadb": "active", "redis-server": "inactive",
	}}
}

func (m *MockRunner) Run(_ context.Context, name string, args ...string) (string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if name != "systemctl" || len(args) < 2 {
		return "", fmt.Errorf("mock runner: unsupported command")
	}
	action, service := args[0], args[1]
	state := m.States[service]
	if state == "" {
		state = "inactive"
	}
	switch action {
	case "is-active":
		return state + "\n", nil
	case "start", "restart":
		m.States[service] = "active"
		return "", nil
	case "stop":
		m.States[service] = "inactive"
		return "", nil
	default:
		return "", fmt.Errorf("mock runner: unsupported systemctl action %q", action)
	}
}
