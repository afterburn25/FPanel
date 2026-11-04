package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"os/user"
	"path/filepath"
	"strconv"
	"syscall"
	"time"

	"privora.local/panel/agent/internal/api"
	"privora.local/panel/agent/internal/audit"
	"privora.local/panel/agent/internal/config"
	"privora.local/panel/agent/internal/runner"
)

func main() {
	var socketPath, socketGroup, auditPath, statePath, mockRoot, allowed, token, hostCertification, backupRoot, migrationInbox, migrationRoot, registrarProvider, registrarAdapterURL, registrarToken string
	var mock, hostMutations bool
	flag.StringVar(&socketPath, "socket", "/run/privora-panel/agent.sock", "Unix socket path")
	flag.StringVar(&socketGroup, "socket-group", "", "optional group owner for the Unix socket")
	flag.StringVar(&auditPath, "audit", "/var/log/privora-panel/audit.jsonl", "audit log path")
	flag.StringVar(&statePath, "state", "/var/lib/privora-panel/agent-state.json", "agent state path")
	flag.StringVar(&mockRoot, "mock-root", "/tmp/privora-panel-mock-root", "mock filesystem root")
	flag.StringVar(&allowed, "services", "", "comma-separated service allow-list")
	flag.StringVar(&token, "token", os.Getenv("PRIVORA_AGENT_TOKEN"), "panel-agent shared token")
	flag.BoolVar(&mock, "mock", false, "run without touching system services")
	flag.BoolVar(&hostMutations, "host-mutations", false, "enable certified real host mutations; ignored in mock mode")
	flag.StringVar(&hostCertification, "host-certification", "/var/lib/privora-panel/certifications/host-adapter-certification.json", "machine-bound host adapter certification evidence")
	flag.StringVar(&backupRoot, "backup-root", "/var/backups/privora-panel", "local backup destination root")
	flag.StringVar(&migrationInbox, "migration-inbox", "/var/lib/privora-panel/migration-inbox", "approved inbound backup directory")
	flag.StringVar(&migrationRoot, "migration-root", "/var/lib/privora-panel/migrations", "safe migration staging root")
	flag.StringVar(&registrarProvider, "registrar-provider", os.Getenv("PRIVORA_REGISTRAR_PROVIDER"), "registrar adapter provider label")
	flag.StringVar(&registrarAdapterURL, "registrar-adapter-url", os.Getenv("PRIVORA_REGISTRAR_ADAPTER_URL"), "Privora-compatible registrar adapter base URL")
	flag.StringVar(&registrarToken, "registrar-token", os.Getenv("PRIVORA_REGISTRAR_TOKEN"), "registrar adapter bearer token")
	flag.Parse()
	if token == "" {
		log.Fatal("agent token is required (--token or PRIVORA_AGENT_TOKEN)")
	}
	cfg := config.Config{SocketPath: socketPath, AuditPath: auditPath, StatePath: statePath, MockRoot: mockRoot, AgentToken: token, Mock: mock, HostMutations: hostMutations, HostCertificationPath: hostCertification, BackupRoot: backupRoot, MigrationInbox: migrationInbox, MigrationRoot: migrationRoot, RegistrarProvider: registrarProvider, RegistrarAdapterURL: registrarAdapterURL, RegistrarToken: registrarToken, AllowedServices: config.ParseAllowedServices(allowed)}
	var r runner.Runner = runner.ExecRunner{}
	if mock {
		r = runner.NewMockRunner()
	}
	for _, p := range []string{filepath.Dir(socketPath), filepath.Dir(auditPath), filepath.Dir(statePath), mockRoot} {
		if err := os.MkdirAll(p, 0750); err != nil {
			log.Fatal(err)
		}
	}
	_ = os.Remove(socketPath)
	ln, err := net.Listen("unix", socketPath)
	if err != nil {
		log.Fatal(err)
	}
	if socketGroup != "" {
		g, err := user.LookupGroup(socketGroup)
		if err != nil {
			log.Fatalf("lookup socket group %q: %v", socketGroup, err)
		}
		gid, err := strconv.Atoi(g.Gid)
		if err != nil {
			log.Fatalf("parse socket group %q gid: %v", socketGroup, err)
		}
		if err := os.Chown(socketPath, -1, gid); err != nil {
			log.Fatalf("set socket group %q: %v", socketGroup, err)
		}
	}
	if err := os.Chmod(socketPath, 0660); err != nil {
		log.Fatal(err)
	}
	agentServer := api.New(cfg, r, audit.New(auditPath))
	bgCtx, bgCancel := context.WithCancel(context.Background())
	defer bgCancel()
	agentServer.StartBackground(bgCtx)
	srv := &http.Server{Handler: agentServer.Handler(), ReadHeaderTimeout: 5 * time.Second}
	go func() {
		log.Printf("Privora Agent 5.0.0-dev.7.0 listening on unix://%s (mock=%v)", socketPath, mock)
		if err := srv.Serve(ln); err != nil && err != http.ErrServerClosed {
			log.Fatal(err)
		}
	}()
	ch := make(chan os.Signal, 1)
	signal.Notify(ch, syscall.SIGINT, syscall.SIGTERM)
	<-ch
	_ = srv.Close()
	fmt.Println("agent stopped")
}
