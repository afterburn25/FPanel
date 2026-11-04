package hostadapter

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"regexp"
	"strings"
	"time"
)

var isolatedUnitPart = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{1,40}$`)

// runIsolatedRootCommand launches one typed Privora maintenance operation in a
// short-lived systemd unit. The long-running Agent deliberately keeps
// NoNewPrivileges=true and MemoryDenyWriteExecute=true; package managers and
// selected vendor CLIs that legitimately need uid transitions/JIT-capable
// runtimes are never granted those permissions inside the Agent itself.
//
// Callers must supply a fixed Privora-owned operation prefix, an absolute or
// LookPath-resolved executable, fixed/validated arguments, and an explicit
// environment allow-list. This helper is not exposed through the HTTP API.
func runIsolatedRootCommand(ctx context.Context, unitPrefix string, timeout time.Duration, command string, args []string, allowedEnv map[string]bool, extraEnv ...string) (string, error) {
	unitPrefix = strings.TrimSpace(strings.ToLower(unitPrefix))
	if !isolatedUnitPart.MatchString(unitPrefix) {
		return "", errors.New("invalid isolated operation identifier")
	}
	systemdRun, err := exec.LookPath("systemd-run")
	if err != nil {
		return "", errors.New("isolated privileged operation requires systemd-run")
	}
	if !strings.HasPrefix(command, "/") {
		command, err = exec.LookPath(command)
		if err != nil {
			return "", fmt.Errorf("isolated operation executable is unavailable: %w", err)
		}
	}
	if timeout <= 0 || timeout > 15*time.Minute {
		return "", errors.New("invalid isolated operation timeout")
	}
	runArgs := []string{
		"--wait", "--collect", "--pipe", "--quiet",
		"--unit=" + unitPrefix + "-" + fmt.Sprint(os.Getpid()) + "-" + fmt.Sprint(time.Now().UnixNano()),
		"--property=Type=exec",
		"--property=User=root",
		"--property=Group=root",
		"--property=NoNewPrivileges=no",
		"--property=MemoryDenyWriteExecute=no",
		"--property=UMask=0022",
		"--property=TimeoutStartSec=" + fmt.Sprintf("%ds", int(timeout.Seconds())),
	}
	for _, item := range extraEnv {
		kv := strings.SplitN(item, "=", 2)
		if len(kv) != 2 || !allowedEnv[kv[0]] {
			key := ""
			if len(kv) > 0 {
				key = strings.TrimSpace(kv[0])
			}
			return "", fmt.Errorf("unsupported isolated operation environment key: %s", key)
		}
		runArgs = append(runArgs, "--setenv="+item)
	}
	runArgs = append(runArgs, command)
	runArgs = append(runArgs, args...)

	cctx, cancel := context.WithTimeout(ctx, timeout+30*time.Second)
	defer cancel()
	cmd := exec.CommandContext(cctx, systemdRun, runArgs...)
	var out bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &out
	if err := cmd.Run(); err != nil {
		tail := out.String()
		if len(tail) > 7000 {
			tail = tail[len(tail)-7000:]
		}
		return tail, fmt.Errorf("isolated operation failed: %w: %s", err, strings.TrimSpace(tail))
	}
	return out.String(), nil
}

// parseRunuserInvocation recognizes the only runuser form Privora uses from
// the Agent. It deliberately does not accept arbitrary runuser flags, shells,
// or root as the target identity.
func parseRunuserInvocation(args []string) (string, string, []string, error) {
	if len(args) < 4 || args[0] != "-u" || args[2] != "--" {
		return "", "", nil, errors.New("unsupported runuser invocation")
	}
	userName := strings.TrimSpace(args[1])
	if !validUser(userName) || userName == "root" {
		return "", "", nil, errors.New("invalid isolated target user")
	}
	command := strings.TrimSpace(args[3])
	if command == "" {
		return "", "", nil, errors.New("missing isolated target command")
	}
	return userName, command, append([]string(nil), args[4:]...), nil
}

// runIsolatedUserIO asks PID 1 to create a short-lived service directly as the
// validated target account. This avoids setuid/setgid transitions inside the
// long-running Agent, whose RestrictSUIDSGID=true policy is intentionally kept
// intact. No shell is involved and the executable/arguments remain discrete.
func runIsolatedUserIO(ctx context.Context, unitPrefix string, timeout time.Duration, userName, command string, args []string, stdin io.Reader, stdout, stderr io.Writer, workingDir string) error {
	unitPrefix = strings.TrimSpace(strings.ToLower(unitPrefix))
	if !isolatedUnitPart.MatchString(unitPrefix) {
		return errors.New("invalid isolated operation identifier")
	}
	userName = strings.TrimSpace(userName)
	if !validUser(userName) || userName == "root" {
		return errors.New("invalid isolated target user")
	}
	systemdRun, err := exec.LookPath("systemd-run")
	if err != nil {
		return errors.New("isolated user operation requires systemd-run")
	}
	if !strings.HasPrefix(command, "/") {
		command, err = exec.LookPath(command)
		if err != nil {
			return fmt.Errorf("isolated user executable is unavailable: %w", err)
		}
	}
	if timeout <= 0 || timeout > 15*time.Minute {
		return errors.New("invalid isolated user operation timeout")
	}
	if workingDir != "" {
		if !strings.HasPrefix(workingDir, "/") || strings.ContainsRune(workingDir, '\x00') {
			return errors.New("invalid isolated working directory")
		}
	}
	runArgs := []string{
		"--wait", "--collect", "--pipe", "--quiet",
		"--unit=" + unitPrefix + "-" + fmt.Sprint(os.Getpid()) + "-" + fmt.Sprint(time.Now().UnixNano()),
		"--property=Type=exec",
		"--property=User=" + userName,
		"--property=NoNewPrivileges=yes",
		"--property=MemoryDenyWriteExecute=no",
		"--property=UMask=0022",
		"--property=TimeoutStartSec=" + fmt.Sprintf("%ds", int(timeout.Seconds())),
	}
	if workingDir != "" {
		runArgs = append(runArgs, "--working-directory="+workingDir)
	}
	runArgs = append(runArgs, command)
	runArgs = append(runArgs, args...)

	cctx, cancel := context.WithTimeout(ctx, timeout+30*time.Second)
	defer cancel()
	cmd := exec.CommandContext(cctx, systemdRun, runArgs...)
	cmd.Stdin = stdin
	cmd.Stdout = stdout
	cmd.Stderr = stderr
	return cmd.Run()
}

func runIsolatedUserCommand(ctx context.Context, unitPrefix string, timeout time.Duration, userName, command string, args []string, input, workingDir string) (string, error) {
	var out, stderr bytes.Buffer
	var stdin io.Reader
	if input != "" {
		stdin = strings.NewReader(input)
	}
	err := runIsolatedUserIO(ctx, unitPrefix, timeout, userName, command, args, stdin, &out, &stderr, workingDir)
	if err != nil {
		tail := stderr.String()
		if len(tail) > 7000 {
			tail = tail[len(tail)-7000:]
		}
		return out.String(), fmt.Errorf("isolated user operation failed: %w: %s", err, strings.TrimSpace(tail))
	}
	return out.String(), nil
}

// runAsSystemUserIO preserves the existing hermetic certification path while
// using a systemd transient user unit on production hosts.
func (a *Adapter) runAsSystemUserIO(ctx context.Context, timeout time.Duration, userName, command string, args []string, stdin io.Reader, stdout, stderr io.Writer, workingDir string) error {
	if !validUser(userName) || userName == "root" {
		return errors.New("invalid target user")
	}
	if a.cfg.CertificationMode {
		cctx, cancel := context.WithTimeout(ctx, timeout)
		defer cancel()
		runArgs := append([]string{"-u", userName, "--", command}, args...)
		cmd := exec.CommandContext(cctx, "runuser", runArgs...)
		cmd.Stdin = stdin
		cmd.Stdout = stdout
		cmd.Stderr = stderr
		cmd.Dir = workingDir
		return cmd.Run()
	}
	return runIsolatedUserIO(ctx, "privora-user-command", timeout, userName, command, args, stdin, stdout, stderr, workingDir)
}
