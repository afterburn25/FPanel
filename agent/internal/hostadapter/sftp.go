package hostadapter

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/user"
	"path/filepath"
	"strings"
	"syscall"
)

type SFTPProvisionResult struct {
	Username string `json:"username"`
	Root     string `json:"root"`
	Auth     string `json:"auth"`
	Password string `json:"password"` // returned once
	Status   string `json:"status"`
}

func (a *Adapter) EnableAccountSFTPPassword(ctx context.Context, username string) (SFTPProvisionResult, error) {
	if !a.cfg.AllowMutations {
		return SFTPProvisionResult{}, errors.New("host mutations disabled")
	}
	if err := a.requireCertified("openssh-sftp"); err != nil {
		return SFTPProvisionResult{}, err
	}
	if !validUser(username) {
		return SFTPProvisionResult{}, errors.New("invalid username")
	}
	for _, cmd := range []string{"groupadd", "usermod", "sshd", "systemctl", "openssl"} {
		if _, ok := commandExists(cmd); !ok {
			return SFTPProvisionResult{}, fmt.Errorf("%s not installed", cmd)
		}
	}
	if _, err := user.Lookup(username); err != nil {
		return SFTPProvisionResult{}, errors.New("hosting user does not exist")
	}
	home := filepath.Join(a.cfg.AccountHomeBase, username)
	st, err := os.Stat(home)
	if err != nil {
		return SFTPProvisionResult{}, err
	}
	sys, ok := st.Sys().(*syscall.Stat_t)
	if !ok || sys.Uid != 0 {
		return SFTPProvisionResult{}, errors.New("SFTP chroot home must be root-owned")
	}
	if st.Mode().Perm()&0022 != 0 {
		return SFTPProvisionResult{}, errors.New("SFTP chroot home must not be group/world writable")
	}
	group := a.cfg.SFTPGroup
	if group == "" {
		group = "privora-sftp"
	}
	cfgPath := a.cfg.SSHDConfigPath
	if cfgPath == "" {
		cfgPath = "/etc/ssh/sshd_config.d/90-privora-sftp.conf"
	}
	oldCfg, cfgHad := readIfExists(cfgPath)
	snippet := fmt.Sprintf(`# Managed by Privora Panel. Do not edit by hand.
Match Group %s
    ChrootDirectory %s/%%u
    ForceCommand internal-sftp -d /domains
    PasswordAuthentication yes
    AllowTcpForwarding no
    X11Forwarding no
    PermitTunnel no
`, group, filepath.Clean(a.cfg.AccountHomeBase))
	if _, err := a.run(ctx, "groupadd", "--force", group); err != nil {
		return SFTPProvisionResult{}, err
	}
	if _, err := a.run(ctx, "usermod", "-a", "-G", group, username); err != nil {
		return SFTPProvisionResult{}, err
	}
	if err := os.MkdirAll(filepath.Dir(cfgPath), 0755); err != nil {
		return SFTPProvisionResult{}, err
	}
	if err := AtomicWrite(cfgPath, []byte(snippet), 0644); err != nil {
		return SFTPProvisionResult{}, err
	}
	rollbackCfg := func() { restoreFile(cfgPath, oldCfg, cfgHad, 0644) }
	if _, err := a.run(ctx, "sshd", "-t"); err != nil {
		rollbackCfg()
		return SFTPProvisionResult{}, fmt.Errorf("sshd validation failed; rolled back: %w", err)
	}
	password, err := randomPassword(32)
	if err != nil {
		rollbackCfg()
		return SFTPProvisionResult{}, err
	}
	hashOut, err := a.runInput(ctx, password+"\n", "openssl", "passwd", "-6", "-stdin")
	if err != nil {
		rollbackCfg()
		return SFTPProvisionResult{}, err
	}
	hash := strings.TrimSpace(hashOut)
	if !strings.HasPrefix(hash, "$6$") {
		rollbackCfg()
		return SFTPProvisionResult{}, errors.New("unexpected password hash format")
	}
	if _, err := a.run(ctx, "usermod", "--password", hash, username); err != nil {
		rollbackCfg()
		return SFTPProvisionResult{}, err
	}
	if _, err := a.run(ctx, "systemctl", "reload", "ssh"); err != nil {
		rollbackCfg()
		return SFTPProvisionResult{}, fmt.Errorf("SSH reload failed; config rolled back: %w", err)
	}
	return SFTPProvisionResult{Username: username, Root: home, Auth: "password", Password: password, Status: "provisioned-real"}, nil
}
