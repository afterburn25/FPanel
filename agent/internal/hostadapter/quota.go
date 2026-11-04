package hostadapter

import (
	"context"
	"errors"
	"fmt"
	"os/user"
	"strconv"
	"strings"
)

type DiskQuotaResult struct {
	Username   string `json:"username"`
	Filesystem string `json:"filesystem"`
	SoftBytes  uint64 `json:"soft_bytes"`
	HardBytes  uint64 `json:"hard_bytes"`
	Applied    bool   `json:"applied"`
}

func (a *Adapter) ApplyUserDiskQuota(ctx context.Context, username, filesystem string, softBytes, hardBytes uint64) (DiskQuotaResult, error) {
	if !a.cfg.AllowMutations {
		return DiskQuotaResult{}, errors.New("host mutations disabled")
	}
	if err := a.requireCertified("filesystem-quota"); err != nil {
		return DiskQuotaResult{}, err
	}
	if !validUser(username) {
		return DiskQuotaResult{}, errors.New("invalid username")
	}
	filesystem = strings.TrimSpace(filesystem)
	if filesystem == "" || !strings.HasPrefix(filesystem, "/") || strings.ContainsAny(filesystem, "\r\n\x00") {
		return DiskQuotaResult{}, errors.New("invalid quota filesystem")
	}
	if hardBytes == 0 || softBytes == 0 || softBytes > hardBytes {
		return DiskQuotaResult{}, errors.New("invalid quota limits")
	}
	if hardBytes > 100*1024*1024*1024*1024 {
		return DiskQuotaResult{}, errors.New("quota limit exceeds safety ceiling")
	}
	if _, err := user.Lookup(username); err != nil {
		return DiskQuotaResult{}, fmt.Errorf("hosting user does not exist: %w", err)
	}
	if _, ok := commandExists("setquota"); !ok {
		return DiskQuotaResult{}, errors.New("setquota not installed")
	}
	// setquota uses 1 KiB blocks for block soft/hard limits. Inode limits remain unlimited here.
	softKB := (softBytes + 1023) / 1024
	hardKB := (hardBytes + 1023) / 1024
	if _, err := a.run(ctx, "setquota", "-u", username, strconv.FormatUint(softKB, 10), strconv.FormatUint(hardKB, 10), "0", "0", filesystem); err != nil {
		return DiskQuotaResult{}, fmt.Errorf("apply disk quota: %w", err)
	}
	return DiskQuotaResult{Username: username, Filesystem: filesystem, SoftBytes: softBytes, HardBytes: hardBytes, Applied: true}, nil
}
