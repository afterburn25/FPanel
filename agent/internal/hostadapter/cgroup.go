package hostadapter

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
)

type CgroupLimitResult struct {
	Username   string `json:"username"`
	Path       string `json:"path"`
	CPUPercent int    `json:"cpu_percent"`
	MemoryMB   int    `json:"memory_mb"`
	PIDs       int    `json:"pids"`
	IOWeight   int    `json:"io_weight"`
	Applied    bool   `json:"applied"`
}

type cgroupBefore struct {
	path string
	data []byte
	had  bool
}

func readCgroupFile(path string) cgroupBefore {
	b, err := os.ReadFile(path)
	return cgroupBefore{path: path, data: b, had: err == nil}
}
func restoreCgroupFiles(items []cgroupBefore) {
	for i := len(items) - 1; i >= 0; i-- {
		x := items[i]
		if x.had {
			_ = os.WriteFile(x.path, x.data, 0644)
		} else {
			_ = os.Remove(x.path)
		}
	}
}

func (a *Adapter) ApplyCgroupV2Limits(username string, cpuPercent, memoryMB, pids, ioWeight int) (CgroupLimitResult, error) {
	if !a.cfg.AllowMutations {
		return CgroupLimitResult{}, errors.New("host mutations disabled")
	}
	if err := a.requireCertified("cgroup-v2"); err != nil {
		return CgroupLimitResult{}, err
	}
	if !validUser(username) {
		return CgroupLimitResult{}, errors.New("invalid username")
	}
	if cpuPercent < 1 || cpuPercent > 800 || memoryMB < 128 || memoryMB > 1048576 || pids < 16 || pids > 1048576 || ioWeight < 1 || ioWeight > 10000 {
		return CgroupLimitResult{}, errors.New("invalid cgroup limits")
	}
	root := a.cfg.CgroupRoot
	if root == "" {
		root = "/sys/fs/cgroup"
	}
	if _, err := os.Stat(filepath.Join(root, "cgroup.controllers")); err != nil {
		return CgroupLimitResult{}, errors.New("cgroup v2 hierarchy not available")
	}
	group := filepath.Join(root, "privora", username)
	cleanRoot := filepath.Clean(root) + string(os.PathSeparator)
	if !filepath.IsAbs(group) || !stringsHasPathPrefix(group, cleanRoot) {
		return CgroupLimitResult{}, errors.New("unsafe cgroup path")
	}
	if err := os.MkdirAll(group, 0755); err != nil {
		return CgroupLimitResult{}, fmt.Errorf("create cgroup: %w", err)
	}
	values := map[string]string{
		"cpu.max":    fmt.Sprintf("%d 100000\n", cpuPercent*1000),
		"memory.max": strconv.FormatInt(int64(memoryMB)*1024*1024, 10) + "\n",
		"pids.max":   strconv.Itoa(pids) + "\n",
		"io.weight":  strconv.Itoa(ioWeight) + "\n",
	}
	before := make([]cgroupBefore, 0, len(values))
	for name, value := range values {
		path := filepath.Join(group, name)
		before = append(before, readCgroupFile(path))
		if err := os.WriteFile(path, []byte(value), 0644); err != nil {
			restoreCgroupFiles(before)
			return CgroupLimitResult{}, fmt.Errorf("write %s: %w", name, err)
		}
	}
	return CgroupLimitResult{Username: username, Path: group, CPUPercent: cpuPercent, MemoryMB: memoryMB, PIDs: pids, IOWeight: ioWeight, Applied: true}, nil
}

func stringsHasPathPrefix(path, prefix string) bool {
	return len(path) >= len(prefix) && path[:len(prefix)] == prefix
}
