package systeminfo

import (
	"bufio"
	"os"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"time"
)

type Info struct {
	Hostname       string    `json:"hostname"`
	OS             string    `json:"os"`
	Architecture   string    `json:"architecture"`
	CPUCores       int       `json:"cpu_cores"`
	MemoryTotalMB  uint64    `json:"memory_total_mb"`
	MemoryFreeMB   uint64    `json:"memory_free_mb"`
	DiskTotalGB    float64   `json:"disk_total_gb"`
	DiskFreeGB     float64   `json:"disk_free_gb"`
	Load1          float64   `json:"load_1"`
	Load5          float64   `json:"load_5"`
	Load15         float64   `json:"load_15"`
	UptimeSeconds  uint64    `json:"uptime_seconds"`
	NetworkRxBytes uint64    `json:"network_rx_bytes"`
	NetworkTxBytes uint64    `json:"network_tx_bytes"`
	CollectedAt    time.Time `json:"collected_at"`
}

func Read() Info {
	hostname, _ := os.Hostname()
	info := Info{Hostname: hostname, OS: runtime.GOOS, Architecture: runtime.GOARCH, CPUCores: runtime.NumCPU(), CollectedAt: time.Now().UTC()}
	info.MemoryTotalMB, info.MemoryFreeMB = readMemInfo()
	var stat syscall.Statfs_t
	if syscall.Statfs("/", &stat) == nil {
		info.DiskTotalGB = float64(stat.Blocks*uint64(stat.Bsize)) / (1024 * 1024 * 1024)
		info.DiskFreeGB = float64(stat.Bavail*uint64(stat.Bsize)) / (1024 * 1024 * 1024)
	}
	info.Load1, info.Load5, info.Load15 = readLoad()
	info.UptimeSeconds = readUptime()
	info.NetworkRxBytes, info.NetworkTxBytes = readNetwork()
	return info
}

func readMemInfo() (uint64, uint64) {
	f, err := os.Open("/proc/meminfo")
	if err != nil {
		return 0, 0
	}
	defer f.Close()
	var total, available uint64
	s := bufio.NewScanner(f)
	for s.Scan() {
		fields := strings.Fields(s.Text())
		if len(fields) < 2 {
			continue
		}
		v, _ := strconv.ParseUint(fields[1], 10, 64)
		switch fields[0] {
		case "MemTotal:":
			total = v / 1024
		case "MemAvailable:":
			available = v / 1024
		}
	}
	return total, available
}

func readLoad() (float64, float64, float64) {
	b, err := os.ReadFile("/proc/loadavg")
	if err != nil {
		return 0, 0, 0
	}
	f := strings.Fields(string(b))
	if len(f) < 3 {
		return 0, 0, 0
	}
	a, _ := strconv.ParseFloat(f[0], 64)
	c, _ := strconv.ParseFloat(f[1], 64)
	d, _ := strconv.ParseFloat(f[2], 64)
	return a, c, d
}
func readUptime() uint64 {
	b, err := os.ReadFile("/proc/uptime")
	if err != nil {
		return 0
	}
	f := strings.Fields(string(b))
	if len(f) == 0 {
		return 0
	}
	v, _ := strconv.ParseFloat(f[0], 64)
	return uint64(v)
}
func readNetwork() (uint64, uint64) {
	f, err := os.Open("/proc/net/dev")
	if err != nil {
		return 0, 0
	}
	defer f.Close()
	var rx, tx uint64
	s := bufio.NewScanner(f)
	for s.Scan() {
		line := s.Text()
		if !strings.Contains(line, ":") {
			continue
		}
		p := strings.SplitN(line, ":", 2)
		name := strings.TrimSpace(p[0])
		if name == "lo" {
			continue
		}
		fields := strings.Fields(p[1])
		if len(fields) < 9 {
			continue
		}
		a, _ := strconv.ParseUint(fields[0], 10, 64)
		b, _ := strconv.ParseUint(fields[8], 10, 64)
		rx += a
		tx += b
	}
	return rx, tx
}
