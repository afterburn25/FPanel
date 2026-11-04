package hostadapter

import (
	"bufio"
	"errors"
	"fmt"
	"net"
	"os"
	"os/user"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
)

type AccountUsage struct {
	DiskBytes      int64   `json:"disk_bytes"`
	FileCount      int64   `json:"file_count"`
	DirectoryCount int64   `json:"directory_count"`
	ProcessCount   int     `json:"process_count"`
	MemoryBytes    uint64  `json:"memory_bytes"`
	CPUMinutes     float64 `json:"cpu_minutes"`
	ScanLimited    bool    `json:"scan_limited"`
}

type TrafficCounter struct {
	Name  string `json:"name"`
	Count int64  `json:"count"`
	Bytes int64  `json:"bytes,omitempty"`
}
type DailyTraffic struct {
	Date     string `json:"date"`
	Requests int64  `json:"requests"`
	Bytes    int64  `json:"bytes"`
	Visitors int64  `json:"visitors"`
	Errors   int64  `json:"errors"`
}
type VisitorEvent struct {
	Time      string `json:"time"`
	Domain    string `json:"domain"`
	IP        string `json:"ip"`
	Method    string `json:"method"`
	Path      string `json:"path"`
	Status    int    `json:"status"`
	Bytes     int64  `json:"bytes"`
	Referer   string `json:"referer"`
	UserAgent string `json:"user_agent"`
}
type ErrorEvent struct {
	Time   string `json:"time"`
	Domain string `json:"domain"`
	Source string `json:"source"`
	Detail string `json:"detail"`
}
type DomainTraffic struct {
	Domain   string `json:"domain"`
	Requests int64  `json:"requests"`
	Bytes    int64  `json:"bytes"`
	Visitors int64  `json:"visitors"`
	Errors   int64  `json:"errors"`
}

type AccountAnalytics struct {
	GeneratedAt     time.Time        `json:"generated_at"`
	IPv4            string           `json:"ipv4,omitempty"`
	IPv6            string           `json:"ipv6,omitempty"`
	Usage           AccountUsage     `json:"usage"`
	Requests        int64            `json:"requests"`
	BandwidthBytes  int64            `json:"bandwidth_bytes"`
	UniqueVisitors  int64            `json:"unique_visitors"`
	HTTP4xx         int64            `json:"http_4xx"`
	HTTP5xx         int64            `json:"http_5xx"`
	TopPaths        []TrafficCounter `json:"top_paths"`
	TopReferrers    []TrafficCounter `json:"top_referrers"`
	StatusCodes     []TrafficCounter `json:"status_codes"`
	Daily           []DailyTraffic   `json:"daily"`
	Domains         []DomainTraffic  `json:"domains"`
	RecentVisitors  []VisitorEvent   `json:"recent_visitors"`
	RecentErrors    []ErrorEvent     `json:"recent_errors"`
	AccessLogPeriod string           `json:"access_log_period"`
	LogScanLimited  bool             `json:"log_scan_limited"`
}

var nginxCombinedRE = regexp.MustCompile(`^(\S+)\s+\S+\s+\S+\s+\[([^\]]+)\]\s+"(\S+)\s+([^\"]*)\s+HTTP/[^\"]+"\s+(\d{3})\s+(\d+|-)\s+"([^\"]*)"\s+"([^\"]*)"`)

func parseNginxTime(v string) time.Time {
	t, _ := time.Parse("02/Jan/2006:15:04:05 -0700", v)
	return t
}

func tailTextFile(path string, maxBytes int64) ([]string, bool) {
	f, err := os.Open(path)
	if err != nil {
		return nil, false
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return nil, false
	}
	limited := false
	start := int64(0)
	if info.Size() > maxBytes {
		start = info.Size() - maxBytes
		limited = true
	}
	if start > 0 {
		_, _ = f.Seek(start, 0)
		r := bufio.NewReader(f)
		_, _ = r.ReadString('\n')
	}
	s := bufio.NewScanner(f)
	buf := make([]byte, 64*1024)
	s.Buffer(buf, 1024*1024)
	lines := make([]string, 0)
	for s.Scan() {
		lines = append(lines, s.Text())
	}
	return lines, limited
}

func (a *Adapter) accountUsage(username string) (AccountUsage, error) {
	if err := a.requireCertified("linux-users"); err != nil {
		return AccountUsage{}, err
	}
	u, err := user.Lookup(username)
	if err != nil {
		return AccountUsage{}, err
	}
	uid64, err := strconv.ParseUint(u.Uid, 10, 32)
	if err != nil {
		return AccountUsage{}, err
	}
	uid := uint32(uid64)
	base := filepath.Join(a.cfg.AccountHomeBase, username)
	var usage AccountUsage
	entries := 0
	walkErr := filepath.WalkDir(base, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if d.Type()&os.ModeSymlink != 0 {
			if d.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}
		entries++
		if entries > 250000 {
			usage.ScanLimited = true
			return errors.New("scan-limit")
		}
		info, e := d.Info()
		if e != nil {
			return nil
		}
		if d.IsDir() {
			usage.DirectoryCount++
		} else if info.Mode().IsRegular() {
			usage.FileCount++
			usage.DiskBytes += info.Size()
		}
		return nil
	})
	if walkErr != nil && walkErr.Error() != "scan-limit" {
		return usage, walkErr
	}
	procEntries, _ := os.ReadDir("/proc")
	ticksPerSecond := float64(100)
	for _, e := range procEntries {
		pid, err := strconv.Atoi(e.Name())
		if err != nil || pid <= 0 {
			continue
		}
		status, err := os.ReadFile(filepath.Join("/proc", e.Name(), "status"))
		if err != nil {
			continue
		}
		var procUID uint64
		var rssKB uint64
		for _, line := range strings.Split(string(status), "\n") {
			if strings.HasPrefix(line, "Uid:") {
				f := strings.Fields(line)
				if len(f) > 1 {
					procUID, _ = strconv.ParseUint(f[1], 10, 32)
				}
			}
			if strings.HasPrefix(line, "VmRSS:") {
				f := strings.Fields(line)
				if len(f) > 1 {
					rssKB, _ = strconv.ParseUint(f[1], 10, 64)
				}
			}
		}
		if uint32(procUID) != uid {
			continue
		}
		usage.ProcessCount++
		usage.MemoryBytes += rssKB * 1024
		stat, err := os.ReadFile(filepath.Join("/proc", e.Name(), "stat"))
		if err == nil {
			parts := strings.Fields(string(stat))
			if len(parts) > 14 {
				ut, _ := strconv.ParseFloat(parts[13], 64)
				st, _ := strconv.ParseFloat(parts[14], 64)
				usage.CPUMinutes += (ut + st) / ticksPerSecond / 60
			}
		}
	}
	return usage, nil
}

func (a *Adapter) AccountAnalytics(username string, domains []string) (AccountAnalytics, error) {
	usage, err := a.accountUsage(username)
	if err != nil {
		return AccountAnalytics{}, err
	}
	v4, v6 := a.PrimaryHostAddresses()
	out := AccountAnalytics{GeneratedAt: time.Now().UTC(), IPv4: v4, IPv6: v6, Usage: usage, AccessLogPeriod: "current Nginx log files"}
	type dayAgg struct {
		req, bytes, errors int64
		vis                map[string]struct{}
	}
	days := map[string]*dayAgg{}
	pathCounts := map[string]*TrafficCounter{}
	refCounts := map[string]*TrafficCounter{}
	statusCounts := map[string]*TrafficCounter{}
	visitorSet := map[string]struct{}{}
	domainAgg := map[string]*DomainTraffic{}
	var visitors []VisitorEvent
	var errs []ErrorEvent
	for _, domain := range domains {
		domain = strings.ToLower(strings.TrimSpace(domain))
		if !validDomain(domain) {
			continue
		}
		da := &DomainTraffic{Domain: domain}
		domainAgg[domain] = da
		domainVisitors := map[string]struct{}{}
		access := filepath.Join(a.cfg.NginxLogDir, domain+".access.log")
		lines, limited := tailTextFile(access, 16<<20)
		out.LogScanLimited = out.LogScanLimited || limited
		for _, line := range lines {
			m := nginxCombinedRE.FindStringSubmatch(line)
			if len(m) != 9 {
				continue
			}
			ip := m[1]
			tm := parseNginxTime(m[2])
			method := m[3]
			path := m[4]
			status, _ := strconv.Atoi(m[5])
			b := int64(0)
			if m[6] != "-" {
				b, _ = strconv.ParseInt(m[6], 10, 64)
			}
			ref := m[7]
			ua := m[8]
			out.Requests++
			out.BandwidthBytes += b
			da.Requests++
			da.Bytes += b
			visitorSet[ip] = struct{}{}
			domainVisitors[ip] = struct{}{}
			if status >= 400 && status < 500 {
				out.HTTP4xx++
			}
			if status >= 500 {
				out.HTTP5xx++
			}
			if status >= 400 {
				da.Errors++
			}
			key := path
			if q := strings.IndexByte(key, '?'); q >= 0 {
				key = key[:q]
			}
			if key == "" {
				key = "/"
			}
			pc := pathCounts[key]
			if pc == nil {
				pc = &TrafficCounter{Name: key}
				pathCounts[key] = pc
			}
			pc.Count++
			pc.Bytes += b
			if ref != "" && ref != "-" {
				rc := refCounts[ref]
				if rc == nil {
					rc = &TrafficCounter{Name: ref}
					refCounts[ref] = rc
				}
				rc.Count++
			}
			sc := statusCounts[strconv.Itoa(status)]
			if sc == nil {
				sc = &TrafficCounter{Name: strconv.Itoa(status)}
				statusCounts[strconv.Itoa(status)] = sc
			}
			sc.Count++
			day := tm.UTC().Format("2006-01-02")
			ag := days[day]
			if ag == nil {
				ag = &dayAgg{vis: map[string]struct{}{}}
				days[day] = ag
			}
			ag.req++
			ag.bytes += b
			ag.vis[ip] = struct{}{}
			if status >= 400 {
				ag.errors++
			}
			visitors = append(visitors, VisitorEvent{Time: tm.UTC().Format(time.RFC3339), Domain: domain, IP: ip, Method: method, Path: path, Status: status, Bytes: b, Referer: ref, UserAgent: ua})
			if status >= 400 {
				errs = append(errs, ErrorEvent{Time: tm.UTC().Format(time.RFC3339), Domain: domain, Source: "access", Detail: fmt.Sprintf("HTTP %d %s %s from %s", status, method, path, ip)})
			}
		}
		da.Visitors = int64(len(domainVisitors))
		errorLines, errorLimited := tailTextFile(filepath.Join(a.cfg.NginxLogDir, domain+".error.log"), 2<<20)
		out.LogScanLimited = out.LogScanLimited || errorLimited
		start := 0
		if len(errorLines) > 120 {
			start = len(errorLines) - 120
		}
		for _, line := range errorLines[start:] {
			errs = append(errs, ErrorEvent{Domain: domain, Source: "nginx", Detail: line})
		}
	}
	out.UniqueVisitors = int64(len(visitorSet))
	toSorted := func(m map[string]*TrafficCounter, max int) []TrafficCounter {
		rows := make([]TrafficCounter, 0, len(m))
		for _, v := range m {
			rows = append(rows, *v)
		}
		sort.Slice(rows, func(i, j int) bool { return rows[i].Count > rows[j].Count })
		if len(rows) > max {
			rows = rows[:max]
		}
		return rows
	}
	out.TopPaths = toSorted(pathCounts, 20)
	out.TopReferrers = toSorted(refCounts, 20)
	out.StatusCodes = toSorted(statusCounts, 20)
	dayKeys := make([]string, 0, len(days))
	for k := range days {
		dayKeys = append(dayKeys, k)
	}
	sort.Strings(dayKeys)
	if len(dayKeys) > 14 {
		dayKeys = dayKeys[len(dayKeys)-14:]
	}
	for _, k := range dayKeys {
		a := days[k]
		out.Daily = append(out.Daily, DailyTraffic{Date: k, Requests: a.req, Bytes: a.bytes, Visitors: int64(len(a.vis)), Errors: a.errors})
	}
	for _, v := range domainAgg {
		out.Domains = append(out.Domains, *v)
	}
	sort.Slice(out.Domains, func(i, j int) bool { return out.Domains[i].Requests > out.Domains[j].Requests })
	sort.Slice(visitors, func(i, j int) bool { return visitors[i].Time > visitors[j].Time })
	if len(visitors) > 250 {
		visitors = visitors[:250]
	}
	out.RecentVisitors = visitors
	sort.Slice(errs, func(i, j int) bool { return errs[i].Time > errs[j].Time })
	if len(errs) > 250 {
		errs = errs[:250]
	}
	out.RecentErrors = errs
	return out, nil
}

func serverIPFamily(v string) string {
	ip := net.ParseIP(v)
	if ip == nil {
		return ""
	}
	if ip.To4() != nil {
		return "ipv4"
	}
	return "ipv6"
}
