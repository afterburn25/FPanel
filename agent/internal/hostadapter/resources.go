package hostadapter

import (
	"archive/tar"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"syscall"
	"time"
)

var dbIdentRE = regexp.MustCompile(`^[A-Za-z0-9_]{1,64}$`)
var dnsOwnerLabelRE = regexp.MustCompile(`^_?[A-Za-z0-9](?:[A-Za-z0-9_-]{0,61}[A-Za-z0-9])?$`)

type DNSRecord struct {
	Type, Name, Value string
	TTL               int
}

func RenderDNSZone(domain string, records []DNSRecord, serial uint32) (string, error) {
	return RenderDNSZoneWithNameservers(domain, "", "", records, serial)
}

func RenderDNSZoneWithNameservers(domain, primaryNS, secondaryNS string, records []DNSRecord, serial uint32) (string, error) {
	if !validDomain(domain) {
		return "", errors.New("invalid zone domain")
	}
	domain = strings.ToLower(strings.TrimSpace(domain))
	if primaryNS == "" {
		primaryNS = "ns1." + domain
	}
	if secondaryNS == "" {
		secondaryNS = "ns2." + domain
	}
	primaryNS = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(primaryNS)), ".")
	secondaryNS = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(secondaryNS)), ".")
	if !validDomain(primaryNS) || !validDomain(secondaryNS) || primaryNS == secondaryNS {
		return "", errors.New("invalid authoritative nameserver")
	}
	if serial == 0 {
		serial = uint32(time.Now().UTC().Unix())
	}
	var b strings.Builder
	fmt.Fprintf(&b, "$TTL 3600\n@ IN SOA %s. hostmaster.%s. ( %d 3600 900 1209600 300 )\n", primaryNS, domain, serial)
	fmt.Fprintf(&b, "@ IN NS %s.\n@ IN NS %s.\n", primaryNS, secondaryNS)
	for _, r := range records {
		typ := strings.ToUpper(strings.TrimSpace(r.Type))
		name := strings.TrimSpace(r.Name)
		value := strings.TrimSpace(r.Value)
		if r.TTL <= 0 {
			r.TTL = 3600
		}
		if r.TTL > 86400 {
			return "", errors.New("invalid TTL")
		}
		switch typ {
		case "A":
			if !netParseIP4(value) {
				return "", errors.New("invalid A record")
			}
		case "AAAA":
			if !netParseIP6(value) {
				return "", errors.New("invalid AAAA record")
			}
		case "CNAME", "NS", "MX":
			parts := strings.Fields(value)
			target := value
			if typ == "MX" {
				if len(parts) != 2 {
					return "", errors.New("invalid MX record")
				}
				target = parts[1]
			}
			target = strings.TrimSuffix(target, ".")
			if !validDomain(target) {
				return "", errors.New("invalid DNS target")
			}
		case "TXT":
			if len(value) > 4096 || strings.ContainsAny(value, "\r\n") {
				return "", errors.New("invalid TXT record")
			}
			value = renderBINDTXTValue(value)
		case "CAA":
			if len(value) > 512 || strings.ContainsAny(value, "\r\n") {
				return "", errors.New("invalid CAA record")
			}
		default:
			return "", fmt.Errorf("unsupported DNS type %s", typ)
		}
		if name == "" {
			name = "@"
		}
		if name != "@" && !validDNSName(name) {
			return "", errors.New("invalid DNS owner name")
		}
		fmt.Fprintf(&b, "%s %d IN %s %s\n", name, r.TTL, typ, value)
	}
	return b.String(), nil
}

func renderBINDTXTValue(value string) string {
	// A DNS TXT RR can contain multiple character-strings, but each individual
	// character-string is limited to 255 octets. 2048-bit DKIM public keys are
	// routinely longer than that, so render adjacent quoted chunks which BIND
	// concatenates into one logical TXT value on the wire.
	const maxChunk = 240
	if value == "" {
		return `""`
	}
	parts := []string{}
	for len(value) > 0 {
		n := maxChunk
		if len(value) < n {
			n = len(value)
		}
		// Do not split a UTF-8 codepoint. Mail auth records are ASCII, but the
		// generic TXT renderer remains correct for other operator-entered text.
		for n > 0 && n < len(value) && (value[n]&0xC0) == 0x80 {
			n--
		}
		if n == 0 {
			n = len(value)
		}
		chunk := value[:n]
		value = value[n:]
		chunk = strings.ReplaceAll(chunk, `\`, `\\`)
		chunk = strings.ReplaceAll(chunk, `"`, `\"`)
		parts = append(parts, `"`+chunk+`"`)
	}
	return strings.Join(parts, " ")
}

func parseBINDTXTValue(value string) string {
	value = strings.TrimSpace(value)
	if !strings.HasPrefix(value, `"`) {
		return value
	}
	var out strings.Builder
	inQuote, escaped := false, false
	for _, r := range value {
		if !inQuote {
			if r == '"' {
				inQuote = true
			}
			continue
		}
		if escaped {
			out.WriteRune(r)
			escaped = false
			continue
		}
		if r == '\\' {
			escaped = true
			continue
		}
		if r == '"' {
			inQuote = false
			continue
		}
		out.WriteRune(r)
	}
	return out.String()
}

func validDNSName(v string) bool {
	if v == "*" {
		return true
	}
	for _, p := range strings.Split(v, ".") {
		if p != "*" && !dnsOwnerLabelRE.MatchString(p) {
			return false
		}
	}
	return true
}
func netParseIP4(v string) bool { ip := net.ParseIP(v); return ip != nil && strings.Count(v, ":") == 0 }
func netParseIP6(v string) bool { ip := net.ParseIP(v); return ip != nil && strings.Contains(v, ":") }

func MariaDBCreateSQL(database, user string) (string, error) {
	if !dbIdentRE.MatchString(database) || !dbIdentRE.MatchString(user) {
		return "", errors.New("invalid database identifier")
	}
	return fmt.Sprintf("CREATE DATABASE `%s` CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;\nCREATE USER IF NOT EXISTS '%s'@'localhost' IDENTIFIED BY ?;\nGRANT ALL PRIVILEGES ON `%s`.* TO '%s'@'localhost';\n", database, user, database, user), nil
}

func PostgreSQLCreatePlan(database, user string) ([]string, error) {
	if !dbIdentRE.MatchString(database) || !dbIdentRE.MatchString(user) {
		return nil, errors.New("invalid database identifier")
	}
	return []string{"CREATE ROLE " + user + " LOGIN PASSWORD $1", "CREATE DATABASE " + database + " OWNER " + user}, nil
}

type BackupResult struct {
	Path   string `json:"path"`
	SHA256 string `json:"sha256"`
	Size   int64  `json:"size_bytes"`
}

type RestoreResult struct {
	Target       string `json:"target"`
	RollbackPath string `json:"rollback_path"`
	Files        int    `json:"files"`
	Directories  int    `json:"directories"`
	SHA256       string `json:"sha256"`
}

func fileSHA256(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// RestoreLocalBackup restores only a Privora-created .tar.zst into an existing
// site directory. It validates the stored digest and rejects links, devices and
// path traversal before atomically exchanging the site directory. The old site
// remains beside the target as an explicit rollback copy.
func (a *Adapter) RestoreLocalBackup(ctx context.Context, archivePath, expectedSHA, target string) (RestoreResult, error) {
	if !a.cfg.AllowMutations {
		return RestoreResult{}, errors.New("host mutations disabled")
	}
	if err := a.requireCertified("local-backup"); err != nil {
		return RestoreResult{}, err
	}
	if _, ok := commandExists("zstd"); !ok {
		return RestoreResult{}, errors.New("zstd not installed")
	}
	archivePath, _ = filepath.Abs(archivePath)
	target, _ = filepath.Abs(target)
	if !strings.HasSuffix(archivePath, ".tar.zst") || target == "/" || target == "/home" {
		return RestoreResult{}, errors.New("unsafe restore path")
	}
	actual, err := fileSHA256(archivePath)
	if err != nil {
		return RestoreResult{}, err
	}
	expectedSHA = strings.ToLower(strings.TrimSpace(expectedSHA))
	if expectedSHA == "" || actual != expectedSHA {
		return RestoreResult{}, fmt.Errorf("backup integrity check failed: expected %s got %s", expectedSHA, actual)
	}
	st, err := os.Stat(target)
	if err != nil || !st.IsDir() {
		return RestoreResult{}, errors.New("restore target must be an existing directory")
	}
	targetUID, targetGID := -1, -1
	if sys, ok := st.Sys().(*syscall.Stat_t); ok {
		targetUID, targetGID = int(sys.Uid), int(sys.Gid)
	}
	parent, base := filepath.Dir(target), filepath.Base(target)
	stage, err := os.MkdirTemp(parent, ".privora-restore-stage-")
	if err != nil {
		return RestoreResult{}, err
	}
	defer os.RemoveAll(stage)
	cctx, cancel := context.WithTimeout(ctx, 3*time.Minute)
	defer cancel()
	cmd := exec.CommandContext(cctx, "zstd", "-q", "-dc", archivePath)
	pipe, err := cmd.StdoutPipe()
	if err != nil {
		return RestoreResult{}, err
	}
	var zerr strings.Builder
	cmd.Stderr = &zerr
	if err := cmd.Start(); err != nil {
		return RestoreResult{}, err
	}
	tr := tar.NewReader(pipe)
	files, dirs := 0, 0
	for {
		h, e := tr.Next()
		if e == io.EOF {
			break
		}
		if e != nil {
			_ = cmd.Process.Kill()
			return RestoreResult{}, e
		}
		clean := filepath.Clean(h.Name)
		if filepath.IsAbs(clean) || clean == ".." || strings.HasPrefix(clean, ".."+string(os.PathSeparator)) {
			_ = cmd.Process.Kill()
			return RestoreResult{}, errors.New("unsafe path in backup")
		}
		parts := strings.Split(clean, string(os.PathSeparator))
		if len(parts) == 0 || parts[0] != base {
			_ = cmd.Process.Kill()
			return RestoreResult{}, errors.New("backup root does not match restore target")
		}
		if h.Typeflag == tar.TypeSymlink || h.Typeflag == tar.TypeLink || h.Typeflag == tar.TypeChar || h.Typeflag == tar.TypeBlock || h.Typeflag == tar.TypeFifo {
			_ = cmd.Process.Kill()
			return RestoreResult{}, errors.New("links/devices are not accepted during restore")
		}
		dst := filepath.Join(stage, clean)
		rel, _ := filepath.Rel(stage, dst)
		if rel == ".." || strings.HasPrefix(rel, ".."+string(os.PathSeparator)) {
			_ = cmd.Process.Kill()
			return RestoreResult{}, errors.New("restore escaped staging directory")
		}
		switch h.Typeflag {
		case tar.TypeDir:
			mode := os.FileMode(h.Mode) & 0755
			if mode&0500 == 0 {
				mode |= 0500
			}
			if err := os.MkdirAll(dst, mode); err != nil {
				_ = cmd.Process.Kill()
				return RestoreResult{}, err
			}
			if targetUID >= 0 {
				if err := os.Chown(dst, targetUID, targetGID); err != nil {
					_ = cmd.Process.Kill()
					return RestoreResult{}, err
				}
			}
			dirs++
		case tar.TypeReg, tar.TypeRegA:
			if err := os.MkdirAll(filepath.Dir(dst), 0755); err != nil {
				_ = cmd.Process.Kill()
				return RestoreResult{}, err
			}
			mode := os.FileMode(h.Mode) & 0755
			if mode == 0 {
				mode = 0644
			}
			f, er := os.OpenFile(dst, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, mode)
			if er != nil {
				_ = cmd.Process.Kill()
				return RestoreResult{}, er
			}
			_, er = io.CopyN(f, tr, h.Size)
			closeErr := f.Close()
			if er != nil && er != io.EOF {
				_ = cmd.Process.Kill()
				return RestoreResult{}, er
			}
			if closeErr != nil {
				_ = cmd.Process.Kill()
				return RestoreResult{}, closeErr
			}
			if targetUID >= 0 {
				if err := os.Chown(dst, targetUID, targetGID); err != nil {
					_ = cmd.Process.Kill()
					return RestoreResult{}, err
				}
			}
			files++
		default:
			_ = cmd.Process.Kill()
			return RestoreResult{}, fmt.Errorf("unsupported tar entry type %d", h.Typeflag)
		}
	}
	if err := cmd.Wait(); err != nil {
		return RestoreResult{}, fmt.Errorf("zstd restore stream: %w: %s", err, zerr.String())
	}
	extracted := filepath.Join(stage, base)
	if si, err := os.Stat(extracted); err != nil || !si.IsDir() {
		return RestoreResult{}, errors.New("backup did not contain expected target root")
	}
	rollback := target + ".privora-before-restore-" + time.Now().UTC().Format("20060102T150405Z")
	if _, err := os.Stat(rollback); err == nil {
		return RestoreResult{}, errors.New("restore rollback path already exists")
	}
	if err := os.Rename(target, rollback); err != nil {
		return RestoreResult{}, fmt.Errorf("preserve current site: %w", err)
	}
	if err := os.Rename(extracted, target); err != nil {
		_ = os.Rename(rollback, target)
		return RestoreResult{}, fmt.Errorf("publish restored site: %w", err)
	}
	return RestoreResult{Target: target, RollbackPath: rollback, Files: files, Directories: dirs, SHA256: actual}, nil
}

func (a *Adapter) CreateLocalBackup(ctx context.Context, source, destination string) (BackupResult, error) {
	if !a.cfg.AllowMutations {
		return BackupResult{}, errors.New("host mutations disabled")
	}
	if err := a.requireCertified("local-backup"); err != nil {
		return BackupResult{}, err
	}
	src, err := filepath.Abs(source)
	if err != nil {
		return BackupResult{}, err
	}
	dst, err := filepath.Abs(destination)
	if err != nil {
		return BackupResult{}, err
	}
	if src == "/" || src == "/home" {
		return BackupResult{}, errors.New("backup source too broad")
	}
	info, err := os.Stat(src)
	if err != nil {
		return BackupResult{}, err
	}
	if !info.IsDir() {
		return BackupResult{}, errors.New("backup source must be directory")
	}
	if filepath.Ext(dst) != ".zst" || !strings.HasSuffix(dst, ".tar.zst") {
		return BackupResult{}, errors.New("backup destination must end .tar.zst")
	}
	if _, ok := commandExists("tar"); !ok {
		return BackupResult{}, errors.New("tar not installed")
	}
	if _, ok := commandExists("zstd"); !ok {
		return BackupResult{}, errors.New("zstd not installed")
	}
	if err := os.MkdirAll(filepath.Dir(dst), 0750); err != nil {
		return BackupResult{}, err
	}
	tmp := dst + ".part"
	_ = os.Remove(tmp)
	defer os.Remove(tmp)
	cctx, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()
	tarCmd := exec.CommandContext(cctx, "tar", "-C", filepath.Dir(src), "-cf", "-", filepath.Base(src))
	zstdCmd := exec.CommandContext(cctx, "zstd", "-q", "-T1", "-3", "-o", tmp)
	pipe, err := tarCmd.StdoutPipe()
	if err != nil {
		return BackupResult{}, err
	}
	zstdCmd.Stdin = pipe
	var tarErr, zstdErr strings.Builder
	tarCmd.Stderr = &tarErr
	zstdCmd.Stderr = &zstdErr
	if err := zstdCmd.Start(); err != nil {
		return BackupResult{}, err
	}
	if err := tarCmd.Start(); err != nil {
		_ = zstdCmd.Process.Kill()
		return BackupResult{}, err
	}
	if err := tarCmd.Wait(); err != nil {
		_ = zstdCmd.Process.Kill()
		return BackupResult{}, fmt.Errorf("tar: %w: %s", err, tarErr.String())
	}
	if err := zstdCmd.Wait(); err != nil {
		return BackupResult{}, fmt.Errorf("zstd: %w: %s", err, zstdErr.String())
	}
	f, err := os.Open(tmp)
	if err != nil {
		return BackupResult{}, err
	}
	h := sha256.New()
	if _, err = io.Copy(h, f); err != nil {
		f.Close()
		return BackupResult{}, err
	}
	f.Close()
	st, err := os.Stat(tmp)
	if err != nil {
		return BackupResult{}, err
	}
	if err := os.Rename(tmp, dst); err != nil {
		return BackupResult{}, err
	}
	return BackupResult{Path: dst, SHA256: hex.EncodeToString(h.Sum(nil)), Size: st.Size()}, nil
}

type CPanelManifest struct {
	Entries     int  `json:"entries"`
	Files       int  `json:"files"`
	Directories int  `json:"directories"`
	HasHomedir  bool `json:"has_homedir"`
	HasMysql    bool `json:"has_mysql"`
	HasDNS      bool `json:"has_dns"`
}

func InspectCPanelBackup(path string) (CPanelManifest, error) {
	f, err := os.Open(path)
	if err != nil {
		return CPanelManifest{}, err
	}
	defer f.Close()
	var r io.Reader = f
	if strings.HasSuffix(path, ".gz") || strings.HasSuffix(path, ".tgz") {
		gz, e := gzip.NewReader(f)
		if e != nil {
			return CPanelManifest{}, e
		}
		defer gz.Close()
		r = gz
	}
	tr := tar.NewReader(r)
	var m CPanelManifest
	for {
		h, e := tr.Next()
		if e == io.EOF {
			break
		}
		if e != nil {
			return CPanelManifest{}, e
		}
		clean := filepath.Clean(h.Name)
		if filepath.IsAbs(clean) || clean == ".." || strings.HasPrefix(clean, ".."+string(os.PathSeparator)) {
			return CPanelManifest{}, errors.New("unsafe path in cPanel backup")
		}
		if h.Typeflag == tar.TypeSymlink || h.Typeflag == tar.TypeLink {
			return CPanelManifest{}, errors.New("links are not accepted during cPanel inspection")
		}
		m.Entries++
		if h.FileInfo().IsDir() {
			m.Directories++
		} else {
			m.Files++
		}
		lower := strings.ToLower(clean)
		if strings.Contains(lower, "homedir/") {
			m.HasHomedir = true
		}
		if strings.Contains(lower, "mysql") || strings.HasSuffix(lower, ".sql") {
			m.HasMysql = true
		}
		if strings.Contains(lower, "dns") || strings.HasSuffix(lower, ".db") {
			m.HasDNS = true
		}
	}
	if m.Entries == 0 {
		return m, errors.New("empty cPanel backup")
	}
	return m, nil
}
