package hostadapter

import (
	"archive/zip"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

var updateChannelRE = regexp.MustCompile(`^(stable|early-access|developer)$`)
var uploadIDRE = regexp.MustCompile(`^[0-9]{8}T[0-9]{6}Z-[0-9a-f]{16}$`)

type UpdateStart struct {
	Mode       string `json:"mode"`
	Channel    string `json:"channel"`
	ReleaseURL string `json:"release_url,omitempty"`
}
type UpdateJob struct {
	ID      string   `json:"id"`
	Unit    string   `json:"unit"`
	Mode    string   `json:"mode"`
	Channel string   `json:"channel"`
	Status  string   `json:"status"`
	Command []string `json:"command,omitempty"`
}
type UploadInspection struct {
	OK            bool     `json:"ok"`
	UploadID      string   `json:"upload_id"`
	OriginalName  string   `json:"original_name,omitempty"`
	Version       string   `json:"version"`
	Channel       string   `json:"channel"`
	MinVersion    string   `json:"min_version,omitempty"`
	CreatedAt     string   `json:"created_at"`
	Services      []string `json:"services,omitempty"`
	Migrations    []string `json:"migrations,omitempty"`
	PayloadSHA256 string   `json:"payload_sha256"`
	ZipSHA256     string   `json:"zip_sha256"`
	SizeBytes     int64    `json:"size_bytes"`
	PayloadBytes  int64    `json:"payload_bytes"`
	StagedPath    string   `json:"-"`
}
type UploadPrepare struct {
	UploadPath   string `json:"upload_path"`
	OriginalName string `json:"original_name,omitempty"`
}
type UploadInstallStart struct {
	UploadID     string `json:"upload_id"`
	RootPassword string `json:"root_password"`
	Actor        string `json:"-"`
}

type updateAuthToken struct {
	UploadID  string `json:"upload_id"`
	ZipSHA256 string `json:"zip_sha256"`
	Version   string `json:"version"`
	Actor     string `json:"actor"`
	ExpiresAt string `json:"expires_at"`
}

func detectPrivoraArchiveKind(filename string) string {
	zr, err := zip.OpenReader(filename)
	if err != nil {
		return "invalid"
	}
	defer zr.Close()
	hasUpdateManifest := false
	hasUpdateSignature := false
	hasFullCoreManifest := false
	for _, zf := range zr.File {
		name := strings.TrimSuffix(strings.ReplaceAll(zf.Name, "\\", "/"), "/")
		if name == "" {
			continue
		}
		base := name[strings.LastIndex(name, "/")+1:]
		switch base {
		case "UPDATE-MANIFEST.json":
			hasUpdateManifest = true
		case "UPDATE-MANIFEST.sig":
			hasUpdateSignature = true
		case "FULL-CORE-MANIFEST.json":
			hasFullCoreManifest = true
		}
	}
	if hasUpdateManifest || hasUpdateSignature {
		return "update"
	}
	if hasFullCoreManifest {
		return "full-core"
	}
	return "unknown"
}

func validateHTTPSURL(raw string) error {
	u, e := url.Parse(raw)
	if e != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.Fragment != "" {
		return errors.New("release URL must be an absolute HTTPS URL without credentials or fragments")
	}
	return nil
}
func (a *Adapter) StartSafeUpdate(ctx context.Context, in UpdateStart) (UpdateJob, error) {
	var out UpdateJob
	if !a.cfg.AllowMutations {
		return out, errors.New("host mutations disabled")
	}
	if e := a.requireCertified("privora-updater"); e != nil {
		return out, e
	}
	if in.Mode != "security" && in.Mode != "full" {
		return out, errors.New("update mode must be security or full")
	}
	if !updateChannelRE.MatchString(in.Channel) {
		return out, errors.New("invalid update channel")
	}
	if in.Mode == "full" {
		if e := validateHTTPSURL(in.ReleaseURL); e != nil {
			return out, e
		}
	}
	st, e := os.Stat(a.cfg.UpdaterPath)
	if e != nil || !st.Mode().IsRegular() || st.Mode()&0111 == 0 {
		return out, errors.New("Privora updater is not installed")
	}
	sr, ok := commandExists("systemd-run")
	if !ok {
		return out, errors.New("systemd-run not installed")
	}
	id := fmt.Sprintf("%d", time.Now().UTC().UnixNano())
	unit := "privora-update-" + id
	args := []string{"--unit", unit, "--collect", "--property=Nice=10", "--property=IOSchedulingClass=best-effort", a.cfg.UpdaterPath, "--channel", in.Channel}
	if in.Mode == "security" {
		args = append(args, "--security-only")
	} else {
		args = append(args, "--release-url", in.ReleaseURL)
	}
	c, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	cmd := exec.CommandContext(c, sr, args...)
	b, e := cmd.CombinedOutput()
	if e != nil {
		return out, fmt.Errorf("launch update job: %w: %s", e, strings.TrimSpace(string(b)))
	}
	return UpdateJob{ID: id, Unit: unit, Mode: in.Mode, Channel: in.Channel, Status: "accepted", Command: append([]string{sr}, args...)}, nil
}

func updateRandomHex(n int) (string, error) {
	b := make([]byte, n)
	if _, e := rand.Read(b); e != nil {
		return "", e
	}
	return hex.EncodeToString(b), nil
}

func cleanupUpdateArtifacts(root string, maxAge time.Duration, allowed *regexp.Regexp) {
	entries, e := os.ReadDir(root)
	if e != nil {
		return
	}
	cutoff := time.Now().Add(-maxAge)
	for _, ent := range entries {
		if ent.IsDir() || !allowed.MatchString(ent.Name()) {
			continue
		}
		info, e := ent.Info()
		if e == nil && info.ModTime().Before(cutoff) {
			_ = os.Remove(filepath.Join(root, ent.Name()))
		}
	}
}

func (a *Adapter) PrepareUploadedUpdate(ctx context.Context, in UploadPrepare) (UploadInspection, error) {
	var out UploadInspection
	if !a.cfg.AllowMutations {
		return out, errors.New("host mutations disabled")
	}
	if e := a.requireCertified("privora-updater"); e != nil {
		return out, e
	}
	src, e := filepath.Abs(in.UploadPath)
	if e != nil {
		return out, errors.New("invalid upload path")
	}
	inbox, _ := filepath.Abs(a.cfg.UpdateUploadInbox)
	rel, e := filepath.Rel(inbox, src)
	if e != nil || rel == "." || strings.HasPrefix(rel, ".."+string(os.PathSeparator)) || filepath.IsAbs(rel) {
		return out, errors.New("update upload path is outside the protected inbox")
	}
	if !regexp.MustCompile(`^[A-Za-z0-9._-]{8,180}\.zip$`).MatchString(filepath.Base(src)) {
		return out, errors.New("invalid update upload filename")
	}
	st, e := os.Lstat(src)
	if e != nil || !st.Mode().IsRegular() || st.Mode()&os.ModeSymlink != 0 {
		return out, errors.New("update upload must be a regular file")
	}
	if st.Size() < 1024 || st.Size() > 536870912 {
		return out, errors.New("update upload size is outside the allowed range")
	}
	if e = os.MkdirAll(a.cfg.UpdateUploadStaging, 0700); e != nil {
		return out, e
	}
	_ = os.Chmod(a.cfg.UpdateUploadStaging, 0700)
	cleanupUpdateArtifacts(a.cfg.UpdateUploadStaging, time.Hour, regexp.MustCompile(`^[0-9]{8}T[0-9]{6}Z-[0-9a-f]{16}\.(zip|json)$`))
	rnd, e := updateRandomHex(8)
	if e != nil {
		return out, e
	}
	id := time.Now().UTC().Format("20060102T150405Z") + "-" + rnd
	dst := filepath.Join(a.cfg.UpdateUploadStaging, id+".zip")
	sf, e := os.Open(src)
	if e != nil {
		return out, e
	}
	defer sf.Close()
	df, e := os.OpenFile(dst, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if e != nil {
		return out, e
	}
	_, copyErr := io.Copy(df, io.LimitReader(sf, 536870913))
	syncErr := df.Sync()
	closeErr := df.Close()
	if copyErr != nil || syncErr != nil || closeErr != nil {
		_ = os.Remove(dst)
		return out, errors.New("failed to stage update package")
	}
	verifier := a.cfg.UpdateVerifierPath
	vst, e := os.Stat(verifier)
	if e != nil || !vst.Mode().IsRegular() || vst.Mode()&0111 == 0 {
		_ = os.Remove(dst)
		return out, errors.New("Privora upload verifier is not installed")
	}
	pub := a.cfg.ReleasePublicKey
	if pst, e := os.Stat(pub); e != nil || !pst.Mode().IsRegular() {
		_ = os.Remove(dst)
		return out, errors.New("Privora release public key is not installed")
	}
	switch detectPrivoraArchiveKind(dst) {
	case "full-core":
		_ = os.Remove(dst)
		return out, errors.New("this is a Privora fresh-install full-core package, not an Update Center package; upload a signed Privora update ZIP instead")
	case "invalid":
		_ = os.Remove(dst)
		return out, errors.New("uploaded file is not a readable ZIP archive")
	}
	c, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	cmd := exec.CommandContext(c, verifier, dst, "--public-key", pub, "--inspect-only")
	b, e := cmd.CombinedOutput()
	if e != nil {
		_ = os.Remove(dst)
		detail := strings.TrimSpace(string(b))
		if detail != "" && len(detail) <= 300 {
			return out, fmt.Errorf("uploaded Privora update package validation failed: %s", detail)
		}
		return out, errors.New("uploaded Privora update package failed signature validation")
	}
	if e = json.Unmarshal(b, &out); e != nil {
		_ = os.Remove(dst)
		return UploadInspection{}, errors.New("invalid verifier response")
	}
	if policy, pe := os.ReadFile("/etc/privora-panel/update-policy.env"); pe == nil {
		for _, line := range strings.Split(string(policy), "\n") {
			if strings.HasPrefix(line, "PRIVORA_UPDATE_CHANNEL=") {
				expected := strings.Trim(strings.TrimPrefix(line, "PRIVORA_UPDATE_CHANNEL="), "'\"")
				if updateChannelRE.MatchString(expected) && expected != out.Channel {
					_ = os.Remove(dst)
					return UploadInspection{}, fmt.Errorf("update package channel %s does not match this server's %s channel; change Maintenance Policy before uploading", out.Channel, expected)
				}
				break
			}
		}
	}
	out.UploadID = id
	out.OriginalName = safeUploadName(in.OriginalName)
	out.StagedPath = dst
	meta, _ := json.MarshalIndent(out, "", "  ")
	if e = os.WriteFile(filepath.Join(a.cfg.UpdateUploadStaging, id+".json"), append(meta, '\n'), 0600); e != nil {
		_ = os.Remove(dst)
		return UploadInspection{}, e
	}
	_ = os.Remove(src)
	return out, nil
}
func safeUploadName(s string) string {
	s = filepath.Base(strings.TrimSpace(s))
	if len(s) > 180 {
		s = s[:180]
	}
	if !regexp.MustCompile(`^[A-Za-z0-9._ -]{1,180}$`).MatchString(s) {
		return "privora-update.zip"
	}
	return s
}

func (a *Adapter) loadUploadInspection(id string) (UploadInspection, error) {
	var out UploadInspection
	if !uploadIDRE.MatchString(id) {
		return out, errors.New("invalid update upload id")
	}
	b, e := os.ReadFile(filepath.Join(a.cfg.UpdateUploadStaging, id+".json"))
	if e != nil {
		return out, errors.New("staged update not found")
	}
	if e = json.Unmarshal(b, &out); e != nil {
		return UploadInspection{}, errors.New("staged update metadata is invalid")
	}
	out.UploadID = id
	out.StagedPath = filepath.Join(a.cfg.UpdateUploadStaging, id+".zip")
	return out, nil
}

func updateJournalEscape(v string) string {
	v = strings.ReplaceAll(v, "\n", " ")
	v = strings.ReplaceAll(v, "\r", " ")
	v = strings.TrimSpace(v)
	if len(v) > 512 {
		v = v[:512]
	}
	return strings.ReplaceAll(v, " ", `\ `)
}

func (a *Adapter) appendUpdateLaunchJournal(id string, fields map[string]string) error {
	if !uploadIDRE.MatchString(id) {
		return errors.New("invalid update transaction id")
	}
	dir := filepath.Join(a.cfg.UpdateStateRoot, id)
	if err := os.MkdirAll(dir, 0750); err != nil {
		return err
	}
	f, err := os.OpenFile(filepath.Join(dir, "journal.env"), os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0600)
	if err != nil {
		return err
	}
	defer f.Close()
	order := []string{"started_at", "phase", "status", "phase_started_at", "activity_at", "operation", "error"}
	for _, k := range order {
		if v, ok := fields[k]; ok {
			if _, err = fmt.Fprintf(f, "%s=%s\n", k, updateJournalEscape(v)); err != nil {
				return err
			}
		}
	}
	return f.Sync()
}

func (a *Adapter) verifyRootPassword(ctx context.Context, password string) error {
	if len(password) < 1 || len(password) > 1024 {
		return errors.New("root authentication failed")
	}
	pam, ok := commandExists("pamtester")
	if !ok {
		return errors.New("root reauthorization is unavailable: pamtester is not installed")
	}
	c, cancel := context.WithTimeout(ctx, 8*time.Second)
	defer cancel()
	cmd := exec.CommandContext(c, pam, "login", "root", "authenticate")
	cmd.Stdin = strings.NewReader(password + "\n")
	cmd.Stdout = io.Discard
	cmd.Stderr = io.Discard
	if e := cmd.Run(); e != nil {
		return errors.New("root authentication failed")
	}
	return nil
}

func (a *Adapter) StartUploadedUpdate(ctx context.Context, in UploadInstallStart) (UpdateJob, error) {
	var out UpdateJob
	if !a.cfg.AllowMutations {
		return out, errors.New("host mutations disabled")
	}
	if e := a.requireCertified("privora-updater"); e != nil {
		return out, e
	}
	ins, e := a.loadUploadInspection(in.UploadID)
	if e != nil {
		return out, e
	}
	st, e := os.Stat(ins.StagedPath)
	if e != nil || !st.Mode().IsRegular() {
		return out, errors.New("staged update package is missing")
	}
	if e = a.verifyRootPassword(ctx, in.RootPassword); e != nil {
		return out, e
	}
	// The caller-supplied credential is needed only for PAM verification.
	in.RootPassword = ""
	if e = os.MkdirAll(a.cfg.UpdateAuthRoot, 0700); e != nil {
		return out, e
	}
	_ = os.Chmod(a.cfg.UpdateAuthRoot, 0700)
	// Authorization is transaction-bound and root-owned.  Do not carry a secret
	// bearer token on the transient systemd unit command line.  The updater
	// derives this exact path from its validated transaction id and consumes it
	// once during preflight.
	cleanupUpdateArtifacts(a.cfg.UpdateAuthRoot, 10*time.Minute, regexp.MustCompile(`^[0-9]{8}T[0-9]{6}Z-[0-9a-f]{16}\.json$`))
	auth := updateAuthToken{UploadID: in.UploadID, ZipSHA256: ins.ZipSHA256, Version: ins.Version, Actor: strings.TrimSpace(in.Actor), ExpiresAt: time.Now().UTC().Add(2 * time.Minute).Format(time.RFC3339)}
	raw, _ := json.Marshal(auth)
	authPath := filepath.Join(a.cfg.UpdateAuthRoot, in.UploadID+".json")
	tmpAuthPath := authPath + ".tmp"
	if e = os.WriteFile(tmpAuthPath, append(raw, '\n'), 0600); e != nil {
		return out, e
	}
	_ = os.Chmod(tmpAuthPath, 0600)
	if e = os.Rename(tmpAuthPath, authPath); e != nil {
		_ = os.Remove(tmpAuthPath)
		return out, e
	}
	updaterSt, e := os.Stat(a.cfg.UpdaterPath)
	if e != nil || !updaterSt.Mode().IsRegular() || updaterSt.Mode()&0111 == 0 {
		_ = os.Remove(authPath)
		return out, errors.New("Privora updater is not installed")
	}
	sr, ok := commandExists("systemd-run")
	if !ok {
		_ = os.Remove(authPath)
		return out, errors.New("systemd-run not installed")
	}
	now := time.Now().UTC().Format(time.RFC3339)
	if e = a.appendUpdateLaunchJournal(in.UploadID, map[string]string{
		"started_at": now, "phase": "launch", "status": "running",
		"phase_started_at": now, "activity_at": now, "operation": "Launching privileged update worker",
	}); e != nil {
		_ = os.Remove(authPath)
		return out, fmt.Errorf("initialize update transaction journal: %w", e)
	}
	unit := "privora-update-" + in.UploadID
	args := []string{"--unit", unit, "--collect", "--property=Nice=10", "--property=IOSchedulingClass=best-effort", "--", a.cfg.UpdaterPath, "--uploaded-zip", ins.StagedPath, "--transaction-id", in.UploadID, "--channel", ins.Channel}
	c, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	cmd := exec.CommandContext(c, sr, args...)
	b, e := cmd.CombinedOutput()
	if e != nil {
		_ = os.Remove(authPath)
		msg := fmt.Sprintf("launch uploaded update job: %v: %s", e, strings.TrimSpace(string(b)))
		_ = a.appendUpdateLaunchJournal(in.UploadID, map[string]string{
			"status": "failed", "activity_at": time.Now().UTC().Format(time.RFC3339),
			"operation": "Update worker failed to launch", "error": msg,
		})
		return out, errors.New(msg)
	}
	// Do not include the token-bearing command in the API response or audit stream.
	return UpdateJob{ID: in.UploadID, Unit: unit, Mode: "uploaded", Channel: ins.Channel, Status: "accepted"}, nil
}

func (a *Adapter) RootReauthAvailable() bool { _, ok := commandExists("pamtester"); return ok }

func (a *Adapter) WriteUpdatePolicy(channel string, securityAuto, packageAuto, majorManual, autoReboot bool, reboot string) error {
	if !a.cfg.AllowMutations {
		return errors.New("host mutations disabled")
	}
	if e := a.requireCertified("privora-updater"); e != nil {
		return e
	}
	if !updateChannelRE.MatchString(channel) {
		return errors.New("invalid update channel")
	}
	if !regexp.MustCompile(`^[A-Za-z]{3} [0-2][0-9]:[0-5][0-9]$`).MatchString(reboot) {
		return errors.New("invalid reboot window")
	}
	path := "/etc/privora-panel/update-policy.env"
	releaseLine := fmt.Sprintf("PRIVORA_UPDATE_RELEASE_URL=https://downloads.privora.example/releases/%s/privora-panel-current.tar.zst", channel)
	appLine := "PRIVORA_APP_MANIFEST_URL=https://downloads.privora.example/apps/releases.json"
	if existing, err := os.ReadFile(path); err == nil {
		for _, line := range strings.Split(string(existing), "\n") {
			if regexp.MustCompile(`^PRIVORA_UPDATE_RELEASE_URL=https://[A-Za-z0-9._~:/?#\[\]@!$&()*+,;=%-]+$`).MatchString(line) {
				releaseLine = line
			}
			if regexp.MustCompile(`^PRIVORA_APP_MANIFEST_URL=https://[A-Za-z0-9._~:/?#\[\]@!$&()*+,;=%-]+$`).MatchString(line) {
				appLine = line
			}
		}
	}
	b := fmt.Sprintf("PRIVORA_SECURITY_AUTO=%d\nPRIVORA_PACKAGE_AUTO=%d\nPRIVORA_MAJOR_VERSIONS_MANUAL=%d\nPRIVORA_AUTO_REBOOT=%d\nPRIVORA_UPDATE_CHANNEL=%s\n%s\n%s\nPRIVORA_REBOOT_WINDOW='%s'\n", bi(securityAuto), bi(packageAuto), bi(majorManual), bi(autoReboot), channel, releaseLine, appLine, reboot)
	if e := os.MkdirAll(filepath.Dir(path), 0750); e != nil {
		return e
	}
	tmp := path + ".tmp"
	if e := os.WriteFile(tmp, []byte(b), 0640); e != nil {
		return e
	}
	return os.Rename(tmp, path)
}
func bi(v bool) int {
	if v {
		return 1
	}
	return 0
}
