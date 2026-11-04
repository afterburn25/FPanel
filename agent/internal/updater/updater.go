package updater

import (
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

var versionRE = regexp.MustCompile(`^[0-9]+\.[0-9]+\.[0-9]+(?:[-.][A-Za-z0-9][A-Za-z0-9.-]*)?$`)

type Manifest struct {
	Version      string   `json:"version"`
	Channel      string   `json:"channel"`
	BundleSHA256 string   `json:"bundle_sha256"`
	MinVersion   string   `json:"min_version,omitempty"`
	Services     []string `json:"services,omitempty"`
	Migrations   []string `json:"migrations,omitempty"`
	CreatedAt    string   `json:"created_at"`
}
type Plan struct {
	Version      string   `json:"version"`
	Channel      string   `json:"channel"`
	Automatic    bool     `json:"automatic"`
	SecurityOnly bool     `json:"security_only"`
	Steps        []string `json:"steps"`
	Rollback     []string `json:"rollback"`
}
type Journal struct {
	ID              string    `json:"id"`
	OldVersion      string    `json:"old_version"`
	NewVersion      string    `json:"new_version,omitempty"`
	Phase           string    `json:"phase"`
	Status          string    `json:"status"`
	BackupPath      string    `json:"backup_path,omitempty"`
	Error           string    `json:"error,omitempty"`
	Operation       string    `json:"operation,omitempty"`
	FailedPhase     string    `json:"failed_phase,omitempty"`
	FailedOperation string    `json:"failed_operation,omitempty"`
	FailedCommand   string    `json:"failed_command,omitempty"`
	FailedRC        string    `json:"failed_rc,omitempty"`
	FailedError     string    `json:"failed_error,omitempty"`
	StartedAt       time.Time `json:"started_at,omitempty"`
	PhaseStartedAt  time.Time `json:"phase_started_at,omitempty"`
	ActivityAt      time.Time `json:"activity_at,omitempty"`
	UpdatedAt       time.Time `json:"updated_at"`
}

func ValidateManifest(m Manifest) error {
	if !versionRE.MatchString(m.Version) {
		return errors.New("invalid release version")
	}
	if m.Channel != "stable" && m.Channel != "early-access" && m.Channel != "developer" {
		return errors.New("invalid release channel")
	}
	if len(m.BundleSHA256) != 64 {
		return errors.New("invalid bundle sha256")
	}
	if _, e := hex.DecodeString(m.BundleSHA256); e != nil {
		return errors.New("invalid bundle sha256")
	}
	if strings.TrimSpace(m.CreatedAt) == "" {
		return errors.New("missing release timestamp")
	}
	return nil
}
func VerifySignedManifest(raw, sig, bundle, pubPEM []byte) (Manifest, error) {
	var m Manifest
	if e := json.Unmarshal(raw, &m); e != nil {
		return m, e
	}
	if e := ValidateManifest(m); e != nil {
		return m, e
	}
	b, _ := pem.Decode(pubPEM)
	if b == nil {
		return m, errors.New("invalid release public key PEM")
	}
	k, e := x509.ParsePKIXPublicKey(b.Bytes)
	if e != nil {
		return m, e
	}
	pub, ok := k.(*rsa.PublicKey)
	if !ok {
		return m, errors.New("release public key must be RSA")
	}
	d := sha256.Sum256(raw)
	if e = rsa.VerifyPKCS1v15(pub, crypto.SHA256, d[:], sig); e != nil {
		return m, errors.New("release signature verification failed")
	}
	got := sha256.Sum256(bundle)
	if hex.EncodeToString(got[:]) != strings.ToLower(m.BundleSHA256) {
		return m, errors.New("release bundle checksum mismatch")
	}
	return m, nil
}
func BuildPlan(v, c string, a, s bool) Plan {
	p := Plan{Version: v, Channel: c, Automatic: a, SecurityOnly: s, Steps: []string{"preflight-supported-os-and-capacity", "snapshot-privora-config-state", "snapshot-service-configurations", "update-system-package-index"}, Rollback: []string{"stop-promotion", "restore-previous-release", "restore-config-snapshot", "restart-previous-services", "health-check-previous-release"}}
	if s {
		p.Steps = append(p.Steps, "apply-security-library-updates", "validate-configurations", "restart-affected-services", "health-check")
	} else {
		p.Steps = append(p.Steps, "download-release-over-https", "verify-release-signature-and-sha256", "resolve-and-verify-application-dependencies", "stage-release-private", "preflight-database-migrations", "apply-database-migrations", "validate-nginx-php-and-runtime-config", "atomic-release-promotion", "restart-affected-services", "health-check")
	}
	return p
}
func WriteJournal(path string, j Journal) error {
	if j.ID == "" || j.Phase == "" || (j.Status != "running" && j.Status != "pass" && j.Status != "failed" && j.Status != "rolled-back") {
		return errors.New("invalid update journal")
	}
	j.UpdatedAt = time.Now().UTC()
	b, e := json.MarshalIndent(j, "", "  ")
	if e != nil {
		return e
	}
	if e = os.MkdirAll(filepath.Dir(path), 0750); e != nil {
		return e
	}
	tmp := path + ".tmp"
	if e = os.WriteFile(tmp, append(b, '\n'), 0600); e != nil {
		return e
	}
	return os.Rename(tmp, path)
}
func ReadJournal(path string) (Journal, error) {
	var j Journal
	b, e := os.ReadFile(path)
	if e != nil {
		return j, e
	}
	e = json.Unmarshal(b, &j)
	return j, e
}

var journalIDRE = regexp.MustCompile(`^[0-9A-Za-z._-]{6,96}$`)

func readEnvJournal(path, id string) (Journal, error) {
	bp, e := os.ReadFile(path)
	if e != nil {
		return Journal{}, e
	}
	j := Journal{ID: id, Status: "running", Phase: "unknown"}
	for _, line := range strings.Split(string(bp), "\n") {
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		parts := strings.SplitN(line, "=", 2)
		if len(parts) != 2 {
			continue
		}
		key, val := parts[0], strings.Trim(parts[1], "'\"")
		// journal values are shell-escaped by the updater.  The fields surfaced here
		// are deliberately simple identifiers/paths; strip the common %q escapes
		// without evaluating shell syntax.
		val = strings.ReplaceAll(val, `\ `, " ")
		switch key {
		case "result":
			if strings.Contains(val, "pass") {
				j.Status = "pass"
				j.Phase = "complete"
			}
			if strings.Contains(val, "rolled-back") {
				j.Status = "rolled-back"
			}
		case "status":
			if val != "" {
				j.Status = val
			}
		case "phase":
			if val != "" {
				j.Phase = val
			}
		case "old_version":
			j.OldVersion = val
		case "new_version":
			j.NewVersion = val
		case "backup":
			j.BackupPath = val
		case "error":
			j.Error = val
		case "operation":
			j.Operation = val
		case "failed_phase":
			j.FailedPhase = val
		case "failed_operation":
			j.FailedOperation = val
		case "failed_command":
			j.FailedCommand = val
		case "failed_rc":
			j.FailedRC = val
		case "failed_error":
			j.FailedError = val
		case "started_at":
			if t, err := time.Parse(time.RFC3339, val); err == nil {
				j.StartedAt = t.UTC()
			}
		case "phase_started_at":
			if t, err := time.Parse(time.RFC3339, val); err == nil {
				j.PhaseStartedAt = t.UTC()
			}
		case "activity_at":
			if t, err := time.Parse(time.RFC3339, val); err == nil {
				j.ActivityAt = t.UTC()
			}
		}
	}
	if st, e := os.Stat(path); e == nil {
		j.UpdatedAt = st.ModTime().UTC()
	}
	return j, nil
}

func TransactionJournal(root, id string) (Journal, error) {
	if !journalIDRE.MatchString(id) {
		return Journal{}, errors.New("invalid update transaction id")
	}
	dir := filepath.Join(root, id)
	jp := filepath.Join(dir, "journal.json")
	if _, e := os.Stat(jp); e == nil {
		return ReadJournal(jp)
	}
	return readEnvJournal(filepath.Join(dir, "journal.env"), id)
}

func LatestJournal(root string) (Journal, error) {
	es, e := os.ReadDir(root)
	if e != nil {
		return Journal{}, e
	}
	var n os.DirEntry
	for _, x := range es {
		if x.IsDir() && journalIDRE.MatchString(x.Name()) && (n == nil || x.Name() > n.Name()) {
			n = x
		}
	}
	if n == nil {
		return Journal{}, os.ErrNotExist
	}
	return TransactionJournal(root, n.Name())
}

var _ = fmt.Sprintf
