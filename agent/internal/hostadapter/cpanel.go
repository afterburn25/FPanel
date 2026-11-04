package hostadapter

import (
	"archive/tar"
	"compress/gzip"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

type CPanelStageResult struct {
	Destination string         `json:"destination"`
	Manifest    CPanelManifest `json:"manifest"`
	Bytes       int64          `json:"bytes"`
}

// StageCPanelBackup safely expands a cPanel tar/tar.gz into a new private
// staging directory. It never follows archive links, never overwrites an
// existing destination and does not preserve privileged ownership/mode bits.
func StageCPanelBackup(path, destination string, maxBytes int64) (CPanelStageResult, error) {
	manifest, err := InspectCPanelBackup(path)
	if err != nil {
		return CPanelStageResult{}, err
	}
	if maxBytes <= 0 {
		maxBytes = 20 << 30
	}
	if manifest.Entries > 200000 {
		return CPanelStageResult{}, errors.New("cPanel backup has too many entries")
	}
	dest, err := filepath.Abs(destination)
	if err != nil {
		return CPanelStageResult{}, err
	}
	if _, err := os.Lstat(dest); !os.IsNotExist(err) {
		if err == nil {
			return CPanelStageResult{}, errors.New("migration destination already exists")
		}
		return CPanelStageResult{}, err
	}
	parent := filepath.Dir(dest)
	if err := os.MkdirAll(parent, 0750); err != nil {
		return CPanelStageResult{}, err
	}
	stage, err := os.MkdirTemp(parent, ".privora-cpanel-stage-")
	if err != nil {
		return CPanelStageResult{}, err
	}
	keep := false
	defer func() {
		if !keep {
			_ = os.RemoveAll(stage)
		}
	}()

	f, err := os.Open(path)
	if err != nil {
		return CPanelStageResult{}, err
	}
	defer f.Close()
	var r io.Reader = f
	if strings.HasSuffix(path, ".gz") || strings.HasSuffix(path, ".tgz") {
		gz, e := gzip.NewReader(f)
		if e != nil {
			return CPanelStageResult{}, e
		}
		defer gz.Close()
		r = gz
	}
	tr := tar.NewReader(r)
	var total int64
	for {
		h, e := tr.Next()
		if e == io.EOF {
			break
		}
		if e != nil {
			return CPanelStageResult{}, e
		}
		clean := filepath.Clean(h.Name)
		if filepath.IsAbs(clean) || clean == "." || clean == ".." || strings.HasPrefix(clean, ".."+string(os.PathSeparator)) {
			return CPanelStageResult{}, errors.New("unsafe path in cPanel backup")
		}
		if h.Typeflag == tar.TypeSymlink || h.Typeflag == tar.TypeLink {
			return CPanelStageResult{}, errors.New("links are not accepted during cPanel staging")
		}
		target := filepath.Join(stage, clean)
		rel, err := filepath.Rel(stage, target)
		if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(os.PathSeparator)) {
			return CPanelStageResult{}, errors.New("unsafe migration target")
		}
		switch h.Typeflag {
		case tar.TypeDir:
			if err := os.MkdirAll(target, 0750); err != nil {
				return CPanelStageResult{}, err
			}
		case tar.TypeReg, tar.TypeRegA:
			if h.Size < 0 || total+h.Size > maxBytes {
				return CPanelStageResult{}, errors.New("cPanel backup exceeds staging size limit")
			}
			if err := os.MkdirAll(filepath.Dir(target), 0750); err != nil {
				return CPanelStageResult{}, err
			}
			out, err := os.OpenFile(target, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0640)
			if err != nil {
				return CPanelStageResult{}, err
			}
			n, copyErr := io.CopyN(out, tr, h.Size)
			closeErr := out.Close()
			if copyErr != nil {
				return CPanelStageResult{}, copyErr
			}
			if closeErr != nil {
				return CPanelStageResult{}, closeErr
			}
			if n != h.Size {
				return CPanelStageResult{}, fmt.Errorf("short cPanel archive entry: %s", clean)
			}
			total += n
		default:
			return CPanelStageResult{}, fmt.Errorf("unsupported cPanel archive entry type %d", h.Typeflag)
		}
	}
	if err := os.Rename(stage, dest); err != nil {
		return CPanelStageResult{}, err
	}
	keep = true
	return CPanelStageResult{Destination: dest, Manifest: manifest, Bytes: total}, nil
}
