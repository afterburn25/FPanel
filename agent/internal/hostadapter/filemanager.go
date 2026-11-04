package hostadapter

import (
	"archive/zip"
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"syscall"
	"time"
)

type AccountFileContent struct {
	Path     string    `json:"path"`
	Name     string    `json:"name"`
	Size     int64     `json:"size"`
	Mode     string    `json:"mode"`
	Modified time.Time `json:"modified"`
	Content  []byte    `json:"-"`
}

type AccountFileSearchResult struct {
	Path     string    `json:"path"`
	Name     string    `json:"name"`
	Type     string    `json:"type"`
	Size     int64     `json:"size"`
	Mode     string    `json:"mode"`
	Modified time.Time `json:"modified"`
}

func (a *Adapter) accountPath(username, rel string, targetMayBeSymlink bool) (string, string, error) {
	if err := a.requireCertified("linux-users"); err != nil {
		return "", "", err
	}
	if _, _, err := accountIdentity(username); err != nil {
		return "", "", err
	}
	parts, clean, err := safeFileRelative(rel)
	if err != nil || len(parts) == 0 {
		return "", "", errors.New("invalid account file path")
	}
	base := filepath.Join(a.cfg.AccountHomeBase, username)
	cur := base
	for i, part := range parts {
		cur = filepath.Join(cur, part)
		info, statErr := os.Lstat(cur)
		if statErr != nil {
			if errors.Is(statErr, os.ErrNotExist) && i == len(parts)-1 {
				break
			}
			return "", "", statErr
		}
		if info.Mode()&os.ModeSymlink != 0 {
			if i == len(parts)-1 && targetMayBeSymlink {
				break
			}
			return "", "", errors.New("symlink paths are not followed by the control panel")
		}
		if i < len(parts)-1 && !info.IsDir() {
			return "", "", errors.New("path parent is not a directory")
		}
	}
	full := filepath.Join(base, clean)
	basePrefix := filepath.Clean(base) + string(os.PathSeparator)
	if !stringsHasPathPrefix(filepath.Clean(full)+string(os.PathSeparator), basePrefix) {
		return "", "", errors.New("file path escaped account home")
	}
	return full, clean, nil
}

func (a *Adapter) ReadAccountFile(username, rel string, maxBytes int64) (AccountFileContent, error) {
	if maxBytes <= 0 || maxBytes > 32<<20 {
		maxBytes = 4 << 20
	}
	full, clean, err := a.accountPath(username, rel, false)
	if err != nil {
		return AccountFileContent{}, err
	}
	f, err := os.Open(full)
	if err != nil {
		return AccountFileContent{}, err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return AccountFileContent{}, err
	}
	if !info.Mode().IsRegular() {
		return AccountFileContent{}, errors.New("only regular files can be opened")
	}
	if info.Size() > maxBytes {
		return AccountFileContent{}, fmt.Errorf("file exceeds %d byte control-panel limit", maxBytes)
	}
	b, err := io.ReadAll(io.LimitReader(f, maxBytes+1))
	if err != nil {
		return AccountFileContent{}, err
	}
	if int64(len(b)) > maxBytes {
		return AccountFileContent{}, errors.New("file exceeds control-panel limit")
	}
	return AccountFileContent{Path: clean, Name: filepath.Base(clean), Size: info.Size(), Mode: info.Mode().Perm().String(), Modified: info.ModTime().UTC(), Content: b}, nil
}

func (a *Adapter) WriteAccountBytes(username, rel string, content []byte) (AccountFileEntry, error) {
	if err := a.requireCertified("linux-users"); err != nil {
		return AccountFileEntry{}, err
	}
	if !a.cfg.AllowMutations {
		return AccountFileEntry{}, errors.New("host mutations disabled")
	}
	if len(content) > 32<<20 {
		return AccountFileEntry{}, errors.New("upload exceeds 32 MiB control-panel limit")
	}
	uid, gid, err := accountIdentity(username)
	if err != nil {
		return AccountFileEntry{}, err
	}
	parts, clean, err := safeFileRelative(rel)
	if err != nil || len(parts) == 0 {
		return AccountFileEntry{}, errors.New("invalid file path")
	}
	base := filepath.Join(a.cfg.AccountHomeBase, username)
	parent, err := openDirNoFollow(base, parts[:len(parts)-1], true, uid, gid)
	if err != nil {
		return AccountFileEntry{}, err
	}
	defer parent.Close()
	name := parts[len(parts)-1]
	fd, err := syscall.Openat(int(parent.Fd()), name, syscall.O_WRONLY|syscall.O_CREAT|syscall.O_TRUNC|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0640)
	if err != nil {
		return AccountFileEntry{}, fmt.Errorf("open upload target: %w", err)
	}
	f := os.NewFile(uintptr(fd), name)
	defer f.Close()
	if err := syscall.Fchown(fd, uid, gid); err != nil {
		return AccountFileEntry{}, err
	}
	if err := syscall.Fchmod(fd, 0640); err != nil {
		return AccountFileEntry{}, err
	}
	if _, err := io.Copy(f, bytes.NewReader(content)); err != nil {
		return AccountFileEntry{}, err
	}
	if err := f.Sync(); err != nil {
		return AccountFileEntry{}, err
	}
	info, err := f.Stat()
	if err != nil {
		return AccountFileEntry{}, err
	}
	return AccountFileEntry{Name: name, Path: clean, Type: "file", Size: info.Size(), Mode: info.Mode().Perm().String(), Modified: info.ModTime().UTC()}, nil
}

func (a *Adapter) CreateAccountDirectory(username, rel string) (AccountFileEntry, error) {
	if err := a.requireCertified("linux-users"); err != nil {
		return AccountFileEntry{}, err
	}
	if !a.cfg.AllowMutations {
		return AccountFileEntry{}, errors.New("host mutations disabled")
	}
	uid, gid, err := accountIdentity(username)
	if err != nil {
		return AccountFileEntry{}, err
	}
	parts, clean, err := safeFileRelative(rel)
	if err != nil || len(parts) == 0 {
		return AccountFileEntry{}, errors.New("invalid directory path")
	}
	base := filepath.Join(a.cfg.AccountHomeBase, username)
	parent, err := openDirNoFollow(base, parts[:len(parts)-1], true, uid, gid)
	if err != nil {
		return AccountFileEntry{}, err
	}
	defer parent.Close()
	name := parts[len(parts)-1]
	if err := syscall.Mkdirat(int(parent.Fd()), name, 0750); err != nil && !errors.Is(err, syscall.EEXIST) {
		return AccountFileEntry{}, err
	}
	full := filepath.Join(base, clean)
	if err := os.Chown(full, uid, gid); err != nil {
		return AccountFileEntry{}, err
	}
	_ = os.Chmod(full, 0750)
	info, err := os.Stat(full)
	if err != nil {
		return AccountFileEntry{}, err
	}
	if !info.IsDir() {
		return AccountFileEntry{}, errors.New("target exists and is not a directory")
	}
	return AccountFileEntry{Name: name, Path: clean, Type: "directory", Size: info.Size(), Mode: info.Mode().Perm().String(), Modified: info.ModTime().UTC()}, nil
}

func (a *Adapter) RenameAccountPath(username, from, to string) error {
	if err := a.requireCertified("linux-users"); err != nil {
		return err
	}
	if !a.cfg.AllowMutations {
		return errors.New("host mutations disabled")
	}
	uid, gid, err := accountIdentity(username)
	if err != nil {
		return err
	}
	fromParts, _, err := safeFileRelative(from)
	if err != nil || len(fromParts) == 0 {
		return errors.New("invalid source path")
	}
	toParts, _, err := safeFileRelative(to)
	if err != nil || len(toParts) == 0 {
		return errors.New("invalid destination path")
	}
	base := filepath.Join(a.cfg.AccountHomeBase, username)
	sf, err := openDirNoFollow(base, fromParts[:len(fromParts)-1], false, uid, gid)
	if err != nil {
		return err
	}
	defer sf.Close()
	df, err := openDirNoFollow(base, toParts[:len(toParts)-1], true, uid, gid)
	if err != nil {
		return err
	}
	defer df.Close()
	if _, err := os.Lstat(filepath.Join(base, filepath.Clean(to))); err == nil {
		return errors.New("destination already exists")
	}
	return syscall.Renameat(int(sf.Fd()), fromParts[len(fromParts)-1], int(df.Fd()), toParts[len(toParts)-1])
}

func copyAccountTree(src, dst string, uid, gid int) error {
	info, err := os.Lstat(src)
	if err != nil {
		return err
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return errors.New("copying symbolic links is not supported")
	}
	if info.IsDir() {
		if err := os.Mkdir(dst, info.Mode().Perm()); err != nil && !errors.Is(err, os.ErrExist) {
			return err
		}
		_ = os.Chown(dst, uid, gid)
		_ = os.Chmod(dst, info.Mode().Perm()&0777)
		ents, err := os.ReadDir(src)
		if err != nil {
			return err
		}
		for _, e := range ents {
			if err := copyAccountTree(filepath.Join(src, e.Name()), filepath.Join(dst, e.Name()), uid, gid); err != nil {
				return err
			}
		}
		return nil
	}
	if !info.Mode().IsRegular() {
		return errors.New("only regular files and directories can be copied")
	}
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.OpenFile(dst, os.O_CREATE|os.O_EXCL|os.O_WRONLY, info.Mode().Perm()&0777)
	if err != nil {
		return err
	}
	ok := false
	defer func() {
		_ = out.Close()
		if !ok {
			_ = os.Remove(dst)
		}
	}()
	if _, err = io.Copy(out, in); err != nil {
		return err
	}
	if err = out.Sync(); err != nil {
		return err
	}
	if err = out.Close(); err != nil {
		return err
	}
	_ = os.Chown(dst, uid, gid)
	ok = true
	return nil
}

func pathIsWithin(parent, child string) bool {
	parent = filepath.Clean(parent)
	child = filepath.Clean(child)
	rel, err := filepath.Rel(parent, child)
	if err != nil {
		return false
	}
	return rel == "." || (rel != ".." && !strings.HasPrefix(rel, ".."+string(os.PathSeparator)))
}

func (a *Adapter) CopyAccountPath(username, from, to string) error {
	if !a.cfg.AllowMutations {
		return errors.New("host mutations disabled")
	}
	uid, gid, err := accountIdentity(username)
	if err != nil {
		return err
	}
	src, _, err := a.accountPath(username, from, false)
	if err != nil {
		return err
	}
	srcInfo, err := os.Lstat(src)
	if err != nil {
		return err
	}
	toParts, toClean, err := safeFileRelative(to)
	if err != nil || len(toParts) == 0 {
		return errors.New("invalid destination path")
	}
	base := filepath.Join(a.cfg.AccountHomeBase, username)
	parent, err := openDirNoFollow(base, toParts[:len(toParts)-1], true, uid, gid)
	if err != nil {
		return err
	}
	_ = parent.Close()
	dst := filepath.Join(base, toClean)
	if srcInfo.IsDir() && pathIsWithin(src, dst) {
		return errors.New("cannot copy a directory into itself")
	}
	if _, err := os.Lstat(dst); err == nil {
		return errors.New("destination already exists")
	}
	return copyAccountTree(src, dst, uid, gid)
}

func (a *Adapter) DeleteAccountPath(username, rel string) error {
	if !a.cfg.AllowMutations {
		return errors.New("host mutations disabled")
	}
	full, _, err := a.accountPath(username, rel, true)
	if err != nil {
		return err
	}
	info, err := os.Lstat(full)
	if err != nil {
		return err
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return os.Remove(full)
	}
	return os.RemoveAll(full)
}

func (a *Adapter) ChmodAccountPath(username, rel string, mode os.FileMode) error {
	if !a.cfg.AllowMutations {
		return errors.New("host mutations disabled")
	}
	full, _, err := a.accountPath(username, rel, false)
	if err != nil {
		return err
	}
	mode &= 0777
	return os.Chmod(full, mode)
}

func (a *Adapter) SearchAccountFiles(username, query string, limit int) ([]AccountFileSearchResult, error) {
	if err := a.requireCertified("linux-users"); err != nil {
		return nil, err
	}
	if _, _, err := accountIdentity(username); err != nil {
		return nil, err
	}
	query = strings.ToLower(strings.TrimSpace(query))
	if query == "" {
		return []AccountFileSearchResult{}, nil
	}
	if limit <= 0 || limit > 500 {
		limit = 200
	}
	base := filepath.Join(a.cfg.AccountHomeBase, username)
	out := make([]AccountFileSearchResult, 0)
	visited := 0
	err := filepath.WalkDir(base, func(path string, d os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return nil
		}
		if path == base {
			return nil
		}
		visited++
		if visited > 250000 {
			return io.EOF
		}
		if d.Type()&os.ModeSymlink != 0 {
			if d.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}
		rel, _ := filepath.Rel(base, path)
		if !strings.Contains(strings.ToLower(rel), query) {
			return nil
		}
		info, e := d.Info()
		if e != nil {
			return nil
		}
		typ := "file"
		if d.IsDir() {
			typ = "directory"
		}
		out = append(out, AccountFileSearchResult{Path: rel, Name: d.Name(), Type: typ, Size: info.Size(), Mode: info.Mode().Perm().String(), Modified: info.ModTime().UTC()})
		if len(out) >= limit {
			return io.EOF
		}
		return nil
	})
	if err != nil && !errors.Is(err, io.EOF) {
		return nil, err
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Path < out[j].Path })
	return out, nil
}

func (a *Adapter) CreateAccountZip(username, source, destination string) (AccountFileEntry, error) {
	if !a.cfg.AllowMutations {
		return AccountFileEntry{}, errors.New("host mutations disabled")
	}
	uid, gid, err := accountIdentity(username)
	if err != nil {
		return AccountFileEntry{}, err
	}
	src, srcClean, err := a.accountPath(username, source, false)
	if err != nil {
		return AccountFileEntry{}, err
	}
	srcInfo, err := os.Lstat(src)
	if err != nil {
		return AccountFileEntry{}, err
	}
	if !strings.HasSuffix(strings.ToLower(destination), ".zip") {
		destination += ".zip"
	}
	parts, dstClean, err := safeFileRelative(destination)
	if err != nil || len(parts) == 0 {
		return AccountFileEntry{}, errors.New("invalid archive destination")
	}
	base := filepath.Join(a.cfg.AccountHomeBase, username)
	parent, err := openDirNoFollow(base, parts[:len(parts)-1], true, uid, gid)
	if err != nil {
		return AccountFileEntry{}, err
	}
	_ = parent.Close()
	dst := filepath.Join(base, dstClean)
	if srcInfo.IsDir() && pathIsWithin(src, dst) {
		return AccountFileEntry{}, errors.New("archive destination cannot be inside the source directory")
	}
	if filepath.Clean(src) == filepath.Clean(dst) {
		return AccountFileEntry{}, errors.New("archive destination cannot equal source")
	}
	if _, err := os.Lstat(dst); err == nil {
		return AccountFileEntry{}, errors.New("archive destination already exists")
	}
	f, err := os.OpenFile(dst, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0640)
	if err != nil {
		return AccountFileEntry{}, err
	}
	zw := zip.NewWriter(f)
	ok := false
	defer func() {
		if !ok {
			_ = zw.Close()
			_ = f.Close()
			_ = os.Remove(dst)
		}
	}()
	rootName := filepath.Base(srcClean)
	archiveEntries := 0
	var archiveBytes int64
	err = filepath.Walk(src, func(path string, info os.FileInfo, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if info.Mode()&os.ModeSymlink != 0 {
			return errors.New("archives cannot include symbolic links")
		}
		archiveEntries++
		if archiveEntries > 250000 {
			return errors.New("archive source exceeds 250000 entries")
		}
		if info.Mode().IsRegular() {
			archiveBytes += info.Size()
			if archiveBytes > 4<<30 {
				return errors.New("archive source exceeds 4 GiB control-panel limit")
			}
		}
		rel, e := filepath.Rel(src, path)
		if e != nil {
			return e
		}
		name := rootName
		if rel != "." {
			name = filepath.ToSlash(filepath.Join(rootName, rel))
		}
		if info.IsDir() {
			_, e = zw.Create(name + "/")
			return e
		}
		if !info.Mode().IsRegular() {
			return nil
		}
		hdr, e := zip.FileInfoHeader(info)
		if e != nil {
			return e
		}
		hdr.Name = name
		hdr.Method = zip.Deflate
		w, e := zw.CreateHeader(hdr)
		if e != nil {
			return e
		}
		in, e := os.Open(path)
		if e != nil {
			return e
		}
		_, e = io.Copy(w, in)
		_ = in.Close()
		return e
	})
	if err != nil {
		return AccountFileEntry{}, err
	}
	if err = zw.Close(); err != nil {
		return AccountFileEntry{}, err
	}
	if err = f.Close(); err != nil {
		return AccountFileEntry{}, err
	}
	_ = os.Chown(dst, uid, gid)
	info, err := os.Stat(dst)
	if err != nil {
		return AccountFileEntry{}, err
	}
	ok = true
	return AccountFileEntry{Name: filepath.Base(dstClean), Path: dstClean, Type: "file", Size: info.Size(), Mode: info.Mode().Perm().String(), Modified: info.ModTime().UTC()}, nil
}

func (a *Adapter) ExtractAccountZip(username, archive, destination string) error {
	if !a.cfg.AllowMutations {
		return errors.New("host mutations disabled")
	}
	uid, gid, err := accountIdentity(username)
	if err != nil {
		return err
	}
	src, _, err := a.accountPath(username, archive, false)
	if err != nil {
		return err
	}
	destParts, destClean, err := safeFileRelative(destination)
	if err != nil {
		return err
	}
	base := filepath.Join(a.cfg.AccountHomeBase, username)
	if len(destParts) > 0 {
		d, err := openDirNoFollow(base, destParts, true, uid, gid)
		if err != nil {
			return err
		}
		_ = d.Close()
	}
	zr, err := zip.OpenReader(src)
	if err != nil {
		return err
	}
	defer zr.Close()
	if len(zr.File) > 5000 {
		return errors.New("archive exceeds 5000 entry control-panel limit")
	}
	var declaredTotal uint64
	for _, zf := range zr.File {
		if zf.Mode()&os.ModeSymlink != 0 {
			return errors.New("archive contains symbolic links")
		}
		if !zf.FileInfo().IsDir() && !zf.Mode().IsRegular() {
			return errors.New("archive contains unsupported file type")
		}
		if zf.UncompressedSize64 > 64<<20 {
			return errors.New("archive entry exceeds 64 MiB control-panel limit")
		}
		declaredTotal += zf.UncompressedSize64
		if declaredTotal > 512<<20 {
			return errors.New("archive exceeds 512 MiB extracted-size control-panel limit")
		}
		name := filepath.Clean(filepath.FromSlash(zf.Name))
		if name == "." || filepath.IsAbs(name) || name == ".." || strings.HasPrefix(name, ".."+string(os.PathSeparator)) {
			return errors.New("archive contains unsafe path")
		}
		combined := name
		if len(destParts) > 0 {
			combined = filepath.Join(destClean, name)
		}
		parts, _, err := safeFileRelative(combined)
		if err != nil || len(parts) == 0 {
			return errors.New("archive contains unsafe destination")
		}
	}
	var extractedTotal int64
	for _, zf := range zr.File {
		name := filepath.Clean(filepath.FromSlash(zf.Name))
		combined := name
		if len(destParts) > 0 {
			combined = filepath.Join(destClean, name)
		}
		parts, _, err := safeFileRelative(combined)
		if err != nil || len(parts) == 0 {
			return errors.New("archive contains unsafe destination")
		}
		if zf.FileInfo().IsDir() {
			d, err := openDirNoFollow(base, parts, true, uid, gid)
			if err != nil {
				return err
			}
			_ = d.Close()
			continue
		}
		parent, err := openDirNoFollow(base, parts[:len(parts)-1], true, uid, gid)
		if err != nil {
			return err
		}
		fd, err := syscall.Openat(int(parent.Fd()), parts[len(parts)-1], syscall.O_WRONLY|syscall.O_CREAT|syscall.O_TRUNC|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, uint32(zf.Mode().Perm()&0777))
		_ = parent.Close()
		if err != nil {
			return err
		}
		out := os.NewFile(uintptr(fd), parts[len(parts)-1])
		rc, err := zf.Open()
		if err != nil {
			_ = out.Close()
			return err
		}
		written, copyErr := io.Copy(out, io.LimitReader(rc, (64<<20)+1))
		_ = rc.Close()
		extractedTotal += written
		if copyErr == nil && extractedTotal > 512<<20 {
			copyErr = errors.New("archive exceeds 512 MiB extracted-size control-panel limit")
		}
		if copyErr == nil && written > 64<<20 {
			copyErr = errors.New("archive entry exceeds 64 MiB control-panel limit")
		}
		if copyErr == nil {
			copyErr = syscall.Fchown(fd, uid, gid)
		}
		if copyErr == nil {
			copyErr = out.Sync()
		}
		closeErr := out.Close()
		if copyErr != nil {
			_ = os.Remove(filepath.Join(base, filepath.Join(parts...)))
			return copyErr
		}
		if closeErr != nil {
			return closeErr
		}
	}
	return nil
}
