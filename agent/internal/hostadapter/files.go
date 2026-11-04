package hostadapter

import (
	"errors"
	"fmt"
	"os"
	"os/user"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"
)

type AccountFileEntry struct {
	Name     string    `json:"name"`
	Path     string    `json:"path"`
	Type     string    `json:"type"`
	Size     int64     `json:"size"`
	Mode     string    `json:"mode"`
	Modified time.Time `json:"modified"`
}

func safeFileRelative(v string) ([]string, string, error) {
	v = strings.TrimSpace(v)
	if v == "" || v == "." {
		return nil, ".", nil
	}
	if filepath.IsAbs(v) || strings.ContainsRune(v, '\x00') {
		return nil, "", errors.New("absolute/NUL file path rejected")
	}
	clean := filepath.Clean(v)
	if clean == ".." || strings.HasPrefix(clean, ".."+string(os.PathSeparator)) {
		return nil, "", errors.New("path traversal rejected")
	}
	parts := strings.Split(clean, string(os.PathSeparator))
	for _, p := range parts {
		if p == "" || p == "." || p == ".." {
			return nil, "", errors.New("unsafe file path component")
		}
	}
	return parts, clean, nil
}

func openDirNoFollow(base string, parts []string, create bool, uid, gid int) (*os.File, error) {
	fd, err := syscall.Open(base, syscall.O_RDONLY|syscall.O_DIRECTORY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	for _, part := range parts {
		next, e := syscall.Openat(fd, part, syscall.O_RDONLY|syscall.O_DIRECTORY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
		if e != nil && create && errors.Is(e, syscall.ENOENT) {
			if e = syscall.Mkdirat(fd, part, 0750); e != nil && !errors.Is(e, syscall.EEXIST) {
				syscall.Close(fd)
				return nil, e
			}
			next, e = syscall.Openat(fd, part, syscall.O_RDONLY|syscall.O_DIRECTORY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
			if e == nil {
				_ = syscall.Fchown(next, uid, gid)
				_ = syscall.Fchmod(next, 0750)
			}
		}
		if e != nil {
			syscall.Close(fd)
			return nil, fmt.Errorf("unsafe or unavailable directory component %q: %w", part, e)
		}
		syscall.Close(fd)
		fd = next
	}
	openedName := base
	if len(parts) > 0 {
		openedName = filepath.Join(append([]string{base}, parts...)...)
	}
	return os.NewFile(uintptr(fd), openedName), nil
}

func accountIdentity(username string) (int, int, error) {
	if !validUser(username) {
		return 0, 0, errors.New("invalid username")
	}
	u, err := user.Lookup(username)
	if err != nil {
		return 0, 0, errors.New("hosting user does not exist")
	}
	uid64, err := strconv.ParseInt(u.Uid, 10, 32)
	if err != nil {
		return 0, 0, err
	}
	gid64, err := strconv.ParseInt(u.Gid, 10, 32)
	if err != nil {
		return 0, 0, err
	}
	return int(uid64), int(gid64), nil
}

func (a *Adapter) ListAccountFiles(username, rel string) ([]AccountFileEntry, error) {
	if err := a.requireCertified("linux-users"); err != nil {
		return nil, err
	}
	uid, gid, err := accountIdentity(username)
	if err != nil {
		return nil, err
	}
	_, _ = uid, gid
	parts, clean, err := safeFileRelative(rel)
	if err != nil {
		return nil, err
	}
	base := filepath.Join(a.cfg.AccountHomeBase, username)
	f, err := openDirNoFollow(base, parts, false, uid, gid)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	ents, err := f.ReadDir(-1)
	if err != nil {
		return nil, err
	}
	out := make([]AccountFileEntry, 0, len(ents))
	for _, e := range ents {
		info, infoErr := e.Info()
		if infoErr != nil {
			continue
		}
		typ := "file"
		if e.IsDir() {
			typ = "directory"
		} else if e.Type()&os.ModeSymlink != 0 {
			typ = "symlink"
		}
		p := e.Name()
		if clean != "." {
			p = filepath.Join(clean, e.Name())
		}
		out = append(out, AccountFileEntry{Name: e.Name(), Path: p, Type: typ, Size: info.Size(), Mode: info.Mode().Perm().String(), Modified: info.ModTime().UTC()})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Type != out[j].Type {
			return out[i].Type == "directory"
		}
		return out[i].Name < out[j].Name
	})
	return out, nil
}

func (a *Adapter) WriteAccountFile(username, rel, content string) (AccountFileEntry, error) {
	if !a.cfg.AllowMutations {
		return AccountFileEntry{}, errors.New("host mutations disabled")
	}
	if err := a.requireCertified("linux-users"); err != nil {
		return AccountFileEntry{}, err
	}
	if len(content) > 4<<20 {
		return AccountFileEntry{}, errors.New("file exceeds 4 MiB control-panel editor limit")
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
	pfd := int(parent.Fd())
	name := parts[len(parts)-1]
	fd, err := syscall.Openat(pfd, name, syscall.O_WRONLY|syscall.O_CREAT|syscall.O_TRUNC|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0640)
	if err != nil {
		return AccountFileEntry{}, fmt.Errorf("open target without symlink following: %w", err)
	}
	file := os.NewFile(uintptr(fd), name)
	ok := false
	defer func() {
		if !ok {
			_ = file.Close()
		}
	}()
	if err := syscall.Fchown(fd, uid, gid); err != nil {
		return AccountFileEntry{}, err
	}
	if err := syscall.Fchmod(fd, 0640); err != nil {
		return AccountFileEntry{}, err
	}
	if _, err := file.WriteString(content); err != nil {
		return AccountFileEntry{}, err
	}
	if err := file.Sync(); err != nil {
		return AccountFileEntry{}, err
	}
	info, err := file.Stat()
	if err != nil {
		return AccountFileEntry{}, err
	}
	if err := file.Close(); err != nil {
		return AccountFileEntry{}, err
	}
	ok = true
	return AccountFileEntry{Name: name, Path: clean, Type: "file", Size: info.Size(), Mode: info.Mode().Perm().String(), Modified: info.ModTime().UTC()}, nil
}
