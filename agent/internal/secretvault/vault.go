package secretvault

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"sync"
	"time"
)

var nameRE = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9_.:/-]{1,159}$`)

type sealed struct {
	Version    int       `json:"version"`
	Nonce      string    `json:"nonce"`
	Ciphertext string    `json:"ciphertext"`
	UpdatedAt  time.Time `json:"updated_at"`
}

type vaultState struct {
	Records map[string]sealed `json:"records"`
}

type Vault struct {
	mu    sync.Mutex
	path  string
	aead  cipher.AEAD
	state vaultState
}

func Open(path string, key []byte) (*Vault, error) {
	if len(key) != 32 {
		return nil, errors.New("vault key must be exactly 32 bytes")
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	v := &Vault{path: path, aead: aead, state: vaultState{Records: map[string]sealed{}}}
	if path == "" {
		return v, nil
	}
	b, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return v, nil
	}
	if err != nil {
		return nil, err
	}
	if len(b) > 0 {
		if err := json.Unmarshal(b, &v.state); err != nil {
			return nil, fmt.Errorf("invalid vault state: %w", err)
		}
	}
	if v.state.Records == nil {
		v.state.Records = map[string]sealed{}
	}
	return v, nil
}

func (v *Vault) persistLocked() error {
	if v.path == "" {
		return nil
	}
	if err := os.MkdirAll(filepath.Dir(v.path), 0700); err != nil {
		return err
	}
	b, err := json.MarshalIndent(v.state, "", "  ")
	if err != nil {
		return err
	}
	tmp := v.path + ".tmp"
	f, err := os.OpenFile(tmp, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	if _, err = f.Write(b); err == nil {
		err = f.Sync()
	}
	closeErr := f.Close()
	if err != nil {
		_ = os.Remove(tmp)
		return err
	}
	if closeErr != nil {
		_ = os.Remove(tmp)
		return closeErr
	}
	if err := os.Rename(tmp, v.path); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	return nil
}

func (v *Vault) Put(name string, plaintext []byte) (int, error) {
	if !nameRE.MatchString(name) {
		return 0, errors.New("invalid secret name")
	}
	if len(plaintext) < 1 || len(plaintext) > 1<<20 {
		return 0, errors.New("secret size out of bounds")
	}
	v.mu.Lock()
	defer v.mu.Unlock()
	version := 1
	if old, ok := v.state.Records[name]; ok {
		version = old.Version + 1
	}
	nonce := make([]byte, v.aead.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return 0, err
	}
	aad := []byte(fmt.Sprintf("privora-vault-v1:%s:%d", name, version))
	ct := v.aead.Seal(nil, nonce, plaintext, aad)
	old, had := v.state.Records[name]
	v.state.Records[name] = sealed{Version: version, Nonce: base64.RawStdEncoding.EncodeToString(nonce), Ciphertext: base64.RawStdEncoding.EncodeToString(ct), UpdatedAt: time.Now().UTC()}
	if err := v.persistLocked(); err != nil {
		if had {
			v.state.Records[name] = old
		} else {
			delete(v.state.Records, name)
		}
		return 0, err
	}
	return version, nil
}

func (v *Vault) Get(name string) ([]byte, int, error) {
	if !nameRE.MatchString(name) {
		return nil, 0, errors.New("invalid secret name")
	}
	v.mu.Lock()
	defer v.mu.Unlock()
	s, ok := v.state.Records[name]
	if !ok {
		return nil, 0, errors.New("secret not found")
	}
	nonce, err := base64.RawStdEncoding.DecodeString(s.Nonce)
	if err != nil {
		return nil, 0, errors.New("invalid secret nonce")
	}
	ct, err := base64.RawStdEncoding.DecodeString(s.Ciphertext)
	if err != nil {
		return nil, 0, errors.New("invalid secret ciphertext")
	}
	aad := []byte(fmt.Sprintf("privora-vault-v1:%s:%d", name, s.Version))
	pt, err := v.aead.Open(nil, nonce, ct, aad)
	if err != nil {
		return nil, 0, errors.New("secret authentication failed")
	}
	return pt, s.Version, nil
}

func (v *Vault) Delete(name string) error {
	if !nameRE.MatchString(name) {
		return errors.New("invalid secret name")
	}
	v.mu.Lock()
	defer v.mu.Unlock()
	old, ok := v.state.Records[name]
	if !ok {
		return nil
	}
	delete(v.state.Records, name)
	if err := v.persistLocked(); err != nil {
		v.state.Records[name] = old
		return err
	}
	return nil
}

func (v *Vault) Names() []string {
	v.mu.Lock()
	defer v.mu.Unlock()
	out := make([]string, 0, len(v.state.Records))
	for n := range v.state.Records {
		out = append(out, n)
	}
	sort.Strings(out)
	return out
}
