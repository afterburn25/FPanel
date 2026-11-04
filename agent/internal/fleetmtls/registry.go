package fleetmtls

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"
)

type NodeRecord struct {
	ID              string    `json:"id"`
	Role            string    `json:"role"`
	Region          string    `json:"region"`
	Endpoint        string    `json:"endpoint"`
	CertFingerprint string    `json:"cert_fingerprint_sha256"`
	CertSerial      string    `json:"cert_serial"`
	CertNotAfter    time.Time `json:"cert_not_after"`
	Rotation        int       `json:"rotation"`
	Status          string    `json:"status"`
	UpdatedAt       time.Time `json:"updated_at"`
}

type registryState struct {
	Nodes               map[string]NodeRecord `json:"nodes"`
	RevokedFingerprints map[string]time.Time  `json:"revoked_fingerprints"`
}

type NodeRegistry struct {
	mu    sync.Mutex
	path  string
	state registryState
}

func OpenNodeRegistry(path string) (*NodeRegistry, error) {
	r := &NodeRegistry{path: path, state: registryState{Nodes: map[string]NodeRecord{}, RevokedFingerprints: map[string]time.Time{}}}
	if path == "" {
		return r, nil
	}
	b, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return r, nil
	}
	if err != nil {
		return nil, err
	}
	if len(b) == 0 {
		return r, nil
	}
	if err := json.Unmarshal(b, &r.state); err != nil {
		return nil, fmt.Errorf("invalid fleet registry: %w", err)
	}
	if r.state.Nodes == nil {
		r.state.Nodes = map[string]NodeRecord{}
	}
	if r.state.RevokedFingerprints == nil {
		r.state.RevokedFingerprints = map[string]time.Time{}
	}
	return r, nil
}

func certFingerprint(cert *x509.Certificate) string {
	h := sha256.Sum256(cert.Raw)
	return hex.EncodeToString(h[:])
}

func validClientCertificate(nodeID string, cert *x509.Certificate) error {
	if !nodeRE.MatchString(nodeID) || cert == nil {
		return errors.New("invalid node certificate")
	}
	if cert.Subject.CommonName != nodeID {
		return errors.New("node certificate common name mismatch")
	}
	now := time.Now().UTC()
	if now.Before(cert.NotBefore) || !now.Before(cert.NotAfter) {
		return errors.New("node certificate is not currently valid")
	}
	hasClient := false
	for _, u := range cert.ExtKeyUsage {
		if u == x509.ExtKeyUsageClientAuth || u == x509.ExtKeyUsageAny {
			hasClient = true
		}
	}
	if !hasClient {
		return errors.New("node certificate lacks client-auth usage")
	}
	return nil
}

func (r *NodeRegistry) persistLocked() error {
	if r.path == "" {
		return nil
	}
	if err := os.MkdirAll(filepath.Dir(r.path), 0750); err != nil {
		return err
	}
	b, err := json.MarshalIndent(r.state, "", "  ")
	if err != nil {
		return err
	}
	tmp := r.path + ".tmp"
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
	if err := os.Rename(tmp, r.path); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	return nil
}

func (r *NodeRegistry) Enroll(nodeID, role, region, endpoint string, cert *x509.Certificate) (NodeRecord, error) {
	if role == "" || region == "" || endpoint == "" {
		return NodeRecord{}, errors.New("role, region and endpoint required")
	}
	if err := validClientCertificate(nodeID, cert); err != nil {
		return NodeRecord{}, err
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, ok := r.state.Nodes[nodeID]; ok {
		return NodeRecord{}, errors.New("node already enrolled")
	}
	fp := certFingerprint(cert)
	if _, revoked := r.state.RevokedFingerprints[fp]; revoked {
		return NodeRecord{}, errors.New("certificate was previously revoked")
	}
	v := NodeRecord{ID: nodeID, Role: role, Region: region, Endpoint: endpoint, CertFingerprint: fp, CertSerial: cert.SerialNumber.String(), CertNotAfter: cert.NotAfter.UTC(), Rotation: 0, Status: "active", UpdatedAt: time.Now().UTC()}
	r.state.Nodes[nodeID] = v
	if err := r.persistLocked(); err != nil {
		delete(r.state.Nodes, nodeID)
		return NodeRecord{}, err
	}
	return v, nil
}

func (r *NodeRegistry) Rotate(nodeID string, cert *x509.Certificate) (NodeRecord, error) {
	if err := validClientCertificate(nodeID, cert); err != nil {
		return NodeRecord{}, err
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	current, ok := r.state.Nodes[nodeID]
	if !ok {
		return NodeRecord{}, errors.New("node not enrolled")
	}
	if current.Status != "active" {
		return NodeRecord{}, errors.New("revoked node cannot rotate certificate")
	}
	nextFP := certFingerprint(cert)
	if nextFP == current.CertFingerprint {
		return NodeRecord{}, errors.New("replacement certificate must be different")
	}
	if _, revoked := r.state.RevokedFingerprints[nextFP]; revoked {
		return NodeRecord{}, errors.New("replacement certificate was previously revoked")
	}
	old := current
	r.state.RevokedFingerprints[current.CertFingerprint] = time.Now().UTC()
	current.CertFingerprint = nextFP
	current.CertSerial = cert.SerialNumber.String()
	current.CertNotAfter = cert.NotAfter.UTC()
	current.Rotation++
	current.UpdatedAt = time.Now().UTC()
	r.state.Nodes[nodeID] = current
	if err := r.persistLocked(); err != nil {
		r.state.Nodes[nodeID] = old
		delete(r.state.RevokedFingerprints, old.CertFingerprint)
		return NodeRecord{}, err
	}
	return current, nil
}

func (r *NodeRegistry) Revoke(nodeID string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	current, ok := r.state.Nodes[nodeID]
	if !ok {
		return errors.New("node not enrolled")
	}
	if current.Status == "revoked" {
		return nil
	}
	old := current
	current.Status = "revoked"
	current.UpdatedAt = time.Now().UTC()
	r.state.Nodes[nodeID] = current
	r.state.RevokedFingerprints[current.CertFingerprint] = time.Now().UTC()
	if err := r.persistLocked(); err != nil {
		r.state.Nodes[nodeID] = old
		delete(r.state.RevokedFingerprints, current.CertFingerprint)
		return err
	}
	return nil
}

func (r *NodeRegistry) Authorize(cert *x509.Certificate) (NodeRecord, error) {
	if cert == nil {
		return NodeRecord{}, errors.New("client certificate required")
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	fp := certFingerprint(cert)
	if _, revoked := r.state.RevokedFingerprints[fp]; revoked {
		return NodeRecord{}, errors.New("node certificate revoked")
	}
	v, ok := r.state.Nodes[cert.Subject.CommonName]
	if !ok || v.Status != "active" || v.CertFingerprint != fp {
		return NodeRecord{}, errors.New("node certificate not enrolled")
	}
	if err := validClientCertificate(v.ID, cert); err != nil {
		return NodeRecord{}, err
	}
	return v, nil
}

func (r *NodeRegistry) List() []NodeRecord {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]NodeRecord, 0, len(r.state.Nodes))
	for _, v := range r.state.Nodes {
		out = append(out, v)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}
