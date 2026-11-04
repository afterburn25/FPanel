package fleetmtls

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"sync"
	"time"
)

var nodeRE = regexp.MustCompile(`^[a-z][a-z0-9-]{2,63}$`)
var opAllow = map[string]bool{"probe": true, "converge-site": true, "converge-dns": true, "backup": true}

type Command struct {
	NodeID    string    `json:"node_id"`
	Operation string    `json:"operation"`
	Resource  string    `json:"resource"`
	RequestID string    `json:"request_id"`
	Nonce     string    `json:"nonce"`
	IssuedAt  time.Time `json:"issued_at"`
}
type Result struct {
	OK        bool   `json:"ok"`
	NodeID    string `json:"node_id"`
	Operation string `json:"operation"`
	RequestID string `json:"request_id"`
	Status    string `json:"status"`
}

type ReplayProtector interface{ Accept(string, time.Time) error }

type Executor interface {
	Execute(context.Context, Command) (string, error)
}
type ExecutorFunc func(context.Context, Command) (string, error)

func (f ExecutorFunc) Execute(ctx context.Context, c Command) (string, error) { return f(ctx, c) }

type ReplayGuard struct {
	mu     sync.Mutex
	seen   map[string]time.Time
	MaxAge time.Duration
}

func NewReplayGuard(maxAge time.Duration) *ReplayGuard {
	if maxAge == 0 {
		maxAge = 2 * time.Minute
	}
	return &ReplayGuard{seen: map[string]time.Time{}, MaxAge: maxAge}
}
func (g *ReplayGuard) Accept(nonce string, issued time.Time) error {
	g.mu.Lock()
	defer g.mu.Unlock()
	now := time.Now().UTC()
	if nonce == "" || issued.IsZero() {
		return errors.New("nonce and issued_at required")
	}
	if issued.Before(now.Add(-g.MaxAge)) || issued.After(now.Add(30*time.Second)) {
		return errors.New("stale fleet command")
	}
	for n, t := range g.seen {
		if t.Before(now.Add(-g.MaxAge)) {
			delete(g.seen, n)
		}
	}
	if _, ok := g.seen[nonce]; ok {
		return errors.New("fleet command replay rejected")
	}
	g.seen[nonce] = now
	return nil
}

func Handler(expectedNode string, guard ReplayProtector) http.Handler {
	return HandlerWithExecutor(expectedNode, guard, ExecutorFunc(func(_ context.Context, _ Command) (string, error) { return "accepted-typed-command", nil }))
}

func HandlerWithExecutor(expectedNode string, guard ReplayProtector, executor Executor) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" {
			http.Error(w, "method not allowed", 405)
			return
		}
		if r.TLS == nil || len(r.TLS.PeerCertificates) == 0 {
			http.Error(w, "client certificate required", 401)
			return
		}
		cert := r.TLS.PeerCertificates[0]
		if cert.Subject.CommonName != expectedNode {
			http.Error(w, "node certificate identity mismatch", 403)
			return
		}
		var c Command
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&c); err != nil {
			http.Error(w, "invalid json", 400)
			return
		}
		if !nodeRE.MatchString(c.NodeID) || c.NodeID != expectedNode || !opAllow[c.Operation] || len(c.Resource) > 512 || c.RequestID == "" {
			http.Error(w, "invalid command", 400)
			return
		}
		if err := guard.Accept(c.Nonce, c.IssuedAt); err != nil {
			http.Error(w, err.Error(), 409)
			return
		}
		status, err := executor.Execute(r.Context(), c)
		if err != nil {
			http.Error(w, "typed command failed", 502)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(Result{OK: true, NodeID: c.NodeID, Operation: c.Operation, RequestID: c.RequestID, Status: status})
	})
}

type FileReplayGuard struct {
	mu     sync.Mutex
	Path   string
	MaxAge time.Duration
}

func NewFileReplayGuard(path string, maxAge time.Duration) *FileReplayGuard {
	if maxAge == 0 {
		maxAge = 2 * time.Minute
	}
	return &FileReplayGuard{Path: path, MaxAge: maxAge}
}
func (g *FileReplayGuard) Accept(nonce string, issued time.Time) error {
	g.mu.Lock()
	defer g.mu.Unlock()
	now := time.Now().UTC()
	if nonce == "" || issued.IsZero() {
		return errors.New("nonce and issued_at required")
	}
	if issued.Before(now.Add(-g.MaxAge)) || issued.After(now.Add(30*time.Second)) {
		return errors.New("stale fleet command")
	}
	seen := map[string]time.Time{}
	if b, err := os.ReadFile(g.Path); err == nil {
		_ = json.Unmarshal(b, &seen)
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	for n, t := range seen {
		if t.Before(now.Add(-g.MaxAge)) {
			delete(seen, n)
		}
	}
	if _, ok := seen[nonce]; ok {
		return errors.New("fleet command replay rejected")
	}
	seen[nonce] = now
	if err := os.MkdirAll(filepath.Dir(g.Path), 0750); err != nil {
		return err
	}
	b, err := json.Marshal(seen)
	if err != nil {
		return err
	}
	tmp := g.Path + ".tmp"
	if err := os.WriteFile(tmp, b, 0600); err != nil {
		return err
	}
	if err := os.Rename(tmp, g.Path); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	return nil
}

type CA struct {
	Cert *x509.Certificate
	Key  *rsa.PrivateKey
	PEM  []byte
}

func NewCA(name string) (*CA, error) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}
	serial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 120))
	tpl := &x509.Certificate{SerialNumber: serial, Subject: pkix.Name{CommonName: name}, NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().AddDate(5, 0, 0), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
	if err != nil {
		return nil, err
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, err
	}
	return &CA{Cert: cert, Key: key, PEM: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})}, nil
}
func (ca *CA) Issue(commonName string, server bool) (tls.Certificate, []byte, error) {
	if !nodeRE.MatchString(commonName) {
		return tls.Certificate{}, nil, errors.New("invalid certificate common name")
	}
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return tls.Certificate{}, nil, err
	}
	serial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 120))
	usage := []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}
	if server {
		usage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
	}
	tpl := &x509.Certificate{SerialNumber: serial, Subject: pkix.Name{CommonName: commonName}, DNSNames: []string{commonName}, NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().AddDate(1, 0, 0), KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment, ExtKeyUsage: usage}
	der, err := x509.CreateCertificate(rand.Reader, tpl, ca.Cert, &key.PublicKey, ca.Key)
	if err != nil {
		return tls.Certificate{}, nil, err
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	pair, err := tls.X509KeyPair(certPEM, keyPEM)
	return pair, certPEM, err
}
func TLSConfigs(caPEM []byte, serverCert, clientCert tls.Certificate) (*tls.Config, *tls.Config, error) {
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caPEM) {
		return nil, nil, fmt.Errorf("invalid CA")
	}
	srv := &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{serverCert}, ClientAuth: tls.RequireAndVerifyClientCert, ClientCAs: pool}
	cli := &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{clientCert}, RootCAs: pool, ServerName: "fleet-server"}
	return srv, cli, nil
}
