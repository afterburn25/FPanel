package hostadapter

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"
)

type CertificateInspection struct {
	Domain            string `json:"domain"`
	Subject           string `json:"subject"`
	Issuer            string `json:"issuer"`
	Serial            string `json:"serial"`
	NotBefore         string `json:"not_before"`
	NotAfter          string `json:"not_after"`
	SANs              string `json:"sans"`
	FingerprintSHA256 string `json:"fingerprint_sha256"`
	Fullchain         string `json:"fullchain"`
	PrivateKey        string `json:"private_key"`
}

type CSRResult struct {
	Domain         string `json:"domain"`
	CSR            string `json:"csr"`
	CSRPath        string `json:"csr_path"`
	PrivateKeyPath string `json:"private_key_path"`
}

func (a *Adapter) InspectCertificate(ctx context.Context, domain string) (CertificateInspection, error) {
	domain = strings.ToLower(strings.TrimSpace(domain))
	if !validDomain(domain) {
		return CertificateInspection{}, errors.New("invalid certificate domain")
	}
	config := a.cfg.ACMEConfigDir
	if config == "" {
		config = "/etc/letsencrypt"
	}
	full := filepath.Join(config, "live", domain, "fullchain.pem")
	key := filepath.Join(config, "live", domain, "privkey.pem")
	if !regularOrSymlinkExists(full) {
		custom := filepath.Join("/etc/privora-panel/certificates", domain)
		full = filepath.Join(custom, "fullchain.pem")
		key = filepath.Join(custom, "privkey.pem")
	}
	if !regularOrSymlinkExists(full) {
		return CertificateInspection{}, errors.New("certificate files not found")
	}
	out, err := a.run(ctx, "openssl", "x509", "-in", full, "-noout", "-subject", "-issuer", "-serial", "-startdate", "-enddate", "-ext", "subjectAltName", "-fingerprint", "-sha256")
	if err != nil {
		return CertificateInspection{}, err
	}
	r := CertificateInspection{Domain: domain, Fullchain: full, PrivateKey: key}
	for _, line := range strings.Split(out, "\n") {
		x := strings.TrimSpace(line)
		switch {
		case strings.HasPrefix(x, "subject="):
			r.Subject = strings.TrimSpace(strings.TrimPrefix(x, "subject="))
		case strings.HasPrefix(x, "issuer="):
			r.Issuer = strings.TrimSpace(strings.TrimPrefix(x, "issuer="))
		case strings.HasPrefix(x, "serial="):
			r.Serial = strings.TrimSpace(strings.TrimPrefix(x, "serial="))
		case strings.HasPrefix(x, "notBefore="):
			r.NotBefore = strings.TrimSpace(strings.TrimPrefix(x, "notBefore="))
		case strings.HasPrefix(x, "notAfter="):
			r.NotAfter = strings.TrimSpace(strings.TrimPrefix(x, "notAfter="))
		case strings.HasPrefix(x, "sha256 Fingerprint=") || strings.HasPrefix(strings.ToUpper(x), "SHA256 FINGERPRINT="):
			r.FingerprintSHA256 = strings.TrimSpace(strings.SplitN(x, "=", 2)[1])
		case strings.Contains(x, "DNS:"):
			r.SANs = x
		}
	}
	return r, nil
}

func (a *Adapter) GenerateCSR(ctx context.Context, domain string) (CSRResult, error) {
	if !a.cfg.AllowMutations {
		return CSRResult{}, errors.New("host mutations disabled")
	}
	domain = strings.ToLower(strings.TrimSpace(domain))
	if !validDomain(domain) {
		return CSRResult{}, errors.New("invalid certificate domain")
	}
	dir := filepath.Join("/var/lib/privora-panel/csrs", domain)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return CSRResult{}, err
	}
	key := filepath.Join(dir, "private.key")
	csr := filepath.Join(dir, "request.csr")
	_ = os.Remove(key)
	_ = os.Remove(csr)
	if _, err := a.run(ctx, "openssl", "req", "-new", "-newkey", "rsa:2048", "-nodes", "-keyout", key, "-out", csr, "-subj", "/CN="+domain, "-addext", "subjectAltName=DNS:"+domain); err != nil {
		return CSRResult{}, err
	}
	if err := os.Chmod(key, 0600); err != nil {
		return CSRResult{}, err
	}
	if err := os.Chmod(csr, 0640); err != nil {
		return CSRResult{}, err
	}
	b, err := os.ReadFile(csr)
	if err != nil {
		return CSRResult{}, err
	}
	return CSRResult{Domain: domain, CSR: string(b), CSRPath: csr, PrivateKeyPath: key}, nil
}

func (a *Adapter) InstallCustomCertificate(ctx context.Context, domain, username, phpVersion, documentRoot, certificatePEM, keyPEM string) (ACMEProvisionResult, error) {
	if !a.cfg.AllowMutations {
		return ACMEProvisionResult{}, errors.New("host mutations disabled")
	}
	domain = strings.ToLower(strings.TrimSpace(domain))
	if !validDomain(domain) {
		return ACMEProvisionResult{}, errors.New("invalid certificate domain")
	}
	if len(certificatePEM) > 512<<10 || len(keyPEM) > 128<<10 {
		return ACMEProvisionResult{}, errors.New("certificate payload is too large")
	}
	if !strings.Contains(certificatePEM, "BEGIN CERTIFICATE") || !strings.Contains(keyPEM, "PRIVATE KEY") {
		return ACMEProvisionResult{}, errors.New("certificate and private key must be PEM encoded")
	}
	dir := filepath.Join("/etc/privora-panel/certificates", domain)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return ACMEProvisionResult{}, err
	}
	cert := filepath.Join(dir, "fullchain.pem")
	key := filepath.Join(dir, "privkey.pem")
	oldCert, _ := os.ReadFile(cert)
	oldKey, _ := os.ReadFile(key)
	hadCert := regularOrSymlinkExists(cert)
	hadKey := regularOrSymlinkExists(key)
	rollback := func() {
		if hadCert {
			_ = AtomicWrite(cert, oldCert, 0644)
		} else {
			_ = os.Remove(cert)
		}
		if hadKey {
			_ = AtomicWrite(key, oldKey, 0600)
		} else {
			_ = os.Remove(key)
		}
	}
	if err := AtomicWrite(cert, []byte(certificatePEM), 0644); err != nil {
		return ACMEProvisionResult{}, err
	}
	if err := AtomicWrite(key, []byte(keyPEM), 0600); err != nil {
		rollback()
		return ACMEProvisionResult{}, err
	}
	if _, err := a.run(ctx, "openssl", "x509", "-in", cert, "-noout"); err != nil {
		rollback()
		return ACMEProvisionResult{}, fmt.Errorf("invalid certificate: %w", err)
	}
	if _, err := a.run(ctx, "openssl", "pkey", "-in", key, "-noout"); err != nil {
		rollback()
		return ACMEProvisionResult{}, fmt.Errorf("invalid private key: %w", err)
	}
	if _, err := a.run(ctx, "openssl", "x509", "-in", cert, "-noout", "-checkhost", domain); err != nil {
		rollback()
		return ACMEProvisionResult{}, errors.New("certificate does not cover the requested domain")
	}
	certPub, err := a.run(ctx, "openssl", "x509", "-in", cert, "-pubkey", "-noout")
	if err != nil {
		rollback()
		return ACMEProvisionResult{}, err
	}
	keyPub, err := a.run(ctx, "openssl", "pkey", "-in", key, "-pubout")
	if err != nil {
		rollback()
		return ACMEProvisionResult{}, err
	}
	if strings.TrimSpace(certPub) != strings.TrimSpace(keyPub) {
		rollback()
		return ACMEProvisionResult{}, errors.New("certificate and private key do not match")
	}
	end, err := a.run(ctx, "openssl", "x509", "-in", cert, "-noout", "-enddate")
	if err != nil {
		rollback()
		return ACMEProvisionResult{}, err
	}
	expires, err := parseOpenSSLEndDate(strings.TrimSpace(end))
	if err != nil {
		rollback()
		return ACMEProvisionResult{}, err
	}
	if !expires.After(time.Now().UTC().Add(24 * time.Hour)) {
		rollback()
		return ACMEProvisionResult{}, errors.New("certificate expires too soon")
	}
	res := ACMEProvisionResult{Domain: domain, Fullchain: cert, Privkey: key, ExpiresAt: expires, Provider: "custom"}
	if err := a.InstallLetsEncryptNginxTLS(ctx, domain, username, phpVersion, documentRoot, res); err != nil {
		rollback()
		return ACMEProvisionResult{}, err
	}
	return res, nil
}

func (a *Adapter) RevokeLetsEncryptCertificate(ctx context.Context, domain string) error {
	if !a.cfg.AllowMutations {
		return errors.New("host mutations disabled")
	}
	domain = strings.ToLower(strings.TrimSpace(domain))
	if !validDomain(domain) {
		return errors.New("invalid certificate domain")
	}
	config := a.cfg.ACMEConfigDir
	if config == "" {
		config = "/etc/letsencrypt"
	}
	cert := filepath.Join(config, "live", domain, "cert.pem")
	if !regularOrSymlinkExists(cert) {
		return errors.New("Let's Encrypt certificate not found")
	}
	workDir := filepath.Join(filepath.Dir(config), "privora-acme-work")
	logsDir := filepath.Join(filepath.Dir(config), "privora-acme-logs")
	_, err := a.run(ctx, "certbot", "revoke", "--cert-path", cert, "--non-interactive", "--config-dir", config, "--work-dir", workDir, "--logs-dir", logsDir)
	return err
}

func validateACMEServer(raw string) (string, error) {
	if strings.TrimSpace(raw) == "" {
		return "", nil
	}
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil {
		return "", errors.New("custom ACME server must be an HTTPS URL without embedded credentials")
	}
	return u.String(), nil
}
