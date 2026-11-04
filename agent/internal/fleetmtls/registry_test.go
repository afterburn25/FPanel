package fleetmtls

import (
	"crypto/x509"
	"path/filepath"
	"testing"
)

func parseLeaf(t *testing.T, certDER []byte) *x509.Certificate {
	t.Helper()
	c, err := x509.ParseCertificate(certDER)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func TestPersistentNodeEnrollmentRotationAndRevocation(t *testing.T) {
	ca, err := NewCA("privora-fleet-ca")
	if err != nil {
		t.Fatal(err)
	}
	pair1, _, err := ca.Issue("node-chi-01", false)
	if err != nil {
		t.Fatal(err)
	}
	cert1 := parseLeaf(t, pair1.Certificate[0])
	path := filepath.Join(t.TempDir(), "nodes.json")
	r, err := OpenNodeRegistry(path)
	if err != nil {
		t.Fatal(err)
	}
	enrolled, err := r.Enroll("node-chi-01", "web", "us-central", "10.0.0.10:9443", cert1)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := r.Authorize(cert1); err != nil {
		t.Fatal(err)
	}
	r2, err := OpenNodeRegistry(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := r2.Authorize(cert1); err != nil {
		t.Fatal("authorization did not survive restart:", err)
	}

	pair2, _, err := ca.Issue("node-chi-01", false)
	if err != nil {
		t.Fatal(err)
	}
	cert2 := parseLeaf(t, pair2.Certificate[0])
	rotated, err := r2.Rotate("node-chi-01", cert2)
	if err != nil {
		t.Fatal(err)
	}
	if rotated.Rotation != 1 || rotated.CertFingerprint == enrolled.CertFingerprint {
		t.Fatalf("rotation not recorded: %+v", rotated)
	}
	if _, err := r2.Authorize(cert1); err == nil {
		t.Fatal("old certificate authorized after rotation")
	}
	if _, err := r2.Authorize(cert2); err != nil {
		t.Fatal(err)
	}
	if err := r2.Revoke("node-chi-01"); err != nil {
		t.Fatal(err)
	}
	if _, err := r2.Authorize(cert2); err == nil {
		t.Fatal("revoked certificate authorized")
	}
	r3, err := OpenNodeRegistry(path)
	if err != nil {
		t.Fatal(err)
	}
	nodes := r3.List()
	if len(nodes) != 1 || nodes[0].Status != "revoked" || nodes[0].Rotation != 1 {
		t.Fatalf("registry did not persist: %+v", nodes)
	}
}

func TestRegistryRejectsWrongCertificateIdentity(t *testing.T) {
	ca, _ := NewCA("privora-fleet-ca")
	pair, _, _ := ca.Issue("node-nyc-01", false)
	cert := parseLeaf(t, pair.Certificate[0])
	r, _ := OpenNodeRegistry("")
	if _, err := r.Enroll("node-chi-01", "web", "us-central", "10.0.0.10:9443", cert); err == nil {
		t.Fatal("mismatched certificate identity enrolled")
	}
}
