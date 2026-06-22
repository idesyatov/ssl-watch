package cert

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"io"
	"math/big"
	"os"
	"testing"
	"time"
)

// captureStdout runs fn while capturing everything written to os.Stdout and
// returns it as a string.
func captureStdout(t *testing.T, fn func()) string {
	t.Helper()
	orig := os.Stdout
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("failed to create pipe: %v", err)
	}
	os.Stdout = w
	defer func() { os.Stdout = orig }()

	fn()
	w.Close()
	out, err := io.ReadAll(r)
	if err != nil {
		t.Fatalf("failed to read captured output: %v", err)
	}
	return string(out)
}

// genCert generates a self-signed certificate with its raw DER populated (so
// Fingerprint is meaningful). Each call uses a fresh key → a distinct cert.
func genCert(t *testing.T, cn string, notAfter time.Time) *x509.Certificate {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("key: %v", err)
	}
	tmpl := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: cn},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     notAfter,
		DNSNames:     []string{cn},
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	c, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	return c
}

// certFromKey issues a self-signed certificate from a caller-provided key, so two
// certs can deliberately share a public key (to exercise SPKI pinning).
func certFromKey(t *testing.T, key *rsa.PrivateKey, serial *big.Int, notAfter time.Time) *x509.Certificate {
	t.Helper()
	tmpl := x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: "reissue.example"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     notAfter,
	}
	der, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	c, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	return c
}

// issueChainCerts builds a real leaf ← intermediate ← root hierarchy (the leaf is
// signed by the intermediate, the intermediate by the self-signed root).
func issueChainCerts(t *testing.T) (leaf, inter, root *x509.Certificate) {
	t.Helper()
	mk := func(cn string, org string, parent *x509.Certificate, parentKey *rsa.PrivateKey, serial int64, isCA bool) (*x509.Certificate, *rsa.PrivateKey) {
		key, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			t.Fatalf("key: %v", err)
		}
		tmpl := x509.Certificate{
			SerialNumber:          big.NewInt(serial),
			Subject:               pkix.Name{CommonName: cn, Organization: []string{org}},
			NotBefore:             time.Now().Add(-time.Hour),
			NotAfter:              time.Now().Add(365 * 24 * time.Hour),
			IsCA:                  isCA,
			BasicConstraintsValid: isCA,
		}
		if isCA {
			tmpl.KeyUsage = x509.KeyUsageCertSign
		} else {
			tmpl.DNSNames = []string{cn}
		}
		signer, signerKey := parent, parentKey
		if signer == nil { // self-signed root
			signer, signerKey = &tmpl, key
		}
		der, err := x509.CreateCertificate(rand.Reader, &tmpl, signer, &key.PublicKey, signerKey)
		if err != nil {
			t.Fatalf("create %s: %v", cn, err)
		}
		c, err := x509.ParseCertificate(der)
		if err != nil {
			t.Fatalf("parse %s: %v", cn, err)
		}
		return c, key
	}
	root, rootKey := mk("Test Root", "TestOrg", nil, nil, 1, true)
	inter, interKey := mk("Test Inter", "InterOrg", root, rootKey, 2, true)
	leaf, _ = mk("leaf.example", "LeafOrg", inter, interKey, 3, false)
	return leaf, inter, root
}

// verifyErr returns the (untrusted) verification error for a leaf with the given
// intermediates, against the system roots — i.e. a real UnknownAuthorityError.
func verifyErr(t *testing.T, leaf *x509.Certificate, inters ...*x509.Certificate) error {
	t.Helper()
	pool := x509.NewCertPool()
	for _, c := range inters {
		pool.AddCert(c)
	}
	_, err := leaf.Verify(x509.VerifyOptions{Intermediates: pool})
	if err == nil {
		t.Fatal("expected verification to fail against system roots")
	}
	return err
}
