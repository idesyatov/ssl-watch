package cert

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// TestCertificateLoaderImpl_Load tests the real Load implementation by generating
// a self-signed certificate, writing it to a PEM file, and loading it back.
func TestCertificateLoaderImpl_Load(t *testing.T) {
	// Generate a private key for the self-signed certificate
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	// Build a minimal certificate template
	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "load-test.example"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
	}

	// Create the DER-encoded self-signed certificate
	der, err := x509.CreateCertificate(rand.Reader, &template, &template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("failed to create certificate: %v", err)
	}

	// Write the certificate to a temporary PEM file
	certPath := filepath.Join(t.TempDir(), "cert.pem")
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	if err := os.WriteFile(certPath, pemBytes, 0o600); err != nil {
		t.Fatalf("failed to write cert file: %v", err)
	}

	// Load the certificate using the real implementation
	loader := &CertificateLoaderImpl{}
	info, err := loader.Load(certPath)
	if err != nil {
		t.Fatalf("unexpected error loading certificate: %v", err)
	}
	if info.Cert.Subject.CommonName != "load-test.example" {
		t.Errorf("expected CommonName 'load-test.example', got '%s'", info.Cert.Subject.CommonName)
	}
	if !info.FromFile {
		t.Error("expected FromFile to be true for a loaded certificate")
	}
	if info.Verified {
		t.Error("expected Verified to be false for a file-loaded certificate")
	}
}

// TestCertificateLoaderImpl_Load_Stdin verifies that a certFile of "-" reads the
// PEM from standard input.
func TestCertificateLoaderImpl_Load_Stdin(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}
	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "stdin-test.example"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, &template, &template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("failed to create certificate: %v", err)
	}
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})

	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("failed to create pipe: %v", err)
	}
	orig := os.Stdin
	os.Stdin = r
	defer func() { os.Stdin = orig }()

	go func() {
		_, _ = w.Write(pemBytes)
		_ = w.Close()
	}()

	loader := &CertificateLoaderImpl{}
	info, err := loader.Load("-")
	if err != nil {
		t.Fatalf("unexpected error loading certificate from stdin: %v", err)
	}
	if info.Cert.Subject.CommonName != "stdin-test.example" {
		t.Errorf("expected CommonName 'stdin-test.example', got '%s'", info.Cert.Subject.CommonName)
	}
	if !info.FromFile {
		t.Error("expected FromFile to be true for a stdin-loaded certificate")
	}
}

// TestCertificateLoaderImpl_Load_Bundle verifies that a PEM file holding several
// CERTIFICATE blocks is loaded as a chain (leaf first, intermediates following).
func TestCertificateLoaderImpl_Load_Bundle(t *testing.T) {
	mkCert := func(cn string) []byte {
		key, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			t.Fatalf("failed to generate key: %v", err)
		}
		template := x509.Certificate{
			SerialNumber: big.NewInt(1),
			Subject:      pkix.Name{CommonName: cn},
			NotBefore:    time.Now().Add(-time.Hour),
			NotAfter:     time.Now().Add(24 * time.Hour),
		}
		der, err := x509.CreateCertificate(rand.Reader, &template, &template, &key.PublicKey, key)
		if err != nil {
			t.Fatalf("failed to create certificate: %v", err)
		}
		return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	}

	bundle := append(mkCert("leaf.example"), mkCert("inter.example")...)
	bundlePath := filepath.Join(t.TempDir(), "fullchain.pem")
	if err := os.WriteFile(bundlePath, bundle, 0o600); err != nil {
		t.Fatalf("failed to write bundle: %v", err)
	}

	loader := &CertificateLoaderImpl{}
	info, err := loader.Load(bundlePath)
	if err != nil {
		t.Fatalf("unexpected error loading bundle: %v", err)
	}
	if info.Cert.Subject.CommonName != "leaf.example" {
		t.Errorf("expected leaf CommonName 'leaf.example', got '%s'", info.Cert.Subject.CommonName)
	}
	if len(info.Chain) != 2 {
		t.Fatalf("expected 2 certificates in chain, got %d", len(info.Chain))
	}
	if info.Chain[1].Subject.CommonName != "inter.example" {
		t.Errorf("expected second cert 'inter.example', got '%s'", info.Chain[1].Subject.CommonName)
	}
}

// TestCertificateLoaderImpl_Load_Errors verifies Load returns errors for a missing
// file and for a file that does not contain a valid PEM certificate.
func TestCertificateLoaderImpl_Load_Errors(t *testing.T) {
	loader := &CertificateLoaderImpl{}

	// Missing file should return an error
	if _, err := loader.Load(filepath.Join(t.TempDir(), "nope.pem")); err == nil {
		t.Error("expected error for missing file, got nil")
	}

	// File with non-PEM content should return an error
	badPath := filepath.Join(t.TempDir(), "bad.pem")
	if err := os.WriteFile(badPath, []byte("not a certificate"), 0o600); err != nil {
		t.Fatalf("failed to write bad file: %v", err)
	}
	if _, err := loader.Load(badPath); err == nil {
		t.Error("expected error for invalid PEM content, got nil")
	}
}

// TestLoadCAFile verifies a valid PEM bundle loads and bad inputs error out.
func TestLoadCAFile(t *testing.T) {
	c := genCert(t, "ca.example", time.Now().Add(365*24*time.Hour))
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: c.Raw})
	dir := t.TempDir()

	good := dir + "/ca.pem"
	if err := os.WriteFile(good, pemBytes, 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}
	pool, err := LoadCAFile(good)
	if err != nil || pool == nil {
		t.Fatalf("expected a pool, got pool=%v err=%v", pool, err)
	}

	bad := dir + "/bad.pem"
	if err := os.WriteFile(bad, []byte("not a certificate"), 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}
	if _, err := LoadCAFile(bad); err == nil {
		t.Error("expected an error for a file with no certificates")
	}
	if _, err := LoadCAFile(dir + "/missing.pem"); err == nil {
		t.Error("expected an error for a missing file")
	}
}

// TestLoadClientCert verifies a matching cert/key pair loads and bad inputs error.
func TestLoadClientCert(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("key: %v", err)
	}
	tmpl := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "client"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	dir := t.TempDir()
	certPath := filepath.Join(dir, "client.crt")
	keyPath := filepath.Join(dir, "client.key")
	if err := os.WriteFile(certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o644); err != nil {
		t.Fatalf("write cert: %v", err)
	}
	if err := os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)}), 0o600); err != nil {
		t.Fatalf("write key: %v", err)
	}

	pair, err := LoadClientCert(certPath, keyPath)
	if err != nil || pair == nil {
		t.Fatalf("expected a client certificate, got pair=%v err=%v", pair, err)
	}
	if _, err := LoadClientCert(certPath, filepath.Join(dir, "missing.key")); err == nil {
		t.Error("expected an error for a missing key file")
	}
}
