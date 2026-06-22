package cert

import (
	"bufio"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
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

// TestCertificateFetcherImpl_Fetch exercises the real Fetch against an in-process
// TLS server, covering both the insecure path and chain verification.
func TestCertificateFetcherImpl_Fetch(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer srv.Close()

	u, err := url.Parse(srv.URL)
	if err != nil {
		t.Fatalf("failed to parse server URL: %v", err)
	}
	host, port, err := net.SplitHostPort(u.Host)
	if err != nil {
		t.Fatalf("failed to split host/port: %v", err)
	}

	fetcher := &CertificateFetcherImpl{}

	// Insecure: the certificate is returned and the chain is not verified.
	info, err := fetcher.Fetch(host, port, "", FetchOptions{Insecure: true, Timeout: 5 * time.Second})
	if err != nil {
		t.Fatalf("unexpected error from Fetch: %v", err)
	}
	if info.Cert == nil {
		t.Fatal("expected a certificate, got nil")
	}
	if info.Cert.SerialNumber.Cmp(srv.Certificate().SerialNumber) != 0 {
		t.Errorf("fetched certificate serial does not match the server certificate")
	}
	if len(info.Chain) == 0 {
		t.Error("expected the peer chain to be recorded")
	}
	if info.UsedIP == "" {
		t.Error("expected the used IP to be recorded for a fetched certificate")
	}
	if info.Verified {
		t.Error("expected Verified to be false when insecure is true")
	}

	// Secure: the chain is verified and, for this self-signed test cert against
	// the system roots, fails — but Fetch still succeeds and records the error.
	info, err = fetcher.Fetch(host, port, "", FetchOptions{Timeout: 5 * time.Second})
	if err != nil {
		t.Fatalf("unexpected error from Fetch (secure): %v", err)
	}
	if !info.Verified {
		t.Error("expected Verified to be true when insecure is false")
	}
	if info.ChainErr == nil {
		t.Error("expected chain verification to fail for the self-signed test certificate")
	}

	// With -cafile (Roots) set to the server's own certificate, the same chain
	// now verifies — exercising the replace-roots path.
	pool := x509.NewCertPool()
	pool.AddCert(srv.Certificate())
	info, err = fetcher.Fetch(host, port, "", FetchOptions{Timeout: 5 * time.Second, Roots: pool})
	if err != nil {
		t.Fatalf("unexpected error from Fetch (cafile): %v", err)
	}
	if info.ChainErr != nil {
		t.Errorf("expected verification to pass against the custom root, got: %v", info.ChainErr)
	}

	// -servername overrides the verified name (recorded in CheckedName).
	info, err = fetcher.Fetch(host, port, "", FetchOptions{Insecure: true, Timeout: 5 * time.Second, ServerName: "override.example"})
	if err != nil {
		t.Fatalf("unexpected error from Fetch (servername): %v", err)
	}
	if info.CheckedName != "override.example" {
		t.Errorf("expected CheckedName 'override.example', got %q", info.CheckedName)
	}
}

// runNegotiate drives negotiateStartTLS against a scripted in-memory server and
// returns the negotiation error.
func runNegotiate(t *testing.T, proto string, serverScript func(server net.Conn, r *bufio.Reader)) error {
	t.Helper()
	client, server := net.Pipe()
	errCh := make(chan error, 1)
	go func() {
		client.SetDeadline(time.Now().Add(5 * time.Second))
		errCh <- negotiateStartTLS(client, proto)
		client.Close()
	}()

	r := bufio.NewReader(server)
	serverScript(server, r)
	server.Close()
	return <-errCh
}

// TestNegotiateStartTLS_SMTP verifies a successful SMTP negotiation, including a
// multi-line EHLO reply.
func TestNegotiateStartTLS_SMTP(t *testing.T) {
	err := runNegotiate(t, "smtp", func(server net.Conn, r *bufio.Reader) {
		fmt.Fprint(server, "220 smtp.example.com ESMTP\r\n")
		r.ReadString('\n') // EHLO
		fmt.Fprint(server, "250-smtp.example.com\r\n250-STARTTLS\r\n250 OK\r\n")
		r.ReadString('\n') // STARTTLS
		fmt.Fprint(server, "220 ready to start TLS\r\n")
	})
	if err != nil {
		t.Errorf("expected successful SMTP negotiation, got error: %v", err)
	}
}

// TestNegotiateStartTLS_IMAP verifies a successful IMAP negotiation with a tagged
// OK response.
func TestNegotiateStartTLS_IMAP(t *testing.T) {
	err := runNegotiate(t, "imap", func(server net.Conn, r *bufio.Reader) {
		fmt.Fprint(server, "* OK IMAP4rev1 ready\r\n")
		r.ReadString('\n') // a STARTTLS
		fmt.Fprint(server, "a OK begin TLS negotiation\r\n")
	})
	if err != nil {
		t.Errorf("expected successful IMAP negotiation, got error: %v", err)
	}
}

// TestNegotiateStartTLS_POP3Rejected verifies that a server refusing STLS yields
// a negotiation error.
func TestNegotiateStartTLS_POP3Rejected(t *testing.T) {
	err := runNegotiate(t, "pop3", func(server net.Conn, r *bufio.Reader) {
		fmt.Fprint(server, "+OK POP3 ready\r\n")
		r.ReadString('\n') // STLS
		fmt.Fprint(server, "-ERR command not supported\r\n")
	})
	if err == nil {
		t.Error("expected error when STLS is rejected, got nil")
	}
}

// TestNegotiateStartTLS_Unknown verifies an unsupported protocol is rejected.
func TestNegotiateStartTLS_Unknown(t *testing.T) {
	client, _ := net.Pipe()
	defer client.Close()
	if err := negotiateStartTLS(client, "gopher"); err == nil {
		t.Error("expected error for unknown protocol, got nil")
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
