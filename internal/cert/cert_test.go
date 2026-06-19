package cert

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"io"
	"math/big"
	"os"
	"path/filepath"
	"strings"
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

// TestFormatSerial verifies serial numbers are rendered as colon-separated hex.
func TestFormatSerial(t *testing.T) {
	cases := map[string]struct {
		in   *big.Int
		want string
	}{
		"zero":        {big.NewInt(0), "0"},
		"single byte": {big.NewInt(15), "0F"},
		"two bytes":   {big.NewInt(0x0FA3), "0F:A3"},
	}
	for name, c := range cases {
		if got := formatSerial(c.in); got != c.want {
			t.Errorf("%s: formatSerial(%v) = %q, want %q", name, c.in, got, c.want)
		}
	}
}

// TestCertificatePrinter_Print verifies the full output contains the expected
// fields, including SANs, serial, signature algorithm and chain status.
func TestCertificatePrinter_Print(t *testing.T) {
	cert := &x509.Certificate{
		Subject:            pkix.Name{CommonName: "example.com"},
		DNSNames:           []string{"example.com", "www.example.com"},
		SerialNumber:       big.NewInt(0x0FA3),
		SignatureAlgorithm: x509.SHA256WithRSA,
		NotBefore:          time.Now().Add(-24 * time.Hour),
		NotAfter:           time.Now().Add(30 * 24 * time.Hour),
	}
	info := &CertInfo{Cert: cert, UsedIP: "192.0.2.1", Verified: true, ChainErr: nil}

	printer := &CertificatePrinterImpl{}
	out := captureStdout(t, func() { printer.Print(info, PrintOptions{}) })

	for _, want := range []string{
		"Certificate for example.com",
		"SANs: example.com, www.example.com",
		"Serial: 0F:A3",
		"Signature: SHA256-RSA",
		"Used IP address: 192.0.2.1",
		"Chain: VALID",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("expected output to contain %q, got:\n%s", want, out)
		}
	}
}

// TestCertificatePrinter_Print_Short verifies short mode prints only the days remaining.
func TestCertificatePrinter_Print_Short(t *testing.T) {
	cert := &x509.Certificate{NotAfter: time.Now().Add(30 * 24 * time.Hour)}
	info := &CertInfo{Cert: cert}

	printer := &CertificatePrinterImpl{}
	out := captureStdout(t, func() { printer.Print(info, PrintOptions{Short: true}) })

	if strings.Contains(out, "Certificate for") {
		t.Errorf("short output should not contain full details, got:\n%s", out)
	}
	if strings.TrimSpace(out) == "" {
		t.Error("expected short output to contain days remaining")
	}
}

// TestCertificatePrinter_Print_FileChainOmitted verifies that for a file-loaded
// certificate neither the used IP nor the chain status are printed.
func TestCertificatePrinter_Print_FileChainOmitted(t *testing.T) {
	cert := &x509.Certificate{
		Subject:      pkix.Name{CommonName: "file.example"},
		SerialNumber: big.NewInt(1),
		NotAfter:     time.Now().Add(time.Hour),
	}
	info := &CertInfo{Cert: cert, FromFile: true}

	printer := &CertificatePrinterImpl{}
	out := captureStdout(t, func() { printer.Print(info, PrintOptions{}) })

	if strings.Contains(out, "Used IP address") {
		t.Errorf("file-loaded cert should not print used IP, got:\n%s", out)
	}
	if strings.Contains(out, "Chain:") {
		t.Errorf("file-loaded cert should not print chain status, got:\n%s", out)
	}
}

// TestDaysUntilExpiry verifies the day arithmetic for future and past expiry.
func TestDaysUntilExpiry(t *testing.T) {
	future := &x509.Certificate{NotAfter: time.Now().Add(10*24*time.Hour + time.Hour)}
	if got := DaysUntilExpiry(future); got != 10 {
		t.Errorf("expected 10 days remaining, got %d", got)
	}
	past := &x509.Certificate{NotAfter: time.Now().Add(-2 * 24 * time.Hour)}
	if got := DaysUntilExpiry(past); got >= 0 {
		t.Errorf("expected negative days for expired cert, got %d", got)
	}
}

// TestCertificatePrinter_Print_JSON verifies the JSON output is valid and carries
// the expected fields.
func TestCertificatePrinter_Print_JSON(t *testing.T) {
	cert := &x509.Certificate{
		Subject:            pkix.Name{CommonName: "json.example"},
		DNSNames:           []string{"json.example"},
		SerialNumber:       big.NewInt(0x0FA3),
		SignatureAlgorithm: x509.SHA256WithRSA,
		NotBefore:          time.Now().Add(-24 * time.Hour),
		NotAfter:           time.Now().Add(10 * 24 * time.Hour),
	}
	info := &CertInfo{Cert: cert, UsedIP: "192.0.2.1", Verified: true, ChainErr: nil}

	printer := &CertificatePrinterImpl{}
	out := captureStdout(t, func() { printer.Print(info, PrintOptions{JSON: true}) })

	var got struct {
		CommonName    string   `json:"common_name"`
		SANs          []string `json:"sans"`
		Serial        string   `json:"serial"`
		DaysRemaining int      `json:"days_remaining"`
		UsedIP        string   `json:"used_ip"`
		ChainValid    *bool    `json:"chain_valid"`
	}
	if err := json.Unmarshal([]byte(out), &got); err != nil {
		t.Fatalf("output is not valid JSON: %v\noutput:\n%s", err, out)
	}
	if got.CommonName != "json.example" {
		t.Errorf("expected common_name 'json.example', got '%s'", got.CommonName)
	}
	if got.Serial != "0F:A3" {
		t.Errorf("expected serial '0F:A3', got '%s'", got.Serial)
	}
	if got.UsedIP != "192.0.2.1" {
		t.Errorf("expected used_ip '192.0.2.1', got '%s'", got.UsedIP)
	}
	if got.ChainValid == nil || !*got.ChainValid {
		t.Errorf("expected chain_valid true, got %v", got.ChainValid)
	}
}

// TestMinDaysUntilExpiry verifies the minimum is taken across the whole chain
// and falls back to the leaf when no chain is recorded.
func TestMinDaysUntilExpiry(t *testing.T) {
	leaf := &x509.Certificate{NotAfter: time.Now().Add(90*24*time.Hour + time.Hour)}
	inter := &x509.Certificate{NotAfter: time.Now().Add(20*24*time.Hour + time.Hour)}

	withChain := &CertInfo{Cert: leaf, Chain: []*x509.Certificate{leaf, inter}}
	if got := withChain.MinDaysUntilExpiry(); got != 20 {
		t.Errorf("expected min 20 across chain, got %d", got)
	}

	leafOnly := &CertInfo{Cert: leaf}
	if got := leafOnly.MinDaysUntilExpiry(); got != 90 {
		t.Errorf("expected leaf fallback 90, got %d", got)
	}
}

// TestCertificatePrinter_Print_ChainExpiryWarning verifies the warning is printed
// when an intermediate expires before the leaf, and omitted otherwise.
func TestCertificatePrinter_Print_ChainExpiryWarning(t *testing.T) {
	leaf := &x509.Certificate{
		Subject:      pkix.Name{CommonName: "leaf.example"},
		SerialNumber: big.NewInt(1),
		NotAfter:     time.Now().Add(90 * 24 * time.Hour),
	}
	earlyInter := &x509.Certificate{
		Subject:  pkix.Name{CommonName: "Early Intermediate CA"},
		NotAfter: time.Now().Add(20 * 24 * time.Hour),
	}
	lateInter := &x509.Certificate{
		Subject:  pkix.Name{CommonName: "Late Intermediate CA"},
		NotAfter: time.Now().Add(200 * 24 * time.Hour),
	}

	printer := &CertificatePrinterImpl{}

	warned := &CertInfo{Cert: leaf, Chain: []*x509.Certificate{leaf, earlyInter}}
	out := captureStdout(t, func() { printer.Print(warned, PrintOptions{}) })
	if !strings.Contains(out, "WARNING") || !strings.Contains(out, "Early Intermediate CA") {
		t.Errorf("expected chain expiry warning naming the intermediate, got:\n%s", out)
	}

	ok := &CertInfo{Cert: leaf, Chain: []*x509.Certificate{leaf, lateInter}}
	out = captureStdout(t, func() { printer.Print(ok, PrintOptions{}) })
	if strings.Contains(out, "WARNING") {
		t.Errorf("did not expect a warning when intermediate outlives leaf, got:\n%s", out)
	}
}

// TestCertificatePrinter_Print_JSON_ChainExpiry verifies the chain_expiry_warning
// object is emitted in JSON when an intermediate expires before the leaf.
func TestCertificatePrinter_Print_JSON_ChainExpiry(t *testing.T) {
	leaf := &x509.Certificate{
		Subject:      pkix.Name{CommonName: "leaf.example"},
		SerialNumber: big.NewInt(1),
		NotAfter:     time.Now().Add(90 * 24 * time.Hour),
	}
	inter := &x509.Certificate{
		Subject:      pkix.Name{CommonName: "Early Intermediate CA"},
		SerialNumber: big.NewInt(2),
		NotAfter:     time.Now().Add(20*24*time.Hour + time.Hour),
	}
	info := &CertInfo{Cert: leaf, Chain: []*x509.Certificate{leaf, inter}}

	printer := &CertificatePrinterImpl{}
	out := captureStdout(t, func() { printer.Print(info, PrintOptions{JSON: true}) })

	var got struct {
		ChainExpiry *struct {
			Subject       string `json:"subject"`
			DaysRemaining int    `json:"days_remaining"`
		} `json:"chain_expiry_warning"`
	}
	if err := json.Unmarshal([]byte(out), &got); err != nil {
		t.Fatalf("output is not valid JSON: %v\noutput:\n%s", err, out)
	}
	if got.ChainExpiry == nil {
		t.Fatalf("expected chain_expiry_warning in JSON, got:\n%s", out)
	}
	if got.ChainExpiry.Subject != "Early Intermediate CA" {
		t.Errorf("expected subject 'Early Intermediate CA', got '%s'", got.ChainExpiry.Subject)
	}
	if got.ChainExpiry.DaysRemaining != 20 {
		t.Errorf("expected days_remaining 20, got %d", got.ChainExpiry.DaysRemaining)
	}
}

// TestCertificatePrinter_Print_ColorThreshold verifies the days-remaining value is
// colorized (yellow) when below the threshold.
func TestCertificatePrinter_Print_ColorThreshold(t *testing.T) {
	cert := &x509.Certificate{
		Subject:      pkix.Name{CommonName: "soon.example"},
		SerialNumber: big.NewInt(1),
		NotAfter:     time.Now().Add(5 * 24 * time.Hour),
	}
	info := &CertInfo{Cert: cert}

	printer := &CertificatePrinterImpl{}
	out := captureStdout(t, func() {
		printer.Print(info, PrintOptions{Threshold: 30, Color: true})
	})

	if !strings.Contains(out, colorYellow) {
		t.Errorf("expected yellow highlight for days below threshold, got:\n%q", out)
	}
}
