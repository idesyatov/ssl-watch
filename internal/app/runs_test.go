package app

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"io"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/idesyatov/ssl-watch/internal/cert"
	"github.com/idesyatov/ssl-watch/internal/flags"
)

// realCertInfo builds a CertInfo backed by a real self-signed certificate (with
// DER bytes), so fingerprints and PEM export work. The leaf expires in `days`.
func realCertInfo(t *testing.T, cn string, days int) *cert.CertInfo {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}
	tmpl := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: cn},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Duration(days)*24*time.Hour + time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("failed to create certificate: %v", err)
	}
	c, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("failed to parse certificate: %v", err)
	}
	return &cert.CertInfo{Cert: c, Chain: []*x509.Certificate{c}}
}

// futureCertInfo builds a CertInfo whose certificate is not valid yet (NotBefore
// in the future), which trips a warning — useful for exercising -strict.
func futureCertInfo(t *testing.T, cn string) *cert.CertInfo {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}
	tmpl := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: cn},
		NotBefore:    time.Now().Add(24 * time.Hour),
		NotAfter:     time.Now().Add(72 * time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("failed to create certificate: %v", err)
	}
	c, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("failed to parse certificate: %v", err)
	}
	return &cert.CertInfo{Cert: c, Chain: []*x509.Certificate{c}}
}

// TestEffectiveDefaultPort covers the -port / -starttls default-port resolution.
func TestEffectiveDefaultPort(t *testing.T) {
	cases := []struct{ port, starttls, want string }{
		{"443", "", "443"},       // no starttls → -port
		{"443", "smtp", "587"},   // default port + starttls → protocol port
		{"8443", "smtp", "8443"}, // explicit port overrides the protocol default
		{"443", "bogus", "443"},  // unknown protocol left for validate to reject
	}
	for _, c := range cases {
		got := effectiveDefaultPort(flags.Config{Port: c.port, StartTLS: c.starttls})
		if got != c.want {
			t.Errorf("effectiveDefaultPort(port=%q, starttls=%q) = %q, want %q", c.port, c.starttls, got, c.want)
		}
	}
}

// TestUseColor covers every branch: non-text/short/NO_COLOR disable color, and a
// non-terminal stdout (the test pipe) also disables it.
func TestUseColor(t *testing.T) {
	if useColor(flags.Config{Output: "json"}) {
		t.Error("non-text output should not colorize")
	}
	if useColor(flags.Config{Output: "text", Short: true}) {
		t.Error("short output should not colorize")
	}
	t.Setenv("NO_COLOR", "1")
	if useColor(flags.Config{Output: "text"}) {
		t.Error("NO_COLOR should disable color")
	}
	t.Setenv("NO_COLOR", "")
	// NO_COLOR unset but stdout is the test harness (not a char device) → false.
	if useColor(flags.Config{Output: "text"}) {
		t.Error("non-terminal stdout should not colorize")
	}
}

// TestPrintSingle covers the exit-code branches: OK, threshold, pin mismatch,
// issuer mismatch and a strict warning.
func TestPrintSingle(t *testing.T) {
	info := realCertInfo(t, "x.example", 90)
	printer := &cert.CertificatePrinterImpl{}

	run := func(cfg flags.Config, opts cert.PrintOptions) int {
		var code int
		captureStdout(t, func() { code = printSingle(printer, info, cfg, opts) })
		return code
	}

	if code := run(flags.Config{}, cert.PrintOptions{}); code != exitOK {
		t.Errorf("healthy cert: expected %d, got %d", exitOK, code)
	}
	if code := run(flags.Config{Threshold: 120}, cert.PrintOptions{Threshold: 120}); code != exitSoft {
		t.Errorf("expiry within threshold: expected %d, got %d", exitSoft, code)
	}
	if code := run(flags.Config{}, cert.PrintOptions{Pin: "00deadbeef"}); code != exitMismatch {
		t.Errorf("pin mismatch: expected %d, got %d", exitMismatch, code)
	}
	if code := run(flags.Config{ExpectIssuer: "Some Other CA"}, cert.PrintOptions{}); code != exitMismatch {
		t.Errorf("issuer mismatch: expected %d, got %d", exitMismatch, code)
	}
	// A not-yet-valid certificate trips a warning, so -strict makes it a soft fail.
	nyv := futureCertInfo(t, "future.example")
	var scode int
	captureStdout(t, func() { scode = printSingle(printer, nyv, flags.Config{Strict: true}, cert.PrintOptions{}) })
	if scode != exitSoft {
		t.Errorf("strict + warning: expected %d, got %d", exitSoft, scode)
	}
}

// TestRunExport covers -pem (stdout), -export (file) and the write-error path.
func TestRunExport(t *testing.T) {
	info := realCertInfo(t, "export.example", 90)

	// -pem: PEM to stdout.
	var code int
	out := captureStdout(t, func() { code = runExport(info, flags.Config{Pem: true}) })
	if code != exitOK {
		t.Fatalf("pem: expected %d, got %d", exitOK, code)
	}
	if !strings.Contains(out, "BEGIN CERTIFICATE") {
		t.Errorf("pem output should contain a PEM block, got:\n%s", out)
	}

	// -export: PEM to a file.
	path := filepath.Join(t.TempDir(), "chain.pem")
	out = captureStdout(t, func() { code = runExport(info, flags.Config{Export: path}) })
	if code != exitOK {
		t.Fatalf("export: expected %d, got %d", exitOK, code)
	}
	if !strings.Contains(out, "Wrote 1 certificate(s)") {
		t.Errorf("export should report what it wrote, got: %q", out)
	}
	if b, err := os.ReadFile(path); err != nil || !strings.Contains(string(b), "BEGIN CERTIFICATE") {
		t.Errorf("export file missing or not PEM: err=%v", err)
	}

	// Write error: a path under a non-existent directory.
	code = runExport(info, flags.Config{Export: filepath.Join(t.TempDir(), "nope", "chain.pem")})
	if code != exitError {
		t.Errorf("export to bad path: expected %d, got %d", exitError, code)
	}
}

// TestRunPrometheus covers the prometheus wrapper and collectSamples error branch.
func TestRunPrometheus(t *testing.T) {
	fetcher := &fakeFetcher{
		infos: map[string]*cert.CertInfo{"a.example": leafInfo("a.example", 90)},
		errs:  map[string]error{"bad.example": io.ErrUnexpectedEOF},
	}
	targets := hostTargets("a.example", "bad.example")

	var code int
	out := captureStdout(t, func() {
		code = runPrometheus(fetcher, targets, flags.Config{Output: "prometheus", Concurrency: 1}, cert.FetchOptions{}, "")
	})
	if code != exitError {
		t.Errorf("a failed domain should yield %d, got %d", exitError, code)
	}
	if !strings.Contains(out, "ssl_cert_up") {
		t.Errorf("expected prometheus exposition, got:\n%s", out)
	}
}

// TestRunCSV covers the csv wrapper and the collectSamples expiring branch.
func TestRunCSV(t *testing.T) {
	fetcher := &fakeFetcher{infos: map[string]*cert.CertInfo{
		"a.example": leafInfo("a.example", 90),
		"b.example": leafInfo("b.example", 5),
	}}
	targets := hostTargets("a.example", "b.example")

	var code int
	out := captureStdout(t, func() {
		code = runCSV(fetcher, targets, flags.Config{Output: "csv", Threshold: 30, Concurrency: 1}, cert.FetchOptions{})
	})
	if code != exitSoft {
		t.Errorf("a cert within threshold should yield %d, got %d", exitSoft, code)
	}
	if !strings.Contains(out, "domain,common_name") {
		t.Errorf("expected CSV header, got:\n%s", out)
	}
}

// TestRunNagios covers the nagios wrapper and its Nagios exit code.
func TestRunNagios(t *testing.T) {
	fetcher := &fakeFetcher{infos: map[string]*cert.CertInfo{"expired.example": leafInfo("expired.example", -10)}}
	targets := hostTargets("expired.example")

	var code int
	out := captureStdout(t, func() {
		code = runNagios(fetcher, targets, flags.Config{Output: "nagios", Concurrency: 1}, cert.PrintOptions{}, cert.FetchOptions{})
	})
	if code != 2 {
		t.Errorf("an expired cert should be CRITICAL (2), got %d", code)
	}
	if !strings.Contains(out, "SSL CRITICAL") {
		t.Errorf("expected a Nagios CRITICAL line, got:\n%s", out)
	}
}

// TestRunAllIPs covers the all-ips orchestration with a stubbed resolver: the
// happy path (same cert on every address → OK) and the resolution-error path.
func TestRunAllIPs(t *testing.T) {
	orig := lookupIP
	defer func() { lookupIP = orig }()

	fetcher := &fakeFetcher{infos: map[string]*cert.CertInfo{"example.com": leafInfo("example.com", 90)}}
	tgt := target{host: "example.com", port: "443"}

	// Two IPv4 addresses, same certificate.
	lookupIP = func(string) ([]net.IP, error) {
		return []net.IP{net.ParseIP("203.0.113.10"), net.ParseIP("203.0.113.11")}, nil
	}
	var code int
	out := captureStdout(t, func() {
		code = runAllIPs(fetcher, tgt, flags.Config{Concurrency: 1}, cert.PrintOptions{}, cert.FetchOptions{})
	})
	if code != exitOK {
		t.Errorf("identical certs on all addresses should yield %d, got %d", exitOK, code)
	}
	if !strings.Contains(out, "checking 2 address(es)") || !strings.Contains(out, "same certificate") {
		t.Errorf("unexpected all-ips output:\n%s", out)
	}

	// Resolution failure → error exit.
	lookupIP = func(string) ([]net.IP, error) { return nil, errors.New("no such host") }
	if code := runAllIPs(fetcher, tgt, flags.Config{Concurrency: 1}, cert.PrintOptions{}, cert.FetchOptions{}); code != exitError {
		t.Errorf("resolution failure should yield %d, got %d", exitError, code)
	}

	// No address of the requested family → error exit.
	lookupIP = func(string) ([]net.IP, error) { return []net.IP{net.ParseIP("203.0.113.10")}, nil }
	if code := runAllIPs(fetcher, tgt, flags.Config{Concurrency: 1, IPv6Only: true}, cert.PrintOptions{}, cert.FetchOptions{}); code != exitError {
		t.Errorf("no matching family should yield %d, got %d", exitError, code)
	}
}

// fakeLoader returns a canned CertInfo or error for the -certfile path.
type fakeLoader struct {
	info *cert.CertInfo
	err  error
}

func (f *fakeLoader) Load(string) (*cert.CertInfo, error) { return f.info, f.err }

// runArgs invokes run() with a stubbed os.Args and the given dependencies,
// capturing stdout. It restores os.Args afterwards.
func runArgs(t *testing.T, args []string, fetcher cert.CertificateFetcher, loader cert.CertificateLoader) (int, string) {
	t.Helper()
	orig := os.Args
	defer func() { os.Args = orig }()
	os.Args = append([]string{"ssl-watch"}, args...)
	var code int
	out := captureStdout(t, func() {
		code = run(flags.NewDefaultFlagParser(), fetcher, loader, &cert.CertificatePrinterImpl{})
	})
	return code, out
}

// TestRun exercises the run() dispatcher across its main branches: version, the
// early error paths, and each output/target path with injected dependencies.
func TestRun(t *testing.T) {
	fetcher := &fakeFetcher{
		infos: map[string]*cert.CertInfo{
			"a.example": leafInfo("a.example", 90),
			"b.example": leafInfo("b.example", 80),
		},
		errs: map[string]error{"bad.example": io.ErrUnexpectedEOF},
	}
	loader := &fakeLoader{info: realCertInfo(t, "file.example", 90)}

	t.Run("version", func(t *testing.T) {
		code, out := runArgs(t, []string{"-version"}, fetcher, loader)
		if code != exitOK || !strings.Contains(out, "Version:") {
			t.Errorf("version: code=%d out=%q", code, out)
		}
	})

	t.Run("no target", func(t *testing.T) {
		if code, _ := runArgs(t, nil, fetcher, loader); code != exitError {
			t.Errorf("expected %d with no target, got %d", exitError, code)
		}
	})

	t.Run("validate error", func(t *testing.T) {
		if code, _ := runArgs(t, []string{"-domain", "a.example", "-output", "yaml"}, fetcher, loader); code != exitError {
			t.Errorf("expected %d for bad -output, got %d", exitError, code)
		}
	})

	t.Run("bad pin", func(t *testing.T) {
		if code, _ := runArgs(t, []string{"-domain", "a.example", "-pin", "notahex"}, fetcher, loader); code != exitError {
			t.Errorf("expected %d for malformed -pin, got %d", exitError, code)
		}
	})

	t.Run("cafile load error", func(t *testing.T) {
		bad := filepath.Join(t.TempDir(), "missing.pem")
		if code, _ := runArgs(t, []string{"-domain", "a.example", "-cafile", bad}, fetcher, loader); code != exitError {
			t.Errorf("expected %d for unreadable -cafile, got %d", exitError, code)
		}
	})

	t.Run("prometheus dispatch", func(t *testing.T) {
		code, out := runArgs(t, []string{"-domain", "a.example", "-output", "prometheus"}, fetcher, loader)
		if code != exitOK || !strings.Contains(out, "ssl_cert_up") {
			t.Errorf("prometheus: code=%d out=%q", code, out)
		}
	})

	t.Run("certfile dispatch", func(t *testing.T) {
		code, out := runArgs(t, []string{"-certfile", "file.pem"}, fetcher, loader)
		if code != exitOK || !strings.Contains(out, "Certificate for file.example") {
			t.Errorf("certfile: code=%d out=%q", code, out)
		}
	})

	t.Run("certfile load error", func(t *testing.T) {
		badLoader := &fakeLoader{err: io.ErrUnexpectedEOF}
		if code, _ := runArgs(t, []string{"-certfile", "file.pem"}, fetcher, badLoader); code != exitError {
			t.Errorf("expected %d on loader error, got %d", exitError, code)
		}
	})

	t.Run("single domain dispatch", func(t *testing.T) {
		code, out := runArgs(t, []string{"-domain", "a.example"}, fetcher, loader)
		if code != exitOK || !strings.Contains(out, "Certificate for a.example") {
			t.Errorf("single: code=%d out=%q", code, out)
		}
	})

	t.Run("single domain fetch error", func(t *testing.T) {
		if code, _ := runArgs(t, []string{"-domain", "bad.example"}, fetcher, loader); code != exitError {
			t.Errorf("expected %d on fetch error, got %d", exitError, code)
		}
	})

	t.Run("batch dispatch", func(t *testing.T) {
		code, out := runArgs(t, []string{"-domain", "a.example,b.example"}, fetcher, loader)
		if code != exitOK || !strings.Contains(out, "==> a.example") {
			t.Errorf("batch: code=%d out=%q", code, out)
		}
	})
}
