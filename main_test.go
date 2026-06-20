package main

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"errors"
	"io"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/idesyatov/ssl-watch/internal/cert"
	"github.com/idesyatov/ssl-watch/internal/flags"
)

// captureStdout runs fn while capturing everything written to os.Stdout.
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

// TestValidate covers the flag-combination guards extracted from main().
func TestValidate(t *testing.T) {
	ok := flags.Config{Output: "text", Timeout: 10}
	one := []string{"a.com"}
	two := []string{"a.com", "b.com"}

	cases := []struct {
		name    string
		cfg     flags.Config
		domains []string
		wantErr bool
	}{
		{"single domain", ok, one, false},
		{"certfile only", flags.Config{Output: "text", Timeout: 10, CertFile: "c.pem"}, nil, false},
		{"no target", ok, nil, true},
		{"bad output", flags.Config{Output: "yaml", Timeout: 10}, one, true},
		{"bad timeout", flags.Config{Output: "text", Timeout: 0}, one, true},
		{"ipaddr multi", flags.Config{Output: "text", Timeout: 10, IPAddr: "1.2.3.4"}, two, true},
		{"all-ips + certfile", flags.Config{Output: "text", Timeout: 10, AllIPs: true, CertFile: "c.pem"}, one, true},
		{"all-ips + strict", flags.Config{Output: "text", Timeout: 10, AllIPs: true, Strict: true}, one, true},
		{"all-ips multi", flags.Config{Output: "text", Timeout: 10, AllIPs: true}, two, true},
		{"-4 without all-ips", flags.Config{Output: "text", Timeout: 10, IPv4Only: true}, one, true},
		{"cafile + insecure", flags.Config{Output: "text", Timeout: 10, CAFile: "r.pem", Insecure: true}, one, true},
		{"servername multi", flags.Config{Output: "text", Timeout: 10, ServerName: "x"}, two, true},
		{"pin multi", flags.Config{Output: "text", Timeout: 10, Pin: "sha256:ab"}, two, true},
		{"pem + json", flags.Config{Output: "json", Timeout: 10, Pem: true}, one, true},
		{"pem + export", flags.Config{Output: "text", Timeout: 10, Pem: true, Export: "f"}, one, true},
		{"prometheus + all-ips", flags.Config{Output: "prometheus", Timeout: 10, AllIPs: true}, one, true},
		{"bad starttls", flags.Config{Output: "text", Timeout: 10, StartTLS: "gopher"}, one, true},
		{"good starttls", flags.Config{Output: "text", Timeout: 10, StartTLS: "smtp"}, one, false},
	}
	for _, tc := range cases {
		if err := validate(tc.cfg, tc.domains); (err != nil) != tc.wantErr {
			t.Errorf("%s: validate err=%v, wantErr=%v", tc.name, err, tc.wantErr)
		}
	}
}

// fakeFetcher returns canned certificate info or errors per domain.
type fakeFetcher struct {
	infos map[string]*cert.CertInfo
	errs  map[string]error
}

func (f *fakeFetcher) Fetch(domain, port, ipaddr string, opts cert.FetchOptions) (*cert.CertInfo, error) {
	if err, ok := f.errs[domain]; ok {
		return nil, err
	}
	return f.infos[domain], nil
}

// leafInfo builds a CertInfo whose leaf expires in the given number of days.
func leafInfo(cn string, days int) *cert.CertInfo {
	return &cert.CertInfo{
		Cert: &x509.Certificate{
			Subject:      pkix.Name{CommonName: cn},
			SerialNumber: big.NewInt(1),
			NotAfter:     time.Now().Add(time.Duration(days)*24*time.Hour + time.Hour),
		},
		UsedIP: "192.0.2.1",
	}
}

// TestResolveVersion verifies the stamped version wins and that the fallback
// never yields an empty string.
func TestResolveVersion(t *testing.T) {
	orig := version
	defer func() { version = orig }()

	version = "1.2.3"
	if got := resolveVersion(); got != "1.2.3" {
		t.Errorf("expected stamped version '1.2.3', got %q", got)
	}

	// With the default "dev", resolveVersion falls back to build info, or "dev"
	// when none is available — but never an empty string.
	version = "dev"
	if got := resolveVersion(); got == "" {
		t.Error("expected a non-empty version from the fallback, got empty")
	}
}

// TestIsUnreachable verifies that no-route connection errors are classified as
// skippable, while real failures are not.
func TestIsUnreachable(t *testing.T) {
	for _, s := range []string{
		"failed to connect to [2a02:6b8::2:242]:443: dial tcp: connect: network is unreachable",
		"dial tcp 1.2.3.4:443: connect: no route to host",
	} {
		if !isUnreachable(errors.New(s)) {
			t.Errorf("expected %q to be unreachable", s)
		}
	}
	for _, s := range []string{
		"dial tcp 1.2.3.4:443: connect: connection refused",
		"dial tcp 1.2.3.4:443: i/o timeout",
		"tls: handshake failure",
	} {
		if isUnreachable(errors.New(s)) {
			t.Errorf("expected %q NOT to be unreachable", s)
		}
	}
	if isUnreachable(nil) {
		t.Error("nil error should not be unreachable")
	}
}

// TestResolveDomains verifies comma splitting, trimming, de-duplication and
// reading from a file.
func TestResolveDomains(t *testing.T) {
	file := filepath.Join(t.TempDir(), "domains.txt")
	if err := os.WriteFile(file, []byte("c.com\n# comment\n\n a.com \nd.com\n"), 0o600); err != nil {
		t.Fatalf("failed to write domain file: %v", err)
	}

	cfg := flags.Config{Domain: "a.com, b.com ,a.com", DomainFile: file}
	got, err := resolveDomains(cfg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	want := []string{"a.com", "b.com", "c.com", "d.com"}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Errorf("expected %v, got %v", want, got)
	}
}

// TestResolveDomains_FileError verifies a missing domain file surfaces an error.
func TestResolveDomains_FileError(t *testing.T) {
	cfg := flags.Config{DomainFile: filepath.Join(t.TempDir(), "nope.txt")}
	if _, err := resolveDomains(cfg); err == nil {
		t.Error("expected error for missing domain file, got nil")
	}
}

// TestRunBatch_JSON verifies the multi-domain JSON output is an array carrying a
// domain tag per entry and an error entry for failures, with exit code 1.
func TestRunBatch_JSON(t *testing.T) {
	fetcher := &fakeFetcher{
		infos: map[string]*cert.CertInfo{
			"a.example": leafInfo("a.example", 90),
			"b.example": leafInfo("b.example", 90),
		},
		errs: map[string]error{"bad.example": io.ErrUnexpectedEOF},
	}
	domains := []string{"a.example", "b.example", "bad.example"}
	cfg := flags.Config{Output: "json"}
	opts := cert.PrintOptions{JSON: true}

	var code int
	out := captureStdout(t, func() {
		code = runBatch(fetcher, &cert.CertificatePrinterImpl{}, domains, cfg, opts, cert.FetchOptions{Timeout: time.Second})
	})

	if code != 1 {
		t.Errorf("expected exit code 1 (a domain failed), got %d", code)
	}

	var arr []map[string]any
	if err := json.Unmarshal([]byte(out), &arr); err != nil {
		t.Fatalf("output is not a JSON array: %v\noutput:\n%s", err, out)
	}
	if len(arr) != 3 {
		t.Fatalf("expected 3 entries, got %d:\n%s", len(arr), out)
	}
	if arr[0]["domain"] != "a.example" {
		t.Errorf("expected first entry domain 'a.example', got %v", arr[0]["domain"])
	}
	if arr[2]["domain"] != "bad.example" || arr[2]["error"] == nil {
		t.Errorf("expected last entry to be an error for 'bad.example', got %v", arr[2])
	}
}

// TestRunBatch_Text verifies the text output prints a header per domain and that
// an expiring certificate yields exit code 2 when all domains succeed.
func TestRunBatch_Text(t *testing.T) {
	fetcher := &fakeFetcher{
		infos: map[string]*cert.CertInfo{
			"a.example": leafInfo("a.example", 90),
			"b.example": leafInfo("b.example", 5),
		},
	}
	domains := []string{"a.example", "b.example"}
	cfg := flags.Config{Output: "text", Threshold: 30}
	opts := cert.PrintOptions{Threshold: 30}

	var code int
	out := captureStdout(t, func() {
		code = runBatch(fetcher, &cert.CertificatePrinterImpl{}, domains, cfg, opts, cert.FetchOptions{Timeout: time.Second})
	})

	if code != 2 {
		t.Errorf("expected exit code 2 (a cert expires within threshold), got %d", code)
	}
	for _, want := range []string{"==> a.example", "==> b.example", "Certificate for a.example"} {
		if !strings.Contains(out, want) {
			t.Errorf("expected output to contain %q, got:\n%s", want, out)
		}
	}
}
