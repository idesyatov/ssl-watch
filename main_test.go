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
	ok := flags.Config{Output: "text", Timeout: 10, Concurrency: 1}
	one := hostTargets("a.com")
	two := hostTargets("a.com", "b.com")

	cases := []struct {
		name    string
		cfg     flags.Config
		targets []target
		wantErr bool
	}{
		{"single domain", ok, one, false},
		{"certfile only", flags.Config{Output: "text", Timeout: 10, Concurrency: 1, CertFile: "c.pem"}, nil, false},
		{"no target", ok, nil, true},
		{"bad output", flags.Config{Output: "yaml", Timeout: 10, Concurrency: 1}, one, true},
		{"bad timeout", flags.Config{Output: "text", Timeout: 0, Concurrency: 1}, one, true},
		{"bad concurrency", flags.Config{Output: "text", Timeout: 10, Concurrency: 0}, one, true},
		{"ipaddr multi", flags.Config{Output: "text", Timeout: 10, Concurrency: 1, IPAddr: "1.2.3.4"}, two, true},
		{"all-ips + certfile", flags.Config{Output: "text", Timeout: 10, Concurrency: 1, AllIPs: true, CertFile: "c.pem"}, one, true},
		{"all-ips + strict", flags.Config{Output: "text", Timeout: 10, Concurrency: 1, AllIPs: true, Strict: true}, one, true},
		{"all-ips multi", flags.Config{Output: "text", Timeout: 10, Concurrency: 1, AllIPs: true}, two, true},
		{"-4 without all-ips", flags.Config{Output: "text", Timeout: 10, Concurrency: 1, IPv4Only: true}, one, true},
		{"cafile + insecure", flags.Config{Output: "text", Timeout: 10, Concurrency: 1, CAFile: "r.pem", Insecure: true}, one, true},
		{"client-cert without key", flags.Config{Output: "text", Timeout: 10, Concurrency: 1, ClientCert: "c.crt"}, one, true},
		{"client-cert + certfile", flags.Config{Output: "text", Timeout: 10, Concurrency: 1, ClientCert: "c.crt", ClientKey: "c.key", CertFile: "f.pem"}, nil, true},
		{"client-cert + key ok", flags.Config{Output: "text", Timeout: 10, Concurrency: 1, ClientCert: "c.crt", ClientKey: "c.key"}, one, false},
		{"servername multi", flags.Config{Output: "text", Timeout: 10, Concurrency: 1, ServerName: "x"}, two, true},
		{"pin multi", flags.Config{Output: "text", Timeout: 10, Concurrency: 1, Pin: "sha256:ab"}, two, true},
		{"pem + json", flags.Config{Output: "json", Timeout: 10, Concurrency: 1, Pem: true}, one, true},
		{"pem + export", flags.Config{Output: "text", Timeout: 10, Concurrency: 1, Pem: true, Export: "f"}, one, true},
		{"prometheus + all-ips", flags.Config{Output: "prometheus", Timeout: 10, Concurrency: 1, AllIPs: true}, one, true},
		{"csv ok", flags.Config{Output: "csv", Timeout: 10, Concurrency: 1}, two, false},
		{"csv + all-ips", flags.Config{Output: "csv", Timeout: 10, Concurrency: 1, AllIPs: true}, one, true},
		{"csv + certfile", flags.Config{Output: "csv", Timeout: 10, Concurrency: 1, CertFile: "c.pem"}, nil, true},
		{"bad starttls", flags.Config{Output: "text", Timeout: 10, Concurrency: 1, StartTLS: "gopher"}, one, true},
		{"good starttls", flags.Config{Output: "text", Timeout: 10, Concurrency: 1, StartTLS: "smtp"}, one, false},
	}
	for _, tc := range cases {
		if err := validate(tc.cfg, tc.targets); (err != nil) != tc.wantErr {
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

// TestParseTarget verifies bare host, host:port, URL and IPv6 parsing, the
// default-port fallback and rejection of an out-of-range port.
func TestParseTarget(t *testing.T) {
	cases := []struct {
		in       string
		wantHost string
		wantPort string
		wantErr  bool
	}{
		{"example.com", "example.com", "443", false},
		{"example.com:8443", "example.com", "8443", false},
		{"https://example.com:8443/path", "example.com", "8443", false},
		{"https://example.com/path", "example.com", "443", false},
		{"[2606:4700::1]:8443", "2606:4700::1", "8443", false},
		{"2606:4700::1", "2606:4700::1", "443", false},
		{"example.com:99999", "", "", true},
		{"example.com:abc", "", "", true},
	}
	for _, c := range cases {
		got, err := parseTarget(c.in, "443")
		if c.wantErr {
			if err == nil {
				t.Errorf("parseTarget(%q): expected error, got %+v", c.in, got)
			}
			continue
		}
		if err != nil {
			t.Errorf("parseTarget(%q): unexpected error: %v", c.in, err)
			continue
		}
		if got.host != c.wantHost || got.port != c.wantPort {
			t.Errorf("parseTarget(%q) = {%q,%q}, want {%q,%q}", c.in, got.host, got.port, c.wantHost, c.wantPort)
		}
	}
}

// TestResolveTargets verifies comma splitting, trimming, per-target ports,
// de-duplication by host:port and reading from a file.
func TestResolveTargets(t *testing.T) {
	file := filepath.Join(t.TempDir(), "domains.txt")
	if err := os.WriteFile(file, []byte("c.com\n# comment\n\n a.com \nd.com:8443\n"), 0o600); err != nil {
		t.Fatalf("failed to write domain file: %v", err)
	}

	// "a.com" and "a.com:443" collapse; "d.com" and "d.com:8443" stay distinct.
	cfg := flags.Config{Domain: "a.com, b.com ,a.com:443", DomainFile: file}
	got, err := resolveTargets(cfg, "443")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	want := []target{
		{"a.com", "443"}, {"b.com", "443"}, {"c.com", "443"}, {"d.com", "8443"},
	}
	if len(got) != len(want) {
		t.Fatalf("expected %d targets, got %d: %+v", len(want), len(got), got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("target %d = %+v, want %+v", i, got[i], want[i])
		}
	}
}

// TestResolveTargets_FileError verifies a missing domain file surfaces an error.
func TestResolveTargets_FileError(t *testing.T) {
	cfg := flags.Config{DomainFile: filepath.Join(t.TempDir(), "nope.txt")}
	if _, err := resolveTargets(cfg, "443"); err == nil {
		t.Error("expected error for missing domain file, got nil")
	}
}

// hostTargets builds default-port targets from bare hostnames, for batch tests.
func hostTargets(hosts ...string) []target {
	ts := make([]target, len(hosts))
	for i, h := range hosts {
		ts[i] = target{host: h, port: "443"}
	}
	return ts
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
	targets := hostTargets("a.example", "b.example", "bad.example")
	cfg := flags.Config{Output: "json", Concurrency: 1}
	opts := cert.PrintOptions{JSON: true}

	var code int
	out := captureStdout(t, func() {
		code = runBatch(fetcher, &cert.CertificatePrinterImpl{}, targets, cfg, opts, cert.FetchOptions{Timeout: time.Second})
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
	targets := hostTargets("a.example", "b.example")
	cfg := flags.Config{Output: "text", Threshold: 30, Concurrency: 1}
	opts := cert.PrintOptions{Threshold: 30}

	var code int
	out := captureStdout(t, func() {
		code = runBatch(fetcher, &cert.CertificatePrinterImpl{}, targets, cfg, opts, cert.FetchOptions{Timeout: time.Second})
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

// TestRunBatch_Short verifies that multi-domain short mode prefixes each days
// count with its domain (domain<TAB>days), so the numbers stay attributable.
func TestRunBatch_Short(t *testing.T) {
	fetcher := &fakeFetcher{
		infos: map[string]*cert.CertInfo{
			"a.example": leafInfo("a.example", 90),
			"b.example": leafInfo("b.example", 5),
		},
	}
	targets := hostTargets("a.example", "b.example")
	cfg := flags.Config{Output: "text", Short: true, Concurrency: 1}
	opts := cert.PrintOptions{Short: true}

	out := captureStdout(t, func() {
		runBatch(fetcher, &cert.CertificatePrinterImpl{}, targets, cfg, opts, cert.FetchOptions{Timeout: time.Second})
	})

	for _, want := range []string{"a.example\t90", "b.example\t5"} {
		if !strings.Contains(out, want) {
			t.Errorf("expected output to contain %q, got:\n%s", want, out)
		}
	}
	if strings.Contains(out, "==>") || strings.Contains(out, "Certificate for") {
		t.Errorf("short output should not contain full details, got:\n%s", out)
	}
}

// TestRunBatch_ConcurrencyOrder verifies that with concurrency > 1 the output is
// still rendered in input order, and that per-target ports show in the label.
func TestRunBatch_ConcurrencyOrder(t *testing.T) {
	fetcher := &fakeFetcher{
		infos: map[string]*cert.CertInfo{
			"a.example": leafInfo("a.example", 90),
			"b.example": leafInfo("b.example", 80),
			"c.example": leafInfo("c.example", 70),
		},
	}
	targets := []target{
		{"a.example", "443"}, {"b.example", "8443"}, {"c.example", "443"},
	}
	cfg := flags.Config{Output: "text", Concurrency: 3}
	opts := cert.PrintOptions{}

	out := captureStdout(t, func() {
		runBatch(fetcher, &cert.CertificatePrinterImpl{}, targets, cfg, opts, cert.FetchOptions{Timeout: time.Second})
	})

	ia := strings.Index(out, "==> a.example")
	ib := strings.Index(out, "==> b.example:8443")
	ic := strings.Index(out, "==> c.example")
	if ia < 0 || ib < 0 || ic < 0 {
		t.Fatalf("expected all three headers (with port on b), got:\n%s", out)
	}
	if ia >= ib || ib >= ic {
		t.Errorf("expected input order a,b,c preserved, got positions %d,%d,%d:\n%s", ia, ib, ic, out)
	}
}
