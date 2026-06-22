package app

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/idesyatov/ssl-watch/internal/flags"
)

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
