package app

import (
	"errors"
	"net"
	"strings"
	"testing"

	"github.com/idesyatov/ssl-watch/internal/cert"
	"github.com/idesyatov/ssl-watch/internal/flags"
)

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
