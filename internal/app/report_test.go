package app

import (
	"io"
	"strings"
	"testing"

	"github.com/idesyatov/ssl-watch/internal/cert"
	"github.com/idesyatov/ssl-watch/internal/flags"
)

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
