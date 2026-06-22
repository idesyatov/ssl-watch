package app

import (
	"encoding/json"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/idesyatov/ssl-watch/internal/cert"
	"github.com/idesyatov/ssl-watch/internal/flags"
)

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
