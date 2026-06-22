package app

import (
	"testing"

	"github.com/idesyatov/ssl-watch/internal/cert"
	"github.com/idesyatov/ssl-watch/internal/flags"
)

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
