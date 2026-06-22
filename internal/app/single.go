package app

import (
	"github.com/idesyatov/ssl-watch/internal/cert"
	"github.com/idesyatov/ssl-watch/internal/flags"
)

// printSingle prints one certificate and returns the process exit code: 3 when an
// explicit expectation (a pin or the issuer) fails, 2 for a soft problem (a
// warning under -strict, or expiry within -threshold), otherwise 0.
func printSingle(printer cert.CertificatePrinter, info *cert.CertInfo, cfg flags.Config, opts cert.PrintOptions) int {
	printer.Print(info, opts)
	// Exit code 3 when an explicit expectation about the served certificate fails
	// (a pinned fingerprint or the issuer) — a wrong cert is more urgent than an
	// upcoming expiry, so it takes precedence.
	if opts.Pin != "" && !cert.MatchesPin(info.Cert, opts.Pin) {
		return exitMismatch
	}
	if cfg.ExpectIssuer != "" && !cert.IssuerMatches(info.Cert, cfg.ExpectIssuer) {
		return exitMismatch
	}
	// Exit code 2 for soft problems: with -strict any warning fails, and any
	// certificate in the chain expiring within -threshold fails.
	if cfg.Strict && cert.HasWarnings(info) {
		return exitSoft
	}
	if cfg.Threshold > 0 && info.MinDaysUntilExpiry() < cfg.Threshold {
		return exitSoft
	}
	return exitOK
}
