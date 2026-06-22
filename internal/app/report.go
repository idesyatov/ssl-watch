package app

import (
	"fmt"
	"os"
	"strings"

	"github.com/idesyatov/ssl-watch/internal/cert"
	"github.com/idesyatov/ssl-watch/internal/flags"
)

// runExport writes the served certificate chain as PEM — to stdout (-pem) or to
// a file (-export) — and returns the process exit code (0 on success, 1 on a
// write error).
func runExport(info *cert.CertInfo, cfg flags.Config) int {
	pemBytes := cert.ChainPEM(info)
	if cfg.Export != "" {
		if err := os.WriteFile(cfg.Export, pemBytes, 0o644); err != nil {
			fmt.Fprintf(os.Stderr, "Error: failed to write %s: %v\n", cfg.Export, err)
			return exitError
		}
		fmt.Printf("Wrote %d certificate(s) to %s\n", strings.Count(string(pemBytes), "BEGIN CERTIFICATE"), cfg.Export)
		return exitOK
	}
	if _, err := os.Stdout.Write(pemBytes); err != nil {
		fmt.Fprintf(os.Stderr, "Error: failed to write PEM: %v\n", err)
		return exitError
	}
	return exitOK
}

// runPrometheus fetches every domain and writes the results in Prometheus
// exposition format to stdout. It returns the aggregated exit code: 1 if any
// domain failed to be retrieved, otherwise 2 if any certificate expires within
// -threshold, otherwise 0.
func runPrometheus(fetcher cert.CertificateFetcher, targets []target, cfg flags.Config, fetchOpts cert.FetchOptions, pinHex string) int {
	samples, hadError, expiring := collectSamples(fetcher, targets, cfg, fetchOpts)
	cert.WritePrometheus(os.Stdout, samples, pinHex)
	switch {
	case hadError:
		return exitError
	case expiring:
		return exitSoft
	}
	return exitOK
}

// runCSV fetches every target and writes the results as CSV to stdout. The exit
// code mirrors the other batch report formats: 1 if any target failed, otherwise
// 2 if any certificate expires within -threshold, otherwise 0.
func runCSV(fetcher cert.CertificateFetcher, targets []target, cfg flags.Config, fetchOpts cert.FetchOptions) int {
	samples, hadError, expiring := collectSamples(fetcher, targets, cfg, fetchOpts)
	if err := cert.WriteCSV(os.Stdout, samples); err != nil {
		fmt.Fprintf(os.Stderr, "Error: failed to write CSV: %v\n", err)
		return exitError
	}
	switch {
	case hadError:
		return exitError
	case expiring:
		return exitSoft
	}
	return exitOK
}

// runNagios fetches every target and writes a Nagios/Icinga plugin result. The
// process exit code follows the Nagios convention (0 OK / 1 WARNING / 2 CRITICAL),
// deliberately overriding the tool's normal exit codes for this output format.
func runNagios(fetcher cert.CertificateFetcher, targets []target, cfg flags.Config, opts cert.PrintOptions, fetchOpts cert.FetchOptions) int {
	samples, _, _ := collectSamples(fetcher, targets, cfg, fetchOpts)
	return cert.WriteNagios(os.Stdout, samples, opts, cfg.Strict)
}

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
