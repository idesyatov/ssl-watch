package app

import (
	"fmt"
	"os"

	"github.com/idesyatov/ssl-watch/internal/cert"
	"github.com/idesyatov/ssl-watch/internal/flags"
)

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
