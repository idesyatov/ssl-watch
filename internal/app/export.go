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
