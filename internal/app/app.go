// Package app is the ssl-watch command body: it parses flags, resolves targets,
// validates the request and dispatches to the right output path over the cert
// package. The root main package only calls os.Exit(app.Run()).
//
// File map (setup → fetch → one file per output mode):
//   - app.go: entry point — wiring (Run), dispatch (run), color and version
//   - targets.go: parse and resolve targets (-domain, -domain-file, ports, dedup)
//   - validate.go: reject unsupported flag combinations
//   - gather.go: fetch every target concurrently, results kept in input order
//   - single.go: single-target output and its exit code
//   - batch.go: multi-target aggregated output
//   - allips.go: -all-ips mode (resolve + per-address) and reachability helpers
//   - export.go: PEM export (-pem / -export)
//   - report.go: Prometheus / CSV / Nagios output dispatch
package app

import (
	"fmt"
	"os"
	"runtime/debug"
	"time"

	"github.com/idesyatov/ssl-watch/internal/cert"
	"github.com/idesyatov/ssl-watch/internal/flags"
)

// version is stamped by the release build (goreleaser -ldflags). For "go install
// module@vX.Y.Z" builds it stays "dev" and resolveVersion falls back to the
// module version embedded in the binary's build info.
var version = "dev"

// resolveVersion returns the release version stamped at build time, or, when the
// binary was produced by "go install module@version", the module version from
// the build info. Falls back to "dev" for local go build / go run.
func resolveVersion() string {
	if version != "dev" {
		return version
	}
	if info, ok := debug.ReadBuildInfo(); ok && info.Main.Version != "" && info.Main.Version != "(devel)" {
		return info.Main.Version
	}
	return version
}

// Process exit codes (see the README's "Exit codes" section).
const (
	exitOK       = 0 // success
	exitError    = 1 // operational error: could not check, or invalid arguments
	exitSoft     = 2 // soft problem: expiring within -threshold, a -strict warning, or differing certs
	exitMismatch = 3 // explicit expectation failed: -pin or -expect-issuer
)

// Run wires the real dependencies and executes the program, returning the process
// exit code. The thin main package calls os.Exit(app.Run()).
func Run() int {
	return run(
		flags.NewDefaultFlagParser(),
		&cert.CertificateFetcherImpl{},
		&cert.CertificateLoaderImpl{},
		&cert.CertificatePrinterImpl{},
	)
}

// run is the program body, separated from main so it can be exercised in tests:
// it takes its dependencies as parameters and returns the process exit code
// instead of calling os.Exit, so the dispatch and error handling are unit-testable.
func run(parser flags.FlagParser, fetcher cert.CertificateFetcher, loader cert.CertificateLoader, printer cert.CertificatePrinter) int {
	cfg := parser.Parse()

	// Check if the version flag is set
	if cfg.ShowVersion {
		fmt.Printf("Version: %s\n", resolveVersion())
		fmt.Printf("GitHub: %s\n", flags.GitURL)
		return exitOK
	}

	// Resolve the list of targets from -domain (comma-separated) and -domain-file.
	// Each token may carry its own port (host:port or a URL); bare hosts use the
	// effective default port (the STARTTLS protocol's port when applicable).
	targets, err := resolveTargets(cfg, effectiveDefaultPort(cfg))
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		return exitError
	}

	// Reject unsupported flag combinations up front. validate is pure (no I/O,
	// no exit) so the guard logic is unit-testable; run owns the reporting.
	if err := validate(cfg, targets); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n\n", err)
		parser.Usage()
		return exitError
	}

	// -pin produces the normalized hex used for the match (validate already
	// rejected -pin with multiple domains; here we surface a malformed value).
	var pinHex string
	if cfg.Pin != "" {
		pinHex, err = cert.NormalizePin(cfg.Pin)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: invalid -pin: %v\n\n", err)
			parser.Usage()
			return exitError
		}
	}

	opts := cert.PrintOptions{
		Short:        cfg.Short,
		JSON:         cfg.Output == "json",
		Threshold:    cfg.Threshold,
		Color:        useColor(cfg),
		Chain:        cfg.Chain,
		Fingerprint:  cfg.Fingerprint,
		Pin:          pinHex,
		ExpectIssuer: cfg.ExpectIssuer,
	}
	timeout := time.Duration(cfg.Timeout) * time.Second

	// Connection/verification options shared by every fetch path. -cafile replaces
	// the system roots; -servername overrides the SNI and verified name.
	fetchOpts := cert.FetchOptions{
		Insecure:   cfg.Insecure,
		Timeout:    timeout,
		StartTLS:   cfg.StartTLS,
		ServerName: cfg.ServerName,
		Proxy:      cfg.Proxy,
	}
	if cfg.CAFile != "" {
		roots, loadErr := cert.LoadCAFile(cfg.CAFile)
		if loadErr != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", loadErr)
			return exitError
		}
		fetchOpts.Roots = roots
	}
	if cfg.ClientCert != "" {
		clientCert, loadErr := cert.LoadClientCert(cfg.ClientCert, cfg.ClientKey)
		if loadErr != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", loadErr)
			return exitError
		}
		fetchOpts.ClientCert = clientCert
	}

	// Prometheus exposition: fetch every target and emit one metric set each.
	if cfg.Output == "prometheus" {
		return runPrometheus(fetcher, targets, cfg, fetchOpts, pinHex)
	}

	// CSV: fetch every target and emit one row each.
	if cfg.Output == "csv" {
		return runCSV(fetcher, targets, cfg, fetchOpts)
	}

	// Nagios/Icinga plugin: a status line per run, with Nagios exit codes.
	if cfg.Output == "nagios" {
		return runNagios(fetcher, targets, cfg, opts, fetchOpts)
	}

	// -all-ips: resolve the domain and check the certificate on every address.
	if cfg.AllIPs {
		return runAllIPs(fetcher, targets[0], cfg, opts, fetchOpts)
	}

	// Single target — a certificate file or exactly one domain — keeps the
	// original output format and behavior.
	if cfg.CertFile != "" {
		info, err := loader.Load(cfg.CertFile)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error retrieving certificate: %v\n", err)
			return exitError
		}
		if cfg.Pem || cfg.Export != "" {
			return runExport(info, cfg)
		}
		return printSingle(printer, info, cfg, opts)
	}
	if len(targets) == 1 {
		t := targets[0]
		info, err := fetcher.Fetch(t.host, t.port, cfg.IPAddr, fetchOpts)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error retrieving certificate: %v\n", err)
			return exitError
		}
		if cfg.Pem || cfg.Export != "" {
			return runExport(info, cfg)
		}
		return printSingle(printer, info, cfg, opts)
	}

	// Multiple targets — mass check with aggregated output and exit code.
	return runBatch(fetcher, printer, targets, cfg, opts, fetchOpts)
}

// useColor reports whether the human-readable output should be colorized:
// only for plain text output to an interactive terminal, and never when the
// NO_COLOR environment variable is set.
func useColor(cfg flags.Config) bool {
	if cfg.Output != "text" || cfg.Short {
		return false
	}
	if os.Getenv("NO_COLOR") != "" {
		return false
	}
	fi, err := os.Stdout.Stat()
	if err != nil {
		return false
	}
	return fi.Mode()&os.ModeCharDevice != 0
}
