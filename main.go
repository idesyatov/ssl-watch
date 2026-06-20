package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"github.com/idesyatov/ssl-watch/internal/cert"
	"github.com/idesyatov/ssl-watch/internal/flags"
	"github.com/idesyatov/ssl-watch/internal/validation"
	"io"
	"log"
	"net"
	"os"
	"runtime/debug"
	"sort"
	"strings"
	"time"
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

// defaultPort mirrors the -port flag default; when -starttls is used and the
// port was left at this value, the protocol's standard port is substituted.
const defaultPort = "443"

// starttlsPorts maps each supported STARTTLS protocol to its standard port.
var starttlsPorts = map[string]string{
	"smtp": "587",
	"imap": "143",
	"pop3": "110",
	"ftp":  "21",
}

func main() {
	// Create a new flag parser to handle command-line arguments
	parser := flags.NewDefaultFlagParser()
	// Parse the command-line flags and retrieve the configuration
	cfg := parser.Parse()

	// Check if the version flag is set
	if cfg.ShowVersion {
		fmt.Printf("Version: %s\n", resolveVersion())
		fmt.Printf("GitHub: %s\n", flags.GitURL)
		return
	}

	// Resolve the list of domains from -domain (comma-separated) and -domain-file.
	domains, err := resolveDomains(cfg)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	// Create a new input validator to validate the parsed flags
	validator := validation.NewDefaultInputValidator()
	// At least one target (a domain or a certificate file) must be specified
	if err := validator.Validate(strings.Join(domains, ","), cfg.CertFile); err != nil {
		// If validation fails, report the error, print the usage and exit non-zero
		fmt.Fprintf(os.Stderr, "Error: %v\n\n", err)
		parser.Usage()
		os.Exit(1)
	}

	// Validate the requested output format
	if cfg.Output != "text" && cfg.Output != "json" {
		fmt.Fprintf(os.Stderr, "Error: invalid -output %q (expected \"text\" or \"json\")\n\n", cfg.Output)
		parser.Usage()
		os.Exit(1)
	}

	// Validate the connection timeout
	if cfg.Timeout <= 0 {
		fmt.Fprintf(os.Stderr, "Error: invalid -timeout %d (expected a positive number of seconds)\n\n", cfg.Timeout)
		parser.Usage()
		os.Exit(1)
	}

	// A fixed IP address makes sense only for a single domain
	if cfg.IPAddr != "" && len(domains) > 1 {
		fmt.Fprintf(os.Stderr, "Error: -ipaddr cannot be combined with multiple domains\n\n")
		parser.Usage()
		os.Exit(1)
	}

	// -all-ips resolves and checks every address of a single domain
	if cfg.AllIPs {
		switch {
		case cfg.CertFile != "":
			fmt.Fprintf(os.Stderr, "Error: -all-ips cannot be combined with -certfile\n\n")
			parser.Usage()
			os.Exit(1)
		case cfg.IPAddr != "":
			fmt.Fprintf(os.Stderr, "Error: -all-ips cannot be combined with -ipaddr\n\n")
			parser.Usage()
			os.Exit(1)
		case cfg.Short:
			fmt.Fprintf(os.Stderr, "Error: -all-ips cannot be combined with -short\n\n")
			parser.Usage()
			os.Exit(1)
		case len(domains) != 1:
			fmt.Fprintf(os.Stderr, "Error: -all-ips requires exactly one domain\n\n")
			parser.Usage()
			os.Exit(1)
		}
	}

	// -4/-6 restrict the address family and only make sense with -all-ips
	if cfg.IPv4Only && cfg.IPv6Only {
		fmt.Fprintf(os.Stderr, "Error: -4 and -6 cannot be combined\n\n")
		parser.Usage()
		os.Exit(1)
	}
	if (cfg.IPv4Only || cfg.IPv6Only) && !cfg.AllIPs {
		fmt.Fprintf(os.Stderr, "Error: -4/-6 can only be used with -all-ips\n\n")
		parser.Usage()
		os.Exit(1)
	}

	// -pin verifies one cert against an expected fingerprint, so a single pin
	// makes sense only for a single target (one domain, a file, or -all-ips).
	var pinHex string
	if cfg.Pin != "" {
		if len(domains) > 1 {
			fmt.Fprintf(os.Stderr, "Error: -pin cannot be combined with multiple domains\n\n")
			parser.Usage()
			os.Exit(1)
		}
		pinHex, err = cert.NormalizePin(cfg.Pin)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: invalid -pin: %v\n\n", err)
			parser.Usage()
			os.Exit(1)
		}
	}

	// -pem / -export dump the served chain as PEM, an action distinct from the
	// normal report. They need a single direct target and replace the report, so
	// they cannot be combined with another output format or a verification flag.
	if cfg.Pem || cfg.Export != "" {
		switch {
		case cfg.Pem && cfg.Export != "":
			fmt.Fprintf(os.Stderr, "Error: -pem and -export cannot be combined\n\n")
			parser.Usage()
			os.Exit(1)
		case cfg.Output == "json":
			fmt.Fprintf(os.Stderr, "Error: -pem/-export cannot be combined with -output json\n\n")
			parser.Usage()
			os.Exit(1)
		case cfg.AllIPs:
			fmt.Fprintf(os.Stderr, "Error: -pem/-export cannot be combined with -all-ips\n\n")
			parser.Usage()
			os.Exit(1)
		case len(domains) > 1:
			fmt.Fprintf(os.Stderr, "Error: -pem/-export require a single target\n\n")
			parser.Usage()
			os.Exit(1)
		case cfg.Pin != "":
			fmt.Fprintf(os.Stderr, "Error: -pem/-export cannot be combined with -pin\n\n")
			parser.Usage()
			os.Exit(1)
		case cfg.Threshold > 0:
			fmt.Fprintf(os.Stderr, "Error: -pem/-export cannot be combined with -threshold\n\n")
			parser.Usage()
			os.Exit(1)
		}
	}

	// Validate the STARTTLS protocol and pick the protocol's default port when
	// the port was left at its default.
	if cfg.StartTLS != "" {
		port, ok := starttlsPorts[cfg.StartTLS]
		if !ok {
			fmt.Fprintf(os.Stderr, "Error: invalid -starttls %q (expected smtp, imap, pop3 or ftp)\n\n", cfg.StartTLS)
			parser.Usage()
			os.Exit(1)
		}
		if cfg.Port == defaultPort {
			cfg.Port = port
		}
	}

	// Create instances of the certificate fetcher, loader, and printer
	var fetcher cert.CertificateFetcher = &cert.CertificateFetcherImpl{}
	var loader cert.CertificateLoader = &cert.CertificateLoaderImpl{}
	var printer cert.CertificatePrinter = &cert.CertificatePrinterImpl{}

	opts := cert.PrintOptions{
		Short:       cfg.Short,
		JSON:        cfg.Output == "json",
		Threshold:   cfg.Threshold,
		Color:       useColor(cfg),
		Chain:       cfg.Chain,
		Fingerprint: cfg.Fingerprint,
		Pin:         pinHex,
	}
	timeout := time.Duration(cfg.Timeout) * time.Second

	// -all-ips: resolve the domain and check the certificate on every address.
	if cfg.AllIPs {
		os.Exit(runAllIPs(fetcher, domains[0], cfg, opts, timeout))
	}

	// Single target — a certificate file or exactly one domain — keeps the
	// original output format and behavior.
	if cfg.CertFile != "" {
		info, err := loader.Load(cfg.CertFile)
		if err != nil {
			log.Fatalf("Error retrieving certificate: %v", err)
		}
		if cfg.Pem || cfg.Export != "" {
			os.Exit(runExport(info, cfg))
		}
		printSingle(printer, info, cfg, opts)
		return
	}
	if len(domains) == 1 {
		info, err := fetcher.Fetch(domains[0], cfg.Port, cfg.IPAddr, cfg.Insecure, timeout, cfg.StartTLS)
		if err != nil {
			log.Fatalf("Error retrieving certificate: %v", err)
		}
		if cfg.Pem || cfg.Export != "" {
			os.Exit(runExport(info, cfg))
		}
		printSingle(printer, info, cfg, opts)
		return
	}

	// Multiple domains — mass check with aggregated output and exit code.
	os.Exit(runBatch(fetcher, printer, domains, cfg, opts, timeout))
}

// runExport writes the served certificate chain as PEM — to stdout (-pem) or to
// a file (-export) — and returns the process exit code (0 on success, 1 on a
// write error).
func runExport(info *cert.CertInfo, cfg flags.Config) int {
	pemBytes := cert.ChainPEM(info)
	if cfg.Export != "" {
		if err := os.WriteFile(cfg.Export, pemBytes, 0o644); err != nil {
			fmt.Fprintf(os.Stderr, "Error: failed to write %s: %v\n", cfg.Export, err)
			return 1
		}
		fmt.Printf("Wrote %d certificate(s) to %s\n", strings.Count(string(pemBytes), "BEGIN CERTIFICATE"), cfg.Export)
		return 0
	}
	if _, err := os.Stdout.Write(pemBytes); err != nil {
		fmt.Fprintf(os.Stderr, "Error: failed to write PEM: %v\n", err)
		return 1
	}
	return 0
}

// printSingle prints one certificate and exits with code 2 when it expires
// within the configured threshold.
func printSingle(printer cert.CertificatePrinter, info *cert.CertInfo, cfg flags.Config, opts cert.PrintOptions) {
	printer.Print(info, opts)
	// Exit code 3 when a pinned fingerprint does not match — a wrong/forged cert
	// is more urgent than an upcoming expiry, so it takes precedence.
	if opts.Pin != "" && !cert.MatchesPin(info.Cert, opts.Pin) {
		os.Exit(3)
	}
	// Exit code 2 when any certificate in the chain (leaf or an intermediate)
	// expires within the configured threshold, so the tool can drive alerts in
	// cron/CI off the weakest link.
	if cfg.Threshold > 0 && info.MinDaysUntilExpiry() < cfg.Threshold {
		os.Exit(2)
	}
}

// runBatch checks every domain in turn and renders the aggregated result. In
// JSON mode it emits an array (one object per domain, with an "error" entry for
// failures); in text mode it prints one block per domain, with failures on
// stderr. It returns the process exit code: 1 if any domain failed to be
// retrieved, otherwise 2 if any certificate in a chain expires within the
// threshold, otherwise 0.
func runBatch(fetcher cert.CertificateFetcher, printer cert.CertificatePrinter, domains []string, cfg flags.Config, opts cert.PrintOptions, timeout time.Duration) int {
	hadError := false
	expiring := false
	printedText := false
	var entries []any

	for _, d := range domains {
		info, err := fetcher.Fetch(d, cfg.Port, cfg.IPAddr, cfg.Insecure, timeout, cfg.StartTLS)
		if err != nil {
			hadError = true
			if opts.JSON {
				entries = append(entries, cert.ErrorPayload(d, err.Error()))
			} else {
				fmt.Fprintf(os.Stderr, "Error retrieving certificate for %s: %v\n", d, err)
			}
			continue
		}

		if opts.JSON {
			entries = append(entries, cert.Payload(info, d, opts.Chain, opts.Fingerprint))
		} else {
			if printedText && !cfg.Short {
				fmt.Println()
			}
			if !cfg.Short {
				fmt.Printf("==> %s\n", d)
			}
			printer.Print(info, opts)
			printedText = true
		}

		if cfg.Threshold > 0 && info.MinDaysUntilExpiry() < cfg.Threshold {
			expiring = true
		}
	}

	if opts.JSON {
		b, err := json.MarshalIndent(entries, "", "  ")
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: failed to encode JSON: %v\n", err)
			return 1
		}
		fmt.Println(string(b))
	}

	switch {
	case hadError:
		return 1
	case expiring:
		return 2
	}
	return 0
}

// runAllIPs resolves every address of the domain (optionally filtered to one
// family by -4/-6), checks the certificate on each (same SNI), prints the
// per-address result and reports the exit code: 1 if nothing was reachable or an
// address failed for a real reason (addresses unreachable from this host are
// skipped, not errors), otherwise 2 if the certificates differ or any expires
// within -threshold, otherwise 0.
func runAllIPs(fetcher cert.CertificateFetcher, domain string, cfg flags.Config, opts cert.PrintOptions, timeout time.Duration) int {
	ips, err := net.LookupIP(domain)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: failed to resolve %s: %v\n", domain, err)
		return 1
	}

	seen := make(map[string]bool)
	var addrs []string
	for _, ip := range ips {
		if cfg.IPv4Only && ip.To4() == nil {
			continue
		}
		if cfg.IPv6Only && ip.To4() != nil {
			continue
		}
		s := ip.String()
		if !seen[s] {
			seen[s] = true
			addrs = append(addrs, s)
		}
	}
	if len(addrs) == 0 {
		fmt.Fprintf(os.Stderr, "Error: no matching addresses resolved for %s\n", domain)
		return 1
	}
	sort.Strings(addrs)

	results := make([]cert.IPResult, 0, len(addrs))
	for _, ip := range addrs {
		info, err := fetcher.Fetch(domain, cfg.Port, ip, cfg.Insecure, timeout, cfg.StartTLS)
		results = append(results, cert.IPResult{
			IP:      ip,
			Info:    info,
			Err:     err,
			Skipped: err != nil && isUnreachable(err),
		})
	}

	res := cert.PrintAllIPs(domain, results, opts)
	switch {
	case res.Reachable == 0:
		return 1
	case res.HadError:
		return 1
	case res.PinMismatch:
		return 3
	case !res.AllMatch:
		return 2
	case cfg.Threshold > 0 && res.MinDays < cfg.Threshold:
		return 2
	}
	return 0
}

// isUnreachable reports whether a connection error means the address family is
// not routable from this host (e.g. no IPv6 route) — a benign skip rather than a
// real failure. Matched by message text to stay portable (the syscall error
// constants differ on Windows).
func isUnreachable(err error) bool {
	if err == nil {
		return false
	}
	s := err.Error()
	return strings.Contains(s, "network is unreachable") ||
		strings.Contains(s, "no route to host")
}

// resolveDomains builds the ordered, de-duplicated list of domains from the
// comma-separated -domain flag and the -domain-file flag (one per line, "-"
// reads stdin; blank lines and lines starting with "#" are ignored).
func resolveDomains(cfg flags.Config) ([]string, error) {
	var out []string
	seen := make(map[string]bool)
	add := func(d string) {
		d = strings.TrimSpace(d)
		if d == "" || seen[d] {
			return
		}
		seen[d] = true
		out = append(out, d)
	}

	for _, d := range strings.Split(cfg.Domain, ",") {
		add(d)
	}
	if cfg.DomainFile != "" {
		lines, err := readDomainFile(cfg.DomainFile)
		if err != nil {
			return nil, err
		}
		for _, d := range lines {
			add(d)
		}
	}
	return out, nil
}

// readDomainFile reads domains from the given path, one per line, skipping blank
// lines and lines starting with "#". A path of "-" reads from stdin.
func readDomainFile(path string) ([]string, error) {
	var r io.Reader = os.Stdin
	if path != "-" {
		f, err := os.Open(path)
		if err != nil {
			return nil, fmt.Errorf("failed to read domain file %s: %v", path, err)
		}
		defer f.Close()
		r = f
	}

	var lines []string
	sc := bufio.NewScanner(r)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		lines = append(lines, line)
	}
	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("failed to read domain file %s: %v", path, err)
	}
	return lines, nil
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
