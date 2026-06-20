package main

import (
	"bufio"
	"encoding/json"
	"errors"
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

	// Reject unsupported flag combinations up front. validate is pure (no I/O,
	// no exit) so the guard logic is unit-testable; main owns the reporting.
	if err := validate(cfg, domains); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n\n", err)
		parser.Usage()
		os.Exit(1)
	}

	// -pin produces the normalized hex used for the match (validate already
	// rejected -pin with multiple domains; here we surface a malformed value).
	var pinHex string
	if cfg.Pin != "" {
		pinHex, err = cert.NormalizePin(cfg.Pin)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: invalid -pin: %v\n\n", err)
			parser.Usage()
			os.Exit(1)
		}
	}

	// With -starttls, substitute the protocol's default port when the port was
	// left at its default (validate has confirmed the protocol is known).
	if cfg.StartTLS != "" && cfg.Port == defaultPort {
		cfg.Port = starttlsPorts[cfg.StartTLS]
	}

	// Create instances of the certificate fetcher, loader, and printer
	var fetcher cert.CertificateFetcher = &cert.CertificateFetcherImpl{}
	var loader cert.CertificateLoader = &cert.CertificateLoaderImpl{}
	var printer cert.CertificatePrinter = &cert.CertificatePrinterImpl{}

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
	}
	if cfg.CAFile != "" {
		roots, loadErr := cert.LoadCAFile(cfg.CAFile)
		if loadErr != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", loadErr)
			os.Exit(1)
		}
		fetchOpts.Roots = roots
	}

	// Prometheus exposition: fetch every domain and emit one metric set each.
	if cfg.Output == "prometheus" {
		os.Exit(runPrometheus(fetcher, domains, cfg, fetchOpts, pinHex))
	}

	// -all-ips: resolve the domain and check the certificate on every address.
	if cfg.AllIPs {
		os.Exit(runAllIPs(fetcher, domains[0], cfg, opts, fetchOpts))
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
		info, err := fetcher.Fetch(domains[0], cfg.Port, cfg.IPAddr, fetchOpts)
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
	os.Exit(runBatch(fetcher, printer, domains, cfg, opts, fetchOpts))
}

// validate reports the first unsupported flag combination in cfg, or nil. It is
// pure — no I/O and no process exit — so every guard is unit-testable.
func validate(cfg flags.Config, domains []string) error {
	// At least one target (a domain or a certificate file) must be specified.
	if err := validation.NewDefaultInputValidator().Validate(strings.Join(domains, ","), cfg.CertFile); err != nil {
		return err
	}
	if cfg.Output != "text" && cfg.Output != "json" && cfg.Output != "prometheus" {
		return fmt.Errorf("invalid -output %q (expected \"text\", \"json\" or \"prometheus\")", cfg.Output)
	}
	if cfg.Timeout <= 0 {
		return fmt.Errorf("invalid -timeout %d (expected a positive number of seconds)", cfg.Timeout)
	}
	if cfg.IPAddr != "" && len(domains) > 1 {
		return errors.New("-ipaddr cannot be combined with multiple domains")
	}
	if cfg.AllIPs {
		switch {
		case cfg.CertFile != "":
			return errors.New("-all-ips cannot be combined with -certfile")
		case cfg.IPAddr != "":
			return errors.New("-all-ips cannot be combined with -ipaddr")
		case cfg.Short:
			return errors.New("-all-ips cannot be combined with -short")
		case cfg.ExpectIssuer != "" || cfg.Strict:
			return errors.New("-all-ips cannot be combined with -expect-issuer/-strict")
		case len(domains) != 1:
			return errors.New("-all-ips requires exactly one domain")
		}
	}
	if cfg.IPv4Only && cfg.IPv6Only {
		return errors.New("-4 and -6 cannot be combined")
	}
	if (cfg.IPv4Only || cfg.IPv6Only) && !cfg.AllIPs {
		return errors.New("-4/-6 can only be used with -all-ips")
	}
	if cfg.CAFile != "" && cfg.Insecure {
		return errors.New("-cafile cannot be combined with -insecure")
	}
	if (cfg.CAFile != "" || cfg.ServerName != "") && cfg.CertFile != "" {
		return errors.New("-cafile/-servername cannot be combined with -certfile")
	}
	if cfg.ServerName != "" && len(domains) > 1 {
		return errors.New("-servername cannot be combined with multiple domains")
	}
	if cfg.Pin != "" && len(domains) > 1 {
		return errors.New("-pin cannot be combined with multiple domains")
	}
	if cfg.Pem || cfg.Export != "" {
		switch {
		case cfg.Pem && cfg.Export != "":
			return errors.New("-pem and -export cannot be combined")
		case cfg.Output != "text":
			return fmt.Errorf("-pem/-export cannot be combined with -output %s", cfg.Output)
		case cfg.AllIPs:
			return errors.New("-pem/-export cannot be combined with -all-ips")
		case len(domains) > 1:
			return errors.New("-pem/-export require a single target")
		case cfg.Pin != "":
			return errors.New("-pem/-export cannot be combined with -pin")
		case cfg.Threshold > 0:
			return errors.New("-pem/-export cannot be combined with -threshold")
		case cfg.ExpectIssuer != "" || cfg.Strict:
			return errors.New("-pem/-export cannot be combined with -expect-issuer/-strict")
		}
	}
	if cfg.Output == "prometheus" {
		switch {
		case cfg.AllIPs:
			return errors.New("-output prometheus cannot be combined with -all-ips")
		case cfg.CertFile != "":
			return errors.New("-output prometheus cannot be combined with -certfile")
		}
	}
	if cfg.StartTLS != "" {
		if _, ok := starttlsPorts[cfg.StartTLS]; !ok {
			return fmt.Errorf("invalid -starttls %q (expected smtp, imap, pop3 or ftp)", cfg.StartTLS)
		}
	}
	return nil
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

// runPrometheus fetches every domain and writes the results in Prometheus
// exposition format to stdout. It returns the aggregated exit code: 1 if any
// domain failed to be retrieved, otherwise 2 if any certificate expires within
// -threshold, otherwise 0.
func runPrometheus(fetcher cert.CertificateFetcher, domains []string, cfg flags.Config, fetchOpts cert.FetchOptions, pinHex string) int {
	samples := make([]cert.PromSample, 0, len(domains))
	hadError := false
	expiring := false
	for _, d := range domains {
		info, err := fetcher.Fetch(d, cfg.Port, cfg.IPAddr, fetchOpts)
		if err != nil {
			hadError = true
			samples = append(samples, cert.PromSample{Domain: d, Err: err})
			continue
		}
		samples = append(samples, cert.PromSample{Domain: d, Info: info})
		if cfg.Threshold > 0 && info.MinDaysUntilExpiry() < cfg.Threshold {
			expiring = true
		}
	}
	cert.WritePrometheus(os.Stdout, samples, pinHex)
	switch {
	case hadError:
		return 1
	case expiring:
		return 2
	}
	return 0
}

// printSingle prints one certificate and exits with code 2 when it expires
// within the configured threshold.
func printSingle(printer cert.CertificatePrinter, info *cert.CertInfo, cfg flags.Config, opts cert.PrintOptions) {
	printer.Print(info, opts)
	// Exit code 3 when an explicit expectation about the served certificate fails
	// (a pinned fingerprint or the issuer) — a wrong cert is more urgent than an
	// upcoming expiry, so it takes precedence.
	if opts.Pin != "" && !cert.MatchesPin(info.Cert, opts.Pin) {
		os.Exit(3)
	}
	if cfg.ExpectIssuer != "" && !cert.IssuerMatches(info.Cert, cfg.ExpectIssuer) {
		os.Exit(3)
	}
	// Exit code 2 for soft problems: with -strict any warning fails, and any
	// certificate in the chain expiring within -threshold fails.
	if cfg.Strict && cert.HasWarnings(info) {
		os.Exit(2)
	}
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
func runBatch(fetcher cert.CertificateFetcher, printer cert.CertificatePrinter, domains []string, cfg flags.Config, opts cert.PrintOptions, fetchOpts cert.FetchOptions) int {
	hadError := false
	expiring := false
	issuerFail := false
	strictFail := false
	printedText := false
	var entries []any

	for _, d := range domains {
		info, err := fetcher.Fetch(d, cfg.Port, cfg.IPAddr, fetchOpts)
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
		if cfg.ExpectIssuer != "" && !cert.IssuerMatches(info.Cert, cfg.ExpectIssuer) {
			issuerFail = true
		}
		if cfg.Strict && cert.HasWarnings(info) {
			strictFail = true
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
	case issuerFail:
		return 3
	case expiring || strictFail:
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
func runAllIPs(fetcher cert.CertificateFetcher, domain string, cfg flags.Config, opts cert.PrintOptions, fetchOpts cert.FetchOptions) int {
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
		info, err := fetcher.Fetch(domain, cfg.Port, ip, fetchOpts)
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
