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
	"net/url"
	"os"
	"runtime/debug"
	"sort"
	"strconv"
	"strings"
	"sync"
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

// Process exit codes (see the README's "Exit codes" section).
const (
	exitOK       = 0 // success
	exitError    = 1 // operational error: could not check, or invalid arguments
	exitSoft     = 2 // soft problem: expiring within -threshold, a -strict warning, or differing certs
	exitMismatch = 3 // explicit expectation failed: -pin or -expect-issuer
)

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

// effectiveDefaultPort is the port used for targets that do not carry their own:
// the -port value, or the STARTTLS protocol's standard port when -starttls is set
// and -port was left at its default. An unknown protocol is left for validate to
// reject, so it does not substitute here.
func effectiveDefaultPort(cfg flags.Config) string {
	if cfg.Port == defaultPort && cfg.StartTLS != "" {
		if p, ok := starttlsPorts[cfg.StartTLS]; ok {
			return p
		}
	}
	return cfg.Port
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

	// Resolve the list of targets from -domain (comma-separated) and -domain-file.
	// Each token may carry its own port (host:port or a URL); bare hosts use the
	// effective default port (the STARTTLS protocol's port when applicable).
	targets, err := resolveTargets(cfg, effectiveDefaultPort(cfg))
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(exitError)
	}

	// Reject unsupported flag combinations up front. validate is pure (no I/O,
	// no exit) so the guard logic is unit-testable; main owns the reporting.
	if err := validate(cfg, targets); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n\n", err)
		parser.Usage()
		os.Exit(exitError)
	}

	// -pin produces the normalized hex used for the match (validate already
	// rejected -pin with multiple domains; here we surface a malformed value).
	var pinHex string
	if cfg.Pin != "" {
		pinHex, err = cert.NormalizePin(cfg.Pin)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: invalid -pin: %v\n\n", err)
			parser.Usage()
			os.Exit(exitError)
		}
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
		Proxy:      cfg.Proxy,
	}
	if cfg.CAFile != "" {
		roots, loadErr := cert.LoadCAFile(cfg.CAFile)
		if loadErr != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", loadErr)
			os.Exit(exitError)
		}
		fetchOpts.Roots = roots
	}
	if cfg.ClientCert != "" {
		clientCert, loadErr := cert.LoadClientCert(cfg.ClientCert, cfg.ClientKey)
		if loadErr != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", loadErr)
			os.Exit(exitError)
		}
		fetchOpts.ClientCert = clientCert
	}

	// Prometheus exposition: fetch every target and emit one metric set each.
	if cfg.Output == "prometheus" {
		os.Exit(runPrometheus(fetcher, targets, cfg, fetchOpts, pinHex))
	}

	// CSV: fetch every target and emit one row each.
	if cfg.Output == "csv" {
		os.Exit(runCSV(fetcher, targets, cfg, fetchOpts))
	}

	// Nagios/Icinga plugin: a status line per run, with Nagios exit codes.
	if cfg.Output == "nagios" {
		os.Exit(runNagios(fetcher, targets, cfg, opts, fetchOpts))
	}

	// -all-ips: resolve the domain and check the certificate on every address.
	if cfg.AllIPs {
		os.Exit(runAllIPs(fetcher, targets[0], cfg, opts, fetchOpts))
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
	if len(targets) == 1 {
		t := targets[0]
		info, err := fetcher.Fetch(t.host, t.port, cfg.IPAddr, fetchOpts)
		if err != nil {
			log.Fatalf("Error retrieving certificate: %v", err)
		}
		if cfg.Pem || cfg.Export != "" {
			os.Exit(runExport(info, cfg))
		}
		printSingle(printer, info, cfg, opts)
		return
	}

	// Multiple targets — mass check with aggregated output and exit code.
	os.Exit(runBatch(fetcher, printer, targets, cfg, opts, fetchOpts))
}

// validate reports the first unsupported flag combination in cfg, or nil. It is
// pure — no I/O and no process exit — so every guard is unit-testable.
func validate(cfg flags.Config, targets []target) error {
	// At least one target (a domain or a certificate file) must be specified.
	domainArg := ""
	if len(targets) > 0 {
		domainArg = targets[0].host
	}
	if err := validation.NewDefaultInputValidator().Validate(domainArg, cfg.CertFile); err != nil {
		return err
	}
	if cfg.Output != "text" && cfg.Output != "json" && cfg.Output != "prometheus" && cfg.Output != "csv" && cfg.Output != "nagios" {
		return fmt.Errorf("invalid -output %q (expected \"text\", \"json\", \"prometheus\", \"csv\" or \"nagios\")", cfg.Output)
	}
	if cfg.Timeout <= 0 {
		return fmt.Errorf("invalid -timeout %d (expected a positive number of seconds)", cfg.Timeout)
	}
	if cfg.Concurrency < 1 {
		return fmt.Errorf("invalid -concurrency %d (expected a positive number)", cfg.Concurrency)
	}
	if cfg.IPAddr != "" && len(targets) > 1 {
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
		case len(targets) != 1:
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
	if (cfg.ClientCert != "") != (cfg.ClientKey != "") {
		return errors.New("-client-cert and -client-key must be used together")
	}
	if (cfg.ClientCert != "" || cfg.ClientKey != "") && cfg.CertFile != "" {
		return errors.New("-client-cert/-client-key cannot be combined with -certfile")
	}
	if cfg.Proxy != "" && cfg.CertFile != "" {
		return errors.New("-proxy cannot be combined with -certfile")
	}
	if cfg.ServerName != "" && len(targets) > 1 {
		return errors.New("-servername cannot be combined with multiple domains")
	}
	if cfg.Pin != "" && len(targets) > 1 {
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
		case len(targets) > 1:
			return errors.New("-pem/-export require a single target")
		case cfg.Pin != "":
			return errors.New("-pem/-export cannot be combined with -pin")
		case cfg.Threshold > 0:
			return errors.New("-pem/-export cannot be combined with -threshold")
		case cfg.ExpectIssuer != "" || cfg.Strict:
			return errors.New("-pem/-export cannot be combined with -expect-issuer/-strict")
		}
	}
	if cfg.Output == "prometheus" || cfg.Output == "csv" || cfg.Output == "nagios" {
		switch {
		case cfg.AllIPs:
			return fmt.Errorf("-output %s cannot be combined with -all-ips", cfg.Output)
		case cfg.CertFile != "":
			return fmt.Errorf("-output %s cannot be combined with -certfile", cfg.Output)
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

// collectSamples fetches every target (respecting -concurrency, order preserved)
// and returns the per-target samples plus whether any failed to be retrieved or
// expires within -threshold. Shared by the prometheus and csv report formats.
func collectSamples(fetcher cert.CertificateFetcher, targets []target, cfg flags.Config, fetchOpts cert.FetchOptions) (samples []cert.PromSample, hadError, expiring bool) {
	samples = make([]cert.PromSample, 0, len(targets))
	for _, r := range fetchAll(fetcher, targets, cfg.IPAddr, fetchOpts, cfg.Concurrency) {
		label := r.target.label()
		if r.err != nil {
			hadError = true
			samples = append(samples, cert.PromSample{Domain: label, Err: r.err})
			continue
		}
		samples = append(samples, cert.PromSample{Domain: label, Info: r.info})
		if cfg.Threshold > 0 && r.info.MinDaysUntilExpiry() < cfg.Threshold {
			expiring = true
		}
	}
	return samples, hadError, expiring
}

// printSingle prints one certificate and exits with code 2 when it expires
// within the configured threshold.
func printSingle(printer cert.CertificatePrinter, info *cert.CertInfo, cfg flags.Config, opts cert.PrintOptions) {
	printer.Print(info, opts)
	// Exit code 3 when an explicit expectation about the served certificate fails
	// (a pinned fingerprint or the issuer) — a wrong cert is more urgent than an
	// upcoming expiry, so it takes precedence.
	if opts.Pin != "" && !cert.MatchesPin(info.Cert, opts.Pin) {
		os.Exit(exitMismatch)
	}
	if cfg.ExpectIssuer != "" && !cert.IssuerMatches(info.Cert, cfg.ExpectIssuer) {
		os.Exit(exitMismatch)
	}
	// Exit code 2 for soft problems: with -strict any warning fails, and any
	// certificate in the chain expiring within -threshold fails.
	if cfg.Strict && cert.HasWarnings(info) {
		os.Exit(exitSoft)
	}
	if cfg.Threshold > 0 && info.MinDaysUntilExpiry() < cfg.Threshold {
		os.Exit(exitSoft)
	}
}

// fetchResult is one target's outcome from fetchAll: either Info or Err is set.
type fetchResult struct {
	target target
	info   *cert.CertInfo
	err    error
}

// fetchAll fetches every target's certificate, running up to concurrency fetches
// at once, and returns the results in the same order as targets (so the rendered
// output is deterministic regardless of completion order). A concurrency of 1 is
// effectively sequential. The fetcher must be safe for concurrent use.
func fetchAll(fetcher cert.CertificateFetcher, targets []target, ipaddr string, fetchOpts cert.FetchOptions, concurrency int) []fetchResult {
	if concurrency < 1 {
		concurrency = 1
	}
	results := make([]fetchResult, len(targets))
	sem := make(chan struct{}, concurrency)
	var wg sync.WaitGroup
	for i, t := range targets {
		wg.Add(1)
		sem <- struct{}{}
		go func(i int, t target) {
			defer wg.Done()
			defer func() { <-sem }()
			info, err := fetcher.Fetch(t.host, t.port, ipaddr, fetchOpts)
			results[i] = fetchResult{target: t, info: info, err: err}
		}(i, t)
	}
	wg.Wait()
	return results
}

// runBatch checks every target and renders the aggregated result. Targets are
// fetched with up to cfg.Concurrency in flight, then rendered in input order. In
// JSON mode it emits an array (one object per target, with an "error" entry for
// failures); in text mode it prints one block per target, with failures on
// stderr. It returns the process exit code: 1 if any target failed to be
// retrieved, otherwise 2 if any certificate in a chain expires within the
// threshold, otherwise 0.
func runBatch(fetcher cert.CertificateFetcher, printer cert.CertificatePrinter, targets []target, cfg flags.Config, opts cert.PrintOptions, fetchOpts cert.FetchOptions) int {
	hadError := false
	expiring := false
	issuerFail := false
	strictFail := false
	printedText := false
	var entries []any

	for _, r := range fetchAll(fetcher, targets, cfg.IPAddr, fetchOpts, cfg.Concurrency) {
		label := r.target.label()
		if r.err != nil {
			hadError = true
			if opts.JSON {
				entries = append(entries, cert.ErrorPayload(label, r.err.Error()))
			} else {
				fmt.Fprintf(os.Stderr, "Error retrieving certificate for %s: %v\n", label, r.err)
			}
			continue
		}
		info := r.info

		if opts.JSON {
			entries = append(entries, cert.Payload(info, label, opts.Chain, opts.Fingerprint))
		} else if cfg.Short {
			// Multi-domain short mode: prefix each days count with its target so
			// the numbers stay attributable and greppable (target<TAB>days).
			fmt.Printf("%s\t", label)
			printer.Print(info, opts)
		} else {
			if printedText {
				fmt.Println()
			}
			fmt.Printf("==> %s\n", label)
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
			return exitError
		}
		fmt.Println(string(b))
	}

	switch {
	case hadError:
		return exitError
	case issuerFail:
		return exitMismatch
	case expiring || strictFail:
		return exitSoft
	}
	return exitOK
}

// runAllIPs resolves every address of the domain (optionally filtered to one
// family by -4/-6), checks the certificate on each (same SNI), prints the
// per-address result and reports the exit code: 1 if nothing was reachable or an
// address failed for a real reason (addresses unreachable from this host are
// skipped, not errors), otherwise 2 if the certificates differ or any expires
// within -threshold, otherwise 0.
func runAllIPs(fetcher cert.CertificateFetcher, t target, cfg flags.Config, opts cert.PrintOptions, fetchOpts cert.FetchOptions) int {
	domain := t.host
	ips, err := net.LookupIP(domain)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: failed to resolve %s: %v\n", domain, err)
		return exitError
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
		return exitError
	}
	sort.Strings(addrs)

	results := make([]cert.IPResult, 0, len(addrs))
	for _, ip := range addrs {
		info, err := fetcher.Fetch(domain, t.port, ip, fetchOpts)
		results = append(results, cert.IPResult{
			IP:      ip,
			Info:    info,
			Err:     err,
			Skipped: err != nil && isUnreachable(err),
		})
	}

	res := cert.PrintAllIPs(t.label(), results, opts)
	switch {
	case res.Reachable == 0:
		return exitError
	case res.HadError:
		return exitError
	case res.PinMismatch:
		return exitMismatch
	case !res.AllMatch:
		return exitSoft
	case cfg.Threshold > 0 && res.MinDays < cfg.Threshold:
		return exitSoft
	}
	return exitOK
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

// target is a single check target: the hostname to connect to and verify against
// (used for SNI) plus the port. The port comes from the target token itself
// (host:port or a URL) or, for a bare host, from the default port.
type target struct {
	host string
	port string
}

// label renders the target for output: the bare host on the standard HTTPS port,
// otherwise host:port (IPv6 bracketed).
func (t target) label() string {
	if t.port == defaultPort {
		return t.host
	}
	return net.JoinHostPort(t.host, t.port)
}

// parseTarget turns one -domain/-domain-file token into a target. It accepts a
// bare host (uses defaultPort), a host:port pair, or a URL (https://host:port/…,
// scheme and path discarded). An unbracketed IPv6 literal has too many colons for
// host:port and is treated as a bare host.
func parseTarget(tok, defaultPort string) (target, error) {
	if strings.Contains(tok, "://") {
		u, err := url.Parse(tok)
		if err != nil {
			return target{}, fmt.Errorf("invalid target URL %q: %v", tok, err)
		}
		host := u.Hostname()
		if host == "" {
			return target{}, fmt.Errorf("invalid target %q: missing host", tok)
		}
		port := u.Port()
		if port == "" {
			return target{host: host, port: defaultPort}, nil
		}
		if err := validatePort(port); err != nil {
			return target{}, fmt.Errorf("invalid target %q: %v", tok, err)
		}
		return target{host: host, port: port}, nil
	}
	if host, port, err := net.SplitHostPort(tok); err == nil {
		if port == "" {
			port = defaultPort
		}
		if err := validatePort(port); err != nil {
			return target{}, fmt.Errorf("invalid target %q: %v", tok, err)
		}
		return target{host: host, port: port}, nil
	}
	return target{host: tok, port: defaultPort}, nil
}

// validatePort checks that p is a decimal port in the 1–65535 range.
func validatePort(p string) error {
	n, err := strconv.Atoi(p)
	if err != nil || n < 1 || n > 65535 {
		return fmt.Errorf("port %q is not a number in 1-65535", p)
	}
	return nil
}

// resolveTargets builds the ordered, de-duplicated list of targets from the
// comma-separated -domain flag and the -domain-file flag (one per line, "-"
// reads stdin; blank lines and lines starting with "#" are ignored). defaultPort
// is used for tokens that do not carry their own port. De-duplication is by the
// resolved host:port pair, so "a.com" and "a.com:443" collapse to one.
func resolveTargets(cfg flags.Config, defaultPort string) ([]target, error) {
	var out []target
	seen := make(map[string]bool)
	var firstErr error
	add := func(tok string) {
		tok = strings.TrimSpace(tok)
		if tok == "" {
			return
		}
		t, err := parseTarget(tok, defaultPort)
		if err != nil {
			if firstErr == nil {
				firstErr = err
			}
			return
		}
		key := t.host + "\x00" + t.port
		if seen[key] {
			return
		}
		seen[key] = true
		out = append(out, t)
	}

	for _, tok := range strings.Split(cfg.Domain, ",") {
		add(tok)
	}
	if cfg.DomainFile != "" {
		lines, err := readDomainFile(cfg.DomainFile)
		if err != nil {
			return nil, err
		}
		for _, l := range lines {
			add(l)
		}
	}
	if firstErr != nil {
		return nil, firstErr
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
