package flags

import (
	"flag"
	"fmt"
	"os"
)

// Project metadata shared by the help header and the version output.
const (
	appName      = "ssl-watch"
	appShortDesc = "check the SSL certificate of a domain or a local certificate file"
	// GitURL is the project home page, shown in help and version output.
	GitURL = "https://github.com/idesyatov/ssl-watch"
)

// Config holds the parsed command-line options.
type Config struct {
	Domain       string // Domain(s) to check, comma-separated for several
	DomainFile   string // Path to a file with one domain per line ("-" reads stdin)
	CertFile     string // Path to the local certificate file
	Port         string // Port to connect to
	IPAddr       string // IP address to connect to (optional)
	ServerName   string // SNI / hostname to verify against (overrides the domain)
	CAFile       string // PEM bundle of trust anchors to verify against (replaces system roots)
	ClientCert   string // Client certificate (PEM) for mutual TLS
	ClientKey    string // Private key (PEM) for the client certificate
	Short        bool   // Output only the number of days remaining until expiration
	Insecure     bool   // Skip certificate chain verification
	Threshold    int    // Expiry warning threshold in days (0 = disabled); drives exit code 2
	ExpectIssuer string // Assert the issuer contains this substring; exit 3 on mismatch
	Strict       bool   // Treat warnings as failures (exit 2)
	Output       string // Output format: "text" or "json"
	Chain        bool   // Print every certificate in the chain
	Fingerprint  bool   // Print the certificate and public-key SHA-256 fingerprints
	Pin          string // Verify against a pinned fingerprint (sha256:<hex>); exit 3 on mismatch
	Pem          bool   // Print the certificate chain as PEM to stdout
	Export       string // Write the certificate chain as PEM to the given file
	AllIPs       bool   // Check the certificate on every resolved IP of the domain
	IPv4Only     bool   // Restrict -all-ips to IPv4 addresses
	IPv6Only     bool   // Restrict -all-ips to IPv6 addresses
	Timeout      int    // Connection timeout in seconds for fetching a remote certificate
	Concurrency  int    // Number of targets to check in parallel in a batch (1 = sequential)
	StartTLS     string // STARTTLS protocol to upgrade the connection: smtp/imap/pop3/ftp (empty = direct TLS)
	ShowVersion  bool   // Show version and exit
}

// FlagParser defines an interface for parsing command-line flags.
type FlagParser interface {
	// Parse processes the command-line flags and returns the parsed configuration.
	Parse() Config

	// PrintDefaults prints the default values of the command-line flags.
	PrintDefaults()

	// Usage prints the full usage text (header with description, examples and
	// the project link, followed by the flags) to the flag set's output.
	Usage()
}

// DefaultFlagParser is an implementation of the FlagParser interface.
// It owns its own flag set to avoid relying on global state, which makes it
// safe to construct and parse repeatedly (e.g. in tests).
type DefaultFlagParser struct {
	fs           *flag.FlagSet
	domain       *string
	domainFile   *string
	certFile     *string
	port         *string
	ipaddr       *string
	serverName   *string
	caFile       *string
	clientCert   *string
	clientKey    *string
	short        *bool
	insecure     *bool
	threshold    *int
	output       *string
	chain        *bool
	fingerprint  *bool
	pin          *string
	expectIssuer *string
	strict       *bool
	pem          *bool
	export       *string
	allIPs       *bool
	ipv4Only     *bool
	ipv6Only     *bool
	timeout      *int
	concurrency  *int
	starttls     *string
	showVersion  *bool
}

// Parse processes the command-line flags and returns the parsed configuration.
func (d *DefaultFlagParser) Parse() Config {
	// flag.ExitOnError makes Parse exit on error rather than return one.
	_ = d.fs.Parse(os.Args[1:])
	return Config{
		Domain:       *d.domain,
		DomainFile:   *d.domainFile,
		CertFile:     *d.certFile,
		Port:         *d.port,
		IPAddr:       *d.ipaddr,
		ServerName:   *d.serverName,
		CAFile:       *d.caFile,
		ClientCert:   *d.clientCert,
		ClientKey:    *d.clientKey,
		Short:        *d.short,
		Insecure:     *d.insecure,
		Threshold:    *d.threshold,
		Output:       *d.output,
		Chain:        *d.chain,
		ExpectIssuer: *d.expectIssuer,
		Strict:       *d.strict,
		Fingerprint:  *d.fingerprint,
		Pin:          *d.pin,
		Pem:          *d.pem,
		Export:       *d.export,
		AllIPs:       *d.allIPs,
		IPv4Only:     *d.ipv4Only,
		IPv6Only:     *d.ipv6Only,
		Timeout:      *d.timeout,
		Concurrency:  *d.concurrency,
		StartTLS:     *d.starttls,
		ShowVersion:  *d.showVersion,
	}
}

// PrintDefaults prints the default values of the command-line flags.
func (d *DefaultFlagParser) PrintDefaults() {
	d.fs.PrintDefaults()
}

// Usage prints the full usage text to the flag set's output.
func (d *DefaultFlagParser) Usage() {
	d.fs.Usage()
}

// NewDefaultFlagParser creates and returns a new instance of DefaultFlagParser,
// which implements the FlagParser interface.
func NewDefaultFlagParser() FlagParser {
	fs := flag.NewFlagSet(appName, flag.ExitOnError)
	p := &DefaultFlagParser{
		fs:           fs,
		domain:       fs.String("domain", "", "Domain(s) to check, comma-separated for several; each may carry a port (host:port) or be a URL (e.g. a.com,b.com:8443)"),
		domainFile:   fs.String("domain-file", "", "Path to a file with one domain per line (\"-\" reads stdin)"),
		certFile:     fs.String("certfile", "", "Path to the local certificate file (- for stdin)"),
		port:         fs.String("port", "443", "Default port for targets that don't carry their own (host:port overrides)"),
		ipaddr:       fs.String("ipaddr", "", "IP address to connect to (optional)"),
		serverName:   fs.String("servername", "", "SNI/hostname to verify against, overriding the domain (e.g. with -ipaddr)"),
		caFile:       fs.String("cafile", "", "PEM bundle of trusted roots to verify against, replacing the system roots"),
		clientCert:   fs.String("client-cert", "", "Client certificate (PEM) for mutual TLS (requires -client-key)"),
		clientKey:    fs.String("client-key", "", "Private key (PEM) for the client certificate (requires -client-cert)"),
		short:        fs.Bool("short", false, "Output only the number of days remaining until certificate expiration"),
		insecure:     fs.Bool("insecure", false, "Skip certificate chain verification"),
		threshold:    fs.Int("threshold", 0, "Warn (exit code 2) when days remaining is below this value (0 disables)"),
		output:       fs.String("output", "text", "Output format: text, json, prometheus or csv"),
		chain:        fs.Bool("chain", false, "Print every certificate in the chain"),
		fingerprint:  fs.Bool("fingerprint", false, "Print the certificate and public-key SHA-256 fingerprints"),
		pin:          fs.String("pin", "", "Verify against a pinned fingerprint (sha256:<hex>, cert or public key); exit 3 on mismatch"),
		expectIssuer: fs.String("expect-issuer", "", "Assert the certificate issuer contains this substring (case-insensitive); exit 3 on mismatch"),
		strict:       fs.Bool("strict", false, "Treat warnings (not-yet-valid, name mismatch, untrusted chain, …) as failures; exit 2"),
		pem:          fs.Bool("pem", false, "Print the certificate chain as PEM to stdout"),
		export:       fs.String("export", "", "Write the certificate chain as PEM to the given file"),
		allIPs:       fs.Bool("all-ips", false, "Check the certificate on every resolved IP of the domain (single domain only)"),
		ipv4Only:     fs.Bool("4", false, "With -all-ips, check IPv4 addresses only"),
		ipv6Only:     fs.Bool("6", false, "With -all-ips, check IPv6 addresses only"),
		timeout:      fs.Int("timeout", 10, "Connection timeout in seconds when fetching a remote certificate"),
		concurrency:  fs.Int("concurrency", 1, "Number of targets to check in parallel when several are given (1 = sequential)"),
		starttls:     fs.String("starttls", "", "Upgrade the connection via STARTTLS: smtp, imap, pop3 or ftp (default: direct TLS)"),
		showVersion:  fs.Bool("version", false, "Show version"),
	}

	// Custom usage: description, examples, the project link and flags grouped by
	// purpose for readability.
	fs.Usage = func() {
		out := fs.Output()

		// flagLine prints one flag as "-name  usage (default ...)", omitting the
		// default when it is the zero value (matching flag.PrintDefaults).
		flagLine := func(name string) {
			f := fs.Lookup(name)
			if f == nil {
				return
			}
			line := fmt.Sprintf("  -%-12s %s", f.Name, f.Usage)
			if f.DefValue != "" && f.DefValue != "false" && f.DefValue != "0" {
				line += fmt.Sprintf(" (default %s)", f.DefValue)
			}
			fmt.Fprintln(out, line)
		}

		fmt.Fprintf(out, "%s - %s\n\n", appName, appShortDesc)
		fmt.Fprintf(out, "Usage:\n")
		fmt.Fprintf(out, "  %s -domain example.com\n", appName)
		fmt.Fprintf(out, "  %s -domain a.com,b.com:8443\n", appName)
		fmt.Fprintf(out, "  %s -domain-file domains.txt -concurrency 10\n", appName)
		fmt.Fprintf(out, "  %s -domain smtp.example.com -starttls smtp\n", appName)
		fmt.Fprintf(out, "  %s -domain example.com -chain\n", appName)
		fmt.Fprintf(out, "  %s -domain example.com -all-ips\n", appName)
		fmt.Fprintf(out, "  %s -domain example.com -pin sha256:<hex>\n", appName)
		fmt.Fprintf(out, "  %s -certfile /path/to/cert.crt\n", appName)
		fmt.Fprintf(out, "  cat cert.pem | %s -certfile -\n\n", appName)
		fmt.Fprintf(out, "GitHub: %s\n\n", GitURL)

		fmt.Fprintf(out, "Target:\n")
		flagLine("domain")
		flagLine("domain-file")
		flagLine("certfile")
		fmt.Fprintf(out, "\nConnection:\n")
		flagLine("port")
		flagLine("ipaddr")
		flagLine("servername")
		flagLine("starttls")
		flagLine("timeout")
		flagLine("concurrency")
		flagLine("cafile")
		flagLine("client-cert")
		flagLine("client-key")
		flagLine("insecure")
		fmt.Fprintf(out, "\nOutput:\n")
		flagLine("output")
		flagLine("short")
		flagLine("chain")
		flagLine("fingerprint")
		flagLine("pem")
		flagLine("export")
		flagLine("all-ips")
		flagLine("4")
		flagLine("6")
		fmt.Fprintf(out, "\nMonitoring:\n")
		flagLine("threshold")
		flagLine("pin")
		flagLine("expect-issuer")
		flagLine("strict")
		fmt.Fprintf(out, "\nMisc:\n")
		flagLine("version")
	}

	return p
}
