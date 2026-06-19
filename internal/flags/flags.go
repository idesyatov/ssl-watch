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
	Domain      string // Domain(s) to check, comma-separated for several
	DomainFile  string // Path to a file with one domain per line ("-" reads stdin)
	CertFile    string // Path to the local certificate file
	Port        string // Port to connect to
	IPAddr      string // IP address to connect to (optional)
	Short       bool   // Output only the number of days remaining until expiration
	Insecure    bool   // Skip certificate chain verification
	Threshold   int    // Expiry warning threshold in days (0 = disabled); drives exit code 2
	Output      string // Output format: "text" or "json"
	Chain       bool   // Print every certificate in the chain
	AllIPs      bool   // Check the certificate on every resolved IP of the domain
	Timeout     int    // Connection timeout in seconds for fetching a remote certificate
	StartTLS    string // STARTTLS protocol to upgrade the connection: smtp/imap/pop3/ftp (empty = direct TLS)
	ShowVersion bool   // Show version and exit
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
	fs          *flag.FlagSet
	domain      *string
	domainFile  *string
	certFile    *string
	port        *string
	ipaddr      *string
	short       *bool
	insecure    *bool
	threshold   *int
	output      *string
	chain       *bool
	allIPs      *bool
	timeout     *int
	starttls    *string
	showVersion *bool
}

// Parse processes the command-line flags and returns the parsed configuration.
func (d *DefaultFlagParser) Parse() Config {
	// flag.ExitOnError makes Parse exit on error rather than return one.
	_ = d.fs.Parse(os.Args[1:])
	return Config{
		Domain:      *d.domain,
		DomainFile:  *d.domainFile,
		CertFile:    *d.certFile,
		Port:        *d.port,
		IPAddr:      *d.ipaddr,
		Short:       *d.short,
		Insecure:    *d.insecure,
		Threshold:   *d.threshold,
		Output:      *d.output,
		Chain:       *d.chain,
		AllIPs:      *d.allIPs,
		Timeout:     *d.timeout,
		StartTLS:    *d.starttls,
		ShowVersion: *d.showVersion,
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
		fs:          fs,
		domain:      fs.String("domain", "", "Domain(s) to check, comma-separated for several (e.g. a.com,b.com)"),
		domainFile:  fs.String("domain-file", "", "Path to a file with one domain per line (\"-\" reads stdin)"),
		certFile:    fs.String("certfile", "", "Path to the local certificate file"),
		port:        fs.String("port", "443", "Port to connect to (optional)"),
		ipaddr:      fs.String("ipaddr", "", "IP address to connect to (optional)"),
		short:       fs.Bool("short", false, "Output only the number of days remaining until certificate expiration"),
		insecure:    fs.Bool("insecure", false, "Skip certificate chain verification"),
		threshold:   fs.Int("threshold", 0, "Warn (exit code 2) when days remaining is below this value (0 disables)"),
		output:      fs.String("output", "text", "Output format: text or json"),
		chain:       fs.Bool("chain", false, "Print every certificate in the chain"),
		allIPs:      fs.Bool("all-ips", false, "Check the certificate on every resolved IP of the domain (single domain only)"),
		timeout:     fs.Int("timeout", 10, "Connection timeout in seconds when fetching a remote certificate"),
		starttls:    fs.String("starttls", "", "Upgrade the connection via STARTTLS: smtp, imap, pop3 or ftp (default: direct TLS)"),
		showVersion: fs.Bool("version", false, "Show version"),
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
		fmt.Fprintf(out, "  %s -domain a.com,b.com\n", appName)
		fmt.Fprintf(out, "  %s -domain-file domains.txt\n", appName)
		fmt.Fprintf(out, "  %s -domain smtp.example.com -starttls smtp\n", appName)
		fmt.Fprintf(out, "  %s -domain example.com -chain\n", appName)
		fmt.Fprintf(out, "  %s -domain example.com -all-ips\n", appName)
		fmt.Fprintf(out, "  %s -certfile /path/to/cert.crt\n\n", appName)
		fmt.Fprintf(out, "GitHub: %s\n\n", GitURL)

		fmt.Fprintf(out, "Target:\n")
		flagLine("domain")
		flagLine("domain-file")
		flagLine("certfile")
		fmt.Fprintf(out, "\nConnection:\n")
		flagLine("port")
		flagLine("ipaddr")
		flagLine("starttls")
		flagLine("timeout")
		flagLine("insecure")
		fmt.Fprintf(out, "\nOutput:\n")
		flagLine("output")
		flagLine("short")
		flagLine("chain")
		flagLine("all-ips")
		fmt.Fprintf(out, "\nMonitoring:\n")
		flagLine("threshold")
		fmt.Fprintf(out, "\nMisc:\n")
		flagLine("version")
	}

	return p
}
