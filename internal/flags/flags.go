package flags

import (
	"flag"
	"os"
)

// Config holds the parsed command-line options.
type Config struct {
	Domain      string // Domain to check the certificate for
	CertFile    string // Path to the local certificate file
	Port        string // Port to connect to
	IPAddr      string // IP address to connect to (optional)
	Short       bool   // Output only the number of days remaining until expiration
	ShowVersion bool   // Show version and exit
}

// FlagParser defines an interface for parsing command-line flags.
type FlagParser interface {
	// Parse processes the command-line flags and returns the parsed configuration.
	Parse() Config

	// PrintDefaults prints the default values of the command-line flags.
	PrintDefaults()
}

// DefaultFlagParser is an implementation of the FlagParser interface.
// It owns its own flag set to avoid relying on global state, which makes it
// safe to construct and parse repeatedly (e.g. in tests).
type DefaultFlagParser struct {
	fs          *flag.FlagSet
	domain      *string
	certFile    *string
	port        *string
	ipaddr      *string
	short       *bool
	showVersion *bool
}

// Parse processes the command-line flags and returns the parsed configuration.
func (d *DefaultFlagParser) Parse() Config {
	d.fs.Parse(os.Args[1:])
	return Config{
		Domain:      *d.domain,
		CertFile:    *d.certFile,
		Port:        *d.port,
		IPAddr:      *d.ipaddr,
		Short:       *d.short,
		ShowVersion: *d.showVersion,
	}
}

// PrintDefaults prints the default values of the command-line flags.
func (d *DefaultFlagParser) PrintDefaults() {
	d.fs.PrintDefaults()
}

// NewDefaultFlagParser creates and returns a new instance of DefaultFlagParser,
// which implements the FlagParser interface.
func NewDefaultFlagParser() FlagParser {
	fs := flag.NewFlagSet("ssl-watch", flag.ExitOnError)
	return &DefaultFlagParser{
		fs:          fs,
		domain:      fs.String("domain", "", "Domain to check the certificate for"),
		certFile:    fs.String("certfile", "", "Path to the local certificate file"),
		port:        fs.String("port", "443", "Port to connect to (optional)"),
		ipaddr:      fs.String("ipaddr", "", "IP address to connect to (optional)"),
		short:       fs.Bool("short", false, "Output only the number of days remaining until certificate expiration"),
		showVersion: fs.Bool("version", false, "Show version"),
	}
}
