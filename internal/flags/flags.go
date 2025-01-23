package flags

import (
	"flag"
)

// FlagParser defines an interface for parsing command-line flags.
type FlagParser interface {
	// Parse processes the command-line flags and returns the parsed values.
	// It returns the domain, certificate file path, port, IP address, and a boolean indicating
	// whether to output only the number of days remaining until certificate expiration.
	Parse() (string, string, string, string, bool)
	
	// PrintDefaults prints the default values of the command-line flags.
	PrintDefaults()
}

// DefaultFlagParser is an implementation of the FlagParser interface.
// It provides a standard mechanism for parsing command-line flags.
type DefaultFlagParser struct{}

// Parse processes the command-line flags and returns the values for domain, certFile, port, ipaddr, and short.
// It uses the flag package to define and parse the flags.
func (d *DefaultFlagParser) Parse() (string, string, string, string, bool) {
	domain := flag.String("domain", "", "Domain to check the certificate file")
	certFile := flag.String("certfile", "", "Path to the local certificate file")
	port := flag.String("port", "443", "Port to connect (optional)")
	ipaddr := flag.String("ipaddr", "", "IP address to connect to (optional)")
	short := flag.Bool("short", false, "Output only the number of days remaining until certificate expiration")
	flag.Parse()
	return *domain, *certFile, *port, *ipaddr, *short
}

// PrintDefaults prints the default values of the command-line flags using the flag package.
func (d *DefaultFlagParser) PrintDefaults() {
	flag.PrintDefaults()
}

// NewDefaultFlagParser creates and returns a new instance of DefaultFlagParser,
// which implements the FlagParser interface.
func NewDefaultFlagParser() FlagParser {
	return &DefaultFlagParser{}
}
