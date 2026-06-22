package cert

import (
	"crypto/tls"
	"crypto/x509"
	"time"
)

// CertInfo aggregates a retrieved certificate together with metadata about how
// it was obtained and the result of chain verification.
type CertInfo struct {
	Cert        *x509.Certificate   // The retrieved certificate (leaf)
	Chain       []*x509.Certificate // Full peer chain (leaf first); nil when loaded from a file
	UsedIP      string              // Remote IP address; empty when loaded from a file
	TLSVersion  string              // Negotiated TLS version; empty when loaded from a file
	CipherSuite string              // Negotiated cipher suite; empty when loaded from a file
	CheckedName string              // Hostname the cert was requested for; empty when loaded from a file
	FromFile    bool                // True when the certificate was loaded from a local file
	Verified    bool                // True when chain verification was attempted
	ChainErr    error               // Chain verification error; nil means valid (only meaningful when Verified)
}

// FetchOptions controls how Fetch connects and verifies. The zero value dials
// direct TLS, verifies against the system roots, and uses the domain as the SNI.
type FetchOptions struct {
	Insecure   bool             // Skip chain verification (still retrieves the cert)
	Timeout    time.Duration    // Bounds the connection (and STARTTLS negotiation)
	StartTLS   string           // smtp/imap/pop3/ftp to upgrade via STARTTLS; empty = direct TLS
	ServerName string           // SNI and hostname to verify against; empty = use domain
	Roots      *x509.CertPool   // Trust anchors for verification; nil = system roots
	ClientCert *tls.Certificate // Client certificate for mutual TLS; nil = none
	Proxy      string           // HTTP CONNECT proxy URL; empty = direct connection
}

// CertificateFetcher defines an interface for fetching certificates from a domain or IP address.
type CertificateFetcher interface {
	// Fetch retrieves the certificate for the specified domain and port, or IP
	// address, with the connection and verification behaviour set by opts.
	// Returns the certificate information and an error if any occurred.
	Fetch(domain, port, ipaddr string, opts FetchOptions) (*CertInfo, error)
}

// CertificateLoader defines an interface for loading certificates from a file.
type CertificateLoader interface {
	// Load reads a certificate from the specified file and returns it.
	// Returns the loaded certificate information and an error if any occurred.
	Load(certFile string) (*CertInfo, error)
}

// PrintOptions controls how certificate information is rendered.
type PrintOptions struct {
	Short     bool // Print only the number of days remaining
	JSON      bool // Print machine-readable JSON
	Threshold int  // Days threshold for the expiry warning highlight (0 = disabled)
	Color     bool // Colorize the human-readable output
	Chain     bool // Print every certificate in the chain

	Fingerprint  bool   // Print the certificate and public-key SHA-256 fingerprints
	Pin          string // Normalized hex pin to verify against (empty = disabled)
	ExpectIssuer string // Warn when the issuer does not contain this substring (empty = disabled)
}

// CertificatePrinter defines an interface for printing certificate details.
type CertificatePrinter interface {
	// Print outputs the details of the certificate according to the given options.
	Print(info *CertInfo, opts PrintOptions)
}

// DaysUntilExpiry returns the whole number of days until the certificate expires.
// The value is negative if the certificate has already expired.
func DaysUntilExpiry(cert *x509.Certificate) int {
	return int(time.Until(cert.NotAfter).Hours() / 24)
}

// MinDaysUntilExpiry returns the smallest days-until-expiry across the whole
// chain (leaf plus any intermediates). When no chain is recorded (file load) it
// falls back to the leaf, so callers can drive the expiry exit code off the
// weakest link rather than the leaf alone.
func (info *CertInfo) MinDaysUntilExpiry() int {
	min := DaysUntilExpiry(info.Cert)
	for _, c := range info.Chain {
		if d := DaysUntilExpiry(c); d < min {
			min = d
		}
	}
	return min
}
