package cert

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"os"
	"strings"
	"time"
)

// CertInfo aggregates a retrieved certificate together with metadata about how
// it was obtained and the result of chain verification.
type CertInfo struct {
	Cert     *x509.Certificate   // The retrieved certificate (leaf)
	Chain    []*x509.Certificate // Full peer chain (leaf first); nil when loaded from a file
	UsedIP   string              // Remote IP address; empty when loaded from a file
	FromFile bool                // True when the certificate was loaded from a local file
	Verified bool                // True when chain verification was attempted
	ChainErr error               // Chain verification error; nil means valid (only meaningful when Verified)
}

// CertificateFetcher defines an interface for fetching certificates from a domain or IP address.
type CertificateFetcher interface {
	// Fetch retrieves the certificate for the specified domain and port, or IP address.
	// When insecure is false, the certificate chain is verified against the system roots.
	// Returns the certificate information and an error if any occurred.
	Fetch(domain, port, ipaddr string, insecure bool) (*CertInfo, error)
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

// earliestExpiringBefore returns the intermediate certificate (from chain[1:])
// that expires soonest among those expiring before the leaf, or nil when every
// intermediate outlives the leaf (or there are no intermediates). Such an
// intermediate breaks the chain before the leaf certificate itself expires.
func earliestExpiringBefore(chain []*x509.Certificate) *x509.Certificate {
	if len(chain) < 2 {
		return nil
	}
	leaf := chain[0]
	var earliest *x509.Certificate
	for _, c := range chain[1:] {
		if !c.NotAfter.Before(leaf.NotAfter) {
			continue
		}
		if earliest == nil || c.NotAfter.Before(earliest.NotAfter) {
			earliest = c
		}
	}
	return earliest
}

// subjectName returns the certificate's common name, falling back to the full
// subject DN when no common name is present.
func subjectName(c *x509.Certificate) string {
	if c.Subject.CommonName != "" {
		return c.Subject.CommonName
	}
	return c.Subject.String()
}

// CertificateFetcherImpl is an implementation of the CertificateFetcher interface.
// It provides functionality to fetch certificates from a specified domain or IP address.
type CertificateFetcherImpl struct{}

// Fetch connects to the specified domain or IP address and retrieves the TLS certificate.
// The handshake always skips verification so that details of an invalid certificate can
// still be displayed; the chain is then verified separately unless insecure is true.
func (f *CertificateFetcherImpl) Fetch(domain, port, ipaddr string, insecure bool) (*CertInfo, error) {
	host := domain
	if ipaddr != "" {
		host = ipaddr
	}
	address := net.JoinHostPort(host, port)

	dialer := &net.Dialer{Timeout: 10 * time.Second}
	conn, err := tls.DialWithDialer(dialer, "tcp", address, &tls.Config{
		InsecureSkipVerify: true,
		ServerName:         domain,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to connect to %s: %v", address, err)
	}
	defer conn.Close()

	certs := conn.ConnectionState().PeerCertificates
	if len(certs) == 0 {
		return nil, fmt.Errorf("no certificates found for %s", address)
	}

	usedIP := conn.RemoteAddr().String()
	if tcpAddr, ok := conn.RemoteAddr().(*net.TCPAddr); ok {
		usedIP = tcpAddr.IP.String()
	}

	info := &CertInfo{Cert: certs[0], Chain: certs, UsedIP: usedIP}
	if !insecure {
		info.Verified = true
		info.ChainErr = verifyChain(certs, domain)
	}
	return info, nil
}

// verifyChain validates the leaf certificate (certs[0]) against the system root
// store, using the remaining peer certificates as intermediates. The check covers
// trust, hostname match and validity period.
func verifyChain(certs []*x509.Certificate, domain string) error {
	intermediates := x509.NewCertPool()
	for _, c := range certs[1:] {
		intermediates.AddCert(c)
	}
	_, err := certs[0].Verify(x509.VerifyOptions{
		DNSName:       domain,
		Intermediates: intermediates,
	})
	return err
}

// CertificateLoaderImpl is an implementation of the CertificateLoader interface.
// It provides functionality to load certificates from a specified file.
type CertificateLoaderImpl struct{}

// Load reads a certificate from the specified file and returns it.
// Returns an error if the file cannot be read or if the certificate cannot be parsed.
func (l *CertificateLoaderImpl) Load(certFile string) (*CertInfo, error) {
	certPEM, err := os.ReadFile(certFile)
	if err != nil {
		return nil, fmt.Errorf("failed to read certificate file %s: %v", certFile, err)
	}

	block, _ := pem.Decode(certPEM)
	if block == nil || block.Type != "CERTIFICATE" {
		return nil, fmt.Errorf("failed to parse certificate from file %s", certFile)
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, err
	}

	return &CertInfo{Cert: cert, FromFile: true}, nil
}

// CertificatePrinterImpl is an implementation of the CertificatePrinter interface.
// It provides functionality to print details of a certificate.
type CertificatePrinterImpl struct{}

// Print outputs the details of the certificate according to opts: as JSON,
// as a single days-remaining number (short), or as full human-readable text.
func (p *CertificatePrinterImpl) Print(info *CertInfo, opts PrintOptions) {
	days := DaysUntilExpiry(info.Cert)

	switch {
	case opts.JSON:
		p.printJSON(info, days)
	case opts.Short:
		fmt.Println(days)
	default:
		p.printText(info, days, opts)
	}
}

// printText renders the full human-readable output, including subject, issuer,
// SANs, serial number, signature algorithm, validity period and days remaining.
// For fetched certificates it also reports the used IP address and the chain
// verification status. When opts.Color is set, the days-remaining value and the
// chain status are colorized.
func (p *CertificatePrinterImpl) printText(info *CertInfo, days int, opts PrintOptions) {
	cert := info.Cert

	fmt.Printf("Certificate for %s\n", cert.Subject.CommonName)
	fmt.Printf("Subject: %s\n", cert.Subject)
	fmt.Printf("Issuer: %s\n", cert.Issuer)
	if len(cert.DNSNames) > 0 {
		fmt.Printf("SANs: %s\n", strings.Join(cert.DNSNames, ", "))
	}
	fmt.Printf("Serial: %s\n", formatSerial(cert.SerialNumber))
	fmt.Printf("Signature: %s\n", cert.SignatureAlgorithm)
	fmt.Printf("Valid from: %s\n", cert.NotBefore)
	fmt.Printf("Expires on: %s\n", cert.NotAfter)

	daysStr := fmt.Sprintf("%d", days)
	if opts.Color {
		switch {
		case days < 0:
			daysStr = colorize(daysStr, colorRed)
		case opts.Threshold > 0 && days < opts.Threshold:
			daysStr = colorize(daysStr, colorYellow)
		default:
			daysStr = colorize(daysStr, colorGreen)
		}
	}
	fmt.Printf("Days remaining: %s\n", daysStr)

	if !info.FromFile {
		fmt.Printf("Used IP address: %s\n", info.UsedIP)
	}
	if info.Verified {
		if info.ChainErr == nil {
			fmt.Printf("Chain: %s\n", maybeColor("VALID", colorGreen, opts.Color))
		} else {
			fmt.Printf("Chain: %s (%v)\n", maybeColor("INVALID", colorRed, opts.Color), info.ChainErr)
		}
	}

	if early := earliestExpiringBefore(info.Chain); early != nil {
		earlyDays := DaysUntilExpiry(early)
		msg := fmt.Sprintf("WARNING: intermediate %q expires in %d days, before the leaf (%d days)",
			subjectName(early), earlyDays, days)
		if opts.Color {
			color := colorYellow
			if earlyDays < 0 {
				color = colorRed
			}
			msg = colorize(msg, color)
		}
		fmt.Println(msg)
	}
}

// printJSON renders the certificate information as indented JSON.
func (p *CertificatePrinterImpl) printJSON(info *CertInfo, days int) {
	cert := info.Cert
	out := struct {
		CommonName    string   `json:"common_name"`
		Subject       string   `json:"subject"`
		Issuer        string   `json:"issuer"`
		SANs          []string `json:"sans,omitempty"`
		Serial        string   `json:"serial"`
		Signature     string   `json:"signature_algorithm"`
		NotBefore     string   `json:"not_before"`
		NotAfter      string   `json:"not_after"`
		DaysRemaining int      `json:"days_remaining"`
		UsedIP        string   `json:"used_ip,omitempty"`
		ChainValid    *bool    `json:"chain_valid,omitempty"`
		ChainError    string   `json:"chain_error,omitempty"`
		ChainExpiry   *struct {
			Subject       string `json:"subject"`
			DaysRemaining int    `json:"days_remaining"`
		} `json:"chain_expiry_warning,omitempty"`
	}{
		CommonName:    cert.Subject.CommonName,
		Subject:       cert.Subject.String(),
		Issuer:        cert.Issuer.String(),
		SANs:          cert.DNSNames,
		Serial:        formatSerial(cert.SerialNumber),
		Signature:     cert.SignatureAlgorithm.String(),
		NotBefore:     cert.NotBefore.UTC().Format(time.RFC3339),
		NotAfter:      cert.NotAfter.UTC().Format(time.RFC3339),
		DaysRemaining: days,
		UsedIP:        info.UsedIP,
	}
	if info.Verified {
		valid := info.ChainErr == nil
		out.ChainValid = &valid
		if info.ChainErr != nil {
			out.ChainError = info.ChainErr.Error()
		}
	}
	if early := earliestExpiringBefore(info.Chain); early != nil {
		out.ChainExpiry = &struct {
			Subject       string `json:"subject"`
			DaysRemaining int    `json:"days_remaining"`
		}{Subject: subjectName(early), DaysRemaining: DaysUntilExpiry(early)}
	}

	b, err := json.MarshalIndent(out, "", "  ")
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: failed to encode JSON: %v\n", err)
		return
	}
	fmt.Println(string(b))
}

// ANSI color codes used for the human-readable output.
const (
	colorReset  = "\033[0m"
	colorRed    = "\033[31m"
	colorYellow = "\033[33m"
	colorGreen  = "\033[32m"
)

// colorize wraps s in the given ANSI color and a reset.
func colorize(s, color string) string { return color + s + colorReset }

// maybeColor colorizes s only when on is true.
func maybeColor(s, color string, on bool) string {
	if on {
		return colorize(s, color)
	}
	return s
}

// formatSerial renders a certificate serial number as upper-case, colon-separated
// hex bytes (e.g. "0F:A3:..."), matching the common openssl-style representation.
func formatSerial(serial *big.Int) string {
	b := serial.Bytes()
	if len(b) == 0 {
		return "0"
	}
	parts := make([]string, len(b))
	for i, v := range b {
		parts[i] = fmt.Sprintf("%02X", v)
	}
	return strings.Join(parts, ":")
}
