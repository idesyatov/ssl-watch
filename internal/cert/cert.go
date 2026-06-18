package cert

import (
	"crypto/tls"
	"crypto/x509"
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
	Cert     *x509.Certificate // The retrieved certificate
	UsedIP   string            // Remote IP address; empty when loaded from a file
	FromFile bool              // True when the certificate was loaded from a local file
	Verified bool              // True when chain verification was attempted
	ChainErr error             // Chain verification error; nil means valid (only meaningful when Verified)
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

// CertificatePrinter defines an interface for printing certificate details.
type CertificatePrinter interface {
	// Print outputs the details of the certificate, with an option for short output.
	Print(info *CertInfo, short bool)
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

	info := &CertInfo{Cert: certs[0], UsedIP: usedIP}
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

// Print outputs the details of the certificate, including subject, issuer, SANs,
// serial number, signature algorithm, validity period and the number of days
// remaining until expiration. For fetched certificates it also reports the used
// IP address and the chain verification status. Output is reduced when short is true.
func (p *CertificatePrinterImpl) Print(info *CertInfo, short bool) {
	cert := info.Cert
	daysRemaining := int(time.Until(cert.NotAfter).Hours() / 24)

	if short {
		fmt.Println(daysRemaining)
		return
	}

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
	fmt.Printf("Days remaining: %d\n", daysRemaining)

	if !info.FromFile {
		fmt.Printf("Used IP address: %s\n", info.UsedIP)
	}
	if info.Verified {
		if info.ChainErr == nil {
			fmt.Println("Chain: VALID")
		} else {
			fmt.Printf("Chain: INVALID (%v)\n", info.ChainErr)
		}
	}
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
