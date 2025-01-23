package cert

import (
    "crypto/tls"
    "crypto/x509"
    "encoding/pem"
    "fmt"
    "net"
    "os"
    "time"
)

// CertificateFetcher defines an interface for fetching certificates from a domain or IP address.
type CertificateFetcher interface {
  // Fetch retrieves the certificate for the specified domain and port, or IP address.
  // Returns the certificate, the used IP address, and an error if any occurred.
  Fetch(domain, port, ipaddr string) (*x509.Certificate, string, error)
}

// CertificateLoader defines an interface for loading certificates from a file.
type CertificateLoader interface {
  // Load reads a certificate from the specified file and returns it.
  // Returns the loaded certificate and an error if any occurred.
  Load(certFile string) (*x509.Certificate, error)
}

// CertificatePrinter defines an interface for printing certificate details.
type CertificatePrinter interface {
  // Print outputs the details of the certificate, including the used IP address
  // and whether the certificate was loaded from a file, with an option for short output.
  Print(cert *x509.Certificate, usedIP string, usingCertFile bool, short bool)
}

// CertificateFetcherImpl is an implementation of the CertificateFetcher interface.
// It provides functionality to fetch certificates from a specified domain or IP address.
type CertificateFetcherImpl struct{}

// Fetch connects to the specified domain or IP address and retrieves the TLS certificate.
// It returns the certificate, the used IP address, and an error if the connection fails.
func (f *CertificateFetcherImpl) Fetch(domain, port, ipaddr string) (*x509.Certificate, string, error) {
  address := fmt.Sprintf("%s:%s", domain, port)
  if ipaddr != "" {
    address = fmt.Sprintf("%s:%s", ipaddr, port)
  }

  conn, err := tls.Dial("tcp", address, &tls.Config{
    InsecureSkipVerify: true,
    ServerName:         domain,
  })
  if err != nil {
    return nil, "", fmt.Errorf("failed to connect to %s: %v", address, err)
  }
  defer conn.Close()

  certs := conn.ConnectionState().PeerCertificates
  if len(certs) == 0 {
    return nil, "", fmt.Errorf("no certificates found for %s", address)
  }

  usedIP := conn.RemoteAddr().(*net.TCPAddr).IP.String()
  return certs[0], usedIP, nil
}

// CertificateLoaderImpl is an implementation of the CertificateLoader interface.
// It provides functionality to load certificates from a specified file.
type CertificateLoaderImpl struct{}

// Load reads a certificate from the specified file and returns it.
// Returns an error if the file cannot be read or if the certificate cannot be parsed.
func (l *CertificateLoaderImpl) Load(certFile string) (*x509.Certificate, error) {
  certPEM, err := os.ReadFile(certFile)
  if err != nil {
    return nil, fmt.Errorf("failed to read certificate file %s: %v", certFile, err)
  }

  block, _ := pem.Decode(certPEM)
  if block == nil || block.Type != "CERTIFICATE" {
    return nil, fmt.Errorf("failed to parse certificate from file %s", certFile)
  }

  return x509.ParseCertificate(block.Bytes)
}

// CertificatePrinterImpl is an implementation of the CertificatePrinter interface.
// It provides functionality to print details of a certificate.
type CertificatePrinterImpl struct{}

// Print outputs the details of the certificate, including the subject, issuer, expiration date,
// and the number of days remaining until expiration. It also indicates the used IP address
// if the certificate was not loaded from a file. The output can be shortened based on the 'short' parameter.
func (p *CertificatePrinterImpl) Print(cert *x509.Certificate, usedIP string, usingCertFile bool, short bool) {
  daysRemaining := int(time.Until(cert.NotAfter).Hours() / 24)

  if short {
    fmt.Println(daysRemaining)
  } else {
    fmt.Printf("Certificate for %s\n", cert.Subject.CommonName)
    fmt.Printf("Subject: %s\n", cert.Subject)
    fmt.Printf("Issuer: %s\n", cert.Issuer)
    fmt.Printf("Expires on: %s\n", cert.NotAfter)
    fmt.Printf("Days remaining: %d\n", daysRemaining)

    if !usingCertFile {
        fmt.Printf("Used IP address: %s\n", usedIP)
    }
  }
}
