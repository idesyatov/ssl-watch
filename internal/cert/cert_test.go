package cert

import (
  "crypto/x509"
  "crypto/x509/pkix"
  "testing"
  "time"
)

// Mock implementation of CertificateFetcher for testing purposes
type MockCertificateFetcher struct {
  Cert      *x509.Certificate // The certificate to be returned
  UsedIP    string            // The IP address that was used
  FetchErr  error             // Any error that might occur during fetching
}

// Fetch simulates fetching a certificate for a given domain and port
func (m *MockCertificateFetcher) Fetch(domain, port, ipaddr string) (*x509.Certificate, string, error) {
  return m.Cert, m.UsedIP, m.FetchErr // Return the mock certificate, used IP, and any error
}

// Mock implementation of CertificateLoader for testing purposes
type MockCertificateLoader struct {
  Cert     *x509.Certificate // The certificate to be loaded
  LoadErr  error             // Any error that might occur during loading
}

// Load simulates loading a certificate from a file
func (m *MockCertificateLoader) Load(certFile string) (*x509.Certificate, error) {
  return m.Cert, m.LoadErr // Return the mock certificate and any error
}

// Mock implementation of CertificatePrinter for testing purposes
type MockCertificatePrinter struct {
  PrintedCert   *x509.Certificate // The certificate that was printed
  UsedIP        string            // The IP address that was used
  UsingCertFile bool              // Indicates if a certificate file was used
  Short         bool              // Indicates if the short format was used
}

// Print simulates printing a certificate with associated information
func (m *MockCertificatePrinter) Print(cert *x509.Certificate, usedIP string, usingCertFile bool, short bool) {
  m.PrintedCert = cert            // Store the printed certificate
  m.UsedIP = usedIP               // Store the used IP address
  m.UsingCertFile = usingCertFile // Store whether a cert file was used
  m.Short = short                 // Store whether the short format was used
}

// TestCertificateFetcher_Fetch tests the Fetch method of MockCertificateFetcher
func TestCertificateFetcher_Fetch(t *testing.T) {
  cert := &x509.Certificate{
    Subject: pkix.Name{
      CommonName: "example.com", // Set the common name for the certificate
    },
    NotAfter: time.Now().Add(30 * 24 * time.Hour), // Set expiration to 30 days from now
  }

  fetcher := &MockCertificateFetcher{
    Cert:   cert,               // Initialize the fetcher with the mock certificate
    UsedIP: "192.0.2.1",        // Set the used IP address
  }

  // Call the Fetch method and check the results
  resultCert, usedIP, err := fetcher.Fetch("example.com", "443", "")
  if err != nil {
    t.Errorf("unexpected error: %v", err) // Check for unexpected errors
  }
  if resultCert != cert {
    t.Errorf("expected cert %v, got %v", cert, resultCert) // Validate the returned certificate
  }
  if usedIP != "192.0.2.1" {
    t.Errorf("expected used IP '192.0.2.1', got '%s'", usedIP) // Validate the used IP address
  }
}

// TestCertificateLoader_Load tests the Load method of MockCertificateLoader
func TestCertificateLoader_Load(t *testing.T) {
  cert := &x509.Certificate{
    Subject: pkix.Name{
      CommonName: "example.com", // Set the common name for the certificate
    },
  }

  loader := &MockCertificateLoader{
    Cert: cert, // Initialize the loader with the mock certificate
  }

  // Call the Load method and check the results
  resultCert, err := loader.Load("test.crt")
  if err != nil {
    t.Errorf("unexpected error: %v", err) // Check for unexpected errors
  }
  if resultCert != cert {
    t.Errorf("expected cert %v, got %v", cert, resultCert) // Validate the returned certificate
  }
}

// TestCertificatePrinter_Print tests the Print method of MockCertificatePrinter
func TestCertificatePrinter_Print(t *testing.T) {
  cert := &x509.Certificate{
    Subject: pkix.Name{
      CommonName: "example.com", // Set the common name for the certificate
    },
    NotAfter: time.Now().Add(30 * 24 * time.Hour), // Set expiration to 30 days from now
  }

  printer := &MockCertificatePrinter{} // Initialize the printer

  // Call the Print method with the mock certificate and associated information
  printer.Print(cert, "192.0.2.1", false, false)

  // Validate the printed certificate
  if printer.PrintedCert != cert {
    t.Errorf("expected printed cert %v, got %v", cert, printer.PrintedCert) // Check if the printed certificate matches the expected one
  }
  // Validate the used IP address
  if printer.UsedIP != "192.0.2.1" {
    t.Errorf("expected used IP '192.0.2.1', got '%s'", printer.UsedIP) // Check if the used IP address matches the expected one
  }
  // Validate that the usingCertFile flag is false
  if printer.UsingCertFile {
    t.Error("expected usingCertFile to be false") // Ensure that the usingCertFile flag is set correctly
  }
  // Validate that the short flag is false
  if printer.Short {
    t.Error("expected short to be false") // Ensure that the short flag is set correctly
  }
}
