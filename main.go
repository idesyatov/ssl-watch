package main

import (
    "crypto/tls"
    "crypto/x509"
    "encoding/pem"
    "flag"
    "fmt"
    "log"
    "net"
    "os"
    "time"
)

func main() {
    domain, certFile, port, ipaddr, short := parseFlags()

    // Validate the input to ensure at least one of domain or certFile is provided
    if err := validateInput(domain, certFile); err != nil {
        log.Printf("Input validation error: %v", err)
        flag.PrintDefaults()
        return
    }

    var cert *x509.Certificate
    var err error
    var usedIP string

    // Load the certificate from the file or fetch it from the specified domain
    if certFile != "" {
        cert, err = loadCertificate(certFile)
    } else {
        cert, usedIP, err = fetchCertificate(domain, port, ipaddr)
    }

    // Handle any errors that occurred while retrieving the certificate
    if err != nil {
        log.Fatalf("Error retrieving certificate: %v", err)
    }

    // Print the certificate information
    printCertificateInfo(cert, usedIP, certFile != "", short)
}

// parseFlags parses command-line flags and returns the values for domain, certFile, port, ipaddr, and short
func parseFlags() (string, string, string, string, bool) {
    domain := flag.String("domain", "", "Domain to check the certificate file")
    certFile := flag.String("certfile", "", "Path to the local certificate file")
    port := flag.String("port", "443", "Port to connect (optional)")
    ipaddr := flag.String("ipaddr", "", "IP address to connect to (optional)")
    short := flag.Bool("short", false, "Output only the number of days remaining until certificate expiration")
    flag.Parse()
    return *domain, *certFile, *port, *ipaddr, *short
}

// validateInput checks that at least one of domain or certFile is specified
func validateInput(domain, certFile string) error {
    if domain == "" && certFile == "" {
        return fmt.Errorf("either domain or certfile must be specified")
    }
    return nil
}

// fetchCertificate connects to the specified domain or IP address and retrieves the TLS certificate
func fetchCertificate(domain, port, ipaddr string) (*x509.Certificate, string, error) {
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

// loadCertificate reads a certificate from a local file and parses it
func loadCertificate(certFile string) (*x509.Certificate, error) {
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
        return nil, fmt.Errorf("failed to parse certificate: %v", err)
    }

    return cert, nil
}

// printCertificateInfo prints the details of the certificate, including expiration and remaining days
func printCertificateInfo(cert *x509.Certificate, usedIP string, usingCertFile bool, short bool) {
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