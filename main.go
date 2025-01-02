package main

import (
    "crypto/tls"
    "crypto/x509"
    "encoding/pem"
    "flag"
    "fmt"
    "log"
    "os"
    "time"
)

func main() {
    // Define flags
    domain := flag.String("domain", "", "Domain to check")
    certFile := flag.String("certfile", "", "Path to the local certificate file")
    port := flag.String("port", "443", "Port to connect (default is 443)")
    ipaddr := flag.String("ipaddr", "", "IP address to connect to (optional)")
    short := flag.Bool("short", false, "Output only the number of days remaining until certificate expiration")
    flag.Parse()

    // Check if either domain or certfile is specified
    if *domain == "" && *certFile == "" {
        fmt.Println("Usage: SSLWatch -domain <domain> [-port <port>] [-ipaddr <ipaddr>] [-short] | -certfile <path>")
        os.Exit(1)
    }

    var cert *x509.Certificate
    var err error

    // If certFile is provided, load the certificate from the file
    if *certFile != "" {
        cert, err = loadCertificate(*certFile)
        if err != nil {
            log.Fatalf("Failed to load certificate: %v", err)
        }
    } else {
        // Determine the address to connect to
        address := fmt.Sprintf("%s:%s", *domain, *port)
        if *ipaddr != "" {
            address = fmt.Sprintf("%s:%s", *ipaddr, *port)
        }

        // Create a TLS connection with the specified server name
        conn, err := tls.Dial("tcp", address, &tls.Config{
            InsecureSkipVerify: true,
            ServerName:         *domain, // Specify the server name
        })
        if err != nil {
            log.Printf("Failed to connect: %v", err)
            os.Exit(1)
        }
        defer conn.Close()

        // Retrieve certificates
        certs := conn.ConnectionState().PeerCertificates
        if len(certs) == 0 {
            log.Fatal("No certificates found")
        }

        cert = certs[0] // Take the first certificate, which is usually the end-entity certificate
    }

    // Calculate days remaining until expiration
    daysRemaining := int(time.Until(cert.NotAfter).Hours() / 24)

    // Print certificate information based on the short flag
    if *short {
        fmt.Println(daysRemaining)
    } else {
        fmt.Printf("Certificate for %s\n", cert.Subject.CommonName)
        fmt.Printf("Subject: %s\n", cert.Subject)
        fmt.Printf("Issuer: %s\n", cert.Issuer)
        fmt.Printf("Expires on: %s\n", cert.NotAfter)
        fmt.Printf("Days remaining: %d\n", daysRemaining)
    }
}

// loadCertificate loads a certificate from a file
func loadCertificate(certFile string) (*x509.Certificate, error) {
    certPEM, err := os.ReadFile(certFile)
    if err != nil {
        return nil, err
    }

    block, _ := pem.Decode(certPEM)
    if block == nil || block.Type != "CERTIFICATE" {
        return nil, fmt.Errorf("failed to parse certificate")
    }

    cert, err := x509.ParseCertificate(block.Bytes)
    if err != nil {
        return nil, err
    }

    return cert, nil
}