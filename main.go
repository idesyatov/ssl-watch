package main

import (
    "crypto/tls"
    "flag"
    "fmt"
    "log"
    "os"
    "time"

)

// it's just an implementation of a shell command with some extensions
// echo | openssl s_client -connect example.com:443 | openssl x509 -noout -dates
func main() {
    // Define flags
    domain := flag.String("domain", "", "Domain to check")
    port := flag.String("port", "443", "Port to connect (default is 443)")
    ipaddr := flag.String("ipaddr", "", "IP address to connect to (optional)")
    flag.Parse()

    // Check if the domain is specified
    if *domain == "" {
        fmt.Println("Usage: SSLWatch -domain <domain> [-port <port>] [-ipaddr <ipaddr>]")
        os.Exit(1)
    }

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

    // Output information about the end certificate
    cert := certs[0] // Take the first certificate, which is usually the end-entity certificate
    daysRemaining := int(time.Until(cert.NotAfter).Hours() / 24)

    // Print certificate information
    fmt.Printf("Certificate for %s\n", *domain)
    fmt.Printf("Subject: %s\n", cert.Subject)
    fmt.Printf("Issuer: %s\n", cert.Issuer)
    fmt.Printf("Expires on: %s\n", cert.NotAfter)
    fmt.Printf("Days remaining: %d\n", daysRemaining)
}