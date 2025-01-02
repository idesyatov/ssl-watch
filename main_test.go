package main

import (
    "os"
    "testing"
)

func TestParseFlags(t *testing.T) {
    // Save the original command line arguments
    originalArgs := os.Args

    // Set command line arguments for the test
    testArgs := []string{"cmd", "-domain", "example.com", "-certfile", "/path/to/cert.pem", "-port", "8443", "-ipaddr", "192.168.1.1", "-short"}
    os.Args = testArgs

    // Call the function
    domain, certFile, port, ipaddr, short := parseFlags()

    // Check the results
    if domain != "example.com" {
        t.Errorf("Expected domain 'example.com', got '%s'", domain)
    }
    if certFile != "/path/to/cert.pem" {
        t.Errorf("Expected certFile '/path/to/cert.pem', got '%s'", certFile)
    }
    if port != "8443" {
        t.Errorf("Expected port '8443', got '%s'", port)
    }
    if ipaddr != "192.168.1.1" {
        t.Errorf("Expected ipaddr '192.168.1.1', got '%s'", ipaddr)
    }
    if !short {
        t.Error("Expected short to be true, got false")
    }

    // Restore the original command line arguments
    os.Args = originalArgs
}

func TestValidateInput(t *testing.T) {
    tests := []struct {
        domain   string
        certFile string
        expectErr bool
    }{
        {"", "", true},               // Both parameters are empty, an error is expected
        {"example.com", "", false},   // Only the domain is specified, no error is expected
        {"", "/path/to/cert.pem", false}, // Only certFile is specified, no error is expected
        {"example.com", "/path/to/cert.pem", false}, // Both parameters are specified, no error is expected
    }

    for _, test := range tests {
        err := validateInput(test.domain, test.certFile)
        if (err != nil) != test.expectErr {
            t.Errorf("validateInput(%q, %q) = %v; expectErr = %v", test.domain, test.certFile, err, test.expectErr)
        }
    }
}