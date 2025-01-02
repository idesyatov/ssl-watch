package main

import (
    "errors"
    "testing"
    "time"
    "crypto/x509"
)

// Mock function for loadCertificate
func mockLoadCertificate(certFile string) (*x509.Certificate, error) {
    if certFile == "valid_cert.pem" {
        // Return a mock certificate that expires in 10 days
        return &x509.Certificate{
            NotAfter: time.Now().Add(10 * 24 * time.Hour), // Set the date to 10 days ahead
        }, nil
    }
    return nil, errors.New("failed to load certificate")
}

// TestLoadCertificate tests the mockLoadCertificate function
func TestLoadCertificate(t *testing.T) {
    cert, err := mockLoadCertificate("valid_cert.pem")
    if err != nil {
        t.Fatalf("Expected no error, got: %v", err)
    }

    if cert == nil {
        t.Fatal("Expected a certificate, got nil")
    }
}

// TestLoadCertificateInvalid tests loading an invalid certificate
func TestLoadCertificateInvalid(t *testing.T) {
    _, err := mockLoadCertificate("invalid_cert.pem")
    if err == nil {
        t.Fatal("Expected an error, got none")
    }
}

// TestDaysRemaining tests the calculation of days remaining until expiration
func TestDaysRemaining(t *testing.T) {
    // Set a fixed time to the beginning of the day
    fixedNow := time.Date(2023, 10, 1, 0, 0, 0, 0, time.UTC) // Fixed date
    cert := &x509.Certificate{
        NotAfter: fixedNow.Add(10 * 24 * time.Hour), // Set the date to 10 days ahead
    }

    daysRemaining := int(cert.NotAfter.Sub(fixedNow).Hours() / 24)

    if daysRemaining != 10 {
        t.Fatalf("Expected 10 days remaining, got: %d", daysRemaining)
    }
}