package main

import (
	"crypto/x509"
	"github.com/idesyatov/ssl-watch/internal/cert"
	"github.com/idesyatov/ssl-watch/internal/flags"
	"github.com/idesyatov/ssl-watch/internal/validation"
	"log"
)

func main() {
	// Create a new flag parser to handle command-line arguments
	parser := flags.NewDefaultFlagParser()
	// Parse the command-line flags and retrieve the values
	domain, certFile, port, ipaddr, short := parser.Parse()

	// Create a new input validator to validate the parsed flags
	validator := validation.NewDefaultInputValidator()
	// Validate the domain and certificate file inputs
	if err := validator.Validate(domain, certFile); err != nil {
		// If validation fails, print the default flag values and exit
		parser.PrintDefaults()
		return
	}

	var certInfo *x509.Certificate // Variable to hold the retrieved certificate information
	var err error                  // Variable to hold any error that occurs
	var usedIP string              // Variable to hold the used IP address

	// Create instances of the certificate fetcher, loader, and printer
	var fetcher cert.CertificateFetcher = &cert.CertificateFetcherImpl{}
	var loader cert.CertificateLoader = &cert.CertificateLoaderImpl{}
	var printer cert.CertificatePrinter = &cert.CertificatePrinterImpl{}

	// If a certificate file is provided, load the certificate from the file
	if certFile != "" {
		certInfo, err = loader.Load(certFile)
	} else {
		// Otherwise, fetch the certificate from the specified domain or IP address
		certInfo, usedIP, err = fetcher.Fetch(domain, port, ipaddr)
	}

	// Check for errors during certificate retrieval
	if err != nil {
		log.Fatalf("Error retrieving certificate: %v", err)
	}

	// Print the certificate information, including the used IP address and whether a cert file was used
	printer.Print(certInfo, usedIP, certFile != "", short)
}
