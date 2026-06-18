package main

import (
	"crypto/x509"
	"fmt"
	"github.com/idesyatov/ssl-watch/internal/cert"
	"github.com/idesyatov/ssl-watch/internal/flags"
	"github.com/idesyatov/ssl-watch/internal/validation"
	"log"
	"os"
)

var version = "dev"

const gitUrl = "https://github.com/idesyatov/ssl-watch"

func main() {
	// Create a new flag parser to handle command-line arguments
	parser := flags.NewDefaultFlagParser()
	// Parse the command-line flags and retrieve the configuration
	cfg := parser.Parse()

	// Check if the version flag is set
	if cfg.ShowVersion {
		fmt.Printf("Version: %s\n", version)
		fmt.Printf("GitHub: %s\n", gitUrl)
		return
	}

	// Create a new input validator to validate the parsed flags
	validator := validation.NewDefaultInputValidator()
	// Validate the domain and certificate file inputs
	if err := validator.Validate(cfg.Domain, cfg.CertFile); err != nil {
		// If validation fails, report the error, print the default flag values and exit non-zero
		fmt.Fprintf(os.Stderr, "Error: %v\n\n", err)
		parser.PrintDefaults()
		os.Exit(1)
	}

	var certInfo *x509.Certificate // Variable to hold the retrieved certificate information
	var err error                  // Variable to hold any error that occurs
	var usedIP string              // Variable to hold the used IP address

	// Create instances of the certificate fetcher, loader, and printer
	var fetcher cert.CertificateFetcher = &cert.CertificateFetcherImpl{}
	var loader cert.CertificateLoader = &cert.CertificateLoaderImpl{}
	var printer cert.CertificatePrinter = &cert.CertificatePrinterImpl{}

	// If a certificate file is provided, load the certificate from the file
	if cfg.CertFile != "" {
		certInfo, err = loader.Load(cfg.CertFile)
	} else {
		// Otherwise, fetch the certificate from the specified domain or IP address
		certInfo, usedIP, err = fetcher.Fetch(cfg.Domain, cfg.Port, cfg.IPAddr)
	}

	// Check for errors during certificate retrieval
	if err != nil {
		log.Fatalf("Error retrieving certificate: %v", err)
	}

	// Print the certificate information, including the used IP address and whether a cert file was used
	printer.Print(certInfo, usedIP, cfg.CertFile != "", cfg.Short)
}
