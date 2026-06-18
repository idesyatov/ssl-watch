package main

import (
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

	// Validate the requested output format
	if cfg.Output != "text" && cfg.Output != "json" {
		fmt.Fprintf(os.Stderr, "Error: invalid -output %q (expected \"text\" or \"json\")\n\n", cfg.Output)
		parser.PrintDefaults()
		os.Exit(1)
	}

	var info *cert.CertInfo // Variable to hold the retrieved certificate information
	var err error           // Variable to hold any error that occurs

	// Create instances of the certificate fetcher, loader, and printer
	var fetcher cert.CertificateFetcher = &cert.CertificateFetcherImpl{}
	var loader cert.CertificateLoader = &cert.CertificateLoaderImpl{}
	var printer cert.CertificatePrinter = &cert.CertificatePrinterImpl{}

	// If a certificate file is provided, load the certificate from the file
	if cfg.CertFile != "" {
		info, err = loader.Load(cfg.CertFile)
	} else {
		// Otherwise, fetch the certificate from the specified domain or IP address
		info, err = fetcher.Fetch(cfg.Domain, cfg.Port, cfg.IPAddr, cfg.Insecure)
	}

	// Check for errors during certificate retrieval
	if err != nil {
		log.Fatalf("Error retrieving certificate: %v", err)
	}

	// Print the certificate information
	printer.Print(info, cert.PrintOptions{
		Short:     cfg.Short,
		JSON:      cfg.Output == "json",
		Threshold: cfg.Threshold,
		Color:     useColor(cfg),
	})

	// Exit code 2 when the certificate expires within the configured threshold,
	// so the tool can drive alerts in cron/CI.
	if cfg.Threshold > 0 && cert.DaysUntilExpiry(info.Cert) < cfg.Threshold {
		os.Exit(2)
	}
}

// useColor reports whether the human-readable output should be colorized:
// only for plain text output to an interactive terminal, and never when the
// NO_COLOR environment variable is set.
func useColor(cfg flags.Config) bool {
	if cfg.Output != "text" || cfg.Short {
		return false
	}
	if os.Getenv("NO_COLOR") != "" {
		return false
	}
	fi, err := os.Stdout.Stat()
	if err != nil {
		return false
	}
	return fi.Mode()&os.ModeCharDevice != 0
}
