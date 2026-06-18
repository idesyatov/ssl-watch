package flags

import (
	"bytes"
	"os"
	"testing"
)

// TestParse tests the parsing of command-line flags using the DefaultFlagParser.
// It sets up a mock command-line argument list and verifies that the parsed values
// match the expected values.
func TestParse(t *testing.T) {
	// Mock command-line arguments for testing
	os.Args = []string{"cmd",
		"-domain", "example.com",
		"-certfile", "cert.pem",
		"-port", "443",
		"-ipaddr", "192.168.1.1",
		"-short",
		"-insecure",
		"-threshold", "30",
		"-output", "json",
		"-version"}

	// Create a new instance of the DefaultFlagParser
	parser := NewDefaultFlagParser()
	// Parse the command-line flags
	cfg := parser.Parse()

	// Verify that the parsed values match the expected values
	if cfg.Domain != "example.com" {
		t.Errorf("expected domain to be 'example.com', got '%s'", cfg.Domain)
	}
	if cfg.CertFile != "cert.pem" {
		t.Errorf("expected certFile to be 'cert.pem', got '%s'", cfg.CertFile)
	}
	if cfg.Port != "443" {
		t.Errorf("expected port to be '443', got '%s'", cfg.Port)
	}
	if cfg.IPAddr != "192.168.1.1" {
		t.Errorf("expected ipaddr to be '192.168.1.1', got '%s'", cfg.IPAddr)
	}
	if !cfg.Short {
		t.Error("expected short to be true")
	}
	if !cfg.Insecure {
		t.Error("expected insecure to be true")
	}
	if cfg.Threshold != 30 {
		t.Errorf("expected threshold to be 30, got %d", cfg.Threshold)
	}
	if cfg.Output != "json" {
		t.Errorf("expected output to be 'json', got '%s'", cfg.Output)
	}
	if !cfg.ShowVersion {
		t.Error("expected showVersion to be true")
	}
}

// TestPrintDefaults tests the PrintDefaults method of the DefaultFlagParser.
// It captures the output of the flag defaults and verifies that some output is produced.
func TestPrintDefaults(t *testing.T) {
	// Create a new instance of the DefaultFlagParser
	parser := NewDefaultFlagParser()

	// Create a buffer to capture the output of PrintDefaults
	var buf bytes.Buffer
	parser.(*DefaultFlagParser).fs.SetOutput(&buf)

	// Call PrintDefaults to output the default flag values
	parser.PrintDefaults()

	// Verify that the output buffer is not empty
	if buf.Len() == 0 {
		t.Error("expected PrintDefaults to produce output, but got none")
	}
}
