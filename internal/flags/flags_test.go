package flags

import (
	"bytes"
	"os"
	"strings"
	"testing"
)

// TestParse tests the parsing of command-line flags using the DefaultFlagParser.
// It sets up a mock command-line argument list and verifies that the parsed values
// match the expected values.
func TestParse(t *testing.T) {
	// Mock command-line arguments for testing
	os.Args = []string{"cmd",
		"-domain", "example.com",
		"-domain-file", "domains.txt",
		"-certfile", "cert.pem",
		"-port", "443",
		"-ipaddr", "192.168.1.1",
		"-short",
		"-insecure",
		"-threshold", "30",
		"-output", "json",
		"-chain",
		"-timeout", "5",
		"-starttls", "smtp",
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
	if cfg.Timeout != 5 {
		t.Errorf("expected timeout to be 5, got %d", cfg.Timeout)
	}
	if cfg.DomainFile != "domains.txt" {
		t.Errorf("expected domainFile to be 'domains.txt', got '%s'", cfg.DomainFile)
	}
	if cfg.StartTLS != "smtp" {
		t.Errorf("expected starttls to be 'smtp', got '%s'", cfg.StartTLS)
	}
	if !cfg.Chain {
		t.Error("expected chain to be true")
	}
	if !cfg.ShowVersion {
		t.Error("expected showVersion to be true")
	}
}

// TestParseDefaults verifies the timeout falls back to its 10-second default
// when the flag is not supplied.
func TestParseDefaults(t *testing.T) {
	os.Args = []string{"cmd", "-domain", "example.com"}

	cfg := NewDefaultFlagParser().Parse()

	if cfg.Timeout != 10 {
		t.Errorf("expected default timeout 10, got %d", cfg.Timeout)
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

// TestUsage verifies the usage header includes the project link, a usage example
// and the flag list.
func TestUsage(t *testing.T) {
	parser := NewDefaultFlagParser()

	var buf bytes.Buffer
	parser.(*DefaultFlagParser).fs.SetOutput(&buf)

	parser.Usage()

	out := buf.String()
	for _, want := range []string{GitURL, "Usage:", "Target:", "Connection:", "Output:", "Monitoring:", "-domain", "-domain-file", "-threshold", "-timeout", "-starttls", "-chain"} {
		if !strings.Contains(out, want) {
			t.Errorf("expected usage output to contain %q, got:\n%s", want, out)
		}
	}
}
