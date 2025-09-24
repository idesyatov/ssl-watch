package flags

import (
	"bytes"
	"flag"
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
		"-version"}

	// Create a new instance of the DefaultFlagParser
	parser := NewDefaultFlagParser()
	// Parse the command-line flags
	domain, certFile, port, ipaddr, short, showVersion := parser.Parse()

	// Verify that the parsed values match the expected values
	if domain != "example.com" {
		t.Errorf("expected domain to be 'example.com', got '%s'", domain)
	}
	if certFile != "cert.pem" {
		t.Errorf("expected certFile to be 'cert.pem', got '%s'", certFile)
	}
	if port != "443" {
		t.Errorf("expected port to be '443', got '%s'", port)
	}
	if ipaddr != "192.168.1.1" {
		t.Errorf("expected ipaddr to be '192.168.1.1', got '%s'", ipaddr)
	}
	if !short {
		t.Error("expected short to be true")
	}
	if !showVersion {
		t.Error("expected showVersion to be true")
	}
}

// TestPrintDefaults tests the PrintDefaults method of the DefaultFlagParser.
// It captures the output of the flag defaults and verifies that some output is produced.
func TestPrintDefaults(t *testing.T) {
	// Create a buffer to capture the output of PrintDefaults
	var buf bytes.Buffer
	flag.CommandLine.SetOutput(&buf)

	// Create a new instance of the DefaultFlagParser
	parser := NewDefaultFlagParser()
	// Call PrintDefaults to output the default flag values
	parser.PrintDefaults()

	// Verify that the output buffer is not empty
	if buf.Len() == 0 {
		t.Error("expected PrintDefaults to produce output, but got none")
	}
}
