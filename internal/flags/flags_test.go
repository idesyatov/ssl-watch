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
		"-servername", "vhost.example.com",
		"-cafile", "roots.pem",
		"-client-cert", "client.crt",
		"-client-key", "client.key",
		"-short",
		"-insecure",
		"-threshold", "30",
		"-output", "json",
		"-chain",
		"-expect-issuer", "Let's Encrypt",
		"-strict",
		"-fingerprint",
		"-pin", "sha256:e4134cbc32c0c0976599c684ae0b6ac849b2d75546d934dfdb611fa0d9a0e9cb",
		"-pem",
		"-export", "out.pem",
		"-all-ips",
		"-4",
		"-timeout", "5",
		"-concurrency", "8",
		"-starttls", "smtp",
		"-proxy", "http://127.0.0.1:3128",
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
	if cfg.ServerName != "vhost.example.com" {
		t.Errorf("expected servername to be parsed, got '%s'", cfg.ServerName)
	}
	if cfg.CAFile != "roots.pem" {
		t.Errorf("expected cafile to be 'roots.pem', got '%s'", cfg.CAFile)
	}
	if cfg.ClientCert != "client.crt" || cfg.ClientKey != "client.key" {
		t.Errorf("expected client-cert/client-key parsed, got '%s'/'%s'", cfg.ClientCert, cfg.ClientKey)
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
	if cfg.Concurrency != 8 {
		t.Errorf("expected concurrency to be 8, got %d", cfg.Concurrency)
	}
	if cfg.DomainFile != "domains.txt" {
		t.Errorf("expected domainFile to be 'domains.txt', got '%s'", cfg.DomainFile)
	}
	if cfg.StartTLS != "smtp" {
		t.Errorf("expected starttls to be 'smtp', got '%s'", cfg.StartTLS)
	}
	if cfg.Proxy != "http://127.0.0.1:3128" {
		t.Errorf("expected proxy to be parsed, got '%s'", cfg.Proxy)
	}
	if !cfg.Chain {
		t.Error("expected chain to be true")
	}
	if cfg.ExpectIssuer != "Let's Encrypt" {
		t.Errorf("expected expect-issuer to be parsed, got '%s'", cfg.ExpectIssuer)
	}
	if !cfg.Strict {
		t.Error("expected strict to be true")
	}
	if !cfg.Fingerprint {
		t.Error("expected fingerprint to be true")
	}
	if cfg.Pin != "sha256:e4134cbc32c0c0976599c684ae0b6ac849b2d75546d934dfdb611fa0d9a0e9cb" {
		t.Errorf("expected pin to be parsed, got '%s'", cfg.Pin)
	}
	if !cfg.Pem {
		t.Error("expected pem to be true")
	}
	if cfg.Export != "out.pem" {
		t.Errorf("expected export to be 'out.pem', got '%s'", cfg.Export)
	}
	if !cfg.AllIPs {
		t.Error("expected all-ips to be true")
	}
	if !cfg.IPv4Only {
		t.Error("expected ipv4-only (-4) to be true")
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
	if cfg.Concurrency != 1 {
		t.Errorf("expected default concurrency 1, got %d", cfg.Concurrency)
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
	for _, want := range []string{GitURL, "Usage:", "Target:", "Connection:", "Output:", "Monitoring:", "-domain", "-domain-file", "-threshold", "-timeout", "-concurrency", "-starttls", "-proxy", "-cafile", "-servername", "-client-cert", "-client-key", "-chain", "-fingerprint", "-pin", "-expect-issuer", "-strict", "-pem", "-export", "-all-ips", "-4", "-6", "prometheus", "csv"} {
		if !strings.Contains(out, want) {
			t.Errorf("expected usage output to contain %q, got:\n%s", want, out)
		}
	}
}
