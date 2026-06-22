package app

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/idesyatov/ssl-watch/internal/flags"
)

// TestRunExport covers -pem (stdout), -export (file) and the write-error path.
func TestRunExport(t *testing.T) {
	info := realCertInfo(t, "export.example", 90)

	// -pem: PEM to stdout.
	var code int
	out := captureStdout(t, func() { code = runExport(info, flags.Config{Pem: true}) })
	if code != exitOK {
		t.Fatalf("pem: expected %d, got %d", exitOK, code)
	}
	if !strings.Contains(out, "BEGIN CERTIFICATE") {
		t.Errorf("pem output should contain a PEM block, got:\n%s", out)
	}

	// -export: PEM to a file.
	path := filepath.Join(t.TempDir(), "chain.pem")
	out = captureStdout(t, func() { code = runExport(info, flags.Config{Export: path}) })
	if code != exitOK {
		t.Fatalf("export: expected %d, got %d", exitOK, code)
	}
	if !strings.Contains(out, "Wrote 1 certificate(s)") {
		t.Errorf("export should report what it wrote, got: %q", out)
	}
	if b, err := os.ReadFile(path); err != nil || !strings.Contains(string(b), "BEGIN CERTIFICATE") {
		t.Errorf("export file missing or not PEM: err=%v", err)
	}

	// Write error: a path under a non-existent directory.
	code = runExport(info, flags.Config{Export: filepath.Join(t.TempDir(), "nope", "chain.pem")})
	if code != exitError {
		t.Errorf("export to bad path: expected %d, got %d", exitError, code)
	}
}
