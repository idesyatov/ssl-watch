package app

import (
	"io"
	"path/filepath"
	"strings"
	"testing"

	"github.com/idesyatov/ssl-watch/internal/cert"
	"github.com/idesyatov/ssl-watch/internal/flags"
)

// TestResolveVersion verifies the stamped version wins and that the fallback
// never yields an empty string.
func TestResolveVersion(t *testing.T) {
	orig := version
	defer func() { version = orig }()

	version = "1.2.3"
	if got := resolveVersion(); got != "1.2.3" {
		t.Errorf("expected stamped version '1.2.3', got %q", got)
	}

	// With the default "dev", resolveVersion falls back to build info, or "dev"
	// when none is available — but never an empty string.
	version = "dev"
	if got := resolveVersion(); got == "" {
		t.Error("expected a non-empty version from the fallback, got empty")
	}
}

// TestUseColor covers every branch: non-text/short/NO_COLOR disable color, and a
// non-terminal stdout (the test pipe) also disables it.
func TestUseColor(t *testing.T) {
	if useColor(flags.Config{Output: "json"}) {
		t.Error("non-text output should not colorize")
	}
	if useColor(flags.Config{Output: "text", Short: true}) {
		t.Error("short output should not colorize")
	}
	t.Setenv("NO_COLOR", "1")
	if useColor(flags.Config{Output: "text"}) {
		t.Error("NO_COLOR should disable color")
	}
	t.Setenv("NO_COLOR", "")
	// NO_COLOR unset but stdout is the test harness (not a char device) → false.
	if useColor(flags.Config{Output: "text"}) {
		t.Error("non-terminal stdout should not colorize")
	}
}

// TestRun exercises the run() dispatcher across its main branches: version, the
// early error paths, and each output/target path with injected dependencies.
func TestRun(t *testing.T) {
	fetcher := &fakeFetcher{
		infos: map[string]*cert.CertInfo{
			"a.example": leafInfo("a.example", 90),
			"b.example": leafInfo("b.example", 80),
		},
		errs: map[string]error{"bad.example": io.ErrUnexpectedEOF},
	}
	loader := &fakeLoader{info: realCertInfo(t, "file.example", 90)}

	t.Run("version", func(t *testing.T) {
		code, out := runArgs(t, []string{"-version"}, fetcher, loader)
		if code != exitOK || !strings.Contains(out, "Version:") {
			t.Errorf("version: code=%d out=%q", code, out)
		}
	})

	t.Run("no target", func(t *testing.T) {
		if code, _ := runArgs(t, nil, fetcher, loader); code != exitError {
			t.Errorf("expected %d with no target, got %d", exitError, code)
		}
	})

	t.Run("validate error", func(t *testing.T) {
		if code, _ := runArgs(t, []string{"-domain", "a.example", "-output", "yaml"}, fetcher, loader); code != exitError {
			t.Errorf("expected %d for bad -output, got %d", exitError, code)
		}
	})

	t.Run("bad pin", func(t *testing.T) {
		if code, _ := runArgs(t, []string{"-domain", "a.example", "-pin", "notahex"}, fetcher, loader); code != exitError {
			t.Errorf("expected %d for malformed -pin, got %d", exitError, code)
		}
	})

	t.Run("cafile load error", func(t *testing.T) {
		bad := filepath.Join(t.TempDir(), "missing.pem")
		if code, _ := runArgs(t, []string{"-domain", "a.example", "-cafile", bad}, fetcher, loader); code != exitError {
			t.Errorf("expected %d for unreadable -cafile, got %d", exitError, code)
		}
	})

	t.Run("prometheus dispatch", func(t *testing.T) {
		code, out := runArgs(t, []string{"-domain", "a.example", "-output", "prometheus"}, fetcher, loader)
		if code != exitOK || !strings.Contains(out, "ssl_cert_up") {
			t.Errorf("prometheus: code=%d out=%q", code, out)
		}
	})

	t.Run("certfile dispatch", func(t *testing.T) {
		code, out := runArgs(t, []string{"-certfile", "file.pem"}, fetcher, loader)
		if code != exitOK || !strings.Contains(out, "Certificate for file.example") {
			t.Errorf("certfile: code=%d out=%q", code, out)
		}
	})

	t.Run("certfile load error", func(t *testing.T) {
		badLoader := &fakeLoader{err: io.ErrUnexpectedEOF}
		if code, _ := runArgs(t, []string{"-certfile", "file.pem"}, fetcher, badLoader); code != exitError {
			t.Errorf("expected %d on loader error, got %d", exitError, code)
		}
	})

	t.Run("single domain dispatch", func(t *testing.T) {
		code, out := runArgs(t, []string{"-domain", "a.example"}, fetcher, loader)
		if code != exitOK || !strings.Contains(out, "Certificate for a.example") {
			t.Errorf("single: code=%d out=%q", code, out)
		}
	})

	t.Run("single domain fetch error", func(t *testing.T) {
		if code, _ := runArgs(t, []string{"-domain", "bad.example"}, fetcher, loader); code != exitError {
			t.Errorf("expected %d on fetch error, got %d", exitError, code)
		}
	})

	t.Run("batch dispatch", func(t *testing.T) {
		code, out := runArgs(t, []string{"-domain", "a.example,b.example"}, fetcher, loader)
		if code != exitOK || !strings.Contains(out, "==> a.example") {
			t.Errorf("batch: code=%d out=%q", code, out)
		}
	})
}
