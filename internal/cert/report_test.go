package cert

import (
	"crypto/x509"
	"encoding/csv"
	"errors"
	"strings"
	"testing"
	"time"
)

// TestWritePrometheus verifies the exposition output: TYPE headers, up=1/0,
// per-domain samples, chain_valid only when verified, and pin_match only with a pin.
func TestWritePrometheus(t *testing.T) {
	ok := genCert(t, "ok.example", time.Now().Add(90*24*time.Hour))
	samples := []PromSample{
		{Domain: "ok.example", Info: &CertInfo{Cert: ok, Chain: []*x509.Certificate{ok}, Verified: true}},
		{Domain: "bad.example", Err: errors.New("connection refused")},
	}

	var buf strings.Builder
	WritePrometheus(&buf, samples, "")
	out := buf.String()

	for _, want := range []string{
		"# TYPE ssl_cert_up gauge",
		`ssl_cert_up{domain="ok.example"} 1`,
		`ssl_cert_up{domain="bad.example"} 0`,
		`ssl_cert_expiry_days{domain="ok.example"}`,
		`ssl_cert_not_after_timestamp{domain="ok.example"}`,
		`ssl_cert_chain_valid{domain="ok.example"} 1`,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("prometheus output missing %q:\n%s", want, out)
		}
	}
	// A failed domain has only ssl_cert_up, no expiry sample.
	if strings.Contains(out, `ssl_cert_expiry_days{domain="bad.example"}`) {
		t.Errorf("failed domain should not have an expiry sample:\n%s", out)
	}
	// No pin → no pin_match family.
	if strings.Contains(out, "ssl_cert_pin_match") {
		t.Errorf("pin_match should be absent without a pin:\n%s", out)
	}

	// With a matching pin, the pin_match family appears as 1.
	buf.Reset()
	WritePrometheus(&buf, samples[:1], Fingerprint(ok))
	if pinOut := buf.String(); !strings.Contains(pinOut, `ssl_cert_pin_match{domain="ok.example"} 1`) {
		t.Errorf("expected pin_match 1 with a matching pin:\n%s", pinOut)
	}
}

// TestWriteCSV verifies the header, one row per domain, an empty cert row with
// the error filled for a failed domain, and that a comma-bearing issuer DN is
// quoted (parsed back cleanly by encoding/csv).
func TestWriteCSV(t *testing.T) {
	ok := genCert(t, "ok.example", time.Now().Add(90*24*time.Hour))
	samples := []PromSample{
		{Domain: "ok.example", Info: &CertInfo{Cert: ok, Chain: []*x509.Certificate{ok}, Verified: true}},
		{Domain: "bad.example:8443", Err: errors.New("connection refused")},
	}

	var buf strings.Builder
	if err := WriteCSV(&buf, samples); err != nil {
		t.Fatalf("WriteCSV: %v", err)
	}

	rows, err := csv.NewReader(strings.NewReader(buf.String())).ReadAll()
	if err != nil {
		t.Fatalf("output is not valid CSV: %v\n%s", err, buf.String())
	}
	if len(rows) != 3 {
		t.Fatalf("expected header + 2 rows, got %d:\n%s", len(rows), buf.String())
	}
	if rows[0][0] != "domain" || rows[0][len(rows[0])-1] != "error" {
		t.Errorf("unexpected header: %v", rows[0])
	}
	if len(rows[1]) != len(csvHeader) {
		t.Fatalf("data row has %d columns, want %d", len(rows[1]), len(csvHeader))
	}
	if rows[1][0] != "ok.example" || rows[1][7] != "true" {
		t.Errorf("ok row: domain/chain_valid wrong: %v", rows[1])
	}
	// The issuer DN (self-signed → contains the subject CN with commas in a real
	// DN) round-trips through csv quoting; here just confirm the field is intact.
	if !strings.Contains(rows[1][2], "ok.example") {
		t.Errorf("issuer column should carry the DN, got %q", rows[1][2])
	}
	// Failed domain: empty cert columns, error filled, label keeps its port.
	if rows[2][0] != "bad.example:8443" || rows[2][1] != "" || rows[2][8] != "connection refused" {
		t.Errorf("error row wrong: %v", rows[2])
	}
}

// TestWriteNagios verifies the Nagios plugin output and exit codes: OK with
// perfdata, WARNING on an upcoming expiry within -threshold, CRITICAL on an
// expired certificate and on a fetch error, and the multi-target summary that
// reports the worst status with per-target counts.
func TestWriteNagios(t *testing.T) {
	now := time.Now()
	ok := genCert(t, "ok.example", now.Add(90*24*time.Hour))
	soon := genCert(t, "soon.example", now.Add(8*24*time.Hour))
	expired := genCert(t, "exp.example", now.Add(-24*time.Hour))
	infoOf := func(c *x509.Certificate) *CertInfo {
		return &CertInfo{Cert: c, Chain: []*x509.Certificate{c}, Verified: true}
	}

	t.Run("ok with perfdata", func(t *testing.T) {
		var buf strings.Builder
		code := WriteNagios(&buf, []PromSample{{Domain: "ok.example", Info: infoOf(ok)}}, PrintOptions{}, false)
		if code != nagiosOK {
			t.Fatalf("expected OK (0), got %d", code)
		}
		out := buf.String()
		if !strings.HasPrefix(out, "SSL OK - ok.example: valid") {
			t.Errorf("unexpected OK line: %q", out)
		}
		if !strings.Contains(out, "| 'ok.example'=") {
			t.Errorf("expected perfdata, got: %q", out)
		}
	})

	t.Run("warning on threshold", func(t *testing.T) {
		var buf strings.Builder
		code := WriteNagios(&buf, []PromSample{{Domain: "soon.example", Info: infoOf(soon)}}, PrintOptions{Threshold: 30}, false)
		if code != nagiosWarning {
			t.Fatalf("expected WARNING (1), got %d", code)
		}
		out := buf.String()
		if !strings.HasPrefix(out, "SSL WARNING - soon.example: expires in") {
			t.Errorf("unexpected WARNING line: %q", out)
		}
		if !strings.Contains(out, ";30;;") {
			t.Errorf("expected perfdata with threshold in the warn slot, got: %q", out)
		}
	})

	t.Run("critical on expired", func(t *testing.T) {
		var buf strings.Builder
		code := WriteNagios(&buf, []PromSample{{Domain: "exp.example", Info: infoOf(expired)}}, PrintOptions{}, false)
		if code != nagiosCritical {
			t.Fatalf("expected CRITICAL (2), got %d", code)
		}
		if out := buf.String(); !strings.HasPrefix(out, "SSL CRITICAL - exp.example: certificate expired") {
			t.Errorf("unexpected CRITICAL line: %q", out)
		}
	})

	t.Run("critical on error, no perfdata", func(t *testing.T) {
		var buf strings.Builder
		code := WriteNagios(&buf, []PromSample{{Domain: "bad.example", Err: errors.New("connection refused")}}, PrintOptions{}, false)
		if code != nagiosCritical {
			t.Fatalf("expected CRITICAL (2), got %d", code)
		}
		out := buf.String()
		if !strings.HasPrefix(out, "SSL CRITICAL - bad.example: connection refused") {
			t.Errorf("unexpected error line: %q", out)
		}
		if strings.Contains(out, "|") {
			t.Errorf("a failed fetch should carry no perfdata, got: %q", out)
		}
	})

	t.Run("multi reports worst with counts", func(t *testing.T) {
		var buf strings.Builder
		samples := []PromSample{
			{Domain: "ok.example", Info: infoOf(ok)},
			{Domain: "soon.example", Info: infoOf(soon)},
			{Domain: "bad.example", Err: errors.New("connection refused")},
		}
		code := WriteNagios(&buf, samples, PrintOptions{Threshold: 30}, false)
		if code != nagiosCritical {
			t.Fatalf("expected worst status CRITICAL (2), got %d", code)
		}
		out := buf.String()
		for _, want := range []string{
			"SSL CRITICAL - 1 OK, 1 WARNING, 1 CRITICAL",
			"OK ok.example: valid",
			"WARNING soon.example: expires in",
			"CRITICAL bad.example: connection refused",
		} {
			if !strings.Contains(out, want) {
				t.Errorf("multi output missing %q:\n%s", want, out)
			}
		}
		// Perfdata for the two retrieved targets, none for the failed one.
		if !strings.Contains(out, "'ok.example'=") || !strings.Contains(out, "'soon.example'=") {
			t.Errorf("expected perfdata for retrieved targets:\n%s", out)
		}
	})
}

// TestNagiosEval covers the CRITICAL branches not exercised by TestWriteNagios:
// pin mismatch, issuer mismatch and an invalid chain.
func TestNagiosEval(t *testing.T) {
	c := genCert(t, "n.example", time.Now().Add(90*24*time.Hour))
	healthy := &CertInfo{Cert: c, Chain: []*x509.Certificate{c}}

	if code, d := nagiosEval(PromSample{Domain: "n.example", Info: healthy}, PrintOptions{Pin: "00ff"}, false); code != nagiosCritical || !strings.Contains(d, "pin") {
		t.Errorf("pin mismatch: code=%d detail=%q", code, d)
	}
	if code, d := nagiosEval(PromSample{Domain: "n.example", Info: healthy}, PrintOptions{ExpectIssuer: "Nonexistent CA"}, false); code != nagiosCritical || !strings.Contains(d, "issuer") {
		t.Errorf("issuer mismatch: code=%d detail=%q", code, d)
	}
	invalid := &CertInfo{Cert: c, Chain: []*x509.Certificate{c}, Verified: true, ChainErr: x509.UnknownAuthorityError{}}
	if code, d := nagiosEval(PromSample{Domain: "n.example", Info: invalid}, PrintOptions{}, false); code != nagiosCritical || !strings.Contains(d, "INVALID") {
		t.Errorf("invalid chain: code=%d detail=%q", code, d)
	}
}
