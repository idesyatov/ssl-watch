package cert

import (
	"crypto/x509"
	"encoding/csv"
	"encoding/json"
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

// TestPrintAllIPs verifies the per-address table, the "differ" verdict and the
// JSON object, including the AllIPsResult summary.
func TestPrintAllIPs(t *testing.T) {
	now := time.Now()
	same := genCert(t, "example.com", now.Add(90*24*time.Hour))
	diff := genCert(t, "example.com", now.Add(8*24*time.Hour))
	results := []IPResult{
		{IP: "203.0.113.10", Info: &CertInfo{Cert: same, Chain: []*x509.Certificate{same}, Verified: true, UsedIP: "203.0.113.10"}},
		{IP: "203.0.113.11", Info: &CertInfo{Cert: same, Chain: []*x509.Certificate{same}, Verified: true}},
		{IP: "203.0.113.12", Info: &CertInfo{Cert: diff, Chain: []*x509.Certificate{diff}, Verified: true}},
		{IP: "203.0.113.13", Err: errors.New("connection refused")},
	}

	var res AllIPsResult
	out := captureStdout(t, func() { res = PrintAllIPs("example.com", results, PrintOptions{}) })

	if res.AllMatch {
		t.Error("expected AllMatch false (certificates differ)")
	}
	if !res.HadError {
		t.Error("expected HadError true (one address failed)")
	}
	for _, want := range []string{"checking 4 address(es)", "203.0.113.10", "error: connection refused", "differ across addresses"} {
		if !strings.Contains(out, want) {
			t.Errorf("text output missing %q:\n%s", want, out)
		}
	}

	out = captureStdout(t, func() { PrintAllIPs("example.com", results, PrintOptions{JSON: true}) })
	var got struct {
		Domain            string           `json:"domain"`
		CertificatesMatch bool             `json:"certificates_match"`
		Addresses         []map[string]any `json:"addresses"`
	}
	if err := json.Unmarshal([]byte(out), &got); err != nil {
		t.Fatalf("invalid JSON: %v\n%s", err, out)
	}
	if got.Domain != "example.com" || got.CertificatesMatch {
		t.Errorf("expected domain example.com and certificates_match false, got %+v", got)
	}
	if len(got.Addresses) != 4 {
		t.Fatalf("expected 4 addresses, got %d:\n%s", len(got.Addresses), out)
	}
	if got.Addresses[0]["ip"] != "203.0.113.10" || got.Addresses[0]["fingerprint"] == nil {
		t.Errorf("first address should carry ip+fingerprint, got %v", got.Addresses[0])
	}
	if _, ok := got.Addresses[0]["used_ip"]; ok {
		t.Errorf("used_ip is redundant in -all-ips and must be omitted, got %v", got.Addresses[0])
	}
	if got.Addresses[3]["error"] == nil {
		t.Errorf("last address should be an error entry, got %v", got.Addresses[3])
	}
}

// TestPrintAllIPs_AllMatch verifies the matching verdict and AllMatch=true.
func TestPrintAllIPs_AllMatch(t *testing.T) {
	c := genCert(t, "example.com", time.Now().Add(90*24*time.Hour))
	results := []IPResult{
		{IP: "203.0.113.10", Info: &CertInfo{Cert: c, Chain: []*x509.Certificate{c}, Verified: true}},
		{IP: "203.0.113.11", Info: &CertInfo{Cert: c, Chain: []*x509.Certificate{c}, Verified: true}},
	}

	var res AllIPsResult
	out := captureStdout(t, func() { res = PrintAllIPs("example.com", results, PrintOptions{}) })
	if !res.AllMatch || res.HadError {
		t.Errorf("expected AllMatch true and no error, got %+v", res)
	}
	if !strings.Contains(out, "same certificate") {
		t.Errorf("expected matching verdict, got:\n%s", out)
	}
}

// TestPrintAllIPs_Skipped verifies an unreachable (skipped) address does not
// count as an error and is reported separately.
func TestPrintAllIPs_Skipped(t *testing.T) {
	c := genCert(t, "example.com", time.Now().Add(90*24*time.Hour))
	results := []IPResult{
		{IP: "2a02:6b8::2:242", Err: errors.New("connect: network is unreachable"), Skipped: true},
		{IP: "5.255.255.242", Info: &CertInfo{Cert: c, Chain: []*x509.Certificate{c}, Verified: true}},
		{IP: "77.88.44.242", Info: &CertInfo{Cert: c, Chain: []*x509.Certificate{c}, Verified: true}},
	}

	var res AllIPsResult
	out := captureStdout(t, func() { res = PrintAllIPs("example.com", results, PrintOptions{}) })

	if res.HadError {
		t.Error("a skipped address must not count as an error")
	}
	if res.Skipped != 1 || res.Reachable != 2 {
		t.Errorf("expected 1 skipped / 2 reachable, got %d / %d", res.Skipped, res.Reachable)
	}
	if !res.AllMatch {
		t.Error("two identical reachable certs should match")
	}
	for _, want := range []string{"skipped (unreachable from this host)", "All reachable addresses serve the same certificate", "1 address(es) skipped"} {
		if !strings.Contains(out, want) {
			t.Errorf("text output missing %q:\n%s", want, out)
		}
	}

	out = captureStdout(t, func() { PrintAllIPs("example.com", results, PrintOptions{JSON: true}) })
	var got struct {
		Addresses []map[string]any `json:"addresses"`
	}
	if err := json.Unmarshal([]byte(out), &got); err != nil {
		t.Fatalf("invalid JSON: %v\n%s", err, out)
	}
	if got.Addresses[0]["skipped"] != true {
		t.Errorf("first address should be marked skipped, got %v", got.Addresses[0])
	}
}
