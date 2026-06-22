package cert

import (
	"crypto/x509"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"
)

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

// TestAnyPinMismatch covers the pin-comparison helper used by -all-ips.
func TestAnyPinMismatch(t *testing.T) {
	c := genCert(t, "a.example", time.Now().Add(24*time.Hour))
	results := []IPResult{{IP: "203.0.113.1", Info: &CertInfo{Cert: c, Chain: []*x509.Certificate{c}}}}

	if anyPinMismatch(results, "") {
		t.Error("empty pin should never report a mismatch")
	}
	if !anyPinMismatch(results, "00deadbeef") {
		t.Error("a non-matching pin should report a mismatch")
	}
	if anyPinMismatch(results, Fingerprint(c)) {
		t.Error("the matching fingerprint should not report a mismatch")
	}
	skipped := []IPResult{{IP: "2001:db8::1", Err: errors.New("unreachable"), Skipped: true}}
	if anyPinMismatch(skipped, "00ff") {
		t.Error("skipped/errored addresses must be ignored")
	}
}
