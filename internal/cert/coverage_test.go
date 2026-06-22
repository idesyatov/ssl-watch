package cert

import (
	"crypto/x509"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"
)

// TestPayloadAndErrorPayload covers the exported JSON-assembly helpers used for
// the multi-domain result array.
func TestPayloadAndErrorPayload(t *testing.T) {
	c := genCert(t, "p.example", time.Now().Add(30*24*time.Hour))
	info := &CertInfo{Cert: c, Chain: []*x509.Certificate{c}}

	b, err := json.Marshal(Payload(info, "p.example", true, true))
	if err != nil {
		t.Fatalf("marshal Payload: %v", err)
	}
	for _, want := range []string{`"domain":"p.example"`, `"fingerprint"`, `"chain"`} {
		if !strings.Contains(string(b), want) {
			t.Errorf("Payload JSON missing %s:\n%s", want, b)
		}
	}

	eb, err := json.Marshal(ErrorPayload("bad.example", "connection refused"))
	if err != nil {
		t.Fatalf("marshal ErrorPayload: %v", err)
	}
	if !strings.Contains(string(eb), `"domain":"bad.example"`) || !strings.Contains(string(eb), `"error":"connection refused"`) {
		t.Errorf("ErrorPayload JSON wrong: %s", eb)
	}
}

// TestClassifyChainErrKinds covers the error-kind classification branches.
func TestClassifyChainErrKinds(t *testing.T) {
	c := genCert(t, "c.example", time.Now().Add(24*time.Hour))
	cases := []struct {
		name string
		err  error
		want string
	}{
		{"hostname", x509.HostnameError{Certificate: c, Host: "other"}, "hostname_mismatch"},
		{"expired", x509.CertificateInvalidError{Cert: c, Reason: x509.Expired}, "expired"},
		{"generic", errors.New("boom"), "invalid"},
		{"untrusted_root", x509.UnknownAuthorityError{}, "untrusted_root"},
	}
	for _, tc := range cases {
		info := &CertInfo{Cert: c, Chain: []*x509.Certificate{c}, Verified: true, ChainErr: tc.err}
		if kind, _ := classifyChainErr(info); kind != tc.want {
			t.Errorf("%s: kind=%q, want %q", tc.name, kind, tc.want)
		}
	}
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
