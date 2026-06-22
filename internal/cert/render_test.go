package cert

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"math/big"
	"strings"
	"testing"
	"time"
)

// TestPrint_ExpiredMarker verifies an expired leaf gets a textual "(expired)"
// marker that survives without color, in addition to the negative day count.
func TestPrint_ExpiredMarker(t *testing.T) {
	cert := genCert(t, "old.example", time.Now().Add(-3*24*time.Hour))
	info := &CertInfo{Cert: cert}

	out := captureStdout(t, func() { (&CertificatePrinterImpl{}).Print(info, PrintOptions{}) })

	if !strings.Contains(out, "(expired)") {
		t.Errorf("expected an (expired) marker, got:\n%s", out)
	}
}

// TestPrint_DateFormat verifies the leaf validity dates use the unified layout.
func TestPrint_DateFormat(t *testing.T) {
	cert := genCert(t, "fmt.example", time.Now().Add(90*24*time.Hour))
	info := &CertInfo{Cert: cert}

	out := captureStdout(t, func() { (&CertificatePrinterImpl{}).Print(info, PrintOptions{}) })

	want := "Expires on: " + cert.NotAfter.Format(dateFormat)
	if !strings.Contains(out, want) {
		t.Errorf("expected output to contain %q, got:\n%s", want, out)
	}
}

// TestPrint_UntrustedRoot verifies the trust diagnostics in text and JSON for an
// untrusted chain whose leaf carries no SCTs.
func TestPrint_UntrustedRoot(t *testing.T) {
	leaf, inter, _ := issueChainCerts(t)
	info := &CertInfo{Cert: leaf, Chain: []*x509.Certificate{leaf, inter}, Verified: true, ChainErr: verifyErr(t, leaf, inter)}
	printer := &CertificatePrinterImpl{}

	out := captureStdout(t, func() { printer.Print(info, PrintOptions{}) })
	for _, want := range []string{"INVALID — not anchored to a trusted root", "Test Inter", "no embedded SCTs"} {
		if !strings.Contains(out, want) {
			t.Errorf("text output missing %q:\n%s", want, out)
		}
	}

	out = captureStdout(t, func() { printer.Print(info, PrintOptions{JSON: true}) })
	var got struct {
		ChainErrorKind  string `json:"chain_error_kind"`
		UntrustedIssuer string `json:"untrusted_issuer"`
		NoSCT           bool   `json:"no_sct"`
	}
	if err := json.Unmarshal([]byte(out), &got); err != nil {
		t.Fatalf("invalid JSON: %v\n%s", err, out)
	}
	if got.ChainErrorKind != "unanchored" {
		t.Errorf("expected chain_error_kind 'unanchored', got %q", got.ChainErrorKind)
	}
	if !strings.Contains(got.UntrustedIssuer, "Test Root") {
		t.Errorf("expected untrusted_issuer to name the root, got %q", got.UntrustedIssuer)
	}
	if !got.NoSCT {
		t.Error("expected no_sct true for a cert without SCTs")
	}
}

// TestPrint_HealthyNoTrustNoise verifies a verified cert adds no trust-diagnostic noise.
func TestPrint_HealthyNoTrustNoise(t *testing.T) {
	cert := genCert(t, "healthy.example", time.Now().Add(90*24*time.Hour))
	info := &CertInfo{Cert: cert, Chain: []*x509.Certificate{cert}, Verified: true, ChainErr: nil}

	printer := &CertificatePrinterImpl{}
	out := captureStdout(t, func() { printer.Print(info, PrintOptions{}) })
	if !strings.Contains(out, "Chain: VALID") {
		t.Errorf("expected Chain: VALID, got:\n%s", out)
	}
	for _, unwanted := range []string{"no embedded SCTs", "INVALID", "not anchored"} {
		if strings.Contains(out, unwanted) {
			t.Errorf("healthy cert should not print %q:\n%s", unwanted, out)
		}
	}
}

// TestPrint_ExpectIssuer verifies the issuer-mismatch warning appears only on a mismatch.
func TestPrint_ExpectIssuer(t *testing.T) {
	c := genCert(t, "issuer.example", time.Now().Add(90*24*time.Hour))
	info := &CertInfo{Cert: c}
	printer := &CertificatePrinterImpl{}

	out := captureStdout(t, func() { printer.Print(info, PrintOptions{ExpectIssuer: "Nonexistent CA"}) })
	if !strings.Contains(out, "WARNING: issuer") {
		t.Errorf("expected an issuer-mismatch warning, got:\n%s", out)
	}

	out = captureStdout(t, func() { printer.Print(info, PrintOptions{ExpectIssuer: "issuer.example"}) })
	if strings.Contains(out, "WARNING: issuer") {
		t.Errorf("a matching issuer should not warn, got:\n%s", out)
	}
}

// TestPrint_Fingerprint verifies the two fingerprint lines appear only with the flag.
func TestPrint_Fingerprint(t *testing.T) {
	c := genCert(t, "fp.example", time.Now().Add(90*24*time.Hour))
	info := &CertInfo{Cert: c}
	printer := &CertificatePrinterImpl{}

	out := captureStdout(t, func() { printer.Print(info, PrintOptions{Fingerprint: true}) })
	for _, want := range []string{"SHA-256 (cert): " + Fingerprint(c), "SHA-256 (pubkey): " + SPKIFingerprint(c)} {
		if !strings.Contains(out, want) {
			t.Errorf("expected %q in:\n%s", want, out)
		}
	}
	out = captureStdout(t, func() { printer.Print(info, PrintOptions{}) })
	if strings.Contains(out, "SHA-256 (") {
		t.Errorf("fingerprints should be hidden without -fingerprint:\n%s", out)
	}
}

// TestPrint_Pin verifies the pin verdict in text (match/mismatch) and JSON.
func TestPrint_Pin(t *testing.T) {
	c := genCert(t, "pin.example", time.Now().Add(90*24*time.Hour))
	info := &CertInfo{Cert: c}
	printer := &CertificatePrinterImpl{}

	out := captureStdout(t, func() { printer.Print(info, PrintOptions{Pin: Fingerprint(c)}) })
	if !strings.Contains(out, "Pin: MATCH") {
		t.Errorf("expected Pin: MATCH, got:\n%s", out)
	}

	out = captureStdout(t, func() { printer.Print(info, PrintOptions{Pin: strings.Repeat("0", 64)}) })
	if !strings.Contains(out, "Pin: MISMATCH") {
		t.Errorf("expected Pin: MISMATCH, got:\n%s", out)
	}
	if !strings.Contains(out, Fingerprint(c)) {
		t.Errorf("a mismatch should show the actual cert fingerprint, got:\n%s", out)
	}

	mustPinMatch := func(pin string, expect bool) {
		t.Helper()
		out := captureStdout(t, func() { printer.Print(info, PrintOptions{JSON: true, Pin: pin}) })
		var got struct {
			PinMatch *bool `json:"pin_match"`
		}
		if err := json.Unmarshal([]byte(out), &got); err != nil {
			t.Fatalf("invalid JSON: %v\n%s", err, out)
		}
		if got.PinMatch == nil || *got.PinMatch != expect {
			t.Errorf("expected pin_match %v, got %v", expect, got.PinMatch)
		}
	}
	mustPinMatch(SPKIFingerprint(c), true)
	mustPinMatch(strings.Repeat("0", 64), false)
}

// TestPrint_KeyAndTLS verifies the public key and TLS connection lines appear in
// the human-readable output.
func TestPrint_KeyAndTLS(t *testing.T) {
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa key: %v", err)
	}
	cert := &x509.Certificate{
		Subject:            pkix.Name{CommonName: "example.com"},
		SerialNumber:       big.NewInt(1),
		SignatureAlgorithm: x509.SHA256WithRSA,
		PublicKey:          &rsaKey.PublicKey,
		NotAfter:           time.Now().Add(30 * 24 * time.Hour),
	}
	info := &CertInfo{Cert: cert, UsedIP: "192.0.2.1", TLSVersion: "TLS 1.3", CipherSuite: "TLS_AES_128_GCM_SHA256"}

	out := captureStdout(t, func() { (&CertificatePrinterImpl{}).Print(info, PrintOptions{}) })
	for _, want := range []string{"Public key: RSA 2048", "TLS: TLS 1.3 (TLS_AES_128_GCM_SHA256)"} {
		if !strings.Contains(out, want) {
			t.Errorf("expected output to contain %q, got:\n%s", want, out)
		}
	}
}

// TestPrint_WeakMarkers verifies the "(weak)" marker on a SHA-1, RSA-1024 cert.
func TestPrint_WeakMarkers(t *testing.T) {
	weak, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatalf("weak rsa key: %v", err)
	}
	cert := &x509.Certificate{
		Subject:            pkix.Name{CommonName: "old.example"},
		SerialNumber:       big.NewInt(1),
		SignatureAlgorithm: x509.SHA1WithRSA,
		PublicKey:          &weak.PublicKey,
		NotAfter:           time.Now().Add(30 * 24 * time.Hour),
	}
	info := &CertInfo{Cert: cert, FromFile: true}

	out := captureStdout(t, func() { (&CertificatePrinterImpl{}).Print(info, PrintOptions{}) })
	if !strings.Contains(out, "Public key: RSA 1024 (weak)") {
		t.Errorf("expected weak key marker, got:\n%s", out)
	}
	if !strings.Contains(out, "(weak)") || !strings.Contains(out, "Signature:") {
		t.Errorf("expected weak signature marker, got:\n%s", out)
	}
}

// TestPrint_CheapWarnings verifies all three warnings appear in text and JSON for
// a problematic certificate.
func TestPrint_CheapWarnings(t *testing.T) {
	now := time.Now()
	cert := &x509.Certificate{
		Subject:      pkix.Name{CommonName: "shop.example.com"},
		SerialNumber: big.NewInt(1),
		DNSNames:     []string{"*.example.com"},
		NotBefore:    now.Add(48 * time.Hour),
		NotAfter:     now.Add(90 * 24 * time.Hour),
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	info := &CertInfo{Cert: cert, CheckedName: "api.shop.example.com"}
	printer := &CertificatePrinterImpl{}

	out := captureStdout(t, func() { printer.Print(info, PrintOptions{}) })
	for _, want := range []string{
		"not valid yet",
		`does not cover "api.shop.example.com"`,
		"not intended for server authentication",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("expected output to contain %q, got:\n%s", want, out)
		}
	}

	out = captureStdout(t, func() { printer.Print(info, PrintOptions{JSON: true}) })
	var got struct {
		NotYetValid   bool `json:"not_yet_valid"`
		NameMismatch  bool `json:"name_mismatch"`
		NotServerAuth bool `json:"not_server_auth"`
	}
	if err := json.Unmarshal([]byte(out), &got); err != nil {
		t.Fatalf("invalid JSON: %v\n%s", err, out)
	}
	if !got.NotYetValid || !got.NameMismatch || !got.NotServerAuth {
		t.Errorf("expected all three flags true, got %+v", got)
	}
}

// TestPrint_HealthyNoWarnings verifies a healthy certificate produces no warnings
// and omits the problem flags from JSON.
func TestPrint_HealthyNoWarnings(t *testing.T) {
	now := time.Now()
	cert := &x509.Certificate{
		Subject:      pkix.Name{CommonName: "good.example"},
		SerialNumber: big.NewInt(1),
		DNSNames:     []string{"good.example"},
		NotBefore:    now.Add(-24 * time.Hour),
		NotAfter:     now.Add(90 * 24 * time.Hour),
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	info := &CertInfo{Cert: cert, CheckedName: "good.example"}
	printer := &CertificatePrinterImpl{}

	out := captureStdout(t, func() { printer.Print(info, PrintOptions{}) })
	if strings.Contains(out, "WARNING") || strings.Contains(out, "not intended") {
		t.Errorf("healthy certificate should produce no warnings, got:\n%s", out)
	}

	out = captureStdout(t, func() { printer.Print(info, PrintOptions{JSON: true}) })
	for _, k := range []string{"not_yet_valid", "name_mismatch", "not_server_auth"} {
		if strings.Contains(out, k) {
			t.Errorf("healthy JSON should omit %q, got:\n%s", k, out)
		}
	}
}

// TestPrint_Chain verifies the -chain text block and JSON array.
func TestPrint_Chain(t *testing.T) {
	leaf := &x509.Certificate{
		Subject:      pkix.Name{CommonName: "leaf.example"},
		Issuer:       pkix.Name{CommonName: "Intermediate CA"},
		SerialNumber: big.NewInt(1),
		NotAfter:     time.Now().Add(60 * 24 * time.Hour),
	}
	inter := &x509.Certificate{
		Subject:      pkix.Name{CommonName: "Intermediate CA"},
		Issuer:       pkix.Name{CommonName: "Root CA"},
		SerialNumber: big.NewInt(2),
		NotAfter:     time.Now().Add(400 * 24 * time.Hour),
	}
	info := &CertInfo{Cert: leaf, Chain: []*x509.Certificate{leaf, inter}, UsedIP: "192.0.2.1"}
	printer := &CertificatePrinterImpl{}

	// Text
	out := captureStdout(t, func() { printer.Print(info, PrintOptions{Chain: true}) })
	for _, want := range []string{"Certificate chain (2):", "[0] leaf.example (issued by Intermediate CA)", "[1] Intermediate CA (issued by Root CA)"} {
		if !strings.Contains(out, want) {
			t.Errorf("expected chain output to contain %q, got:\n%s", want, out)
		}
	}

	// JSON
	out = captureStdout(t, func() { printer.Print(info, PrintOptions{JSON: true, Chain: true}) })
	var got struct {
		Chain []struct {
			Subject       string `json:"subject"`
			Issuer        string `json:"issuer"`
			DaysRemaining int    `json:"days_remaining"`
		} `json:"chain"`
	}
	if err := json.Unmarshal([]byte(out), &got); err != nil {
		t.Fatalf("invalid JSON: %v\n%s", err, out)
	}
	if len(got.Chain) != 2 {
		t.Fatalf("expected 2 chain entries, got %d:\n%s", len(got.Chain), out)
	}
	if got.Chain[0].Subject != "leaf.example" || got.Chain[1].Issuer != "Root CA" {
		t.Errorf("unexpected chain entries: %+v", got.Chain)
	}
}

// TestPrint_Chain_OmittedByDefault verifies the chain field is absent without -chain.
func TestPrint_Chain_OmittedByDefault(t *testing.T) {
	cert := &x509.Certificate{
		Subject:      pkix.Name{CommonName: "leaf.example"},
		SerialNumber: big.NewInt(1),
		NotAfter:     time.Now().Add(60 * 24 * time.Hour),
	}
	info := &CertInfo{Cert: cert, Chain: []*x509.Certificate{cert}}

	out := captureStdout(t, func() { (&CertificatePrinterImpl{}).Print(info, PrintOptions{JSON: true}) })
	if strings.Contains(out, "\"chain\"") {
		t.Errorf("did not expect a chain field without -chain, got:\n%s", out)
	}
}

// TestFormatSerial verifies serial numbers are rendered as colon-separated hex.
func TestFormatSerial(t *testing.T) {
	cases := map[string]struct {
		in   *big.Int
		want string
	}{
		"zero":        {big.NewInt(0), "0"},
		"single byte": {big.NewInt(15), "0F"},
		"two bytes":   {big.NewInt(0x0FA3), "0F:A3"},
	}
	for name, c := range cases {
		if got := formatSerial(c.in); got != c.want {
			t.Errorf("%s: formatSerial(%v) = %q, want %q", name, c.in, got, c.want)
		}
	}
}

// TestCertificatePrinter_Print verifies the full output contains the expected
// fields, including SANs, serial, signature algorithm and chain status.
func TestCertificatePrinter_Print(t *testing.T) {
	cert := &x509.Certificate{
		Subject:            pkix.Name{CommonName: "example.com"},
		DNSNames:           []string{"example.com", "www.example.com"},
		SerialNumber:       big.NewInt(0x0FA3),
		SignatureAlgorithm: x509.SHA256WithRSA,
		NotBefore:          time.Now().Add(-24 * time.Hour),
		NotAfter:           time.Now().Add(30 * 24 * time.Hour),
	}
	info := &CertInfo{Cert: cert, UsedIP: "192.0.2.1", Verified: true, ChainErr: nil}

	printer := &CertificatePrinterImpl{}
	out := captureStdout(t, func() { printer.Print(info, PrintOptions{}) })

	for _, want := range []string{
		"Certificate for example.com",
		"SANs: example.com, www.example.com",
		"Serial: 0F:A3",
		"Signature: SHA256-RSA",
		"Used IP address: 192.0.2.1",
		"Chain: VALID",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("expected output to contain %q, got:\n%s", want, out)
		}
	}
}

// TestCertificatePrinter_Print_Short verifies short mode prints only the days remaining.
func TestCertificatePrinter_Print_Short(t *testing.T) {
	cert := &x509.Certificate{NotAfter: time.Now().Add(30 * 24 * time.Hour)}
	info := &CertInfo{Cert: cert}

	printer := &CertificatePrinterImpl{}
	out := captureStdout(t, func() { printer.Print(info, PrintOptions{Short: true}) })

	if strings.Contains(out, "Certificate for") {
		t.Errorf("short output should not contain full details, got:\n%s", out)
	}
	if strings.TrimSpace(out) == "" {
		t.Error("expected short output to contain days remaining")
	}
}

// TestCertificatePrinter_Print_FileChainOmitted verifies that for a file-loaded
// certificate neither the used IP nor the chain status are printed.
func TestCertificatePrinter_Print_FileChainOmitted(t *testing.T) {
	cert := &x509.Certificate{
		Subject:      pkix.Name{CommonName: "file.example"},
		SerialNumber: big.NewInt(1),
		NotAfter:     time.Now().Add(time.Hour),
	}
	info := &CertInfo{Cert: cert, FromFile: true}

	printer := &CertificatePrinterImpl{}
	out := captureStdout(t, func() { printer.Print(info, PrintOptions{}) })

	if strings.Contains(out, "Used IP address") {
		t.Errorf("file-loaded cert should not print used IP, got:\n%s", out)
	}
	if strings.Contains(out, "Chain:") {
		t.Errorf("file-loaded cert should not print chain status, got:\n%s", out)
	}
}

// TestCertificatePrinter_Print_JSON verifies the JSON output is valid and carries
// the expected fields.
func TestCertificatePrinter_Print_JSON(t *testing.T) {
	cert := &x509.Certificate{
		Subject:            pkix.Name{CommonName: "json.example"},
		DNSNames:           []string{"json.example"},
		SerialNumber:       big.NewInt(0x0FA3),
		SignatureAlgorithm: x509.SHA256WithRSA,
		NotBefore:          time.Now().Add(-24 * time.Hour),
		NotAfter:           time.Now().Add(10 * 24 * time.Hour),
	}
	info := &CertInfo{Cert: cert, UsedIP: "192.0.2.1", Verified: true, ChainErr: nil}

	printer := &CertificatePrinterImpl{}
	out := captureStdout(t, func() { printer.Print(info, PrintOptions{JSON: true}) })

	var got struct {
		CommonName    string   `json:"common_name"`
		SANs          []string `json:"sans"`
		Serial        string   `json:"serial"`
		DaysRemaining int      `json:"days_remaining"`
		UsedIP        string   `json:"used_ip"`
		ChainValid    *bool    `json:"chain_valid"`
	}
	if err := json.Unmarshal([]byte(out), &got); err != nil {
		t.Fatalf("output is not valid JSON: %v\noutput:\n%s", err, out)
	}
	if got.CommonName != "json.example" {
		t.Errorf("expected common_name 'json.example', got '%s'", got.CommonName)
	}
	if got.Serial != "0F:A3" {
		t.Errorf("expected serial '0F:A3', got '%s'", got.Serial)
	}
	if got.UsedIP != "192.0.2.1" {
		t.Errorf("expected used_ip '192.0.2.1', got '%s'", got.UsedIP)
	}
	if got.ChainValid == nil || !*got.ChainValid {
		t.Errorf("expected chain_valid true, got %v", got.ChainValid)
	}
}

// TestCertificatePrinter_Print_ChainExpiryWarning verifies the warning is printed
// when an intermediate expires before the leaf, and omitted otherwise.
func TestCertificatePrinter_Print_ChainExpiryWarning(t *testing.T) {
	leaf := &x509.Certificate{
		Subject:      pkix.Name{CommonName: "leaf.example"},
		SerialNumber: big.NewInt(1),
		NotAfter:     time.Now().Add(90 * 24 * time.Hour),
	}
	earlyInter := &x509.Certificate{
		Subject:  pkix.Name{CommonName: "Early Intermediate CA"},
		NotAfter: time.Now().Add(20 * 24 * time.Hour),
	}
	lateInter := &x509.Certificate{
		Subject:  pkix.Name{CommonName: "Late Intermediate CA"},
		NotAfter: time.Now().Add(200 * 24 * time.Hour),
	}

	printer := &CertificatePrinterImpl{}

	warned := &CertInfo{Cert: leaf, Chain: []*x509.Certificate{leaf, earlyInter}}
	out := captureStdout(t, func() { printer.Print(warned, PrintOptions{}) })
	if !strings.Contains(out, "WARNING") || !strings.Contains(out, "Early Intermediate CA") {
		t.Errorf("expected chain expiry warning naming the intermediate, got:\n%s", out)
	}

	ok := &CertInfo{Cert: leaf, Chain: []*x509.Certificate{leaf, lateInter}}
	out = captureStdout(t, func() { printer.Print(ok, PrintOptions{}) })
	if strings.Contains(out, "WARNING") {
		t.Errorf("did not expect a warning when intermediate outlives leaf, got:\n%s", out)
	}
}

// TestCertificatePrinter_Print_JSON_ChainExpiry verifies the chain_expiry_warning
// object is emitted in JSON when an intermediate expires before the leaf.
func TestCertificatePrinter_Print_JSON_ChainExpiry(t *testing.T) {
	leaf := &x509.Certificate{
		Subject:      pkix.Name{CommonName: "leaf.example"},
		SerialNumber: big.NewInt(1),
		NotAfter:     time.Now().Add(90 * 24 * time.Hour),
	}
	inter := &x509.Certificate{
		Subject:      pkix.Name{CommonName: "Early Intermediate CA"},
		SerialNumber: big.NewInt(2),
		NotAfter:     time.Now().Add(20*24*time.Hour + time.Hour),
	}
	info := &CertInfo{Cert: leaf, Chain: []*x509.Certificate{leaf, inter}}

	printer := &CertificatePrinterImpl{}
	out := captureStdout(t, func() { printer.Print(info, PrintOptions{JSON: true}) })

	var got struct {
		ChainExpiry *struct {
			Subject       string `json:"subject"`
			DaysRemaining int    `json:"days_remaining"`
		} `json:"chain_expiry_warning"`
	}
	if err := json.Unmarshal([]byte(out), &got); err != nil {
		t.Fatalf("output is not valid JSON: %v\noutput:\n%s", err, out)
	}
	if got.ChainExpiry == nil {
		t.Fatalf("expected chain_expiry_warning in JSON, got:\n%s", out)
	}
	if got.ChainExpiry.Subject != "Early Intermediate CA" {
		t.Errorf("expected subject 'Early Intermediate CA', got '%s'", got.ChainExpiry.Subject)
	}
	if got.ChainExpiry.DaysRemaining != 20 {
		t.Errorf("expected days_remaining 20, got %d", got.ChainExpiry.DaysRemaining)
	}
}

// TestCertificatePrinter_Print_ColorThreshold verifies the days-remaining value is
// colorized (yellow) when below the threshold.
func TestCertificatePrinter_Print_ColorThreshold(t *testing.T) {
	cert := &x509.Certificate{
		Subject:      pkix.Name{CommonName: "soon.example"},
		SerialNumber: big.NewInt(1),
		NotAfter:     time.Now().Add(5 * 24 * time.Hour),
	}
	info := &CertInfo{Cert: cert}

	printer := &CertificatePrinterImpl{}
	out := captureStdout(t, func() {
		printer.Print(info, PrintOptions{Threshold: 30, Color: true})
	})

	if !strings.Contains(out, colorYellow) {
		t.Errorf("expected yellow highlight for days below threshold, got:\n%q", out)
	}
}

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
