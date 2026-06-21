package cert

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/json"
	"encoding/pem"
	"io"
	"math/big"
	"os"
	"strings"
	"testing"
	"time"
)

// captureStdout runs fn while capturing everything written to os.Stdout and
// returns it as a string.
func captureStdout(t *testing.T, fn func()) string {
	t.Helper()
	orig := os.Stdout
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("failed to create pipe: %v", err)
	}
	os.Stdout = w
	defer func() { os.Stdout = orig }()

	fn()
	w.Close()
	out, err := io.ReadAll(r)
	if err != nil {
		t.Fatalf("failed to read captured output: %v", err)
	}
	return string(out)
}

// genCert generates a self-signed certificate with its raw DER populated (so
// Fingerprint is meaningful). Each call uses a fresh key → a distinct cert.
func genCert(t *testing.T, cn string, notAfter time.Time) *x509.Certificate {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("key: %v", err)
	}
	tmpl := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: cn},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     notAfter,
		DNSNames:     []string{cn},
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	c, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	return c
}

// TestHeaderName verifies the "Certificate for ..." name falls back from an empty
// CommonName to the first SAN, then to the full subject DN.
func TestHeaderName(t *testing.T) {
	cn := &x509.Certificate{Subject: pkix.Name{CommonName: "cn.example"}, DNSNames: []string{"san.example"}}
	if got := headerName(cn); got != "cn.example" {
		t.Errorf("with CN: expected %q, got %q", "cn.example", got)
	}

	san := &x509.Certificate{DNSNames: []string{"san.example", "alt.example"}}
	if got := headerName(san); got != "san.example" {
		t.Errorf("no CN, with SAN: expected %q, got %q", "san.example", got)
	}

	dn := &x509.Certificate{Subject: pkix.Name{Organization: []string{"Acme"}}}
	if got := headerName(dn); got != dn.Subject.String() {
		t.Errorf("no CN, no SAN: expected DN %q, got %q", dn.Subject.String(), got)
	}
}

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

// TestFingerprint verifies the SHA-256 fingerprint is stable and distinguishes
// different certificates.
func TestFingerprint(t *testing.T) {
	a := genCert(t, "a.example", time.Now().Add(90*24*time.Hour))
	b := genCert(t, "b.example", time.Now().Add(90*24*time.Hour))

	fpA := Fingerprint(a)
	if len(fpA) != 64 {
		t.Errorf("expected 64 hex chars, got %d", len(fpA))
	}
	if fpA != Fingerprint(a) {
		t.Error("fingerprint should be stable")
	}
	if fpA == Fingerprint(b) {
		t.Error("different certificates should have different fingerprints")
	}
}

// certFromKey issues a self-signed certificate from a caller-provided key, so two
// certs can deliberately share a public key (to exercise SPKI pinning).
func certFromKey(t *testing.T, key *rsa.PrivateKey, serial *big.Int, notAfter time.Time) *x509.Certificate {
	t.Helper()
	tmpl := x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: "reissue.example"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     notAfter,
	}
	der, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	c, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	return c
}

// TestSPKIFingerprint verifies the public-key fingerprint is stable, distinguishes
// different keys, and — unlike the cert fingerprint — survives a reissue that keeps
// the same key.
func TestSPKIFingerprint(t *testing.T) {
	a := genCert(t, "a.example", time.Now().Add(90*24*time.Hour))
	b := genCert(t, "b.example", time.Now().Add(90*24*time.Hour))

	fp := SPKIFingerprint(a)
	if len(fp) != 64 {
		t.Errorf("expected 64 hex chars, got %d", len(fp))
	}
	if fp != SPKIFingerprint(a) {
		t.Error("SPKI fingerprint should be stable")
	}
	if fp == SPKIFingerprint(b) {
		t.Error("different keys should have different SPKI fingerprints")
	}

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("key: %v", err)
	}
	c1 := certFromKey(t, key, big.NewInt(1), time.Now().Add(30*24*time.Hour))
	c2 := certFromKey(t, key, big.NewInt(2), time.Now().Add(400*24*time.Hour))
	if SPKIFingerprint(c1) != SPKIFingerprint(c2) {
		t.Error("same key should yield the same SPKI fingerprint across reissues")
	}
	if Fingerprint(c1) == Fingerprint(c2) {
		t.Error("different certs should have different cert fingerprints")
	}
}

// TestNormalizePin covers the accepted shapes and the rejected ones.
func TestNormalizePin(t *testing.T) {
	const want = "e4134cbc32c0c0976599c684ae0b6ac849b2d75546d934dfdb611fa0d9a0e9cb"
	var pairs []string
	for i := 0; i < len(want); i += 2 {
		pairs = append(pairs, want[i:i+2])
	}
	colonized := "sha256:" + strings.Join(pairs, ":")

	for _, in := range []string{"sha256:" + want, "SHA256:" + strings.ToUpper(want), "  sha256:" + want + "  ", colonized} {
		got, err := NormalizePin(in)
		if err != nil {
			t.Errorf("NormalizePin(%q) unexpected error: %v", in, err)
			continue
		}
		if got != want {
			t.Errorf("NormalizePin(%q) = %q, want %q", in, got, want)
		}
	}

	for _, in := range []string{want, "md5:" + want, "sha256:abc", "sha256:" + strings.Repeat("z", 64)} {
		if _, err := NormalizePin(in); err == nil {
			t.Errorf("NormalizePin(%q) expected error, got nil", in)
		}
	}
}

// TestMatchesPin verifies a pin matches the cert or the SPKI fingerprint, and
// nothing else.
func TestMatchesPin(t *testing.T) {
	c := genCert(t, "pin.example", time.Now().Add(90*24*time.Hour))
	if !MatchesPin(c, Fingerprint(c)) {
		t.Error("should match the cert fingerprint")
	}
	if !MatchesPin(c, SPKIFingerprint(c)) {
		t.Error("should match the SPKI fingerprint")
	}
	if MatchesPin(c, strings.Repeat("0", 64)) {
		t.Error("should not match an unrelated pin")
	}
}

// TestChainPEM verifies the PEM export contains one valid CERTIFICATE block per
// certificate in the chain, and just the leaf when no chain is recorded.
func TestChainPEM(t *testing.T) {
	leaf := genCert(t, "leaf.example", time.Now().Add(90*24*time.Hour))
	inter := genCert(t, "inter.example", time.Now().Add(200*24*time.Hour))

	out := ChainPEM(&CertInfo{Cert: leaf, Chain: []*x509.Certificate{leaf, inter}})
	n, rest := 0, out
	for {
		block, remaining := pem.Decode(rest)
		if block == nil {
			break
		}
		rest = remaining
		if block.Type != "CERTIFICATE" {
			t.Errorf("unexpected PEM block type %q", block.Type)
		}
		if _, err := x509.ParseCertificate(block.Bytes); err != nil {
			t.Errorf("block %d is not a valid certificate: %v", n, err)
		}
		n++
	}
	if n != 2 {
		t.Errorf("expected 2 PEM blocks, got %d", n)
	}

	single := ChainPEM(&CertInfo{Cert: leaf})
	if got := strings.Count(string(single), "BEGIN CERTIFICATE"); got != 1 {
		t.Errorf("expected 1 block for a single cert, got %d", got)
	}
}

// issueChainCerts builds a real leaf ← intermediate ← root hierarchy (the leaf is
// signed by the intermediate, the intermediate by the self-signed root).
func issueChainCerts(t *testing.T) (leaf, inter, root *x509.Certificate) {
	t.Helper()
	mk := func(cn string, org string, parent *x509.Certificate, parentKey *rsa.PrivateKey, serial int64, isCA bool) (*x509.Certificate, *rsa.PrivateKey) {
		key, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			t.Fatalf("key: %v", err)
		}
		tmpl := x509.Certificate{
			SerialNumber:          big.NewInt(serial),
			Subject:               pkix.Name{CommonName: cn, Organization: []string{org}},
			NotBefore:             time.Now().Add(-time.Hour),
			NotAfter:              time.Now().Add(365 * 24 * time.Hour),
			IsCA:                  isCA,
			BasicConstraintsValid: isCA,
		}
		if isCA {
			tmpl.KeyUsage = x509.KeyUsageCertSign
		} else {
			tmpl.DNSNames = []string{cn}
		}
		signer, signerKey := parent, parentKey
		if signer == nil { // self-signed root
			signer, signerKey = &tmpl, key
		}
		der, err := x509.CreateCertificate(rand.Reader, &tmpl, signer, &key.PublicKey, signerKey)
		if err != nil {
			t.Fatalf("create %s: %v", cn, err)
		}
		c, err := x509.ParseCertificate(der)
		if err != nil {
			t.Fatalf("parse %s: %v", cn, err)
		}
		return c, key
	}
	root, rootKey := mk("Test Root", "TestOrg", nil, nil, 1, true)
	inter, interKey := mk("Test Inter", "InterOrg", root, rootKey, 2, true)
	leaf, _ = mk("leaf.example", "LeafOrg", inter, interKey, 3, false)
	return leaf, inter, root
}

// verifyErr returns the (untrusted) verification error for a leaf with the given
// intermediates, against the system roots — i.e. a real UnknownAuthorityError.
func verifyErr(t *testing.T, leaf *x509.Certificate, inters ...*x509.Certificate) error {
	t.Helper()
	pool := x509.NewCertPool()
	for _, c := range inters {
		pool.AddCert(c)
	}
	_, err := leaf.Verify(x509.VerifyOptions{Intermediates: pool})
	if err == nil {
		t.Fatal("expected verification to fail against system roots")
	}
	return err
}

// TestHasSCT verifies SCT-extension detection.
func TestHasSCT(t *testing.T) {
	plain := genCert(t, "plain.example", time.Now().Add(90*24*time.Hour))
	if hasSCT(plain) {
		t.Error("a cert without the SCT extension should report no SCTs")
	}

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("key: %v", err)
	}
	tmpl := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "sct.example"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(90 * 24 * time.Hour),
		ExtraExtensions: []pkix.Extension{{
			Id:    asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 11129, 2, 4, 2},
			Value: []byte{0x04, 0x00},
		}},
	}
	der, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	withSCT, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if !hasSCT(withSCT) {
		t.Error("a cert carrying the SCT extension should report SCTs present")
	}
}

// TestChainBreak verifies the break point for an unanchored chain and a served
// self-signed root.
func TestChainBreak(t *testing.T) {
	leaf, inter, root := issueChainCerts(t)

	// leaf + inter served, root missing → break at inter, issuer = root, not self-signed.
	brk, issuer, selfSigned, ok := chainBreak(&CertInfo{Cert: leaf, Chain: []*x509.Certificate{leaf, inter}})
	if !ok || brk != inter || selfSigned {
		t.Errorf("expected break at the intermediate (not self-signed), got brk=%v selfSigned=%v ok=%v", brk != nil, selfSigned, ok)
	}
	if !strings.Contains(issuer, "Test Root") {
		t.Errorf("expected the missing issuer to name the root, got %q", issuer)
	}

	// A served self-signed root → selfSigned true.
	_, _, selfSigned, ok = chainBreak(&CertInfo{Cert: root, Chain: []*x509.Certificate{root}})
	if !ok || !selfSigned {
		t.Errorf("expected a served self-signed root, got selfSigned=%v ok=%v", selfSigned, ok)
	}
}

// TestClassifyChainErr verifies the kind for a real unanchored chain.
func TestClassifyChainErr(t *testing.T) {
	leaf, inter, _ := issueChainCerts(t)
	info := &CertInfo{Cert: leaf, Chain: []*x509.Certificate{leaf, inter}, Verified: true, ChainErr: verifyErr(t, leaf, inter)}
	kind, reason := classifyChainErr(info)
	if kind != "unanchored" {
		t.Errorf("expected kind 'unanchored', got %q", kind)
	}
	if reason == "" {
		t.Error("expected a non-empty reason")
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

// TestIssuerMatches verifies case-insensitive substring matching of the issuer DN.
func TestIssuerMatches(t *testing.T) {
	c := genCert(t, "issuer.example", time.Now().Add(90*24*time.Hour)) // self-signed: issuer CN = issuer.example
	if !IssuerMatches(c, "") {
		t.Error("empty substring should match anything")
	}
	if !IssuerMatches(c, "issuer.example") {
		t.Error("expected a match on the issuer CN")
	}
	if !IssuerMatches(c, "ISSUER.EXAMPLE") {
		t.Error("expected a case-insensitive match")
	}
	if IssuerMatches(c, "Let's Encrypt") {
		t.Error("did not expect a match on an unrelated substring")
	}
}

// TestHasWarnings verifies the soft-problem predicate used by -strict.
func TestHasWarnings(t *testing.T) {
	healthy := genCert(t, "healthy.example", time.Now().Add(90*24*time.Hour))
	if HasWarnings(&CertInfo{Cert: healthy, Verified: true}) {
		t.Error("a healthy verified cert should have no warnings")
	}

	notYet := &CertInfo{Cert: &x509.Certificate{
		NotBefore: time.Now().Add(48 * time.Hour),
		NotAfter:  time.Now().Add(90 * 24 * time.Hour),
	}}
	if !HasWarnings(notYet) {
		t.Error("a not-yet-valid cert should warn")
	}

	leaf, inter, _ := issueChainCerts(t)
	untrusted := &CertInfo{Cert: leaf, Chain: []*x509.Certificate{leaf, inter}, Verified: true, ChainErr: verifyErr(t, leaf, inter)}
	if !HasWarnings(untrusted) {
		t.Error("an untrusted chain should warn")
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

// TestLoadCAFile verifies a valid PEM bundle loads and bad inputs error out.
func TestLoadCAFile(t *testing.T) {
	c := genCert(t, "ca.example", time.Now().Add(365*24*time.Hour))
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: c.Raw})
	dir := t.TempDir()

	good := dir + "/ca.pem"
	if err := os.WriteFile(good, pemBytes, 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}
	pool, err := LoadCAFile(good)
	if err != nil || pool == nil {
		t.Fatalf("expected a pool, got pool=%v err=%v", pool, err)
	}

	bad := dir + "/bad.pem"
	if err := os.WriteFile(bad, []byte("not a certificate"), 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}
	if _, err := LoadCAFile(bad); err == nil {
		t.Error("expected an error for a file with no certificates")
	}
	if _, err := LoadCAFile(dir + "/missing.pem"); err == nil {
		t.Error("expected an error for a missing file")
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

// TestFormatPublicKey verifies the algorithm/size rendering for RSA, ECDSA and
// Ed25519 keys.
func TestFormatPublicKey(t *testing.T) {
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa key: %v", err)
	}
	ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("ecdsa key: %v", err)
	}
	edPub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("ed25519 key: %v", err)
	}

	cases := []struct {
		pub  any
		want string
	}{
		{&rsaKey.PublicKey, "RSA 2048"},
		{&ecKey.PublicKey, "ECDSA P-256"},
		{edPub, "Ed25519"},
	}
	for _, c := range cases {
		if got := formatPublicKey(&x509.Certificate{PublicKey: c.pub}); got != c.want {
			t.Errorf("formatPublicKey = %q, want %q", got, c.want)
		}
	}
}

// TestWeakCrypto verifies weak signature and weak RSA key detection.
func TestWeakCrypto(t *testing.T) {
	if !isWeakSignature(&x509.Certificate{SignatureAlgorithm: x509.SHA1WithRSA}) {
		t.Error("SHA1WithRSA should be flagged as weak")
	}
	if isWeakSignature(&x509.Certificate{SignatureAlgorithm: x509.SHA256WithRSA}) {
		t.Error("SHA256WithRSA should not be flagged as weak")
	}

	weak, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatalf("weak rsa key: %v", err)
	}
	if !isWeakKey(&x509.Certificate{PublicKey: &weak.PublicKey}) {
		t.Error("RSA 1024 should be flagged as a weak key")
	}
	strong, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("strong rsa key: %v", err)
	}
	if isWeakKey(&x509.Certificate{PublicKey: &strong.PublicKey}) {
		t.Error("RSA 2048 should not be flagged as a weak key")
	}
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

// TestCheapChecks verifies the not-yet-valid, name-coverage and EKU detectors.
func TestCheapChecks(t *testing.T) {
	now := time.Now()

	// not-yet-valid
	if !notYetValid(&x509.Certificate{NotBefore: now.Add(48 * time.Hour)}) {
		t.Error("future NotBefore should be flagged not-yet-valid")
	}
	if notYetValid(&x509.Certificate{NotBefore: now.Add(-time.Hour)}) {
		t.Error("active certificate should not be flagged not-yet-valid")
	}

	// name coverage with a one-level wildcard
	wild := &x509.Certificate{DNSNames: []string{"*.example.com"}}
	if nameMismatch(&CertInfo{Cert: wild, CheckedName: "shop.example.com"}) {
		t.Error("*.example.com should cover shop.example.com")
	}
	if !nameMismatch(&CertInfo{Cert: wild, CheckedName: "api.shop.example.com"}) {
		t.Error("*.example.com should NOT cover api.shop.example.com")
	}
	if nameMismatch(&CertInfo{Cert: wild, CheckedName: ""}) {
		t.Error("empty CheckedName (file load) should not be flagged")
	}

	// EKU / server auth
	if !notServerAuth(&x509.Certificate{ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}) {
		t.Error("client-auth-only certificate should be flagged")
	}
	if notServerAuth(&x509.Certificate{ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}) {
		t.Error("server-auth certificate should not be flagged")
	}
	if notServerAuth(&x509.Certificate{}) {
		t.Error("certificate without EKU restriction should not be flagged")
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

// TestDaysUntilExpiry verifies the day arithmetic for future and past expiry.
func TestDaysUntilExpiry(t *testing.T) {
	future := &x509.Certificate{NotAfter: time.Now().Add(10*24*time.Hour + time.Hour)}
	if got := DaysUntilExpiry(future); got != 10 {
		t.Errorf("expected 10 days remaining, got %d", got)
	}
	past := &x509.Certificate{NotAfter: time.Now().Add(-2 * 24 * time.Hour)}
	if got := DaysUntilExpiry(past); got >= 0 {
		t.Errorf("expected negative days for expired cert, got %d", got)
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

// TestMinDaysUntilExpiry verifies the minimum is taken across the whole chain
// and falls back to the leaf when no chain is recorded.
func TestMinDaysUntilExpiry(t *testing.T) {
	leaf := &x509.Certificate{NotAfter: time.Now().Add(90*24*time.Hour + time.Hour)}
	inter := &x509.Certificate{NotAfter: time.Now().Add(20*24*time.Hour + time.Hour)}

	withChain := &CertInfo{Cert: leaf, Chain: []*x509.Certificate{leaf, inter}}
	if got := withChain.MinDaysUntilExpiry(); got != 20 {
		t.Errorf("expected min 20 across chain, got %d", got)
	}

	leafOnly := &CertInfo{Cert: leaf}
	if got := leafOnly.MinDaysUntilExpiry(); got != 90 {
		t.Errorf("expected leaf fallback 90, got %d", got)
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
