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
	"encoding/pem"
	"errors"
	"math/big"
	"strings"
	"testing"
	"time"
)

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
