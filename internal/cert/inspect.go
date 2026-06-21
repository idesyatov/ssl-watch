package cert

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"strings"
	"time"
)

// earliestExpiringBefore returns the intermediate certificate (from chain[1:])
// that expires soonest among those expiring before the leaf, or nil when every
// intermediate outlives the leaf (or there are no intermediates). Such an
// intermediate breaks the chain before the leaf certificate itself expires.
func earliestExpiringBefore(chain []*x509.Certificate) *x509.Certificate {
	if len(chain) < 2 {
		return nil
	}
	leaf := chain[0]
	var earliest *x509.Certificate
	for _, c := range chain[1:] {
		if !c.NotAfter.Before(leaf.NotAfter) {
			continue
		}
		if earliest == nil || c.NotAfter.Before(earliest.NotAfter) {
			earliest = c
		}
	}
	return earliest
}

// subjectName returns the certificate's common name, falling back to the full
// subject DN when no common name is present.
func subjectName(c *x509.Certificate) string {
	if c.Subject.CommonName != "" {
		return c.Subject.CommonName
	}
	return c.Subject.String()
}

// headerName picks the most meaningful name for the "Certificate for ..." header:
// the subject CommonName, falling back to the first SAN (modern certs often leave
// CN empty), then to the full subject DN.
func headerName(c *x509.Certificate) string {
	if c.Subject.CommonName != "" {
		return c.Subject.CommonName
	}
	if len(c.DNSNames) > 0 {
		return c.DNSNames[0]
	}
	return c.Subject.String()
}

// issuerName returns the issuer's common name, falling back to the full issuer DN.
func issuerName(c *x509.Certificate) string {
	if c.Issuer.CommonName != "" {
		return c.Issuer.CommonName
	}
	return c.Issuer.String()
}

// formatPublicKey describes the certificate's public key as algorithm and size,
// e.g. "RSA 2048", "ECDSA P-256" or "Ed25519".
func formatPublicKey(c *x509.Certificate) string {
	switch pub := c.PublicKey.(type) {
	case *rsa.PublicKey:
		return fmt.Sprintf("RSA %d", pub.N.BitLen())
	case *ecdsa.PublicKey:
		return fmt.Sprintf("ECDSA %s", pub.Curve.Params().Name)
	case ed25519.PublicKey:
		return "Ed25519"
	default:
		return c.PublicKeyAlgorithm.String()
	}
}

// chainList returns the certificate chain, or a single-element slice with the
// leaf when no chain is recorded (file load).
func chainList(info *CertInfo) []*x509.Certificate {
	if len(info.Chain) > 0 {
		return info.Chain
	}
	return []*x509.Certificate{info.Cert}
}

// ChainPEM returns the PEM encoding of every certificate available for info — the
// served chain (leaf first) or just the leaf for a file-loaded certificate — as
// one CERTIFICATE block per certificate.
func ChainPEM(info *CertInfo) []byte {
	var out []byte
	for _, c := range chainList(info) {
		out = append(out, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: c.Raw})...)
	}
	return out
}

// isWeakSignature reports whether the certificate is signed with a broken or
// deprecated hash (MD2/MD5/SHA-1 family).
func isWeakSignature(c *x509.Certificate) bool {
	switch c.SignatureAlgorithm {
	case x509.MD2WithRSA, x509.MD5WithRSA, x509.SHA1WithRSA, x509.DSAWithSHA1, x509.ECDSAWithSHA1:
		return true
	default:
		return false
	}
}

// isWeakKey reports whether the certificate uses an RSA key smaller than 2048 bits.
func isWeakKey(c *x509.Certificate) bool {
	if pub, ok := c.PublicKey.(*rsa.PublicKey); ok {
		return pub.N.BitLen() < 2048
	}
	return false
}

// notYetValid reports whether the certificate's validity window has not started
// yet (NotBefore is in the future).
func notYetValid(c *x509.Certificate) bool {
	return time.Now().Before(c.NotBefore)
}

// nameMismatch reports whether the certificate does not cover the hostname it was
// requested for. It is only meaningful for fetched certificates (CheckedName set);
// VerifyHostname handles SANs and wildcards per RFC 6125.
func nameMismatch(info *CertInfo) bool {
	return info.CheckedName != "" && info.Cert.VerifyHostname(info.CheckedName) != nil
}

// notServerAuth reports whether the certificate restricts its extended key usage
// and that restriction excludes TLS server authentication. A certificate with no
// EKU extension is valid for any use and is not flagged.
func notServerAuth(c *x509.Certificate) bool {
	if len(c.ExtKeyUsage) == 0 {
		return false
	}
	for _, u := range c.ExtKeyUsage {
		if u == x509.ExtKeyUsageServerAuth || u == x509.ExtKeyUsageAny {
			return false
		}
	}
	return true
}

// Fingerprint returns the lower-case hex SHA-256 of the certificate's raw DER,
// the stable identity used to tell whether two endpoints serve the same cert.
func Fingerprint(c *x509.Certificate) string {
	sum := sha256.Sum256(c.Raw)
	return hex.EncodeToString(sum[:])
}

// SPKIFingerprint returns the lower-case hex SHA-256 of the certificate's
// SubjectPublicKeyInfo (the public key). Unlike Fingerprint it is stable across
// reissues that keep the same key, which makes it useful for pinning that should
// survive a routine renewal.
func SPKIFingerprint(c *x509.Certificate) string {
	sum := sha256.Sum256(c.RawSubjectPublicKeyInfo)
	return hex.EncodeToString(sum[:])
}

// NormalizePin parses a pin of the form "sha256:<hex>" into the bare lower-case
// hex digest. Colons inside the hex are tolerated (paste-friendly) and the digest
// must be 32 bytes (64 hex chars). It returns an error for any other shape.
func NormalizePin(raw string) (string, error) {
	rest, ok := strings.CutPrefix(strings.ToLower(strings.TrimSpace(raw)), "sha256:")
	if !ok {
		return "", fmt.Errorf("pin must start with \"sha256:\"")
	}
	rest = strings.ReplaceAll(rest, ":", "")
	if len(rest) != 64 {
		return "", fmt.Errorf("pin must be a 64-character hex SHA-256 digest")
	}
	if _, err := hex.DecodeString(rest); err != nil {
		return "", fmt.Errorf("pin is not valid hex: %v", err)
	}
	return rest, nil
}

// MatchesPin reports whether the normalized pin (see NormalizePin) equals either
// the certificate's SHA-256 fingerprint or its public-key (SPKI) fingerprint.
func MatchesPin(c *x509.Certificate, pin string) bool {
	return pin == Fingerprint(c) || pin == SPKIFingerprint(c)
}

// IssuerMatches reports whether the certificate's issuer DN contains substr,
// case-insensitively. An empty substr matches anything.
func IssuerMatches(c *x509.Certificate, substr string) bool {
	if substr == "" {
		return true
	}
	return strings.Contains(strings.ToLower(c.Issuer.String()), strings.ToLower(substr))
}

// HasWarnings reports whether the certificate has any soft problem the tool warns
// about — used by -strict to turn warnings into a non-zero exit.
func HasWarnings(info *CertInfo) bool {
	c := info.Cert
	if notYetValid(c) || nameMismatch(info) || notServerAuth(c) {
		return true
	}
	if earliestExpiringBefore(info.Chain) != nil {
		return true
	}
	return info.Verified && info.ChainErr != nil
}

// sctOID is the X.509 extension carrying embedded Signed Certificate Timestamps
// (RFC 6962). Genuine publicly-trusted certificates are logged in Certificate
// Transparency and carry this extension.
var sctOID = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 11129, 2, 4, 2}

// hasSCT reports whether the certificate carries embedded SCTs.
func hasSCT(c *x509.Certificate) bool {
	for _, ext := range c.Extensions {
		if ext.Id.Equal(sctOID) {
			return true
		}
	}
	return false
}

// dnLabel renders a short "CN (O=org)" label, falling back gracefully.
func dnLabel(cn string, orgs []string) string {
	if cn == "" {
		cn = "(no CN)"
	}
	if len(orgs) > 0 {
		return fmt.Sprintf("%s (O=%s)", cn, orgs[0])
	}
	return cn
}

// chainBreak walks the served peer chain from the leaf and returns the highest
// served certificate whose issuer is not itself served — the point where the
// chain leaves the material the server sent. issuer is that certificate's issuer
// label, selfSigned is true when the break certificate is self-signed (a served
// root), and ok is false only when no chain is recorded.
func chainBreak(info *CertInfo) (brk *x509.Certificate, issuer string, selfSigned, ok bool) {
	chain := info.Chain
	if len(chain) == 0 {
		return nil, "", false, false
	}
	bySubject := make(map[string]*x509.Certificate, len(chain))
	for _, c := range chain {
		bySubject[string(c.RawSubject)] = c
	}
	cur := chain[0]
	seen := make(map[string]bool)
	for {
		if string(cur.RawSubject) == string(cur.RawIssuer) {
			return cur, dnLabel(cur.Subject.CommonName, cur.Subject.Organization), true, true
		}
		next, found := bySubject[string(cur.RawIssuer)]
		if !found || seen[string(next.RawSubject)] {
			return cur, dnLabel(cur.Issuer.CommonName, cur.Issuer.Organization), false, true
		}
		seen[string(cur.RawSubject)] = true
		cur = next
	}
}

// classifyChainErr turns a chain verification error into a machine kind and a
// human-readable reason. Returns empty strings when the chain verified.
func classifyChainErr(info *CertInfo) (kind, reason string) {
	switch e := info.ChainErr.(type) {
	case nil:
		return "", ""
	case x509.HostnameError:
		return "hostname_mismatch", "hostname not covered by the certificate"
	case x509.CertificateInvalidError:
		if e.Reason == x509.Expired {
			return "expired", "a certificate in the chain is expired or not yet valid"
		}
		return "invalid", e.Error()
	case x509.UnknownAuthorityError:
		if _, _, selfSigned, ok := chainBreak(info); ok && selfSigned {
			return "untrusted_root", "chain ends at a self-signed root not in the system trust store"
		}
		return "unanchored", "not anchored to a trusted root"
	default:
		return "invalid", info.ChainErr.Error()
	}
}

// untrustedIssuer returns the label of the issuer the chain could not be anchored
// to, for the JSON view. Empty unless the failure is a trust/anchor problem.
func untrustedIssuer(info *CertInfo) string {
	if _, ok := info.ChainErr.(x509.UnknownAuthorityError); !ok {
		return ""
	}
	_, issuer, _, ok := chainBreak(info)
	if !ok {
		return ""
	}
	return issuer
}

// issuerTrail renders "leaf ← intermediate (O=…) … [missing issuer marker]" up to
// the break point, so the untrusted/missing anchor is visible at a glance.
func issuerTrail(info *CertInfo) string {
	brk, issuer, selfSigned, ok := chainBreak(info)
	if !ok {
		return ""
	}
	bySubject := make(map[string]*x509.Certificate, len(info.Chain))
	for _, c := range info.Chain {
		bySubject[string(c.RawSubject)] = c
	}
	var parts []string
	cur := info.Chain[0]
	for {
		parts = append(parts, dnLabel(cur.Subject.CommonName, cur.Subject.Organization))
		if cur == brk {
			break
		}
		next, found := bySubject[string(cur.RawIssuer)]
		if !found {
			break
		}
		cur = next
	}
	trail := strings.Join(parts, " ← ")
	if selfSigned {
		return trail + "   [self-signed root, not in system trust store]"
	}
	return trail + fmt.Sprintf("   [%s: not served and not trusted]", issuer)
}
