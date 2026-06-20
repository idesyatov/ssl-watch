package cert

import (
	"bufio"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/asn1"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"os"
	"strings"
	"time"
)

// CertInfo aggregates a retrieved certificate together with metadata about how
// it was obtained and the result of chain verification.
type CertInfo struct {
	Cert        *x509.Certificate   // The retrieved certificate (leaf)
	Chain       []*x509.Certificate // Full peer chain (leaf first); nil when loaded from a file
	UsedIP      string              // Remote IP address; empty when loaded from a file
	TLSVersion  string              // Negotiated TLS version; empty when loaded from a file
	CipherSuite string              // Negotiated cipher suite; empty when loaded from a file
	CheckedName string              // Hostname the cert was requested for; empty when loaded from a file
	FromFile    bool                // True when the certificate was loaded from a local file
	Verified    bool                // True when chain verification was attempted
	ChainErr    error               // Chain verification error; nil means valid (only meaningful when Verified)
}

// CertificateFetcher defines an interface for fetching certificates from a domain or IP address.
type CertificateFetcher interface {
	// Fetch retrieves the certificate for the specified domain and port, or IP address.
	// When insecure is false, the certificate chain is verified against the system roots.
	// timeout bounds the connection attempt. When starttls is non-empty (one of
	// "smtp", "imap", "pop3", "ftp") the connection is upgraded to TLS via the
	// protocol's STARTTLS command instead of starting TLS directly.
	// Returns the certificate information and an error if any occurred.
	Fetch(domain, port, ipaddr string, insecure bool, timeout time.Duration, starttls string) (*CertInfo, error)
}

// CertificateLoader defines an interface for loading certificates from a file.
type CertificateLoader interface {
	// Load reads a certificate from the specified file and returns it.
	// Returns the loaded certificate information and an error if any occurred.
	Load(certFile string) (*CertInfo, error)
}

// PrintOptions controls how certificate information is rendered.
type PrintOptions struct {
	Short     bool // Print only the number of days remaining
	JSON      bool // Print machine-readable JSON
	Threshold int  // Days threshold for the expiry warning highlight (0 = disabled)
	Color     bool // Colorize the human-readable output
	Chain     bool // Print every certificate in the chain

	Fingerprint bool   // Print the certificate and public-key SHA-256 fingerprints
	Pin         string // Normalized hex pin to verify against (empty = disabled)
}

// CertificatePrinter defines an interface for printing certificate details.
type CertificatePrinter interface {
	// Print outputs the details of the certificate according to the given options.
	Print(info *CertInfo, opts PrintOptions)
}

// DaysUntilExpiry returns the whole number of days until the certificate expires.
// The value is negative if the certificate has already expired.
func DaysUntilExpiry(cert *x509.Certificate) int {
	return int(time.Until(cert.NotAfter).Hours() / 24)
}

// MinDaysUntilExpiry returns the smallest days-until-expiry across the whole
// chain (leaf plus any intermediates). When no chain is recorded (file load) it
// falls back to the leaf, so callers can drive the expiry exit code off the
// weakest link rather than the leaf alone.
func (info *CertInfo) MinDaysUntilExpiry() int {
	min := DaysUntilExpiry(info.Cert)
	for _, c := range info.Chain {
		if d := DaysUntilExpiry(c); d < min {
			min = d
		}
	}
	return min
}

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

// CertificateFetcherImpl is an implementation of the CertificateFetcher interface.
// It provides functionality to fetch certificates from a specified domain or IP address.
type CertificateFetcherImpl struct{}

// Fetch connects to the specified domain or IP address and retrieves the TLS certificate.
// The handshake always skips verification so that details of an invalid certificate can
// still be displayed; the chain is then verified separately unless insecure is true.
func (f *CertificateFetcherImpl) Fetch(domain, port, ipaddr string, insecure bool, timeout time.Duration, starttls string) (*CertInfo, error) {
	host := domain
	if ipaddr != "" {
		host = ipaddr
	}
	address := net.JoinHostPort(host, port)
	tlsConfig := &tls.Config{
		InsecureSkipVerify: true,
		ServerName:         domain,
	}

	conn, err := dialTLS(address, timeout, starttls, tlsConfig)
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	state := conn.ConnectionState()
	certs := state.PeerCertificates
	if len(certs) == 0 {
		return nil, fmt.Errorf("no certificates found for %s", address)
	}

	usedIP := conn.RemoteAddr().String()
	if tcpAddr, ok := conn.RemoteAddr().(*net.TCPAddr); ok {
		usedIP = tcpAddr.IP.String()
	}

	info := &CertInfo{
		Cert:        certs[0],
		Chain:       certs,
		UsedIP:      usedIP,
		TLSVersion:  tls.VersionName(state.Version),
		CipherSuite: tls.CipherSuiteName(state.CipherSuite),
		CheckedName: domain,
	}
	if !insecure {
		info.Verified = true
		info.ChainErr = verifyChain(certs, domain)
	}
	return info, nil
}

// verifyChain validates the leaf certificate (certs[0]) against the system root
// store, using the remaining peer certificates as intermediates. The check covers
// trust, hostname match and validity period.
func verifyChain(certs []*x509.Certificate, domain string) error {
	intermediates := x509.NewCertPool()
	for _, c := range certs[1:] {
		intermediates.AddCert(c)
	}
	_, err := certs[0].Verify(x509.VerifyOptions{
		DNSName:       domain,
		Intermediates: intermediates,
	})
	return err
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

// dialTLS opens a TLS connection to address. When starttls is empty it dials TLS
// directly; otherwise it connects in plaintext, upgrades via the protocol's
// STARTTLS command and then performs the TLS handshake. The timeout bounds both
// the connection and the STARTTLS negotiation.
func dialTLS(address string, timeout time.Duration, starttls string, cfg *tls.Config) (*tls.Conn, error) {
	if starttls == "" {
		dialer := &net.Dialer{Timeout: timeout}
		conn, err := tls.DialWithDialer(dialer, "tcp", address, cfg)
		if err != nil {
			return nil, fmt.Errorf("failed to connect to %s: %v", address, err)
		}
		return conn, nil
	}

	conn, err := net.DialTimeout("tcp", address, timeout)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to %s: %v", address, err)
	}
	// Bound the plaintext negotiation and handshake by the same timeout.
	_ = conn.SetDeadline(time.Now().Add(timeout))
	if err := negotiateStartTLS(conn, starttls); err != nil {
		conn.Close()
		return nil, fmt.Errorf("STARTTLS (%s) failed for %s: %v", starttls, address, err)
	}

	tlsConn := tls.Client(conn, cfg)
	if err := tlsConn.Handshake(); err != nil {
		tlsConn.Close()
		return nil, fmt.Errorf("TLS handshake failed for %s: %v", address, err)
	}
	_ = conn.SetDeadline(time.Time{})
	return tlsConn, nil
}

// negotiateStartTLS performs the protocol-specific STARTTLS exchange on a
// plaintext connection, leaving it ready for the TLS handshake. Supported
// protocols: smtp, imap, pop3, ftp.
func negotiateStartTLS(conn net.Conn, proto string) error {
	br := bufio.NewReader(conn)
	switch proto {
	case "smtp":
		if err := expectCodeReply(br, "220"); err != nil {
			return err
		}
		if _, err := fmt.Fprintf(conn, "EHLO ssl-watch\r\n"); err != nil {
			return err
		}
		if err := expectCodeReply(br, "250"); err != nil {
			return err
		}
		if _, err := fmt.Fprintf(conn, "STARTTLS\r\n"); err != nil {
			return err
		}
		return expectCodeReply(br, "220")
	case "ftp":
		if err := expectCodeReply(br, "220"); err != nil {
			return err
		}
		if _, err := fmt.Fprintf(conn, "AUTH TLS\r\n"); err != nil {
			return err
		}
		return expectCodeReply(br, "234")
	case "pop3":
		if err := expectLinePrefix(br, "+OK"); err != nil {
			return err
		}
		if _, err := fmt.Fprintf(conn, "STLS\r\n"); err != nil {
			return err
		}
		return expectLinePrefix(br, "+OK")
	case "imap":
		if err := expectLinePrefix(br, "* OK"); err != nil {
			return err
		}
		if _, err := fmt.Fprintf(conn, "a STARTTLS\r\n"); err != nil {
			return err
		}
		return expectTaggedOK(br, "a")
	default:
		return fmt.Errorf("unknown STARTTLS protocol %q", proto)
	}
}

// readLine reads a single CRLF-terminated line and trims the line ending.
func readLine(br *bufio.Reader) (string, error) {
	line, err := br.ReadString('\n')
	if err != nil {
		return "", err
	}
	return strings.TrimRight(line, "\r\n"), nil
}

// expectCodeReply reads an SMTP/FTP reply (handling "NNN-" multi-line
// continuations) and verifies the final line starts with the expected code.
func expectCodeReply(br *bufio.Reader, code string) error {
	for {
		line, err := readLine(br)
		if err != nil {
			return err
		}
		// A "-" right after the 3-digit code marks a continuation line.
		if len(line) >= 4 && line[3] == '-' {
			continue
		}
		if !strings.HasPrefix(line, code) {
			return fmt.Errorf("expected reply %s, got %q", code, line)
		}
		return nil
	}
}

// expectLinePrefix reads one line and verifies it starts with prefix.
func expectLinePrefix(br *bufio.Reader, prefix string) error {
	line, err := readLine(br)
	if err != nil {
		return err
	}
	if !strings.HasPrefix(line, prefix) {
		return fmt.Errorf("expected %q, got %q", prefix, line)
	}
	return nil
}

// expectTaggedOK reads IMAP response lines until the one matching the given tag
// and verifies it reports OK.
func expectTaggedOK(br *bufio.Reader, tag string) error {
	for {
		line, err := readLine(br)
		if err != nil {
			return err
		}
		if strings.HasPrefix(line, tag+" ") {
			if !strings.HasPrefix(line, tag+" OK") {
				return fmt.Errorf("STARTTLS rejected: %q", line)
			}
			return nil
		}
	}
}

// CertificateLoaderImpl is an implementation of the CertificateLoader interface.
// It provides functionality to load certificates from a specified file.
type CertificateLoaderImpl struct{}

// Load reads a certificate from the specified file and returns it.
// Returns an error if the file cannot be read or if the certificate cannot be parsed.
func (l *CertificateLoaderImpl) Load(certFile string) (*CertInfo, error) {
	certPEM, err := os.ReadFile(certFile)
	if err != nil {
		return nil, fmt.Errorf("failed to read certificate file %s: %v", certFile, err)
	}

	block, _ := pem.Decode(certPEM)
	if block == nil || block.Type != "CERTIFICATE" {
		return nil, fmt.Errorf("failed to parse certificate from file %s", certFile)
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, err
	}

	return &CertInfo{Cert: cert, FromFile: true}, nil
}

// CertificatePrinterImpl is an implementation of the CertificatePrinter interface.
// It provides functionality to print details of a certificate.
type CertificatePrinterImpl struct{}

// Print outputs the details of the certificate according to opts: as JSON,
// as a single days-remaining number (short), or as full human-readable text.
func (p *CertificatePrinterImpl) Print(info *CertInfo, opts PrintOptions) {
	days := DaysUntilExpiry(info.Cert)

	switch {
	case opts.JSON:
		p.printJSON(info, opts)
	case opts.Short:
		fmt.Println(days)
	default:
		p.printText(info, days, opts)
	}
}

// printText renders the full human-readable output, including subject, issuer,
// SANs, serial number, signature algorithm, validity period and days remaining.
// For fetched certificates it also reports the used IP address and the chain
// verification status. When opts.Color is set, the days-remaining value and the
// chain status are colorized.
func (p *CertificatePrinterImpl) printText(info *CertInfo, days int, opts PrintOptions) {
	cert := info.Cert

	fmt.Printf("Certificate for %s\n", cert.Subject.CommonName)
	fmt.Printf("Subject: %s\n", cert.Subject)
	fmt.Printf("Issuer: %s\n", cert.Issuer)
	if len(cert.DNSNames) > 0 {
		fmt.Printf("SANs: %s\n", strings.Join(cert.DNSNames, ", "))
	}
	fmt.Printf("Serial: %s\n", formatSerial(cert.SerialNumber))

	sig := cert.SignatureAlgorithm.String()
	if isWeakSignature(cert) {
		sig += maybeColor(" (weak)", colorYellow, opts.Color)
	}
	fmt.Printf("Signature: %s\n", sig)

	pubKey := formatPublicKey(cert)
	if isWeakKey(cert) {
		pubKey += maybeColor(" (weak)", colorYellow, opts.Color)
	}
	fmt.Printf("Public key: %s\n", pubKey)

	if opts.Fingerprint {
		fmt.Printf("SHA-256 (cert): %s\n", Fingerprint(cert))
		fmt.Printf("SHA-256 (pubkey): %s\n", SPKIFingerprint(cert))
	}

	fmt.Printf("Valid from: %s\n", cert.NotBefore)
	fmt.Printf("Expires on: %s\n", cert.NotAfter)

	fmt.Printf("Days remaining: %s\n", colorizeDays(days, opts.Threshold, opts.Color))

	if !info.FromFile {
		fmt.Printf("Used IP address: %s\n", info.UsedIP)
		if info.TLSVersion != "" {
			fmt.Printf("TLS: %s (%s)\n", info.TLSVersion, info.CipherSuite)
		}
	}
	if info.Verified {
		if info.ChainErr == nil {
			fmt.Printf("Chain: %s\n", maybeColor("VALID", colorGreen, opts.Color))
		} else {
			_, reason := classifyChainErr(info)
			fmt.Printf("Chain: %s — %s\n", maybeColor("INVALID", colorRed, opts.Color), reason)
			if trail := issuerTrail(info); trail != "" {
				fmt.Printf("  %s\n", trail)
			}
			if !hasSCT(cert) {
				fmt.Println(maybeColor("WARNING: no embedded SCTs — certificate is not in Certificate Transparency; not from a genuine public CA (possible private/re-signed cert)", colorRed, opts.Color))
			}
		}
	}
	if opts.Pin != "" {
		if MatchesPin(cert, opts.Pin) {
			fmt.Printf("Pin: %s\n", maybeColor("MATCH", colorGreen, opts.Color))
		} else {
			fmt.Printf("Pin: %s (got SHA-256 cert %s)\n", maybeColor("MISMATCH", colorRed, opts.Color), Fingerprint(cert))
		}
	}

	if early := earliestExpiringBefore(info.Chain); early != nil {
		earlyDays := DaysUntilExpiry(early)
		msg := fmt.Sprintf("WARNING: intermediate %q expires in %d days, before the leaf (%d days)",
			subjectName(early), earlyDays, days)
		if opts.Color {
			color := colorYellow
			if earlyDays < 0 {
				color = colorRed
			}
			msg = colorize(msg, color)
		}
		fmt.Println(msg)
	}

	if notYetValid(cert) {
		inDays := int(time.Until(cert.NotBefore).Hours() / 24)
		msg := fmt.Sprintf("WARNING: certificate is not valid yet — becomes valid in %d days (%s)",
			inDays, cert.NotBefore.Format("2006-01-02"))
		fmt.Println(maybeColor(msg, colorRed, opts.Color))
	}
	if nameMismatch(info) {
		msg := fmt.Sprintf("WARNING: certificate does not cover %q", info.CheckedName)
		fmt.Println(maybeColor(msg, colorRed, opts.Color))
	}
	if notServerAuth(cert) {
		fmt.Println(maybeColor("WARNING: certificate is not intended for server authentication", colorYellow, opts.Color))
	}

	if opts.Chain {
		printChainText(info)
	}
}

// printChainText prints every certificate in the chain (leaf first), one per
// line, with its subject, issuer and expiry.
func printChainText(info *CertInfo) {
	chain := chainList(info)
	fmt.Printf("Certificate chain (%d):\n", len(chain))
	for i, c := range chain {
		fmt.Printf("  [%d] %s (issued by %s) - expires %s, %d days\n",
			i, subjectName(c), issuerName(c), c.NotAfter.Format("2006-01-02"), DaysUntilExpiry(c))
	}
}

// chainExpiry is the JSON view of an intermediate certificate that expires
// before the leaf.
type chainExpiry struct {
	Subject       string `json:"subject"`
	DaysRemaining int    `json:"days_remaining"`
}

// chainCert is the JSON view of a single certificate in the chain.
type chainCert struct {
	Subject       string `json:"subject"`
	Issuer        string `json:"issuer"`
	NotAfter      string `json:"not_after"`
	DaysRemaining int    `json:"days_remaining"`
}

// certPayload is the JSON-serializable view of a certificate. Domain is set only
// for multi-domain runs and omitted otherwise, so single-target output keeps its
// original schema.
type certPayload struct {
	Domain        string       `json:"domain,omitempty"`
	IP            string       `json:"ip,omitempty"`
	Fingerprint   string       `json:"fingerprint,omitempty"`
	SPKIFinger    string       `json:"spki_fingerprint,omitempty"`
	PinMatch      *bool        `json:"pin_match,omitempty"`
	CommonName    string       `json:"common_name"`
	Subject       string       `json:"subject"`
	Issuer        string       `json:"issuer"`
	SANs          []string     `json:"sans,omitempty"`
	Serial        string       `json:"serial"`
	Signature     string       `json:"signature_algorithm"`
	WeakSignature bool         `json:"weak_signature,omitempty"`
	PublicKey     string       `json:"public_key"`
	WeakKey       bool         `json:"weak_key,omitempty"`
	NotBefore     string       `json:"not_before"`
	NotAfter      string       `json:"not_after"`
	NotYetValid   bool         `json:"not_yet_valid,omitempty"`
	DaysRemaining int          `json:"days_remaining"`
	UsedIP        string       `json:"used_ip,omitempty"`
	TLSVersion    string       `json:"tls_version,omitempty"`
	CipherSuite   string       `json:"cipher_suite,omitempty"`
	NameMismatch  bool         `json:"name_mismatch,omitempty"`
	NotServerAuth bool         `json:"not_server_auth,omitempty"`
	ChainValid    *bool        `json:"chain_valid,omitempty"`
	ChainError    string       `json:"chain_error,omitempty"`
	ChainErrKind  string       `json:"chain_error_kind,omitempty"`
	UntrustedIss  string       `json:"untrusted_issuer,omitempty"`
	NoSCT         bool         `json:"no_sct,omitempty"`
	ChainExpiry   *chainExpiry `json:"chain_expiry_warning,omitempty"`
	Chain         []chainCert  `json:"chain,omitempty"`
}

// buildPayload assembles the JSON view of a certificate, tagged with domain
// (empty domain is omitted from the output). When includeChain is set, the full
// chain is added under the "chain" field. When includeFingerprint is set the
// cert and public-key SHA-256 fingerprints are added; when pin is non-empty a
// "pin_match" verdict is added.
func buildPayload(info *CertInfo, domain string, includeChain, includeFingerprint bool, pin string) certPayload {
	cert := info.Cert
	out := certPayload{
		Domain:        domain,
		CommonName:    cert.Subject.CommonName,
		Subject:       cert.Subject.String(),
		Issuer:        cert.Issuer.String(),
		SANs:          cert.DNSNames,
		Serial:        formatSerial(cert.SerialNumber),
		Signature:     cert.SignatureAlgorithm.String(),
		WeakSignature: isWeakSignature(cert),
		PublicKey:     formatPublicKey(cert),
		WeakKey:       isWeakKey(cert),
		NotBefore:     cert.NotBefore.UTC().Format(time.RFC3339),
		NotAfter:      cert.NotAfter.UTC().Format(time.RFC3339),
		NotYetValid:   notYetValid(cert),
		DaysRemaining: DaysUntilExpiry(cert),
		UsedIP:        info.UsedIP,
		TLSVersion:    info.TLSVersion,
		CipherSuite:   info.CipherSuite,
		NameMismatch:  nameMismatch(info),
		NotServerAuth: notServerAuth(cert),
	}
	if info.Verified {
		valid := info.ChainErr == nil
		out.ChainValid = &valid
		if info.ChainErr != nil {
			out.ChainError = info.ChainErr.Error()
			out.ChainErrKind, _ = classifyChainErr(info)
			out.UntrustedIss = untrustedIssuer(info)
			out.NoSCT = !hasSCT(cert)
		}
	}
	if early := earliestExpiringBefore(info.Chain); early != nil {
		out.ChainExpiry = &chainExpiry{Subject: subjectName(early), DaysRemaining: DaysUntilExpiry(early)}
	}
	if includeFingerprint {
		out.Fingerprint = Fingerprint(cert)
		out.SPKIFinger = SPKIFingerprint(cert)
	}
	if pin != "" {
		m := MatchesPin(cert, pin)
		out.PinMatch = &m
	}
	if includeChain {
		for _, c := range chainList(info) {
			out.Chain = append(out.Chain, chainCert{
				Subject:       subjectName(c),
				Issuer:        issuerName(c),
				NotAfter:      c.NotAfter.UTC().Format(time.RFC3339),
				DaysRemaining: DaysUntilExpiry(c),
			})
		}
	}
	return out
}

// Payload returns the JSON-serializable view of a certificate, tagged with the
// given domain (omitted when empty). When includeChain is set, the full chain is
// added; when includeFingerprint is set the SHA-256 fingerprints are added. Used
// to assemble the array emitted for multi-domain runs.
func Payload(info *CertInfo, domain string, includeChain, includeFingerprint bool) any {
	return buildPayload(info, domain, includeChain, includeFingerprint, "")
}

// ErrorPayload returns a JSON-serializable entry describing a domain that could
// not be checked, for inclusion in a multi-domain result array.
func ErrorPayload(domain, errMsg string) any {
	return struct {
		Domain string `json:"domain"`
		Error  string `json:"error"`
	}{Domain: domain, Error: errMsg}
}

// IPResult is the certificate (or error) obtained from one resolved address.
// Skipped marks an address that is unreachable from this host (no route to its
// family) — a benign condition rather than a real failure.
type IPResult struct {
	IP      string
	Info    *CertInfo // nil when Err is set
	Err     error
	Skipped bool
}

// AllIPsResult summarizes an all-ips run, for the caller's exit code.
type AllIPsResult struct {
	AllMatch    bool // every reachable address served the same certificate
	HadError    bool // at least one address failed for a real reason (not just skipped)
	Reachable   int  // addresses that were actually checked
	Skipped     int  // addresses skipped as unreachable from this host
	MinDays     int  // smallest days-until-expiry across reachable addresses
	PinMismatch bool // -pin was set and at least one reachable address did not match
}

// tallyIPs aggregates per-address results. Skipped addresses count as neither
// reachable nor errors, and are excluded from the certificate comparison.
func tallyIPs(results []IPResult) (distinct, reachable, skipped int, hadError bool, minDays int, haveDays bool) {
	fps := make(map[string]bool)
	for _, r := range results {
		switch {
		case r.Skipped:
			skipped++
		case r.Err != nil:
			hadError = true
		default:
			reachable++
			fps[Fingerprint(r.Info.Cert)] = true
			if d := r.Info.MinDaysUntilExpiry(); !haveDays || d < minDays {
				minDays, haveDays = d, true
			}
		}
	}
	return len(fps), reachable, skipped, hadError, minDays, haveDays
}

// PrintAllIPs renders the per-address results for a domain (text or JSON) and
// reports whether all reachable addresses serve the same certificate.
func PrintAllIPs(domain string, results []IPResult, opts PrintOptions) AllIPsResult {
	distinct, reachable, skipped, hadError, minDays, _ := tallyIPs(results)
	if opts.JSON {
		printAllIPsJSON(domain, results, opts)
	} else {
		printAllIPsText(domain, results, opts)
	}
	return AllIPsResult{
		AllMatch:    distinct <= 1,
		HadError:    hadError,
		Reachable:   reachable,
		Skipped:     skipped,
		MinDays:     minDays,
		PinMismatch: anyPinMismatch(results, opts.Pin),
	}
}

// anyPinMismatch reports whether -pin was set and at least one reachable address
// served a certificate that does not match the pin.
func anyPinMismatch(results []IPResult, pin string) bool {
	if pin == "" {
		return false
	}
	for _, r := range results {
		if r.Skipped || r.Err != nil {
			continue
		}
		if !MatchesPin(r.Info.Cert, pin) {
			return true
		}
	}
	return false
}

// printAllIPsText renders the addresses as a compact table with a final verdict.
func printAllIPsText(domain string, results []IPResult, opts PrintOptions) {
	fmt.Printf("%s — checking %d address(es)\n", domain, len(results))
	for _, r := range results {
		switch {
		case r.Skipped:
			fmt.Printf("  %-39s  skipped (unreachable from this host)\n", r.IP)
		case r.Err != nil:
			fmt.Printf("  %-39s  error: %v\n", r.IP, r.Err)
		default:
			c := r.Info.Cert
			chain := ""
			if r.Info.Verified {
				if r.Info.ChainErr == nil {
					chain = maybeColor("VALID", colorGreen, opts.Color)
				} else {
					chain = maybeColor("INVALID", colorRed, opts.Color)
				}
			}
			pin := ""
			if opts.Pin != "" {
				if MatchesPin(c, opts.Pin) {
					pin = "  " + maybeColor("PIN-OK", colorGreen, opts.Color)
				} else {
					pin = "  " + maybeColor("PIN-MISMATCH", colorRed, opts.Color)
				}
			}
			fmt.Printf("  %-39s  %s  %s days  expires %s  %s%s\n",
				r.IP, Fingerprint(c)[:16], colorizeDays(DaysUntilExpiry(c), opts.Threshold, opts.Color),
				c.NotAfter.Format("2006-01-02"), chain, pin)
		}
	}

	distinct, reachable, skipped, _, _, _ := tallyIPs(results)
	switch {
	case distinct >= 2:
		fmt.Println(maybeColor("WARNING: certificates differ across addresses", colorYellow, opts.Color))
	case reachable >= 2:
		fmt.Println(maybeColor("All reachable addresses serve the same certificate.", colorGreen, opts.Color))
	}
	if skipped > 0 {
		fmt.Printf("(%d address(es) skipped — unreachable from this host)\n", skipped)
	}
}

// printAllIPsJSON renders the addresses as a JSON object with a match verdict.
func printAllIPsJSON(domain string, results []IPResult, opts PrintOptions) {
	distinct, _, _, _, _, _ := tallyIPs(results)
	addresses := make([]any, 0, len(results))
	for _, r := range results {
		switch {
		case r.Skipped:
			addresses = append(addresses, struct {
				IP      string `json:"ip"`
				Skipped bool   `json:"skipped"`
				Error   string `json:"error"`
			}{IP: r.IP, Skipped: true, Error: r.Err.Error()})
		case r.Err != nil:
			addresses = append(addresses, struct {
				IP    string `json:"ip"`
				Error string `json:"error"`
			}{IP: r.IP, Error: r.Err.Error()})
		default:
			p := buildPayload(r.Info, "", opts.Chain, opts.Fingerprint, opts.Pin)
			p.IP = r.IP
			p.UsedIP = "" // redundant in -all-ips: identical to ip
			p.Fingerprint = Fingerprint(r.Info.Cert)
			addresses = append(addresses, p)
		}
	}

	out := struct {
		Domain            string `json:"domain"`
		CertificatesMatch bool   `json:"certificates_match"`
		Addresses         []any  `json:"addresses"`
	}{Domain: domain, CertificatesMatch: distinct <= 1, Addresses: addresses}

	b, err := json.MarshalIndent(out, "", "  ")
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: failed to encode JSON: %v\n", err)
		return
	}
	fmt.Println(string(b))
}

// printJSON renders a single certificate as indented JSON.
func (p *CertificatePrinterImpl) printJSON(info *CertInfo, opts PrintOptions) {
	b, err := json.MarshalIndent(buildPayload(info, "", opts.Chain, opts.Fingerprint, opts.Pin), "", "  ")
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: failed to encode JSON: %v\n", err)
		return
	}
	fmt.Println(string(b))
}

// ANSI color codes used for the human-readable output.
const (
	colorReset  = "\033[0m"
	colorRed    = "\033[31m"
	colorYellow = "\033[33m"
	colorGreen  = "\033[32m"
)

// colorize wraps s in the given ANSI color and a reset.
func colorize(s, color string) string { return color + s + colorReset }

// colorizeDays renders a days-remaining value, colorized (when on) red if expired,
// yellow if below the threshold, green otherwise.
func colorizeDays(days, threshold int, on bool) string {
	s := fmt.Sprintf("%d", days)
	if !on {
		return s
	}
	switch {
	case days < 0:
		return colorize(s, colorRed)
	case threshold > 0 && days < threshold:
		return colorize(s, colorYellow)
	default:
		return colorize(s, colorGreen)
	}
}

// maybeColor colorizes s only when on is true.
func maybeColor(s, color string, on bool) string {
	if on {
		return colorize(s, color)
	}
	return s
}

// formatSerial renders a certificate serial number as upper-case, colon-separated
// hex bytes (e.g. "0F:A3:..."), matching the common openssl-style representation.
func formatSerial(serial *big.Int) string {
	b := serial.Bytes()
	if len(b) == 0 {
		return "0"
	}
	parts := make([]string, len(b))
	for i, v := range b {
		parts[i] = fmt.Sprintf("%02X", v)
	}
	return strings.Join(parts, ":")
}
