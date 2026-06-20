package cert

import (
	"encoding/json"
	"fmt"
	"math/big"
	"os"
	"strings"
	"time"
)

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
	if opts.ExpectIssuer != "" && !IssuerMatches(cert, opts.ExpectIssuer) {
		msg := fmt.Sprintf("WARNING: issuer %q does not contain %q", cert.Issuer.String(), opts.ExpectIssuer)
		fmt.Println(maybeColor(msg, colorRed, opts.Color))
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

// payloadOptions selects the optional fields included when building the JSON view.
type payloadOptions struct {
	IncludeChain       bool   // add the full "chain" array
	IncludeFingerprint bool   // add the cert and public-key SHA-256 fingerprints
	Pin                string // when non-empty, add the "pin_match" verdict
}

// buildPayload assembles the JSON view of a certificate, tagged with domain
// (empty domain is omitted from the output); opts selects the optional fields.
func buildPayload(info *CertInfo, domain string, opts payloadOptions) certPayload {
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
	if opts.IncludeFingerprint {
		out.Fingerprint = Fingerprint(cert)
		out.SPKIFinger = SPKIFingerprint(cert)
	}
	if opts.Pin != "" {
		m := MatchesPin(cert, opts.Pin)
		out.PinMatch = &m
	}
	if opts.IncludeChain {
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
	return buildPayload(info, domain, payloadOptions{IncludeChain: includeChain, IncludeFingerprint: includeFingerprint})
}

// ErrorPayload returns a JSON-serializable entry describing a domain that could
// not be checked, for inclusion in a multi-domain result array.
func ErrorPayload(domain, errMsg string) any {
	return struct {
		Domain string `json:"domain"`
		Error  string `json:"error"`
	}{Domain: domain, Error: errMsg}
}

// printJSON renders a single certificate as indented JSON.
func (p *CertificatePrinterImpl) printJSON(info *CertInfo, opts PrintOptions) {
	b, err := json.MarshalIndent(buildPayload(info, "", payloadOptions{IncludeChain: opts.Chain, IncludeFingerprint: opts.Fingerprint, Pin: opts.Pin}), "", "  ")
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
