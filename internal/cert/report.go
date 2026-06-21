package cert

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
	"time"
)

// PromSample is the result for one domain in a Prometheus run: Info is nil when
// the certificate could not be retrieved (Err is set).
type PromSample struct {
	Domain string
	Info   *CertInfo
	Err    error
}

// promEscape escapes a Prometheus label value (backslash, quote, newline).
func promEscape(s string) string {
	s = strings.ReplaceAll(s, `\`, `\\`)
	s = strings.ReplaceAll(s, `"`, `\"`)
	s = strings.ReplaceAll(s, "\n", `\n`)
	return s
}

// WritePrometheus renders the samples in Prometheus text exposition format,
// grouped by metric family. The pin_match family is emitted only when a pin is
// configured. A domain that failed to be retrieved gets ssl_cert_up 0 and no
// other samples.
func WritePrometheus(w io.Writer, samples []PromSample, pin string) {
	label := func(d string) string { return fmt.Sprintf(`{domain="%s"}`, promEscape(d)) }

	fmt.Fprintln(w, "# HELP ssl_cert_up Whether the certificate was retrieved (1) or not (0).")
	fmt.Fprintln(w, "# TYPE ssl_cert_up gauge")
	for _, s := range samples {
		up := 0
		if s.Info != nil {
			up = 1
		}
		fmt.Fprintf(w, "ssl_cert_up%s %d\n", label(s.Domain), up)
	}

	fmt.Fprintln(w, "# HELP ssl_cert_expiry_days Days until the leaf certificate expires.")
	fmt.Fprintln(w, "# TYPE ssl_cert_expiry_days gauge")
	for _, s := range samples {
		if s.Info != nil {
			fmt.Fprintf(w, "ssl_cert_expiry_days%s %d\n", label(s.Domain), DaysUntilExpiry(s.Info.Cert))
		}
	}

	fmt.Fprintln(w, "# HELP ssl_cert_min_expiry_days Days until the soonest-expiring certificate in the chain.")
	fmt.Fprintln(w, "# TYPE ssl_cert_min_expiry_days gauge")
	for _, s := range samples {
		if s.Info != nil {
			fmt.Fprintf(w, "ssl_cert_min_expiry_days%s %d\n", label(s.Domain), s.Info.MinDaysUntilExpiry())
		}
	}

	fmt.Fprintln(w, "# HELP ssl_cert_not_after_timestamp Leaf certificate expiry as a Unix timestamp.")
	fmt.Fprintln(w, "# TYPE ssl_cert_not_after_timestamp gauge")
	for _, s := range samples {
		if s.Info != nil {
			fmt.Fprintf(w, "ssl_cert_not_after_timestamp%s %d\n", label(s.Domain), s.Info.Cert.NotAfter.Unix())
		}
	}

	fmt.Fprintln(w, "# HELP ssl_cert_chain_valid Whether the certificate chain verified (1) or not (0).")
	fmt.Fprintln(w, "# TYPE ssl_cert_chain_valid gauge")
	for _, s := range samples {
		if s.Info != nil && s.Info.Verified {
			v := 0
			if s.Info.ChainErr == nil {
				v = 1
			}
			fmt.Fprintf(w, "ssl_cert_chain_valid%s %d\n", label(s.Domain), v)
		}
	}

	if pin != "" {
		fmt.Fprintln(w, "# HELP ssl_cert_pin_match Whether the served certificate matches the pinned fingerprint.")
		fmt.Fprintln(w, "# TYPE ssl_cert_pin_match gauge")
		for _, s := range samples {
			if s.Info != nil {
				v := 0
				if MatchesPin(s.Info.Cert, pin) {
					v = 1
				}
				fmt.Fprintf(w, "ssl_cert_pin_match%s %d\n", label(s.Domain), v)
			}
		}
	}
}

// csvHeader is the column order for CSV output. "domain" and "error" are always
// present; for a domain that failed to be retrieved the certificate columns are
// empty and "error" carries the reason.
var csvHeader = []string{
	"domain", "common_name", "issuer",
	"not_before", "not_after", "days_remaining", "min_days_remaining",
	"chain_valid", "error",
}

// WriteCSV renders the samples as RFC 4180 CSV with a header row, one row per
// domain (machine-readable timestamps in RFC 3339, UTC). Quoting is handled by
// encoding/csv, so issuer DNs and other fields containing commas are safe. It
// shares the per-domain PromSample type with the prometheus output.
func WriteCSV(w io.Writer, samples []PromSample) error {
	cw := csv.NewWriter(w)
	if err := cw.Write(csvHeader); err != nil {
		return err
	}
	for _, s := range samples {
		var row []string
		if s.Info == nil {
			errMsg := ""
			if s.Err != nil {
				errMsg = s.Err.Error()
			}
			row = []string{s.Domain, "", "", "", "", "", "", "", errMsg}
		} else {
			c := s.Info.Cert
			chainValid := ""
			if s.Info.Verified {
				chainValid = strconv.FormatBool(s.Info.ChainErr == nil)
			}
			row = []string{
				s.Domain,
				c.Subject.CommonName,
				c.Issuer.String(),
				c.NotBefore.UTC().Format(time.RFC3339),
				c.NotAfter.UTC().Format(time.RFC3339),
				strconv.Itoa(DaysUntilExpiry(c)),
				strconv.Itoa(s.Info.MinDaysUntilExpiry()),
				chainValid,
				"",
			}
		}
		if err := cw.Write(row); err != nil {
			return err
		}
	}
	cw.Flush()
	return cw.Error()
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
				c.NotAfter.Format(dateFormat), chain, pin)
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
			p := buildPayload(r.Info, "", payloadOptions{IncludeChain: opts.Chain, IncludeFingerprint: opts.Fingerprint, Pin: opts.Pin})
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
