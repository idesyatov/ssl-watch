package cert

import (
	"encoding/json"
	"fmt"
	"os"
)

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
		printAllIPsJSON(domain, results, distinct, opts)
	} else {
		printAllIPsText(domain, results, distinct, reachable, skipped, opts)
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
// The distinct/reachable/skipped tallies are computed once by the caller.
func printAllIPsText(domain string, results []IPResult, distinct, reachable, skipped int, opts PrintOptions) {
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
// distinct is computed once by the caller.
func printAllIPsJSON(domain string, results []IPResult, distinct int, opts PrintOptions) {
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
