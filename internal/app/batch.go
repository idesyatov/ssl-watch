package app

import (
	"encoding/json"
	"fmt"
	"os"
	"sort"

	"github.com/idesyatov/ssl-watch/internal/cert"
	"github.com/idesyatov/ssl-watch/internal/flags"
)

// runBatch checks every target and renders the aggregated result. Targets are
// fetched with up to cfg.Concurrency in flight, then rendered in input order. In
// JSON mode it emits an array (one object per target, with an "error" entry for
// failures); in text mode it prints one block per target, with failures on
// stderr. It returns the process exit code: 1 if any target failed to be
// retrieved, otherwise 2 if any certificate in a chain expires within the
// threshold, otherwise 0.
func runBatch(fetcher cert.CertificateFetcher, printer cert.CertificatePrinter, targets []target, cfg flags.Config, opts cert.PrintOptions, fetchOpts cert.FetchOptions) int {
	hadError := false
	expiring := false
	issuerFail := false
	strictFail := false
	printedText := false
	var entries []any

	for _, r := range fetchAll(fetcher, targets, cfg.IPAddr, fetchOpts, cfg.Concurrency) {
		label := r.target.label()
		if r.err != nil {
			hadError = true
			if opts.JSON {
				entries = append(entries, cert.ErrorPayload(label, r.err.Error()))
			} else {
				fmt.Fprintf(os.Stderr, "Error retrieving certificate for %s: %v\n", label, r.err)
			}
			continue
		}
		info := r.info

		if opts.JSON {
			entries = append(entries, cert.Payload(info, label, opts.Chain, opts.Fingerprint))
		} else if cfg.Short {
			// Multi-domain short mode: prefix each days count with its target so
			// the numbers stay attributable and greppable (target<TAB>days).
			fmt.Printf("%s\t", label)
			printer.Print(info, opts)
		} else {
			if printedText {
				fmt.Println()
			}
			fmt.Printf("==> %s\n", label)
			printer.Print(info, opts)
			printedText = true
		}

		if cfg.Threshold > 0 && info.MinDaysUntilExpiry() < cfg.Threshold {
			expiring = true
		}
		if cfg.ExpectIssuer != "" && !cert.IssuerMatches(info.Cert, cfg.ExpectIssuer) {
			issuerFail = true
		}
		if cfg.Strict && cert.HasWarnings(info) {
			strictFail = true
		}
	}

	if opts.JSON {
		b, err := json.MarshalIndent(entries, "", "  ")
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: failed to encode JSON: %v\n", err)
			return exitError
		}
		fmt.Println(string(b))
	}

	switch {
	case hadError:
		return exitError
	case issuerFail:
		return exitMismatch
	case expiring || strictFail:
		return exitSoft
	}
	return exitOK
}

// runAllIPs resolves every address of the domain (optionally filtered to one
// family by -4/-6), checks the certificate on each (same SNI), prints the
// per-address result and reports the exit code: 1 if nothing was reachable or an
// address failed for a real reason (addresses unreachable from this host are
// skipped, not errors), otherwise 2 if the certificates differ or any expires
// within -threshold, otherwise 0.
func runAllIPs(fetcher cert.CertificateFetcher, t target, cfg flags.Config, opts cert.PrintOptions, fetchOpts cert.FetchOptions) int {
	domain := t.host
	ips, err := lookupIP(domain)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: failed to resolve %s: %v\n", domain, err)
		return exitError
	}

	seen := make(map[string]bool)
	var addrs []string
	for _, ip := range ips {
		if cfg.IPv4Only && ip.To4() == nil {
			continue
		}
		if cfg.IPv6Only && ip.To4() != nil {
			continue
		}
		s := ip.String()
		if !seen[s] {
			seen[s] = true
			addrs = append(addrs, s)
		}
	}
	if len(addrs) == 0 {
		fmt.Fprintf(os.Stderr, "Error: no matching addresses resolved for %s\n", domain)
		return exitError
	}
	sort.Strings(addrs)

	results := make([]cert.IPResult, 0, len(addrs))
	for _, ip := range addrs {
		info, err := fetcher.Fetch(domain, t.port, ip, fetchOpts)
		results = append(results, cert.IPResult{
			IP:      ip,
			Info:    info,
			Err:     err,
			Skipped: err != nil && isUnreachable(err),
		})
	}

	res := cert.PrintAllIPs(t.label(), results, opts)
	switch {
	case res.Reachable == 0:
		return exitError
	case res.HadError:
		return exitError
	case res.PinMismatch:
		return exitMismatch
	case !res.AllMatch:
		return exitSoft
	case cfg.Threshold > 0 && res.MinDays < cfg.Threshold:
		return exitSoft
	}
	return exitOK
}
