package app

import (
	"fmt"
	"net"
	"os"
	"sort"
	"strings"

	"github.com/idesyatov/ssl-watch/internal/cert"
	"github.com/idesyatov/ssl-watch/internal/flags"
)

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

// lookupIP resolves a host to its IP addresses. It is a package variable so tests
// can substitute a deterministic resolver in place of real DNS.
var lookupIP = net.LookupIP

// isUnreachable reports whether a connection error means the address family is
// not routable from this host (e.g. no IPv6 route) — a benign skip rather than a
// real failure. Matched by message text to stay portable (the syscall error
// constants differ on Windows).
func isUnreachable(err error) bool {
	if err == nil {
		return false
	}
	s := err.Error()
	return strings.Contains(s, "network is unreachable") ||
		strings.Contains(s, "no route to host")
}
