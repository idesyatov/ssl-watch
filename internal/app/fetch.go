package app

import (
	"net"
	"strings"
	"sync"

	"github.com/idesyatov/ssl-watch/internal/cert"
	"github.com/idesyatov/ssl-watch/internal/flags"
)

// fetchResult is one target's outcome from fetchAll: either Info or Err is set.
type fetchResult struct {
	target target
	info   *cert.CertInfo
	err    error
}

// fetchAll fetches every target's certificate, running up to concurrency fetches
// at once, and returns the results in the same order as targets (so the rendered
// output is deterministic regardless of completion order). A concurrency of 1 is
// effectively sequential. The fetcher must be safe for concurrent use.
func fetchAll(fetcher cert.CertificateFetcher, targets []target, ipaddr string, fetchOpts cert.FetchOptions, concurrency int) []fetchResult {
	if concurrency < 1 {
		concurrency = 1
	}
	results := make([]fetchResult, len(targets))
	sem := make(chan struct{}, concurrency)
	var wg sync.WaitGroup
	for i, t := range targets {
		wg.Add(1)
		sem <- struct{}{}
		go func(i int, t target) {
			defer wg.Done()
			defer func() { <-sem }()
			info, err := fetcher.Fetch(t.host, t.port, ipaddr, fetchOpts)
			results[i] = fetchResult{target: t, info: info, err: err}
		}(i, t)
	}
	wg.Wait()
	return results
}

// collectSamples fetches every target (respecting -concurrency, order preserved)
// and returns the per-target samples plus whether any failed to be retrieved or
// expires within -threshold. Shared by the prometheus and csv report formats.
func collectSamples(fetcher cert.CertificateFetcher, targets []target, cfg flags.Config, fetchOpts cert.FetchOptions) (samples []cert.PromSample, hadError, expiring bool) {
	samples = make([]cert.PromSample, 0, len(targets))
	for _, r := range fetchAll(fetcher, targets, cfg.IPAddr, fetchOpts, cfg.Concurrency) {
		label := r.target.label()
		if r.err != nil {
			hadError = true
			samples = append(samples, cert.PromSample{Domain: label, Err: r.err})
			continue
		}
		samples = append(samples, cert.PromSample{Domain: label, Info: r.info})
		if cfg.Threshold > 0 && r.info.MinDaysUntilExpiry() < cfg.Threshold {
			expiring = true
		}
	}
	return samples, hadError, expiring
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
