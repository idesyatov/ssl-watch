package cert

import (
	"encoding/csv"
	"fmt"
	"io"
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

// Nagios/Icinga plugin exit codes (nagios-plugins.org/doc/guidelines.html).
const (
	nagiosOK       = 0
	nagiosWarning  = 1
	nagiosCritical = 2
)

// nagiosStatusText maps a Nagios exit code to its label.
var nagiosStatusText = []string{"OK", "WARNING", "CRITICAL", "UNKNOWN"}

// nagiosEval determines the Nagios status and a human detail line for one sample,
// applying Nagios severity: an unreachable/invalid/expired/mismatched certificate
// is CRITICAL, an upcoming expiry within -threshold (or any warning under -strict)
// is WARNING, otherwise OK.
func nagiosEval(s PromSample, opts PrintOptions, strict bool) (code int, detail string) {
	if s.Info == nil {
		return nagiosCritical, fmt.Sprintf("%s: %v", s.Domain, s.Err)
	}
	info := s.Info
	c := info.Cert
	expiry := c.NotAfter.Format(dateFormat)
	switch {
	case opts.Pin != "" && !MatchesPin(c, opts.Pin):
		return nagiosCritical, fmt.Sprintf("%s: certificate does not match the pin", s.Domain)
	case opts.ExpectIssuer != "" && !IssuerMatches(c, opts.ExpectIssuer):
		return nagiosCritical, fmt.Sprintf("%s: unexpected issuer %s", s.Domain, c.Issuer.String())
	case info.Verified && info.ChainErr != nil:
		kind, _ := classifyChainErr(info)
		return nagiosCritical, fmt.Sprintf("%s: chain INVALID (%s)", s.Domain, kind)
	}
	days := info.MinDaysUntilExpiry()
	switch {
	case days < 0:
		return nagiosCritical, fmt.Sprintf("%s: certificate expired on %s", s.Domain, expiry)
	case opts.Threshold > 0 && days < opts.Threshold:
		return nagiosWarning, fmt.Sprintf("%s: expires in %d days (%s)", s.Domain, days, expiry)
	case strict && HasWarnings(info):
		return nagiosWarning, fmt.Sprintf("%s: warnings present, expires in %d days (%s)", s.Domain, days, expiry)
	}
	return nagiosOK, fmt.Sprintf("%s: valid, expires in %d days (%s)", s.Domain, days, expiry)
}

// nagiosPerf renders the performance data token for one sample (empty when the
// certificate could not be retrieved): days remaining with -threshold in the
// warning slot.
func nagiosPerf(s PromSample, opts PrintOptions) string {
	if s.Info == nil {
		return ""
	}
	warn := ""
	if opts.Threshold > 0 {
		warn = strconv.Itoa(opts.Threshold)
	}
	return fmt.Sprintf("'%s'=%d;%s;;", s.Domain, s.Info.MinDaysUntilExpiry(), warn)
}

// WriteNagios renders the samples as a Nagios/Icinga plugin result and returns the
// Nagios exit code (0 OK / 1 WARNING / 2 CRITICAL). For a single target it prints
// one "SSL <STATUS> - <detail> | <perfdata>" line; for several it prints a summary
// line (worst status + counts + perfdata) followed by one detail line per target.
// The returned code follows the Nagios convention, overriding the tool's normal
// exit codes.
func WriteNagios(w io.Writer, samples []PromSample, opts PrintOptions, strict bool) int {
	codes := make([]int, len(samples))
	details := make([]string, len(samples))
	perfs := make([]string, 0, len(samples))
	worst := nagiosOK
	for i, s := range samples {
		codes[i], details[i] = nagiosEval(s, opts, strict)
		if codes[i] > worst {
			worst = codes[i]
		}
		if p := nagiosPerf(s, opts); p != "" {
			perfs = append(perfs, p)
		}
	}

	perf := ""
	if len(perfs) > 0 {
		perf = " | " + strings.Join(perfs, " ")
	}

	if len(samples) == 1 {
		fmt.Fprintf(w, "SSL %s - %s%s\n", nagiosStatusText[worst], details[0], perf)
		return worst
	}

	var ok, warn, crit int
	for _, code := range codes {
		switch code {
		case nagiosOK:
			ok++
		case nagiosWarning:
			warn++
		case nagiosCritical:
			crit++
		}
	}
	fmt.Fprintf(w, "SSL %s - %d OK, %d WARNING, %d CRITICAL%s\n", nagiosStatusText[worst], ok, warn, crit, perf)
	for i := range samples {
		fmt.Fprintf(w, "%s %s\n", nagiosStatusText[codes[i]], details[i])
	}
	return worst
}
