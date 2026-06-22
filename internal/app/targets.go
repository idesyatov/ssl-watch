package app

import (
	"bufio"
	"fmt"
	"io"
	"net"
	"net/url"
	"os"
	"strconv"
	"strings"

	"github.com/idesyatov/ssl-watch/internal/flags"
)

// defaultPort mirrors the -port flag default; when -starttls is used and the
// port was left at this value, the protocol's standard port is substituted.
const defaultPort = "443"

// starttlsPorts maps each supported STARTTLS protocol to its standard port.
var starttlsPorts = map[string]string{
	"smtp": "587",
	"imap": "143",
	"pop3": "110",
	"ftp":  "21",
}

// effectiveDefaultPort is the port used for targets that do not carry their own:
// the -port value, or the STARTTLS protocol's standard port when -starttls is set
// and -port was left at its default. An unknown protocol is left for validate to
// reject, so it does not substitute here.
func effectiveDefaultPort(cfg flags.Config) string {
	if cfg.Port == defaultPort && cfg.StartTLS != "" {
		if p, ok := starttlsPorts[cfg.StartTLS]; ok {
			return p
		}
	}
	return cfg.Port
}

// target is a single check target: the hostname to connect to and verify against
// (used for SNI) plus the port. The port comes from the target token itself
// (host:port or a URL) or, for a bare host, from the default port.
type target struct {
	host string
	port string
}

// label renders the target for output: the bare host on the standard HTTPS port,
// otherwise host:port (IPv6 bracketed).
func (t target) label() string {
	if t.port == defaultPort {
		return t.host
	}
	return net.JoinHostPort(t.host, t.port)
}

// parseTarget turns one -domain/-domain-file token into a target. It accepts a
// bare host (uses defaultPort), a host:port pair, or a URL (https://host:port/…,
// scheme and path discarded). An unbracketed IPv6 literal has too many colons for
// host:port and is treated as a bare host.
func parseTarget(tok, defaultPort string) (target, error) {
	if strings.Contains(tok, "://") {
		u, err := url.Parse(tok)
		if err != nil {
			return target{}, fmt.Errorf("invalid target URL %q: %v", tok, err)
		}
		host := u.Hostname()
		if host == "" {
			return target{}, fmt.Errorf("invalid target %q: missing host", tok)
		}
		port := u.Port()
		if port == "" {
			return target{host: host, port: defaultPort}, nil
		}
		if err := validatePort(port); err != nil {
			return target{}, fmt.Errorf("invalid target %q: %v", tok, err)
		}
		return target{host: host, port: port}, nil
	}
	if host, port, err := net.SplitHostPort(tok); err == nil {
		if port == "" {
			port = defaultPort
		}
		if err := validatePort(port); err != nil {
			return target{}, fmt.Errorf("invalid target %q: %v", tok, err)
		}
		return target{host: host, port: port}, nil
	}
	return target{host: tok, port: defaultPort}, nil
}

// validatePort checks that p is a decimal port in the 1–65535 range.
func validatePort(p string) error {
	n, err := strconv.Atoi(p)
	if err != nil || n < 1 || n > 65535 {
		return fmt.Errorf("port %q is not a number in 1-65535", p)
	}
	return nil
}

// resolveTargets builds the ordered, de-duplicated list of targets from the
// comma-separated -domain flag and the -domain-file flag (one per line, "-"
// reads stdin; blank lines and lines starting with "#" are ignored). defaultPort
// is used for tokens that do not carry their own port. De-duplication is by the
// resolved host:port pair, so "a.com" and "a.com:443" collapse to one.
func resolveTargets(cfg flags.Config, defaultPort string) ([]target, error) {
	var out []target
	seen := make(map[string]bool)
	var firstErr error
	add := func(tok string) {
		tok = strings.TrimSpace(tok)
		if tok == "" {
			return
		}
		t, err := parseTarget(tok, defaultPort)
		if err != nil {
			if firstErr == nil {
				firstErr = err
			}
			return
		}
		key := t.host + "\x00" + t.port
		if seen[key] {
			return
		}
		seen[key] = true
		out = append(out, t)
	}

	for _, tok := range strings.Split(cfg.Domain, ",") {
		add(tok)
	}
	if cfg.DomainFile != "" {
		lines, err := readDomainFile(cfg.DomainFile)
		if err != nil {
			return nil, err
		}
		for _, l := range lines {
			add(l)
		}
	}
	if firstErr != nil {
		return nil, firstErr
	}
	return out, nil
}

// readDomainFile reads domains from the given path, one per line, skipping blank
// lines and lines starting with "#". A path of "-" reads from stdin.
func readDomainFile(path string) ([]string, error) {
	var r io.Reader = os.Stdin
	if path != "-" {
		f, err := os.Open(path)
		if err != nil {
			return nil, fmt.Errorf("failed to read domain file %s: %v", path, err)
		}
		defer f.Close()
		r = f
	}

	var lines []string
	sc := bufio.NewScanner(r)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		lines = append(lines, line)
	}
	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("failed to read domain file %s: %v", path, err)
	}
	return lines, nil
}
