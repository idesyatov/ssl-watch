package app

import (
	"errors"
	"fmt"

	"github.com/idesyatov/ssl-watch/internal/flags"
	"github.com/idesyatov/ssl-watch/internal/validation"
)

// validate reports the first unsupported flag combination in cfg, or nil. It is
// pure — no I/O and no process exit — so every guard is unit-testable.
func validate(cfg flags.Config, targets []target) error {
	// At least one target (a domain or a certificate file) must be specified.
	domainArg := ""
	if len(targets) > 0 {
		domainArg = targets[0].host
	}
	if err := validation.NewDefaultInputValidator().Validate(domainArg, cfg.CertFile); err != nil {
		return err
	}
	if cfg.Output != "text" && cfg.Output != "json" && cfg.Output != "prometheus" && cfg.Output != "csv" && cfg.Output != "nagios" {
		return fmt.Errorf("invalid -output %q (expected \"text\", \"json\", \"prometheus\", \"csv\" or \"nagios\")", cfg.Output)
	}
	if cfg.Timeout <= 0 {
		return fmt.Errorf("invalid -timeout %d (expected a positive number of seconds)", cfg.Timeout)
	}
	if cfg.Concurrency < 1 {
		return fmt.Errorf("invalid -concurrency %d (expected a positive number)", cfg.Concurrency)
	}
	if cfg.IPAddr != "" && len(targets) > 1 {
		return errors.New("-ipaddr cannot be combined with multiple domains")
	}
	if cfg.AllIPs {
		switch {
		case cfg.CertFile != "":
			return errors.New("-all-ips cannot be combined with -certfile")
		case cfg.IPAddr != "":
			return errors.New("-all-ips cannot be combined with -ipaddr")
		case cfg.Short:
			return errors.New("-all-ips cannot be combined with -short")
		case cfg.ExpectIssuer != "" || cfg.Strict:
			return errors.New("-all-ips cannot be combined with -expect-issuer/-strict")
		case len(targets) != 1:
			return errors.New("-all-ips requires exactly one domain")
		}
	}
	if cfg.IPv4Only && cfg.IPv6Only {
		return errors.New("-4 and -6 cannot be combined")
	}
	if (cfg.IPv4Only || cfg.IPv6Only) && !cfg.AllIPs {
		return errors.New("-4/-6 can only be used with -all-ips")
	}
	if cfg.CAFile != "" && cfg.Insecure {
		return errors.New("-cafile cannot be combined with -insecure")
	}
	if (cfg.CAFile != "" || cfg.ServerName != "") && cfg.CertFile != "" {
		return errors.New("-cafile/-servername cannot be combined with -certfile")
	}
	if (cfg.ClientCert != "") != (cfg.ClientKey != "") {
		return errors.New("-client-cert and -client-key must be used together")
	}
	if (cfg.ClientCert != "" || cfg.ClientKey != "") && cfg.CertFile != "" {
		return errors.New("-client-cert/-client-key cannot be combined with -certfile")
	}
	if cfg.Proxy != "" && cfg.CertFile != "" {
		return errors.New("-proxy cannot be combined with -certfile")
	}
	if cfg.ServerName != "" && len(targets) > 1 {
		return errors.New("-servername cannot be combined with multiple domains")
	}
	if cfg.Pin != "" && len(targets) > 1 {
		return errors.New("-pin cannot be combined with multiple domains")
	}
	if cfg.Pem || cfg.Export != "" {
		switch {
		case cfg.Pem && cfg.Export != "":
			return errors.New("-pem and -export cannot be combined")
		case cfg.Output != "text":
			return fmt.Errorf("-pem/-export cannot be combined with -output %s", cfg.Output)
		case cfg.AllIPs:
			return errors.New("-pem/-export cannot be combined with -all-ips")
		case len(targets) > 1:
			return errors.New("-pem/-export require a single target")
		case cfg.Pin != "":
			return errors.New("-pem/-export cannot be combined with -pin")
		case cfg.Threshold > 0:
			return errors.New("-pem/-export cannot be combined with -threshold")
		case cfg.ExpectIssuer != "" || cfg.Strict:
			return errors.New("-pem/-export cannot be combined with -expect-issuer/-strict")
		}
	}
	if cfg.Output == "prometheus" || cfg.Output == "csv" || cfg.Output == "nagios" {
		switch {
		case cfg.AllIPs:
			return fmt.Errorf("-output %s cannot be combined with -all-ips", cfg.Output)
		case cfg.CertFile != "":
			return fmt.Errorf("-output %s cannot be combined with -certfile", cfg.Output)
		}
	}
	if cfg.StartTLS != "" {
		if _, ok := starttlsPorts[cfg.StartTLS]; !ok {
			return fmt.Errorf("invalid -starttls %q (expected smtp, imap, pop3 or ftp)", cfg.StartTLS)
		}
	}
	return nil
}
