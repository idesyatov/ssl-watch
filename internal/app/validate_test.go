package app

import (
	"testing"

	"github.com/idesyatov/ssl-watch/internal/flags"
)

// TestValidate covers the flag-combination guards extracted from main().
func TestValidate(t *testing.T) {
	ok := flags.Config{Output: "text", Timeout: 10, Concurrency: 1}
	one := hostTargets("a.com")
	two := hostTargets("a.com", "b.com")

	cases := []struct {
		name    string
		cfg     flags.Config
		targets []target
		wantErr bool
	}{
		{"single domain", ok, one, false},
		{"certfile only", flags.Config{Output: "text", Timeout: 10, Concurrency: 1, CertFile: "c.pem"}, nil, false},
		{"no target", ok, nil, true},
		{"bad output", flags.Config{Output: "yaml", Timeout: 10, Concurrency: 1}, one, true},
		{"bad timeout", flags.Config{Output: "text", Timeout: 0, Concurrency: 1}, one, true},
		{"bad concurrency", flags.Config{Output: "text", Timeout: 10, Concurrency: 0}, one, true},
		{"ipaddr multi", flags.Config{Output: "text", Timeout: 10, Concurrency: 1, IPAddr: "1.2.3.4"}, two, true},
		{"all-ips + certfile", flags.Config{Output: "text", Timeout: 10, Concurrency: 1, AllIPs: true, CertFile: "c.pem"}, one, true},
		{"all-ips + strict", flags.Config{Output: "text", Timeout: 10, Concurrency: 1, AllIPs: true, Strict: true}, one, true},
		{"all-ips multi", flags.Config{Output: "text", Timeout: 10, Concurrency: 1, AllIPs: true}, two, true},
		{"-4 without all-ips", flags.Config{Output: "text", Timeout: 10, Concurrency: 1, IPv4Only: true}, one, true},
		{"cafile + insecure", flags.Config{Output: "text", Timeout: 10, Concurrency: 1, CAFile: "r.pem", Insecure: true}, one, true},
		{"client-cert without key", flags.Config{Output: "text", Timeout: 10, Concurrency: 1, ClientCert: "c.crt"}, one, true},
		{"client-cert + certfile", flags.Config{Output: "text", Timeout: 10, Concurrency: 1, ClientCert: "c.crt", ClientKey: "c.key", CertFile: "f.pem"}, nil, true},
		{"client-cert + key ok", flags.Config{Output: "text", Timeout: 10, Concurrency: 1, ClientCert: "c.crt", ClientKey: "c.key"}, one, false},
		{"proxy + certfile", flags.Config{Output: "text", Timeout: 10, Concurrency: 1, Proxy: "http://127.0.0.1:3128", CertFile: "f.pem"}, nil, true},
		{"proxy ok", flags.Config{Output: "text", Timeout: 10, Concurrency: 1, Proxy: "http://127.0.0.1:3128"}, one, false},
		{"servername multi", flags.Config{Output: "text", Timeout: 10, Concurrency: 1, ServerName: "x"}, two, true},
		{"pin multi", flags.Config{Output: "text", Timeout: 10, Concurrency: 1, Pin: "sha256:ab"}, two, true},
		{"pem + json", flags.Config{Output: "json", Timeout: 10, Concurrency: 1, Pem: true}, one, true},
		{"pem + export", flags.Config{Output: "text", Timeout: 10, Concurrency: 1, Pem: true, Export: "f"}, one, true},
		{"prometheus + all-ips", flags.Config{Output: "prometheus", Timeout: 10, Concurrency: 1, AllIPs: true}, one, true},
		{"csv ok", flags.Config{Output: "csv", Timeout: 10, Concurrency: 1}, two, false},
		{"csv + all-ips", flags.Config{Output: "csv", Timeout: 10, Concurrency: 1, AllIPs: true}, one, true},
		{"csv + certfile", flags.Config{Output: "csv", Timeout: 10, Concurrency: 1, CertFile: "c.pem"}, nil, true},
		{"nagios ok", flags.Config{Output: "nagios", Timeout: 10, Concurrency: 1}, one, false},
		{"nagios + all-ips", flags.Config{Output: "nagios", Timeout: 10, Concurrency: 1, AllIPs: true}, one, true},
		{"nagios + certfile", flags.Config{Output: "nagios", Timeout: 10, Concurrency: 1, CertFile: "c.pem"}, nil, true},
		{"bad starttls", flags.Config{Output: "text", Timeout: 10, Concurrency: 1, StartTLS: "gopher"}, one, true},
		{"good starttls", flags.Config{Output: "text", Timeout: 10, Concurrency: 1, StartTLS: "smtp"}, one, false},
	}
	for _, tc := range cases {
		if err := validate(tc.cfg, tc.targets); (err != nil) != tc.wantErr {
			t.Errorf("%s: validate err=%v, wantErr=%v", tc.name, err, tc.wantErr)
		}
	}
}
