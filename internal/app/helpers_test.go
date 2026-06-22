package app

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"io"
	"math/big"
	"os"
	"testing"
	"time"

	"github.com/idesyatov/ssl-watch/internal/cert"
	"github.com/idesyatov/ssl-watch/internal/flags"
)

// captureStdout runs fn while capturing everything written to os.Stdout.
func captureStdout(t *testing.T, fn func()) string {
	t.Helper()
	orig := os.Stdout
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("failed to create pipe: %v", err)
	}
	os.Stdout = w
	defer func() { os.Stdout = orig }()

	fn()
	w.Close()
	out, err := io.ReadAll(r)
	if err != nil {
		t.Fatalf("failed to read captured output: %v", err)
	}
	return string(out)
}

// fakeFetcher returns canned certificate info or errors per domain.
type fakeFetcher struct {
	infos map[string]*cert.CertInfo
	errs  map[string]error
}

func (f *fakeFetcher) Fetch(domain, port, ipaddr string, opts cert.FetchOptions) (*cert.CertInfo, error) {
	if err, ok := f.errs[domain]; ok {
		return nil, err
	}
	return f.infos[domain], nil
}

// fakeLoader returns a canned CertInfo or error for the -certfile path.
type fakeLoader struct {
	info *cert.CertInfo
	err  error
}

func (f *fakeLoader) Load(string) (*cert.CertInfo, error) { return f.info, f.err }

// leafInfo builds a CertInfo whose leaf expires in the given number of days.
func leafInfo(cn string, days int) *cert.CertInfo {
	return &cert.CertInfo{
		Cert: &x509.Certificate{
			Subject:      pkix.Name{CommonName: cn},
			SerialNumber: big.NewInt(1),
			NotAfter:     time.Now().Add(time.Duration(days)*24*time.Hour + time.Hour),
		},
		UsedIP: "192.0.2.1",
	}
}

// realCertInfo builds a CertInfo backed by a real self-signed certificate (with
// DER bytes), so fingerprints and PEM export work. The leaf expires in `days`.
func realCertInfo(t *testing.T, cn string, days int) *cert.CertInfo {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}
	tmpl := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: cn},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Duration(days)*24*time.Hour + time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("failed to create certificate: %v", err)
	}
	c, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("failed to parse certificate: %v", err)
	}
	return &cert.CertInfo{Cert: c, Chain: []*x509.Certificate{c}}
}

// futureCertInfo builds a CertInfo whose certificate is not valid yet (NotBefore
// in the future), which trips a warning — useful for exercising -strict.
func futureCertInfo(t *testing.T, cn string) *cert.CertInfo {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}
	tmpl := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: cn},
		NotBefore:    time.Now().Add(24 * time.Hour),
		NotAfter:     time.Now().Add(72 * time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("failed to create certificate: %v", err)
	}
	c, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("failed to parse certificate: %v", err)
	}
	return &cert.CertInfo{Cert: c, Chain: []*x509.Certificate{c}}
}

// hostTargets builds default-port targets from bare hostnames, for batch tests.
func hostTargets(hosts ...string) []target {
	ts := make([]target, len(hosts))
	for i, h := range hosts {
		ts[i] = target{host: h, port: "443"}
	}
	return ts
}

// runArgs invokes run() with a stubbed os.Args and the given dependencies,
// capturing stdout. It restores os.Args afterwards.
func runArgs(t *testing.T, args []string, fetcher cert.CertificateFetcher, loader cert.CertificateLoader) (int, string) {
	t.Helper()
	orig := os.Args
	defer func() { os.Args = orig }()
	os.Args = append([]string{"ssl-watch"}, args...)
	var code int
	out := captureStdout(t, func() {
		code = run(flags.NewDefaultFlagParser(), fetcher, loader, &cert.CertificatePrinterImpl{})
	})
	return code, out
}
