package cert

import (
	"bufio"
	"crypto/x509"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

// TestFetch_ViaProxy runs Fetch through a minimal in-process HTTP CONNECT proxy
// that tunnels to an in-process TLS server, verifying the certificate is fetched
// and that the proxy received the expected CONNECT request.
func TestFetch_ViaProxy(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer srv.Close()

	u, err := url.Parse(srv.URL)
	if err != nil {
		t.Fatalf("failed to parse server URL: %v", err)
	}
	host, port, err := net.SplitHostPort(u.Host)
	if err != nil {
		t.Fatalf("failed to split host/port: %v", err)
	}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to start proxy listener: %v", err)
	}
	defer ln.Close()

	connectCh := make(chan string, 1)
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		br := bufio.NewReader(c)
		reqLine, err := br.ReadString('\n')
		if err != nil {
			return
		}
		for {
			h, err := br.ReadString('\n')
			if err != nil {
				return
			}
			if h == "\r\n" || h == "\n" {
				break
			}
		}
		upstream, err := net.Dial("tcp", u.Host)
		if err != nil {
			return
		}
		defer upstream.Close()
		if _, err := c.Write([]byte("HTTP/1.1 200 Connection established\r\n\r\n")); err != nil {
			return
		}
		connectCh <- strings.TrimSpace(reqLine)
		go func() { _, _ = io.Copy(upstream, br) }()
		_, _ = io.Copy(c, upstream)
	}()

	fetcher := &CertificateFetcherImpl{}
	info, err := fetcher.Fetch(host, port, "", FetchOptions{
		Insecure: true,
		Timeout:  5 * time.Second,
		Proxy:    "http://" + ln.Addr().String(),
	})
	if err != nil {
		t.Fatalf("unexpected error from Fetch via proxy: %v", err)
	}
	if info.Cert == nil {
		t.Fatal("expected a certificate via proxy, got nil")
	}

	select {
	case got := <-connectCh:
		want := "CONNECT " + u.Host + " HTTP/1.1"
		if got != want {
			t.Errorf("proxy received %q, want %q", got, want)
		}
	case <-time.After(2 * time.Second):
		t.Error("proxy did not receive a CONNECT request")
	}
}

// TestFetch_ViaProxy_Refused verifies that a non-200 CONNECT response surfaces an
// error instead of attempting a handshake.
func TestFetch_ViaProxy_Refused(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to start proxy listener: %v", err)
	}
	defer ln.Close()

	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		br := bufio.NewReader(c)
		if _, err := br.ReadString('\n'); err != nil {
			return
		}
		for {
			h, err := br.ReadString('\n')
			if err != nil {
				return
			}
			if h == "\r\n" || h == "\n" {
				break
			}
		}
		_, _ = c.Write([]byte("HTTP/1.1 403 Forbidden\r\n\r\n"))
	}()

	fetcher := &CertificateFetcherImpl{}
	_, err = fetcher.Fetch("example.com", "443", "", FetchOptions{
		Insecure: true,
		Timeout:  2 * time.Second,
		Proxy:    "http://" + ln.Addr().String(),
	})
	if err == nil {
		t.Error("expected an error when the proxy refuses CONNECT, got nil")
	}
}

// TestDialViaProxy_BadScheme verifies a non-http proxy scheme is rejected.
func TestDialViaProxy_BadScheme(t *testing.T) {
	if _, err := dialViaProxy("example.com:443", time.Second, "socks5://127.0.0.1:1080"); err == nil {
		t.Error("expected an error for an unsupported proxy scheme, got nil")
	}
}

// TestCertificateFetcherImpl_Fetch exercises the real Fetch against an in-process
// TLS server, covering both the insecure path and chain verification.
func TestCertificateFetcherImpl_Fetch(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer srv.Close()

	u, err := url.Parse(srv.URL)
	if err != nil {
		t.Fatalf("failed to parse server URL: %v", err)
	}
	host, port, err := net.SplitHostPort(u.Host)
	if err != nil {
		t.Fatalf("failed to split host/port: %v", err)
	}

	fetcher := &CertificateFetcherImpl{}

	// Insecure: the certificate is returned and the chain is not verified.
	info, err := fetcher.Fetch(host, port, "", FetchOptions{Insecure: true, Timeout: 5 * time.Second})
	if err != nil {
		t.Fatalf("unexpected error from Fetch: %v", err)
	}
	if info.Cert == nil {
		t.Fatal("expected a certificate, got nil")
	}
	if info.Cert.SerialNumber.Cmp(srv.Certificate().SerialNumber) != 0 {
		t.Errorf("fetched certificate serial does not match the server certificate")
	}
	if len(info.Chain) == 0 {
		t.Error("expected the peer chain to be recorded")
	}
	if info.UsedIP == "" {
		t.Error("expected the used IP to be recorded for a fetched certificate")
	}
	if info.Verified {
		t.Error("expected Verified to be false when insecure is true")
	}

	// Secure: the chain is verified and, for this self-signed test cert against
	// the system roots, fails — but Fetch still succeeds and records the error.
	info, err = fetcher.Fetch(host, port, "", FetchOptions{Timeout: 5 * time.Second})
	if err != nil {
		t.Fatalf("unexpected error from Fetch (secure): %v", err)
	}
	if !info.Verified {
		t.Error("expected Verified to be true when insecure is false")
	}
	if info.ChainErr == nil {
		t.Error("expected chain verification to fail for the self-signed test certificate")
	}

	// With -cafile (Roots) set to the server's own certificate, the same chain
	// now verifies — exercising the replace-roots path.
	pool := x509.NewCertPool()
	pool.AddCert(srv.Certificate())
	info, err = fetcher.Fetch(host, port, "", FetchOptions{Timeout: 5 * time.Second, Roots: pool})
	if err != nil {
		t.Fatalf("unexpected error from Fetch (cafile): %v", err)
	}
	if info.ChainErr != nil {
		t.Errorf("expected verification to pass against the custom root, got: %v", info.ChainErr)
	}

	// -servername overrides the verified name (recorded in CheckedName).
	info, err = fetcher.Fetch(host, port, "", FetchOptions{Insecure: true, Timeout: 5 * time.Second, ServerName: "override.example"})
	if err != nil {
		t.Fatalf("unexpected error from Fetch (servername): %v", err)
	}
	if info.CheckedName != "override.example" {
		t.Errorf("expected CheckedName 'override.example', got %q", info.CheckedName)
	}
}
