package cert

import (
	"bufio"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"io"
	"net"
	"net/url"
	"os"
	"strings"
	"time"
)

// CertificateFetcherImpl is an implementation of the CertificateFetcher interface.
// It provides functionality to fetch certificates from a specified domain or IP address.
type CertificateFetcherImpl struct{}

// Fetch connects to the specified domain or IP address and retrieves the TLS certificate.
// The handshake always skips verification so that details of an invalid certificate can
// still be displayed; the chain is then verified separately unless insecure is true.
func (f *CertificateFetcherImpl) Fetch(domain, port, ipaddr string, opts FetchOptions) (*CertInfo, error) {
	host := domain
	if ipaddr != "" {
		host = ipaddr
	}
	// The name presented (SNI) and verified against; -servername overrides the domain.
	name := domain
	if opts.ServerName != "" {
		name = opts.ServerName
	}
	address := net.JoinHostPort(host, port)
	tlsConfig := &tls.Config{
		InsecureSkipVerify: true,
		ServerName:         name,
	}
	if opts.ClientCert != nil {
		tlsConfig.Certificates = []tls.Certificate{*opts.ClientCert}
	}

	conn, err := dialTLS(address, opts.Timeout, opts.StartTLS, opts.Proxy, tlsConfig)
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	state := conn.ConnectionState()
	certs := state.PeerCertificates
	if len(certs) == 0 {
		return nil, fmt.Errorf("no certificates found for %s", address)
	}

	usedIP := conn.RemoteAddr().String()
	if tcpAddr, ok := conn.RemoteAddr().(*net.TCPAddr); ok {
		usedIP = tcpAddr.IP.String()
	}

	info := &CertInfo{
		Cert:        certs[0],
		Chain:       certs,
		UsedIP:      usedIP,
		TLSVersion:  tls.VersionName(state.Version),
		CipherSuite: tls.CipherSuiteName(state.CipherSuite),
		CheckedName: name,
	}
	if !opts.Insecure {
		info.Verified = true
		info.ChainErr = verifyChain(certs, name, opts.Roots)
	}
	return info, nil
}

// verifyChain validates the leaf certificate (certs[0]) against roots (nil = the
// system root store), using the remaining peer certificates as intermediates. The
// check covers trust, hostname match and validity period.
func verifyChain(certs []*x509.Certificate, name string, roots *x509.CertPool) error {
	intermediates := x509.NewCertPool()
	for _, c := range certs[1:] {
		intermediates.AddCert(c)
	}
	_, err := certs[0].Verify(x509.VerifyOptions{
		DNSName:       name,
		Intermediates: intermediates,
		Roots:         roots,
	})
	return err
}

// dialTLS opens a TLS connection to address, optionally through an HTTP CONNECT
// proxy and/or a STARTTLS upgrade. It dials the raw TCP connection (directly or
// via the proxy), runs the STARTTLS negotiation when requested, and performs the
// TLS handshake. The timeout bounds the connection, the negotiation and the
// handshake.
func dialTLS(address string, timeout time.Duration, starttls, proxy string, cfg *tls.Config) (*tls.Conn, error) {
	conn, err := dialRaw(address, timeout, proxy)
	if err != nil {
		return nil, err
	}
	// Bound the negotiation and handshake by the same timeout.
	_ = conn.SetDeadline(time.Now().Add(timeout))
	if starttls != "" {
		if err := negotiateStartTLS(conn, starttls); err != nil {
			conn.Close()
			return nil, fmt.Errorf("STARTTLS (%s) failed for %s: %v", starttls, address, err)
		}
	}

	tlsConn := tls.Client(conn, cfg)
	if err := tlsConn.Handshake(); err != nil {
		tlsConn.Close()
		return nil, fmt.Errorf("TLS handshake failed for %s: %v", address, err)
	}
	_ = conn.SetDeadline(time.Time{})
	return tlsConn, nil
}

// dialRaw opens a raw TCP connection to address, directly or — when proxy is set
// — through an HTTP CONNECT proxy.
func dialRaw(address string, timeout time.Duration, proxy string) (net.Conn, error) {
	if proxy == "" {
		conn, err := net.DialTimeout("tcp", address, timeout)
		if err != nil {
			return nil, fmt.Errorf("failed to connect to %s: %v", address, err)
		}
		return conn, nil
	}
	return dialViaProxy(address, timeout, proxy)
}

// dialViaProxy connects to an HTTP proxy and issues a CONNECT request to open a
// tunnel to target, returning the tunneled connection ready for a TLS handshake.
// Only the http scheme is supported; optional userinfo becomes Basic auth.
func dialViaProxy(target string, timeout time.Duration, proxy string) (net.Conn, error) {
	u, err := url.Parse(proxy)
	if err != nil {
		return nil, fmt.Errorf("invalid -proxy %q: %v", proxy, err)
	}
	if u.Scheme != "" && u.Scheme != "http" {
		return nil, fmt.Errorf("unsupported proxy scheme %q (only http is supported)", u.Scheme)
	}
	if u.Hostname() == "" {
		return nil, fmt.Errorf("invalid -proxy %q: missing host", proxy)
	}
	// Default to the http scheme's port when the URL omits one.
	proxyAddr := u.Host
	if u.Port() == "" {
		proxyAddr = net.JoinHostPort(u.Hostname(), "80")
	}

	conn, err := net.DialTimeout("tcp", proxyAddr, timeout)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to proxy %s: %v", proxyAddr, err)
	}
	_ = conn.SetDeadline(time.Now().Add(timeout))

	req := fmt.Sprintf("CONNECT %s HTTP/1.1\r\nHost: %s\r\n", target, target)
	if u.User != nil {
		pass, _ := u.User.Password()
		token := base64.StdEncoding.EncodeToString([]byte(u.User.Username() + ":" + pass))
		req += "Proxy-Authorization: Basic " + token + "\r\n"
	}
	req += "\r\n"
	if _, err := conn.Write([]byte(req)); err != nil {
		conn.Close()
		return nil, fmt.Errorf("failed to send CONNECT to proxy %s: %v", proxyAddr, err)
	}

	br := bufio.NewReader(conn)
	status, err := readLine(br)
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("proxy %s: failed to read CONNECT response: %v", proxyAddr, err)
	}
	// Status line: "HTTP/1.1 200 Connection established".
	fields := strings.SplitN(status, " ", 3)
	if len(fields) < 2 || fields[1] != "200" {
		conn.Close()
		return nil, fmt.Errorf("proxy %s refused CONNECT to %s: %s", proxyAddr, target, status)
	}
	// Drain the remaining response headers up to the blank line.
	for {
		line, err := readLine(br)
		if err != nil {
			conn.Close()
			return nil, fmt.Errorf("proxy %s: failed to read CONNECT headers: %v", proxyAddr, err)
		}
		if line == "" {
			break
		}
	}
	_ = conn.SetDeadline(time.Time{})
	return conn, nil
}

// CertificateLoaderImpl is an implementation of the CertificateLoader interface.
// It provides functionality to load certificates from a specified file.
type CertificateLoaderImpl struct{}

// Load reads a certificate from the specified file and returns it.
// A certFile of "-" reads the PEM from standard input.
// Returns an error if the source cannot be read or if the certificate cannot be parsed.
func (l *CertificateLoaderImpl) Load(certFile string) (*CertInfo, error) {
	var certPEM []byte
	var err error
	if certFile == "-" {
		certPEM, err = io.ReadAll(os.Stdin)
		if err != nil {
			return nil, fmt.Errorf("failed to read certificate from stdin: %v", err)
		}
	} else {
		certPEM, err = os.ReadFile(certFile)
		if err != nil {
			return nil, fmt.Errorf("failed to read certificate file %s: %v", certFile, err)
		}
	}

	src := certFile
	if certFile == "-" {
		src = "stdin"
	}

	// Parse every CERTIFICATE block so a bundle (e.g. fullchain.pem) is treated
	// as a chain: the first is the leaf, the rest become the chain.
	var chain []*x509.Certificate
	rest := certPEM
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" {
			continue
		}
		c, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, err
		}
		chain = append(chain, c)
	}
	if len(chain) == 0 {
		return nil, fmt.Errorf("failed to parse certificate from %s", src)
	}

	info := &CertInfo{Cert: chain[0], FromFile: true}
	if len(chain) > 1 {
		info.Chain = chain
	}
	return info, nil
}

// LoadClientCert loads a client certificate and its private key from PEM files,
// for use as the client identity in mutual TLS.
func LoadClientCert(certFile, keyFile string) (*tls.Certificate, error) {
	pair, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return nil, fmt.Errorf("failed to load client certificate: %v", err)
	}
	return &pair, nil
}

// LoadCAFile reads a PEM bundle and returns a certificate pool containing its
// certificates, for use as the verification roots (replacing the system roots).
// It returns an error if the file cannot be read or holds no certificates.
func LoadCAFile(path string) (*x509.CertPool, error) {
	pemBytes, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read CA file %s: %v", path, err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(pemBytes) {
		return nil, fmt.Errorf("no certificates found in CA file %s", path)
	}
	return pool, nil
}
