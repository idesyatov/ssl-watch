package cert

import (
	"bufio"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"net"
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

	conn, err := dialTLS(address, opts.Timeout, opts.StartTLS, tlsConfig)
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

// dialTLS opens a TLS connection to address. When starttls is empty it dials TLS
// directly; otherwise it connects in plaintext, upgrades via the protocol's
// STARTTLS command and then performs the TLS handshake. The timeout bounds both
// the connection and the STARTTLS negotiation.
func dialTLS(address string, timeout time.Duration, starttls string, cfg *tls.Config) (*tls.Conn, error) {
	if starttls == "" {
		dialer := &net.Dialer{Timeout: timeout}
		conn, err := tls.DialWithDialer(dialer, "tcp", address, cfg)
		if err != nil {
			return nil, fmt.Errorf("failed to connect to %s: %v", address, err)
		}
		return conn, nil
	}

	conn, err := net.DialTimeout("tcp", address, timeout)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to %s: %v", address, err)
	}
	// Bound the plaintext negotiation and handshake by the same timeout.
	_ = conn.SetDeadline(time.Now().Add(timeout))
	if err := negotiateStartTLS(conn, starttls); err != nil {
		conn.Close()
		return nil, fmt.Errorf("STARTTLS (%s) failed for %s: %v", starttls, address, err)
	}

	tlsConn := tls.Client(conn, cfg)
	if err := tlsConn.Handshake(); err != nil {
		tlsConn.Close()
		return nil, fmt.Errorf("TLS handshake failed for %s: %v", address, err)
	}
	_ = conn.SetDeadline(time.Time{})
	return tlsConn, nil
}

// negotiateStartTLS performs the protocol-specific STARTTLS exchange on a
// plaintext connection, leaving it ready for the TLS handshake. Supported
// protocols: smtp, imap, pop3, ftp.
func negotiateStartTLS(conn net.Conn, proto string) error {
	br := bufio.NewReader(conn)
	switch proto {
	case "smtp":
		if err := expectCodeReply(br, "220"); err != nil {
			return err
		}
		if _, err := fmt.Fprintf(conn, "EHLO ssl-watch\r\n"); err != nil {
			return err
		}
		if err := expectCodeReply(br, "250"); err != nil {
			return err
		}
		if _, err := fmt.Fprintf(conn, "STARTTLS\r\n"); err != nil {
			return err
		}
		return expectCodeReply(br, "220")
	case "ftp":
		if err := expectCodeReply(br, "220"); err != nil {
			return err
		}
		if _, err := fmt.Fprintf(conn, "AUTH TLS\r\n"); err != nil {
			return err
		}
		return expectCodeReply(br, "234")
	case "pop3":
		if err := expectLinePrefix(br, "+OK"); err != nil {
			return err
		}
		if _, err := fmt.Fprintf(conn, "STLS\r\n"); err != nil {
			return err
		}
		return expectLinePrefix(br, "+OK")
	case "imap":
		if err := expectLinePrefix(br, "* OK"); err != nil {
			return err
		}
		if _, err := fmt.Fprintf(conn, "a STARTTLS\r\n"); err != nil {
			return err
		}
		return expectTaggedOK(br, "a")
	default:
		return fmt.Errorf("unknown STARTTLS protocol %q", proto)
	}
}

// readLine reads a single CRLF-terminated line and trims the line ending.
func readLine(br *bufio.Reader) (string, error) {
	line, err := br.ReadString('\n')
	if err != nil {
		return "", err
	}
	return strings.TrimRight(line, "\r\n"), nil
}

// expectCodeReply reads an SMTP/FTP reply (handling "NNN-" multi-line
// continuations) and verifies the final line starts with the expected code.
func expectCodeReply(br *bufio.Reader, code string) error {
	for {
		line, err := readLine(br)
		if err != nil {
			return err
		}
		// A "-" right after the 3-digit code marks a continuation line.
		if len(line) >= 4 && line[3] == '-' {
			continue
		}
		if !strings.HasPrefix(line, code) {
			return fmt.Errorf("expected reply %s, got %q", code, line)
		}
		return nil
	}
}

// expectLinePrefix reads one line and verifies it starts with prefix.
func expectLinePrefix(br *bufio.Reader, prefix string) error {
	line, err := readLine(br)
	if err != nil {
		return err
	}
	if !strings.HasPrefix(line, prefix) {
		return fmt.Errorf("expected %q, got %q", prefix, line)
	}
	return nil
}

// expectTaggedOK reads IMAP response lines until the one matching the given tag
// and verifies it reports OK.
func expectTaggedOK(br *bufio.Reader, tag string) error {
	for {
		line, err := readLine(br)
		if err != nil {
			return err
		}
		if strings.HasPrefix(line, tag+" ") {
			if !strings.HasPrefix(line, tag+" OK") {
				return fmt.Errorf("STARTTLS rejected: %q", line)
			}
			return nil
		}
	}
}

// CertificateLoaderImpl is an implementation of the CertificateLoader interface.
// It provides functionality to load certificates from a specified file.
type CertificateLoaderImpl struct{}

// Load reads a certificate from the specified file and returns it.
// Returns an error if the file cannot be read or if the certificate cannot be parsed.
func (l *CertificateLoaderImpl) Load(certFile string) (*CertInfo, error) {
	certPEM, err := os.ReadFile(certFile)
	if err != nil {
		return nil, fmt.Errorf("failed to read certificate file %s: %v", certFile, err)
	}

	block, _ := pem.Decode(certPEM)
	if block == nil || block.Type != "CERTIFICATE" {
		return nil, fmt.Errorf("failed to parse certificate from file %s", certFile)
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, err
	}

	return &CertInfo{Cert: cert, FromFile: true}, nil
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
