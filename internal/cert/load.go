package cert

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io"
	"os"
)

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
