package cert

import (
	"bufio"
	"fmt"
	"net"
	"strings"
)

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

// readLine reads a single CRLF-terminated line and trims the line ending. It is
// shared by the STARTTLS negotiation and the HTTP CONNECT proxy response parsing.
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
