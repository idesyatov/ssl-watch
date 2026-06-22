package cert

import (
	"bufio"
	"fmt"
	"net"
	"testing"
	"time"
)

// runNegotiate drives negotiateStartTLS against a scripted in-memory server and
// returns the negotiation error.
func runNegotiate(t *testing.T, proto string, serverScript func(server net.Conn, r *bufio.Reader)) error {
	t.Helper()
	client, server := net.Pipe()
	errCh := make(chan error, 1)
	go func() {
		client.SetDeadline(time.Now().Add(5 * time.Second))
		errCh <- negotiateStartTLS(client, proto)
		client.Close()
	}()

	r := bufio.NewReader(server)
	serverScript(server, r)
	server.Close()
	return <-errCh
}

// TestNegotiateStartTLS_SMTP verifies a successful SMTP negotiation, including a
// multi-line EHLO reply.
func TestNegotiateStartTLS_SMTP(t *testing.T) {
	err := runNegotiate(t, "smtp", func(server net.Conn, r *bufio.Reader) {
		fmt.Fprint(server, "220 smtp.example.com ESMTP\r\n")
		r.ReadString('\n') // EHLO
		fmt.Fprint(server, "250-smtp.example.com\r\n250-STARTTLS\r\n250 OK\r\n")
		r.ReadString('\n') // STARTTLS
		fmt.Fprint(server, "220 ready to start TLS\r\n")
	})
	if err != nil {
		t.Errorf("expected successful SMTP negotiation, got error: %v", err)
	}
}

// TestNegotiateStartTLS_IMAP verifies a successful IMAP negotiation with a tagged
// OK response.
func TestNegotiateStartTLS_IMAP(t *testing.T) {
	err := runNegotiate(t, "imap", func(server net.Conn, r *bufio.Reader) {
		fmt.Fprint(server, "* OK IMAP4rev1 ready\r\n")
		r.ReadString('\n') // a STARTTLS
		fmt.Fprint(server, "a OK begin TLS negotiation\r\n")
	})
	if err != nil {
		t.Errorf("expected successful IMAP negotiation, got error: %v", err)
	}
}

// TestNegotiateStartTLS_POP3Rejected verifies that a server refusing STLS yields
// a negotiation error.
func TestNegotiateStartTLS_POP3Rejected(t *testing.T) {
	err := runNegotiate(t, "pop3", func(server net.Conn, r *bufio.Reader) {
		fmt.Fprint(server, "+OK POP3 ready\r\n")
		r.ReadString('\n') // STLS
		fmt.Fprint(server, "-ERR command not supported\r\n")
	})
	if err == nil {
		t.Error("expected error when STLS is rejected, got nil")
	}
}

// TestNegotiateStartTLS_Unknown verifies an unsupported protocol is rejected.
func TestNegotiateStartTLS_Unknown(t *testing.T) {
	client, _ := net.Pipe()
	defer client.Close()
	if err := negotiateStartTLS(client, "gopher"); err == nil {
		t.Error("expected error for unknown protocol, got nil")
	}
}
