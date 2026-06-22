package cert

import (
	"crypto/x509"
	"testing"
	"time"
)

// TestDaysUntilExpiry verifies the day arithmetic for future and past expiry.
func TestDaysUntilExpiry(t *testing.T) {
	future := &x509.Certificate{NotAfter: time.Now().Add(10*24*time.Hour + time.Hour)}
	if got := DaysUntilExpiry(future); got != 10 {
		t.Errorf("expected 10 days remaining, got %d", got)
	}
	past := &x509.Certificate{NotAfter: time.Now().Add(-2 * 24 * time.Hour)}
	if got := DaysUntilExpiry(past); got >= 0 {
		t.Errorf("expected negative days for expired cert, got %d", got)
	}
}

// TestMinDaysUntilExpiry verifies the minimum is taken across the whole chain
// and falls back to the leaf when no chain is recorded.
func TestMinDaysUntilExpiry(t *testing.T) {
	leaf := &x509.Certificate{NotAfter: time.Now().Add(90*24*time.Hour + time.Hour)}
	inter := &x509.Certificate{NotAfter: time.Now().Add(20*24*time.Hour + time.Hour)}

	withChain := &CertInfo{Cert: leaf, Chain: []*x509.Certificate{leaf, inter}}
	if got := withChain.MinDaysUntilExpiry(); got != 20 {
		t.Errorf("expected min 20 across chain, got %d", got)
	}

	leafOnly := &CertInfo{Cert: leaf}
	if got := leafOnly.MinDaysUntilExpiry(); got != 90 {
		t.Errorf("expected leaf fallback 90, got %d", got)
	}
}
