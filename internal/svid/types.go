package svid

import (
	"context"
	"crypto/x509"
	"time"
)

// Identity is an authenticated workload identity, never a human identity.
type Identity struct {
	SPIFFEID    string    `json:"spiffe_id"`
	TrustDomain string    `json:"trust_domain"`
	ExpiresAt   time.Time `json:"expires_at"`
}

// SVIDValidator authenticates the X.509-SVID presented on the mTLS connection.
type SVIDValidator interface {
	Validate(context.Context, []*x509.Certificate) (Identity, error)
}
