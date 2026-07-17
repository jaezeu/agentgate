package svid

import (
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"time"

	"github.com/spiffe/go-spiffe/v2/spiffeid"
)

var (
	ErrInvalidChain        = errors.New("invalid X.509-SVID chain")
	ErrInvalidProfile      = errors.New("X.509-SVID leaf has an invalid certificate profile")
	ErrInvalidSAN          = errors.New("X.509-SVID must contain exactly one URI SAN and no other SAN types")
	ErrTrustDomainRejected = errors.New("SPIFFE trust domain is not allowed")
)

// X509Validator verifies an mTLS peer chain against configured SPIFFE trust roots.
type X509Validator struct {
	Roots               *x509.CertPool
	AllowedTrustDomains map[string]struct{}
	Clock               func() time.Time
}

// Validate cryptographically verifies the chain and extracts its SPIFFE ID.
func (v X509Validator) Validate(_ context.Context, chain []*x509.Certificate) (Identity, error) {
	if v.Roots == nil {
		return Identity{}, errors.New("SVID trust roots are required")
	}
	if len(chain) == 0 {
		return Identity{}, fmt.Errorf("%w: empty peer chain", ErrInvalidChain)
	}

	leaf := chain[0]
	if leaf.IsCA || leaf.KeyUsage&x509.KeyUsageCertSign != 0 || leaf.KeyUsage&x509.KeyUsageCRLSign != 0 {
		return Identity{}, ErrInvalidProfile
	}
	intermediates := x509.NewCertPool()
	for _, certificate := range chain[1:] {
		intermediates.AddCert(certificate)
	}
	currentTime := time.Now().UTC()
	if v.Clock != nil {
		currentTime = v.Clock().UTC()
	}
	if _, err := leaf.Verify(x509.VerifyOptions{
		Roots:         v.Roots,
		Intermediates: intermediates,
		CurrentTime:   currentTime,
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}); err != nil {
		return Identity{}, fmt.Errorf("%w: %w", ErrInvalidChain, err)
	}
	if len(leaf.URIs) != 1 || len(leaf.DNSNames) != 0 || len(leaf.EmailAddresses) != 0 || len(leaf.IPAddresses) != 0 {
		return Identity{}, ErrInvalidSAN
	}

	spiffeID, err := spiffeid.FromURI(leaf.URIs[0])
	if err != nil {
		return Identity{}, fmt.Errorf("%w: %w", ErrInvalidSAN, err)
	}
	trustDomain := spiffeID.TrustDomain().String()
	if _, allowed := v.AllowedTrustDomains[trustDomain]; !allowed {
		return Identity{}, ErrTrustDomainRejected
	}

	return Identity{
		SPIFFEID:    spiffeID.String(),
		TrustDomain: trustDomain,
		ExpiresAt:   leaf.NotAfter,
	}, nil
}
