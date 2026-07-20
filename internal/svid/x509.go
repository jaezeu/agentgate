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
	// Roots verifies chains when RootsByTrustDomain is nil. A single flat
	// pool cannot tie an issuing CA to a trust domain, so it is only safe
	// when exactly one trust domain is allowed.
	Roots *x509.CertPool
	// RootsByTrustDomain binds each allowed trust domain to the CA bundle
	// entitled to issue identities in it, per the SPIFFE X.509-SVID
	// authentication rule: the chain must verify against the bundle of the
	// trust domain named in the leaf's URI SAN, not against any trusted CA.
	RootsByTrustDomain  map[string]*x509.CertPool
	AllowedTrustDomains map[string]struct{}
	Clock               func() time.Time
}

// Validate cryptographically verifies the chain and extracts its SPIFFE ID.
// The SPIFFE ID is parsed before chain verification because the trust domain
// it names selects which root bundle the chain must verify against.
func (v X509Validator) Validate(_ context.Context, chain []*x509.Certificate) (Identity, error) {
	if v.Roots == nil && len(v.RootsByTrustDomain) == 0 {
		return Identity{}, errors.New("SVID trust roots are required")
	}
	if len(chain) == 0 {
		return Identity{}, fmt.Errorf("%w: empty peer chain", ErrInvalidChain)
	}

	leaf := chain[0]
	if leaf.IsCA || leaf.KeyUsage&x509.KeyUsageCertSign != 0 || leaf.KeyUsage&x509.KeyUsageCRLSign != 0 {
		return Identity{}, ErrInvalidProfile
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
	roots := v.Roots
	if v.RootsByTrustDomain != nil {
		domainRoots, bound := v.RootsByTrustDomain[trustDomain]
		if !bound || domainRoots == nil {
			return Identity{}, ErrTrustDomainRejected
		}
		roots = domainRoots
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
		Roots:         roots,
		Intermediates: intermediates,
		CurrentTime:   currentTime,
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}); err != nil {
		return Identity{}, fmt.Errorf("%w: %w", ErrInvalidChain, err)
	}

	return Identity{
		SPIFFEID:    spiffeID.String(),
		TrustDomain: trustDomain,
		ExpiresAt:   leaf.NotAfter,
	}, nil
}
