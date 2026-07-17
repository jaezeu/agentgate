package svid

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"math/big"
	"net/url"
	"testing"
	"time"
)

func TestX509Validator(t *testing.T) {
	t.Parallel()

	now := time.Date(2030, time.January, 2, 15, 4, 5, 0, time.UTC)
	validURI := mustURL(t, "spiffe://agentgate.test/ns/agents/sa/terraform-runner")
	otherDomainURI := mustURL(t, "spiffe://untrusted.test/ns/agents/sa/terraform-runner")
	secondURI := mustURL(t, "spiffe://agentgate.test/ns/agents/sa/other")
	trustedRoot, validLeaf := certificateFixture(t, 0x11, []*url.URL{validURI}, nil, now.Add(time.Hour))
	_, wrongDomainLeaf := certificateFixture(t, 0x11, []*url.URL{otherDomainURI}, nil, now.Add(time.Hour))
	_, multipleURILeaf := certificateFixture(t, 0x11, []*url.URL{validURI, secondURI}, nil, now.Add(time.Hour))
	_, dnsSANLeaf := certificateFixture(t, 0x11, []*url.URL{validURI}, []string{"runner.example.test"}, now.Add(time.Hour))
	_, missingURILeaf := certificateFixture(t, 0x11, nil, nil, now.Add(time.Hour))
	_, expiredLeaf := certificateFixture(t, 0x11, []*url.URL{validURI}, nil, now.Add(-time.Minute))
	_, untrustedLeaf := certificateFixture(t, 0x44, []*url.URL{validURI}, nil, now.Add(time.Hour))
	caLeaf := *validLeaf
	caLeaf.IsCA = true
	caLeaf.KeyUsage |= x509.KeyUsageCertSign

	roots := x509.NewCertPool()
	roots.AddCert(trustedRoot)
	validator := X509Validator{
		Roots:               roots,
		AllowedTrustDomains: map[string]struct{}{"agentgate.test": {}},
		Clock:               func() time.Time { return now },
	}

	tests := []struct {
		name      string
		chain     []*x509.Certificate
		wantID    string
		wantError error
	}{
		{
			name:   "valid attested workload",
			chain:  []*x509.Certificate{validLeaf},
			wantID: validURI.String(),
		},
		{
			name:      "untrusted issuer",
			chain:     []*x509.Certificate{untrustedLeaf},
			wantError: ErrInvalidChain,
		},
		{
			name:      "CA certificate presented as workload SVID",
			chain:     []*x509.Certificate{&caLeaf},
			wantError: ErrInvalidProfile,
		},
		{
			name:      "wrong trust domain",
			chain:     []*x509.Certificate{wrongDomainLeaf},
			wantError: ErrTrustDomainRejected,
		},
		{
			name:      "missing URI SAN",
			chain:     []*x509.Certificate{missingURILeaf},
			wantError: ErrInvalidSAN,
		},
		{
			name:      "multiple URI SANs",
			chain:     []*x509.Certificate{multipleURILeaf},
			wantError: ErrInvalidSAN,
		},
		{
			name:      "additional DNS SAN",
			chain:     []*x509.Certificate{dnsSANLeaf},
			wantError: ErrInvalidSAN,
		},
		{
			name:      "expired SVID",
			chain:     []*x509.Certificate{expiredLeaf},
			wantError: ErrInvalidChain,
		},
		{
			name:      "empty chain",
			wantError: ErrInvalidChain,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			identity, err := validator.Validate(context.Background(), test.chain)
			if !errors.Is(err, test.wantError) {
				t.Fatalf("Validate() error = %v, want %v", err, test.wantError)
			}
			if identity.SPIFFEID != test.wantID {
				t.Fatalf("Validate() SPIFFE ID = %q, want %q", identity.SPIFFEID, test.wantID)
			}
		})
	}
}

func certificateFixture(
	t *testing.T,
	rootSeedByte byte,
	uriSANs []*url.URL,
	dnsSANs []string,
	notAfter time.Time,
) (*x509.Certificate, *x509.Certificate) {
	t.Helper()

	rootKey := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{rootSeedByte}, ed25519.SeedSize))
	rootTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "AgentGate static test root"},
		NotBefore:             time.Date(2029, time.January, 1, 0, 0, 0, 0, time.UTC),
		NotAfter:              time.Date(2031, time.January, 1, 0, 0, 0, 0, time.UTC),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	rootDER, err := x509.CreateCertificate(bytes.NewReader(make([]byte, 64)), rootTemplate, rootTemplate, rootKey.Public(), rootKey)
	if err != nil {
		t.Fatalf("create root fixture: %v", err)
	}
	root, err := x509.ParseCertificate(rootDER)
	if err != nil {
		t.Fatalf("parse root fixture: %v", err)
	}

	leafKey := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x22}, ed25519.SeedSize))
	leafTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "AgentGate static workload fixture"},
		NotBefore:    time.Date(2029, time.January, 1, 0, 0, 0, 0, time.UTC),
		NotAfter:     notAfter,
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		URIs:         uriSANs,
		DNSNames:     dnsSANs,
	}
	leafDER, err := x509.CreateCertificate(bytes.NewReader(make([]byte, 64)), leafTemplate, root, leafKey.Public(), rootKey)
	if err != nil {
		t.Fatalf("create leaf fixture: %v", err)
	}
	leaf, err := x509.ParseCertificate(leafDER)
	if err != nil {
		t.Fatalf("parse leaf fixture: %v", err)
	}
	return root, leaf
}

func mustURL(t *testing.T, rawURL string) *url.URL {
	t.Helper()
	parsed, err := url.Parse(rawURL)
	if err != nil {
		t.Fatalf("parse fixture URL: %v", err)
	}
	return parsed
}
