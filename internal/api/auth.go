package api

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"errors"
	"net/http"
	"strings"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/jaezeu/agentgate/internal/svid"
)

var ErrHumanUnauthorized = errors.New("human authentication failed")

const maxBearerTokenLength = 16 << 10

// HumanIdentity is an authenticated operational user, never a workload identity.
type HumanIdentity struct {
	Subject string
}

// HumanAuthenticator is the OIDC-ready boundary used only by human routes.
type HumanAuthenticator interface {
	Authenticate(context.Context, string) (HumanIdentity, error)
}

// HumanAuthenticatorFunc adapts an OIDC verifier or deterministic test fake.
type HumanAuthenticatorFunc func(context.Context, string) (HumanIdentity, error)

func (f HumanAuthenticatorFunc) Authenticate(ctx context.Context, token string) (HumanIdentity, error) {
	return f(ctx, token)
}

// OIDCAuthenticator verifies human bearer tokens against one configured issuer and audience.
type OIDCAuthenticator struct {
	verifier *oidc.IDTokenVerifier
}

// NewOIDCAuthenticator performs discovery at startup and fails closed on invalid configuration.
func NewOIDCAuthenticator(
	ctx context.Context,
	issuer string,
	audience string,
) (*OIDCAuthenticator, error) {
	if ctx == nil {
		return nil, errors.New("OIDC initialization context is required")
	}
	if strings.TrimSpace(issuer) == "" || strings.TrimSpace(audience) == "" {
		return nil, errors.New("OIDC issuer and audience are required")
	}
	provider, err := oidc.NewProvider(ctx, issuer)
	if err != nil {
		return nil, errors.New("initialize OIDC provider")
	}
	return &OIDCAuthenticator{
		verifier: provider.Verifier(&oidc.Config{ClientID: audience}),
	}, nil
}

func (a *OIDCAuthenticator) Authenticate(
	ctx context.Context,
	rawToken string,
) (HumanIdentity, error) {
	if a == nil || a.verifier == nil || rawToken == "" || len(rawToken) > maxBearerTokenLength {
		return HumanIdentity{}, ErrHumanUnauthorized
	}
	token, err := a.verifier.Verify(ctx, rawToken)
	if err != nil || strings.TrimSpace(token.Subject) == "" ||
		len(token.Subject) > maxIdentityLength {
		return HumanIdentity{}, ErrHumanUnauthorized
	}
	return HumanIdentity{Subject: token.Subject}, nil
}

// PoCStaticTokenAuthenticator is an explicitly gated development placeholder.
// It retains only a one-way digest of the runtime-supplied bearer token.
type PoCStaticTokenAuthenticator struct {
	expectedTokenHash [sha256.Size]byte
	subject           string
}

// NewPoCStaticTokenAuthenticator creates static auth only in explicit PoC mode.
func NewPoCStaticTokenAuthenticator(
	pocMode bool,
	runtimeToken string,
	subject string,
) (*PoCStaticTokenAuthenticator, error) {
	if !pocMode {
		return nil, errors.New("PoC static human authentication is disabled")
	}
	if runtimeToken == "" {
		return nil, errors.New("PoC static human token is required")
	}
	if strings.TrimSpace(subject) == "" {
		return nil, errors.New("PoC static human subject is required")
	}
	return &PoCStaticTokenAuthenticator{
		expectedTokenHash: sha256.Sum256([]byte(runtimeToken)),
		subject:           subject,
	}, nil
}

func (a *PoCStaticTokenAuthenticator) Authenticate(
	_ context.Context,
	token string,
) (HumanIdentity, error) {
	if a == nil {
		return HumanIdentity{}, ErrHumanUnauthorized
	}
	candidateHash := sha256.Sum256([]byte(token))
	if subtle.ConstantTimeCompare(candidateHash[:], a.expectedTokenHash[:]) != 1 {
		return HumanIdentity{}, ErrHumanUnauthorized
	}
	return HumanIdentity{Subject: a.subject}, nil
}

type principalKind uint8

const (
	principalWorkload principalKind = iota + 1
	principalHuman
)

type authenticatedPrincipal struct {
	kind     principalKind
	workload svid.Identity
	human    HumanIdentity
}

type principalContextKey struct{}

func withPrincipal(ctx context.Context, principal authenticatedPrincipal) context.Context {
	return context.WithValue(ctx, principalContextKey{}, principal)
}

func principalFromContext(ctx context.Context) (authenticatedPrincipal, bool) {
	principal, ok := ctx.Value(principalContextKey{}).(authenticatedPrincipal)
	return principal, ok
}

func parseBearerToken(request *http.Request) (string, error) {
	values := request.Header.Values("Authorization")
	if len(values) != 1 {
		return "", ErrHumanUnauthorized
	}
	parts := strings.Fields(values[0])
	if len(parts) != 2 ||
		!strings.EqualFold(parts[0], "Bearer") ||
		parts[1] == "" ||
		len(parts[1]) > maxBearerTokenLength {
		return "", ErrHumanUnauthorized
	}
	return parts[1], nil
}
