package main

import (
	"context"
	"errors"
	"strings"

	hashicorpapi "github.com/hashicorp/vault/api"
	"github.com/spiffe/go-spiffe/v2/svid/jwtsvid"
	"github.com/spiffe/go-spiffe/v2/workloadapi"
)

type spiffeVaultClientProvider struct {
	baseClient *hashicorpapi.Client
	namespace  string
	authMount  string
	role       string
	audience   string
	jwtSource  *workloadapi.JWTSource
}

func (p *spiffeVaultClientProvider) Client(
	ctx context.Context,
) (*hashicorpapi.Client, error) {
	if p == nil || p.baseClient == nil || p.jwtSource == nil {
		return nil, errors.New("vault SPIFFE client provider is not initialized")
	}
	jwtSVID, err := p.jwtSource.FetchJWTSVID(ctx, jwtsvid.Params{Audience: p.audience})
	if err != nil {
		return nil, errors.New("fetch AgentGate JWT-SVID for Vault")
	}
	if jwtSVID == nil || jwtSVID.Marshal() == "" {
		return nil, errors.New("SPIFFE Workload API returned an empty JWT-SVID")
	}

	client, err := p.baseClient.Clone()
	if err != nil {
		return nil, errors.New("initialize Vault management client")
	}
	client.SetNamespace(p.namespace)
	secret, err := client.Logical().WriteWithContext(
		ctx,
		"auth/"+strings.Trim(p.authMount, "/")+"/login",
		map[string]any{
			"role": p.role,
			"jwt":  jwtSVID.Marshal(),
		},
	)
	if err != nil {
		return nil, errors.New("AgentGate Vault JWT login failed")
	}
	if secret == nil || secret.Auth == nil || secret.Auth.ClientToken == "" {
		return nil, errors.New("AgentGate Vault JWT login returned no client authorization")
	}
	client.SetToken(secret.Auth.ClientToken)
	return client, nil
}
