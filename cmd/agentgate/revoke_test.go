package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/jaezeu/agentgate/internal/vaultmgr"
)

func TestRunRevokeUsesBoundedHumanAuthenticatedAPI(t *testing.T) {
	t.Parallel()

	const requestID = "00000000-0000-4000-8000-000000000401"
	// #nosec G101 -- this runtime-only fixture verifies that the token is not echoed.
	const humanToken = "runtime-human-token-fixture"
	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		if request.Method != http.MethodPost ||
			request.URL.Path != "/v1/requests/"+requestID+"/revoke" {
			t.Errorf("request = %s %s", request.Method, request.URL.Path)
		}
		if request.Header.Get("Authorization") != "Bearer "+humanToken {
			t.Error("missing human bearer authentication")
		}
		response.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(response).Encode(revokeCommandResponse{
			RequestID: requestID,
			Revocation: vaultmgr.RevocationReport{
				RequestID:               requestID,
				RoleRemoved:             true,
				PolicyRemoved:           true,
				STSCredentialsMayRemain: true,
				Warnings: []string{
					"Issued AWS STS credentials may remain valid until their expiry.",
				},
			},
		})
	}))
	defer server.Close()

	var output bytes.Buffer
	err := runRevokeWith(
		[]string{
			"--api-url", server.URL,
			"--allow-insecure-http",
			"--request-id", requestID,
			"--human-token-env", "TEST_HUMAN_TOKEN",
		},
		func(name string) (string, bool) {
			if name != "TEST_HUMAN_TOKEN" {
				return "", false
			}
			return humanToken, true
		},
		&output,
	)
	if err != nil {
		t.Fatalf("runRevokeWith() error = %v", err)
	}
	if !strings.Contains(output.String(), `"sts_credentials_may_remain": true`) ||
		strings.Contains(output.String(), humanToken) {
		t.Fatalf("revoke output = %s", output.String())
	}
}

func TestRunRevokeDoesNotEchoErrorBodiesOrTokens(t *testing.T) {
	t.Parallel()

	const requestID = "00000000-0000-4000-8000-000000000402"
	// #nosec G101 -- this fake marker verifies bounded error redaction.
	const prohibited = "AKIAIOSFODNN7EXAMPLE"
	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) {
		response.Header().Set("Content-Type", "application/json")
		response.WriteHeader(http.StatusBadGateway)
		_, _ = response.Write([]byte(`{"error":{"code":"revocation_failed","message":"` + prohibited + `"}}`))
	}))
	defer server.Close()

	err := runRevokeWith(
		[]string{
			"--api-url", server.URL,
			"--allow-insecure-http",
			"--request-id", requestID,
			"--human-token-env", "TEST_HUMAN_TOKEN",
		},
		func(string) (string, bool) { return "runtime-token", true },
		&bytes.Buffer{},
	)
	if err == nil ||
		strings.Contains(err.Error(), prohibited) ||
		strings.Contains(err.Error(), "runtime-token") ||
		!strings.Contains(err.Error(), "revocation_failed") {
		t.Fatalf("runRevokeWith() error = %v", err)
	}
}

func TestRunRevokeFailsClosedOnUnsafeConfigurationAndResponse(t *testing.T) {
	t.Parallel()

	const requestID = "00000000-0000-4000-8000-000000000403"
	tests := []struct {
		name      string
		arguments []string
		lookup    func(string) (string, bool)
	}{
		{
			name: "missing runtime token",
			arguments: []string{
				"--request-id", requestID,
			},
			lookup: func(string) (string, bool) { return "", false },
		},
		{
			name: "plaintext without explicit PoC override",
			arguments: []string{
				"--api-url", "http://127.0.0.1:8080",
				"--request-id", requestID,
			},
			lookup: func(string) (string, bool) { return "token", true },
		},
		{
			name: "invalid request ID",
			arguments: []string{
				"--request-id", "not-a-request-id",
			},
			lookup: func(string) (string, bool) { return "token", true },
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			if err := runRevokeWith(
				test.arguments,
				test.lookup,
				&bytes.Buffer{},
			); err == nil {
				t.Fatal("runRevokeWith() succeeded, want error")
			}
		})
	}
}

func TestRunRevokeRejectsDishonestSTSReport(t *testing.T) {
	t.Parallel()

	const requestID = "00000000-0000-4000-8000-000000000404"
	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) {
		response.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(response).Encode(revokeCommandResponse{
			RequestID: requestID,
			Revocation: vaultmgr.RevocationReport{
				RequestID: requestID,
			},
		})
	}))
	defer server.Close()

	err := runRevokeWith(
		[]string{
			"--api-url", server.URL,
			"--allow-insecure-http",
			"--request-id", requestID,
		},
		func(string) (string, bool) { return "token", true },
		&bytes.Buffer{},
	)
	if err == nil || !strings.Contains(err.Error(), "STS expiry warning") {
		t.Fatalf("runRevokeWith() error = %v", err)
	}
}

func TestParseServeConfigRequiresExplicitHumanAuthMode(t *testing.T) {
	t.Parallel()

	base := []string{
		"--tls-cert", "server.pem",
		"--tls-key", "server-key.pem",
		"--svid-trust-bundle", "bundle.pem",
		"--allowed-trust-domains", "agentgate.test",
		"--dispatcher-public-key", "dispatcher.pem",
		"--public-base-url", "https://agentgate.example.test",
		"--vault-address", "https://vault.example.test",
		"--vault-management-role", "agentgate-management",
	}
	if _, err := parseServeConfig(base); err == nil ||
		!strings.Contains(err.Error(), "OIDC") {
		t.Fatalf("parseServeConfig() error = %v", err)
	}
	pocArguments := append(append([]string(nil), base...), "--poc-static-human-auth")
	config, err := parseServeConfig(pocArguments)
	if err != nil || !config.pocStaticHumanAuth {
		t.Fatalf("PoC parse = %#v, error %v", config, err)
	}
	oidcArguments := append(
		append([]string(nil), base...),
		"--human-oidc-issuer", "https://identity.example.test",
		"--human-oidc-audience", "agentgate",
	)
	config, err = parseServeConfig(oidcArguments)
	if err != nil || config.pocStaticHumanAuth {
		t.Fatalf("OIDC parse = %#v, error %v", config, err)
	}
}

func TestRequiredEnvironmentNamesMissingSecretWithoutEchoingValue(t *testing.T) {
	t.Parallel()

	_, err := requiredEnvironment("MISSING_TEST_SECRET")
	if err == nil || !strings.Contains(err.Error(), "MISSING_TEST_SECRET") {
		t.Fatalf("requiredEnvironment() error = %v", err)
	}
}
