package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	hashicorpapi "github.com/hashicorp/vault/api"
)

func TestRedeemVaultCredentialsUsesJWTAndRequestIDSession(t *testing.T) {
	now := time.Date(2030, time.January, 2, 3, 4, 5, 0, time.UTC)
	taskGrant := agentTaskGrant(now)
	descriptor := agentDescriptor(taskGrant, now.Add(10*time.Minute))
	// #nosec G101 -- synthetic test-only values exercise credential handling and redaction.
	const (
		jwt          = "eyJhbGciOiJFUzI1NiJ9.eyJhdWQiOiJ2YXVsdCJ9.signature"
		vaultToken   = "hvs.runtime-only-test-token"
		accessKeyID  = "ASIAABCDEFGHIJKLMNOP"
		secretKey    = "runtime-only-secret-access-key-0123456789"
		sessionToken = "runtime-only-session-token-with-more-than-32-characters"
	)
	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		response.Header().Set("Content-Type", "application/json")
		switch request.URL.Path {
		case "/v1/auth/spire-jwt/login":
			if request.Method != http.MethodPut {
				t.Fatalf("login method = %s", request.Method)
			}
			var payload map[string]string
			if err := json.NewDecoder(request.Body).Decode(&payload); err != nil {
				t.Fatalf("decode login: %v", err)
			}
			if payload["role"] != descriptor.AuthRole || payload["jwt"] != jwt {
				t.Fatalf("login payload = %#v", payload)
			}
			_, _ = response.Write([]byte(`{
				"auth": {
					"client_token": "` + vaultToken + `",
					"lease_duration": 600
				}
			}`))
		case "/v1/aws/creds/terraform-sandbox":
			if request.Method != http.MethodGet ||
				request.Header.Get("X-Vault-Token") != vaultToken ||
				request.URL.Query().Get("role_session_name") != taskGrant.RequestID ||
				request.URL.Query().Get("ttl") != "600s" {
				t.Fatalf("credential request = %s %s, headers = %#v", request.Method, request.URL.String(), request.Header)
			}
			_, _ = response.Write([]byte(`{
				"lease_id": "aws/creds/terraform-sandbox/test-lease",
				"lease_duration": 600,
				"data": {
					"access_key": "` + accessKeyID + `",
					"secret_key": "` + secretKey + `",
					"security_token": "` + sessionToken + `"
				}
			}`))
		default:
			http.NotFound(response, request)
		}
	}))
	defer server.Close()

	client := testVaultClient(t, server.URL)
	credentials, err := redeemVaultCredentials(
		context.Background(),
		client,
		descriptor,
		jwt,
		func() time.Time { return now },
	)
	if err != nil {
		t.Fatalf("redeem credentials: %v", err)
	}
	if credentials.accessKeyID != accessKeyID ||
		credentials.secretAccessKey != secretKey ||
		credentials.sessionToken != sessionToken {
		t.Fatal("redeemed STS values do not match the direct Vault response")
	}
	if client.Token() != "" {
		t.Fatal("Vault client retained its workload token")
	}
	credentials.clear()
	if credentials.accessKeyID != "" ||
		credentials.secretAccessKey != "" ||
		credentials.sessionToken != "" {
		t.Fatal("credential references were not cleared")
	}
}

func TestRedeemVaultCredentialsDoesNotEchoVaultFailureBody(t *testing.T) {
	const prohibited = "ASIAABCDEFGHIJKLMNOP"
	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) {
		http.Error(response, prohibited, http.StatusInternalServerError)
	}))
	defer server.Close()
	now := time.Date(2030, time.January, 2, 3, 4, 5, 0, time.UTC)
	taskGrant := agentTaskGrant(now)
	descriptor := agentDescriptor(taskGrant, now.Add(10*time.Minute))

	_, err := redeemVaultCredentials(
		context.Background(),
		testVaultClient(t, server.URL),
		descriptor,
		"runtime-jwt",
		func() time.Time { return now },
	)
	if err == nil {
		t.Fatal("redemption unexpectedly succeeded")
	}
	if strings.Contains(err.Error(), prohibited) {
		t.Fatalf("error exposed Vault response body: %v", err)
	}
}

func testVaultClient(t *testing.T, address string) *hashicorpapi.Client {
	t.Helper()
	client, err := hashicorpapi.NewClient(&hashicorpapi.Config{
		Address:    address,
		HttpClient: &http.Client{Timeout: time.Second},
		MaxRetries: 0,
		Timeout:    time.Second,
	})
	if err != nil {
		t.Fatalf("create Vault client: %v", err)
	}
	return client
}
