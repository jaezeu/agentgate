package vaultapi

import (
	"bufio"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	jose "github.com/go-jose/go-jose/v4"
	josejwt "github.com/go-jose/go-jose/v4/jwt"
	hashicorpapi "github.com/hashicorp/vault/api"
	"github.com/jaezeu/agentgate/internal/approval"
	"github.com/jaezeu/agentgate/internal/audit"
	"github.com/jaezeu/agentgate/internal/authz"
	"github.com/jaezeu/agentgate/internal/expiry"
	"github.com/jaezeu/agentgate/internal/vaultmgr"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/wait"
)

const vaultTestImage = "hashicorp/vault:2.0.3@sha256:a296a888b118615dc01d5f1a6846e6d4a7277946caaed5b447008fff5fe06b54"

func TestVaultManagerWithRealVault(t *testing.T) {
	requireDocker(t)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	signingKey := staticTestJWTSigningKey(t)
	const (
		keyID     = "agentgate-vault-integration"
		issuer    = "https://spire.test.invalid"
		authMount = "jwt-test"
		auditPath = "/tmp/agentgate-vault-audit.log"
	)
	jwksServer, jwksPort := startJWKSServer(t, signingKey, keyID)
	t.Cleanup(jwksServer.Close)

	rootAuthorization := randomOpaqueValue(t)
	container, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
		ContainerRequest: testcontainers.ContainerRequest{
			Image:        vaultTestImage,
			ExposedPorts: []string{"8200/tcp"},
			Env: map[string]string{
				"VAULT_DEV_LISTEN_ADDRESS": "0.0.0.0:8200",
				"VAULT_DEV_ROOT_TOKEN_ID":  rootAuthorization,
			},
			HostAccessPorts: []int{jwksPort},
			WaitingFor: wait.ForHTTP("/v1/sys/health").
				WithPort("8200/tcp").
				WithStartupTimeout(2 * time.Minute),
		},
		Started: true,
	})
	testcontainers.CleanupContainer(t, container)
	if err != nil {
		t.Fatalf("start Vault test container: %v", err)
	}

	address, err := container.Endpoint(ctx, "http")
	if err != nil {
		t.Fatalf("resolve Vault endpoint: %v", err)
	}
	rootClient := newVaultTestClient(t, address, rootAuthorization)
	t.Cleanup(rootClient.ClearToken)
	configureVaultFixture(t, ctx, rootClient, jwksPort, issuer, authMount, auditPath)

	controlAuthorization := createManagementAuthorization(t, ctx, rootClient, authMount)
	t.Cleanup(func() { controlAuthorization = "" })
	audits := &memoryAuditStore{}
	now := time.Now().UTC().Truncate(time.Second)
	config := validManagerConfig()
	config.VaultAddress = address
	config.AuthMount = authMount
	config.Clock = func() time.Time { return now }
	config.RequestTimeout = 10 * time.Second
	config.AuditStore = audits
	config.ClientProvider = ClientProviderFunc(func(context.Context) (*hashicorpapi.Client, error) {
		return newVaultClient(address, controlAuthorization)
	})
	manager, err := New(config)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	binding := validBinding()
	firstDescriptor, err := manager.EnableAccess(ctx, binding)
	if err != nil {
		t.Fatalf("first EnableAccess() error = %v", err)
	}
	secondDescriptor, err := manager.EnableAccess(ctx, binding)
	if err != nil {
		t.Fatalf("second EnableAccess() error = %v", err)
	}
	if firstDescriptor != secondDescriptor {
		t.Fatalf("idempotent descriptors differ: first %#v, second %#v", firstDescriptor, secondDescriptor)
	}
	if firstDescriptor.RequestID != binding.RequestID ||
		firstDescriptor.VaultAddress != address ||
		firstDescriptor.AuthMount != authMount ||
		firstDescriptor.AuthRole != "agentgate-role-"+binding.RequestID ||
		firstDescriptor.SecretsPath != "aws/creds/"+binding.VaultRole ||
		firstDescriptor.Audience != "vault" ||
		!firstDescriptor.ExpiresAt.Equal(now.Add(binding.GrantedTTL)) {
		t.Fatalf("redemption descriptor = %#v", firstDescriptor)
	}

	resources, err := manager.resourcesFor(binding)
	if err != nil {
		t.Fatalf("resourcesFor() error = %v", err)
	}
	storedPolicy, err := rootClient.Sys().GetPolicyWithContext(ctx, resources.policyName)
	if err != nil {
		t.Fatalf("read request policy: %v", err)
	}
	if !samePolicy(storedPolicy, resources.policy) ||
		strings.Count(storedPolicy, "\npath ") != 1 ||
		!strings.Contains(storedPolicy, `capabilities = ["read"]`) {
		t.Fatalf("stored request policy is not exact one-path read policy: %q", storedPolicy)
	}
	storedRole, err := rootClient.Logical().ReadWithContext(ctx, resources.rolePath)
	if err != nil {
		t.Fatalf("read request role: %v", err)
	}
	if storedRole == nil || !sameRole(storedRole.Data, resources) {
		t.Fatal("stored request role does not match exact binding")
	}

	controlClient := newVaultTestClient(t, address, controlAuthorization)
	if result, readErr := controlClient.Logical().ReadWithContext(ctx, resources.secretsPath); readErr == nil || result != nil {
		t.Fatal("AgentGate management authorization could read the credential data-plane path")
	}
	controlClient.ClearToken()

	conflicting := binding
	conflicting.SPIFFEID = "spiffe://agentgate.test/ns/agents/sa/different-runner"
	if _, err := manager.EnableAccess(ctx, conflicting); !errors.Is(err, ErrBindingConflict) {
		t.Fatalf("conflicting EnableAccess() error = %v, want %v", err, ErrBindingConflict)
	}

	matchingJWT := signTestJWT(t, signingKey, keyID, issuer, binding.SPIFFEID, []string{"vault"}, now)
	agentAuthorization := loginWithJWT(t, ctx, address, authMount, resources.roleName, matchingJWT)
	t.Cleanup(func() { agentAuthorization = "" })
	agentClient := newVaultTestClient(t, address, agentAuthorization)
	t.Cleanup(agentClient.ClearToken)
	allowed, err := agentClient.Logical().ReadWithContext(ctx, resources.secretsPath)
	if err != nil || allowed == nil || allowed.Data["proof"] != "allowed-path" {
		t.Fatalf("matching agent read failed without returning expected proof: error %v", err)
	}
	if sibling, siblingErr := agentClient.Logical().ReadWithContext(
		ctx,
		"aws/creds/terraform-sibling",
	); siblingErr == nil || sibling != nil {
		t.Fatal("matching agent token could read a sibling role path")
	}
	if _, privilegedErr := agentClient.Sys().ListPoliciesWithContext(ctx); privilegedErr == nil {
		t.Fatal("matching agent token could list privileged system policies")
	}

	mismatchedJWT := signTestJWT(
		t,
		signingKey,
		keyID,
		issuer,
		"spiffe://agentgate.test/ns/agents/sa/different-runner",
		[]string{"vault"},
		now,
	)
	if authorization, loginErr := tryJWTLogin(
		ctx,
		address,
		authMount,
		resources.roleName,
		mismatchedJWT,
	); loginErr == nil || authorization != "" {
		t.Fatal("mismatched SPIFFE subject authenticated to the request role")
	}
	wrongAudienceJWT := signTestJWT(
		t,
		signingKey,
		keyID,
		issuer,
		binding.SPIFFEID,
		[]string{"not-vault"},
		now,
	)
	if authorization, loginErr := tryJWTLogin(
		ctx,
		address,
		authMount,
		resources.roleName,
		wrongAudienceJWT,
	); loginErr == nil || authorization != "" {
		t.Fatal("wrong JWT audience authenticated to the request role")
	}

	assertVaultAuditAttribution(t, ctx, container, auditPath, authMount, resources, binding.SPIFFEID)

	report := expireBindingWithWorker(t, ctx, manager, binding.RequestID, firstDescriptor)
	assertRevocationReport(t, report)
	if role, readErr := rootClient.Logical().ReadWithContext(ctx, resources.rolePath); readErr != nil || role != nil {
		t.Fatalf("request role remains after revoke: present %t, error %v", role != nil, readErr)
	}
	if policy, readErr := rootClient.Sys().GetPolicyWithContext(ctx, resources.policyName); readErr != nil || policy != "" {
		t.Fatalf("request policy remains after revoke: policy %q, error %v", policy, readErr)
	}
	if authorization, loginErr := tryJWTLogin(
		ctx,
		address,
		authMount,
		resources.roleName,
		matchingJWT,
	); loginErr == nil || authorization != "" {
		t.Fatal("new direct login succeeded after request role removal")
	}
	secondReport, err := manager.Revoke(ctx, binding.RequestID)
	if err != nil {
		t.Fatalf("second Revoke() error = %v", err)
	}
	assertRevocationReport(t, secondReport)
	assertManagerAuditRecords(
		t,
		audits.snapshot(),
		binding,
		conflicting.SPIFFEID,
		resources,
		rootAuthorization,
		controlAuthorization,
		agentAuthorization,
		matchingJWT,
		mismatchedJWT,
		wrongAudienceJWT,
	)
}

func expireBindingWithWorker(
	t *testing.T,
	ctx context.Context,
	manager vaultmgr.VaultManager,
	requestID string,
	descriptor authz.RedemptionDescriptor,
) vaultmgr.RevocationReport {
	t.Helper()
	store := approval.NewMemoryStore()
	descriptor.ExpiresAt = time.Now().UTC().Add(-time.Second)
	if _, _, err := store.Create(ctx, approval.Record{
		AccessRequest: authz.AccessRequest{RequestID: requestID},
		BindingState:  approval.BindingEnabled,
		Descriptor:    &descriptor,
	}); err != nil {
		t.Fatalf("create expired binding record: %v", err)
	}
	worker, err := expiry.NewWorker(
		store,
		manager,
		slog.New(slog.NewTextHandler(io.Discard, nil)),
	)
	if err != nil {
		t.Fatalf("create expiry worker: %v", err)
	}
	workerContext, cancel := context.WithCancel(ctx)
	done := make(chan struct{})
	go func() {
		defer close(done)
		worker.Run(workerContext)
	}()
	t.Cleanup(func() {
		cancel()
		<-done
	})

	deadline := time.NewTimer(10 * time.Second)
	defer deadline.Stop()
	ticker := time.NewTicker(10 * time.Millisecond)
	defer ticker.Stop()
	for {
		select {
		case <-deadline.C:
			t.Fatal("expiry worker did not revoke the Vault binding")
		case <-ticker.C:
			record, getErr := store.Get(ctx, requestID)
			if getErr != nil {
				t.Fatalf("read expiry worker result: %v", getErr)
			}
			if record.BindingState == approval.BindingRevoked && record.Revocation != nil {
				cancel()
				<-done
				return *record.Revocation
			}
		}
	}
}

func configureVaultFixture(
	t *testing.T,
	ctx context.Context,
	client *hashicorpapi.Client,
	jwksPort int,
	issuer string,
	authMount string,
	auditPath string,
) {
	t.Helper()
	if err := client.Sys().EnableAuditWithOptionsWithContext(
		ctx,
		"agentgate-test",
		&hashicorpapi.EnableAuditOptions{
			Type: "file",
			Options: map[string]string{
				"file_path": auditPath,
				"log_raw":   "false",
			},
		},
	); err != nil {
		t.Fatalf("enable Vault audit device: %v", err)
	}
	if err := client.Sys().EnableAuthWithOptionsWithContext(
		ctx,
		authMount,
		&hashicorpapi.EnableAuthOptions{Type: "jwt"},
	); err != nil {
		t.Fatalf("enable JWT auth: %v", err)
	}
	jwksURL := fmt.Sprintf("http://%s:%d/jwks", testcontainers.HostInternal, jwksPort)
	if _, err := client.Logical().WriteWithContext(
		ctx,
		"auth/"+authMount+"/config",
		map[string]any{
			"bound_issuer":       issuer,
			"jwks_url":           jwksURL,
			"jwt_supported_algs": []string{"ES256"},
		},
	); err != nil {
		t.Fatalf("configure JWT auth: %v", err)
	}
	if err := client.Sys().MountWithContext(ctx, "aws", &hashicorpapi.MountInput{
		Type:    "kv",
		Options: map[string]string{"version": "1"},
	}); err != nil {
		t.Fatalf("mount deterministic test secrets engine: %v", err)
	}
	for path, proof := range map[string]string{
		"aws/creds/terraform-sandbox": "allowed-path",
		"aws/creds/terraform-sibling": "sibling-path",
	} {
		if _, err := client.Logical().WriteWithContext(
			ctx,
			path,
			map[string]any{"proof": proof},
		); err != nil {
			t.Fatalf("write deterministic test path %q: %v", path, err)
		}
	}
}

func createManagementAuthorization(
	t *testing.T,
	ctx context.Context,
	client *hashicorpapi.Client,
	authMount string,
) string {
	t.Helper()
	const policyName = "agentgate-integration-management"
	policy := fmt.Sprintf(`
path "auth/%s/role/agentgate-role-*" {
  capabilities = ["create", "read", "update", "delete"]
}

path "sys/policies/acl/agentgate-policy-*" {
  capabilities = ["create", "read", "update", "delete"]
}
`, authMount)
	if err := client.Sys().PutPolicyWithContext(ctx, policyName, policy); err != nil {
		t.Fatalf("write integration management policy: %v", err)
	}
	created, err := client.Auth().Token().CreateWithContext(ctx, &hashicorpapi.TokenCreateRequest{
		Policies:        []string{policyName},
		TTL:             "5m",
		ExplicitMaxTTL:  "5m",
		NoDefaultPolicy: true,
		DisplayName:     "agentgate-control-plane",
	})
	if err != nil {
		t.Fatalf("create integration management authorization: %v", err)
	}
	if created == nil || created.Auth == nil || created.Auth.ClientToken == "" {
		t.Fatal("Vault returned no integration management authorization")
	}
	authorization := created.Auth.ClientToken
	created.Auth.ClientToken = ""
	return authorization
}

func startJWKSServer(
	t *testing.T,
	privateKey *ecdsa.PrivateKey,
	keyID string,
) (*httptest.Server, int) {
	t.Helper()
	jwks, err := json.Marshal(map[string]any{
		"keys": []jose.JSONWebKey{{
			Key:       &privateKey.PublicKey,
			KeyID:     keyID,
			Algorithm: string(jose.ES256),
			Use:       "sig",
		}},
	})
	if err != nil {
		t.Fatalf("encode static test JWKS: %v", err)
	}
	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		if request.URL.Path != "/jwks" {
			http.NotFound(response, request)
			return
		}
		response.Header().Set("Content-Type", "application/json")
		response.Header().Set("Cache-Control", "public, max-age=300")
		_, _ = response.Write(jwks)
	}))
	parsed, err := url.Parse(server.URL)
	if err != nil {
		server.Close()
		t.Fatalf("parse JWKS server URL: %v", err)
	}
	_, rawPort, err := net.SplitHostPort(parsed.Host)
	if err != nil {
		server.Close()
		t.Fatalf("parse JWKS server port: %v", err)
	}
	port, err := strconv.Atoi(rawPort)
	if err != nil {
		server.Close()
		t.Fatalf("parse JWKS port: %v", err)
	}
	return server, port
}

func signTestJWT(
	t *testing.T,
	privateKey *ecdsa.PrivateKey,
	keyID string,
	issuer string,
	subject string,
	audiences []string,
	now time.Time,
) string {
	t.Helper()
	signer, err := jose.NewSigner(
		jose.SigningKey{Algorithm: jose.ES256, Key: privateKey},
		(&jose.SignerOptions{}).WithType("JWT").WithHeader("kid", keyID),
	)
	if err != nil {
		t.Fatalf("create JWT signer: %v", err)
	}
	serialized, err := josejwt.Signed(signer).Claims(josejwt.Claims{
		Issuer:    issuer,
		Subject:   subject,
		Audience:  josejwt.Audience(audiences),
		Expiry:    josejwt.NewNumericDate(now.Add(2 * time.Minute)),
		NotBefore: josejwt.NewNumericDate(now.Add(-time.Second)),
		IssuedAt:  josejwt.NewNumericDate(now),
		ID:        randomOpaqueValue(t),
	}).Serialize()
	if err != nil {
		t.Fatalf("sign test JWT: %v", err)
	}
	return serialized
}

func staticTestJWTSigningKey(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), repeatingByteReader(0x42))
	if err != nil {
		t.Fatalf("generate static test-only JWT signing key: %v", err)
	}
	return privateKey
}

type repeatingByteReader byte

func (r repeatingByteReader) Read(destination []byte) (int, error) {
	for index := range destination {
		destination[index] = byte(r)
	}
	return len(destination), nil
}

func requireDocker(t *testing.T) {
	t.Helper()
	defer func() {
		if recovered := recover(); recovered != nil {
			handleDockerUnavailable(t, fmt.Sprint(recovered))
		}
	}()
	provider, err := testcontainers.ProviderDocker.GetProvider()
	if err == nil {
		err = provider.Health(context.Background())
	}
	if err != nil {
		handleDockerUnavailable(t, err.Error())
	}
}

func handleDockerUnavailable(t *testing.T, reason string) {
	t.Helper()
	if os.Getenv("AGENTGATE_REQUIRE_DOCKER") == "true" {
		t.Fatalf("Docker is required for the Vault integration test: %s", reason)
	}
	t.Skipf("Docker is unavailable; skipping real Vault integration: %s", reason)
}

func loginWithJWT(
	t *testing.T,
	ctx context.Context,
	address string,
	authMount string,
	roleName string,
	serializedJWT string,
) string {
	t.Helper()
	authorization, err := tryJWTLogin(ctx, address, authMount, roleName, serializedJWT)
	if err != nil {
		t.Fatalf("matching direct JWT login failed: %v", err)
	}
	if authorization == "" {
		t.Fatal("matching direct JWT login returned no authorization")
	}
	return authorization
}

func tryJWTLogin(
	ctx context.Context,
	address string,
	authMount string,
	roleName string,
	serializedJWT string,
) (string, error) {
	client, err := newVaultClient(address, "")
	if err != nil {
		return "", err
	}
	result, err := client.Logical().WriteWithContext(
		ctx,
		"auth/"+authMount+"/login",
		map[string]any{
			"jwt":  serializedJWT,
			"role": roleName,
		},
	)
	if err != nil {
		return "", err
	}
	if result == nil || result.Auth == nil || result.Auth.ClientToken == "" {
		return "", fmt.Errorf("Vault returned no client authorization")
	}
	authorization := result.Auth.ClientToken
	result.Auth.ClientToken = ""
	return authorization, nil
}

func newVaultTestClient(t *testing.T, address string, authorization string) *hashicorpapi.Client {
	t.Helper()
	client, err := newVaultClient(address, authorization)
	if err != nil {
		t.Fatalf("create Vault test client: %v", err)
	}
	return client
}

func newVaultClient(address string, authorization string) (*hashicorpapi.Client, error) {
	config := hashicorpapi.DefaultConfig()
	config.Address = address
	config.MaxRetries = 0
	client, err := hashicorpapi.NewClient(config)
	if err != nil {
		return nil, err
	}
	if authorization != "" {
		client.SetToken(authorization)
	}
	return client, nil
}

func assertVaultAuditAttribution(
	t *testing.T,
	ctx context.Context,
	container testcontainers.Container,
	auditPath string,
	authMount string,
	resources bindingResources,
	subject string,
) {
	t.Helper()
	reader, err := container.CopyFileFromContainer(ctx, auditPath)
	if err != nil {
		t.Fatalf("read Vault audit device: %v", err)
	}
	defer func() { _ = reader.Close() }()

	type auditEntry struct {
		Type string `json:"type"`
		Auth struct {
			DisplayName string            `json:"display_name"`
			Metadata    map[string]string `json:"metadata"`
		} `json:"auth"`
		Request struct {
			Path string `json:"path"`
		} `json:"request"`
	}
	loginAttributed := false
	readAttributed := false
	scanner := bufio.NewScanner(io.LimitReader(reader, 4<<20))
	scanner.Buffer(make([]byte, 64<<10), 1<<20)
	for scanner.Scan() {
		var entry auditEntry
		if err := json.Unmarshal(scanner.Bytes(), &entry); err != nil {
			t.Fatalf("decode Vault audit entry: %v", err)
		}
		attributedToSubject := strings.Contains(entry.Auth.DisplayName, subject)
		if entry.Request.Path == "auth/"+authMount+"/login" &&
			entry.Type == "response" &&
			attributedToSubject {
			loginAttributed = true
		}
		if entry.Request.Path == resources.secretsPath && attributedToSubject {
			readAttributed = true
		}
	}
	if err := scanner.Err(); err != nil {
		t.Fatalf("scan Vault audit entries: %v", err)
	}
	if !loginAttributed {
		t.Fatal("Vault audit did not attribute matching direct login to the agent subject")
	}
	if !readAttributed {
		t.Fatal("Vault audit did not attribute allowed path activity to the agent subject")
	}
}

func assertRevocationReport(t *testing.T, report vaultmgr.RevocationReport) {
	t.Helper()
	if report.RequestID != validBinding().RequestID ||
		!report.RoleRemoved ||
		!report.PolicyRemoved ||
		report.LeasesRevoked ||
		!report.STSCredentialsMayRemain ||
		len(report.Warnings) == 0 ||
		!strings.Contains(strings.ToLower(strings.Join(report.Warnings, " ")), "remain") {
		t.Fatalf("revocation report = %#v", report)
	}
}

func assertManagerAuditRecords(
	t *testing.T,
	records []audit.AuditRecord,
	binding vaultmgr.AccessBinding,
	conflictingSPIFFEID string,
	resources bindingResources,
	prohibitedValues ...string,
) {
	t.Helper()
	var enabled, failed, revoked int
	for _, record := range records {
		if record.RequestID != binding.RequestID ||
			record.OnBehalfOf != binding.OnBehalfOf ||
			record.VaultAuthRole != resources.roleName ||
			record.EventID == "" {
			t.Fatal("manager audit correlation metadata is incomplete")
		}
		switch record.EventType {
		case audit.EventBindingEnabled:
			enabled++
			if record.SPIFFEID != binding.SPIFFEID ||
				record.AWSSessionName != binding.RequestID ||
				record.Details["vault_role"] != binding.VaultRole ||
				record.Details["policy_version"] != binding.PolicyVersion ||
				record.Details["vault_policy_name"] != resources.policyName {
				t.Fatalf("binding audit role metadata = %#v", record.Details)
			}
		case audit.EventBindingFailed:
			failed++
			if record.SPIFFEID != conflictingSPIFFEID ||
				record.Details["failure_kind"] != "binding_conflict" {
				t.Fatal("binding conflict audit did not preserve the attempted subject")
			}
		case audit.EventRevocation:
			revoked++
			if record.SPIFFEID != binding.SPIFFEID ||
				record.Details["sts_may_remain"] != "true" {
				t.Fatal("revocation audit did not preserve the established binding")
			}
		default:
			t.Fatalf("unexpected manager audit event type %q", record.EventType)
		}
	}
	if enabled != 2 || failed != 1 || revoked != 2 {
		t.Fatalf("manager audit counts = enabled %d, failed %d, revoked %d", enabled, failed, revoked)
	}
	encoded, err := json.Marshal(records)
	if err != nil {
		t.Fatalf("encode manager audit records: %v", err)
	}
	for _, prohibited := range prohibitedValues {
		if prohibited != "" && strings.Contains(string(encoded), prohibited) {
			t.Fatal("manager audit records contain credential material")
		}
	}
}
