package vaultapi

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	hashicorpapi "github.com/hashicorp/vault/api"
	"github.com/jaezeu/agentgate/internal/audit"
	"github.com/jaezeu/agentgate/internal/authz"
	"github.com/jaezeu/agentgate/internal/vaultmgr"
)

func TestNewValidatesConfigurationBoundaries(t *testing.T) {
	t.Parallel()

	valid := validManagerConfig()
	if _, err := New(valid); err != nil {
		t.Fatalf("New(valid) error = %v", err)
	}

	tests := []struct {
		name   string
		mutate func(*Config)
	}{
		{
			name:   "address path",
			mutate: func(config *Config) { config.VaultAddress = "https://vault.example.test/v1" },
		},
		{
			name:   "address credentials",
			mutate: func(config *Config) { config.VaultAddress = "https://user@vault.example.test" },
		},
		{
			name:   "namespace traversal",
			mutate: func(config *Config) { config.Namespace = "team/../root" },
		},
		{
			name:   "noncanonical auth mount",
			mutate: func(config *Config) { config.AuthMount = "/jwt" },
		},
		{
			name:   "role prefix wildcard",
			mutate: func(config *Config) { config.RolePrefix = "agentgate-*" },
		},
		{
			name:   "policy prefix path",
			mutate: func(config *Config) { config.PolicyPrefix = "agentgate/policy-" },
		},
		{
			name:   "AWS mount traversal",
			mutate: func(config *Config) { config.AWSMount = "aws/../../sys" },
		},
		{
			name:   "zero request timeout",
			mutate: func(config *Config) { config.RequestTimeout = 0 },
		},
		{
			name:   "unbounded request timeout",
			mutate: func(config *Config) { config.RequestTimeout = 31 * time.Second },
		},
		{
			name:   "missing clock",
			mutate: func(config *Config) { config.Clock = nil },
		},
		{
			name:   "missing client provider",
			mutate: func(config *Config) { config.ClientProvider = nil },
		},
		{
			name:   "missing audit store",
			mutate: func(config *Config) { config.AuditStore = nil },
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			config := valid
			test.mutate(&config)
			_, err := New(config)
			if !errors.Is(err, ErrInvalidConfiguration) {
				t.Fatalf("New() error = %v, want %v", err, ErrInvalidConfiguration)
			}
		})
	}
}

func TestResourcesForValidatesAndScopesBinding(t *testing.T) {
	t.Parallel()

	manager, err := New(validManagerConfig())
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	binding := validBinding()
	resources, err := manager.resourcesFor(binding)
	if err != nil {
		t.Fatalf("resourcesFor() error = %v", err)
	}
	if resources.roleName != "agentgate-role-"+binding.RequestID {
		t.Fatalf("role name = %q", resources.roleName)
	}
	if resources.policyName != "agentgate-policy-"+binding.RequestID {
		t.Fatalf("policy name = %q", resources.policyName)
	}
	if resources.secretsPath != "aws/creds/"+binding.VaultRole {
		t.Fatalf("secrets path = %q", resources.secretsPath)
	}
	if strings.Count(resources.policy, "\npath ") != 1 ||
		!strings.Contains(resources.policy, `path "aws/creds/terraform-sandbox"`) ||
		!strings.Contains(resources.policy, `capabilities = ["read"]`) {
		t.Fatalf("policy is not one-path read-only policy: %q", resources.policy)
	}
	for _, forbidden := range []string{"list", "sudo", "sys/", "identity/", "auth/", `path "*"`} {
		if strings.Contains(resources.policy, forbidden) {
			t.Fatalf("policy contains forbidden scope %q", forbidden)
		}
	}
	if !sameRole(resources.roleData, resources) {
		t.Fatal("generated role does not satisfy its exact binding")
	}

	tests := []struct {
		name   string
		mutate func(*vaultmgr.AccessBinding)
	}{
		{
			name:   "request path injection",
			mutate: func(candidate *vaultmgr.AccessBinding) { candidate.RequestID = "../request" },
		},
		{
			name: "request name too long",
			mutate: func(candidate *vaultmgr.AccessBinding) {
				candidate.RequestID = strings.Repeat("a", maxVaultNameLength)
			},
		},
		{
			name: "wildcard subject",
			mutate: func(candidate *vaultmgr.AccessBinding) {
				candidate.SPIFFEID = "spiffe://agentgate.test/ns/agents/sa/*"
			},
		},
		{
			name:   "invalid subject",
			mutate: func(candidate *vaultmgr.AccessBinding) { candidate.SPIFFEID = "https://agent.example.test" },
		},
		{
			name: "subject too long",
			mutate: func(candidate *vaultmgr.AccessBinding) {
				candidate.SPIFFEID = "spiffe://agentgate.test/" + strings.Repeat("a", maxSPIFFEIDLength)
			},
		},
		{
			name:   "role path injection",
			mutate: func(candidate *vaultmgr.AccessBinding) { candidate.VaultRole = "allowed/sibling" },
		},
		{
			name: "role too long",
			mutate: func(candidate *vaultmgr.AccessBinding) {
				candidate.VaultRole = strings.Repeat("a", maxVaultRoleLength+1)
			},
		},
		{
			name:   "zero TTL",
			mutate: func(candidate *vaultmgr.AccessBinding) { candidate.GrantedTTL = 0 },
		},
		{
			name:   "subsecond TTL",
			mutate: func(candidate *vaultmgr.AccessBinding) { candidate.GrantedTTL = 1500 * time.Millisecond },
		},
		{
			name:   "TTL above policy maximum",
			mutate: func(candidate *vaultmgr.AccessBinding) { candidate.GrantedTTL = time.Hour + time.Second },
		},
		{
			name: "uppercase policy digest",
			mutate: func(candidate *vaultmgr.AccessBinding) {
				candidate.PolicyVersion = strings.Repeat("A", 64)
			},
		},
		{
			name:   "missing human attribution",
			mutate: func(candidate *vaultmgr.AccessBinding) { candidate.OnBehalfOf = "" },
		},
		{
			name: "human attribution too long",
			mutate: func(candidate *vaultmgr.AccessBinding) {
				candidate.OnBehalfOf = strings.Repeat("a", maxOnBehalfOfLength+1)
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			candidate := binding
			test.mutate(&candidate)
			_, resourceErr := manager.resourcesFor(candidate)
			if !errors.Is(resourceErr, ErrInvalidBinding) {
				t.Fatalf("resourcesFor() error = %v, want %v", resourceErr, ErrInvalidBinding)
			}
		})
	}
}

func TestSameRoleRejectsConflictingSecurityFields(t *testing.T) {
	t.Parallel()

	manager, err := New(validManagerConfig())
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	resources, err := manager.resourcesFor(validBinding())
	if err != nil {
		t.Fatalf("resourcesFor() error = %v", err)
	}

	tests := []struct {
		name   string
		mutate func(map[string]interface{})
	}{
		{
			name: "different subject",
			mutate: func(role map[string]interface{}) {
				role["bound_subject"] = "spiffe://agentgate.test/ns/agents/sa/different-runner"
			},
		},
		{
			name: "wildcard audience",
			mutate: func(role map[string]interface{}) {
				role["bound_audiences"] = []string{"*"}
			},
		},
		{
			name: "additional policy",
			mutate: func(role map[string]interface{}) {
				role["token_policies"] = []string{resources.policyName, "privileged"}
			},
		},
		{
			name: "default policy enabled",
			mutate: func(role map[string]interface{}) {
				role["token_no_default_policy"] = false
			},
		},
		{
			name: "different token TTL",
			mutate: func(role map[string]interface{}) {
				role["token_ttl"] = int64(time.Minute / time.Second)
			},
		},
		{
			name: "different maximum TTL",
			mutate: func(role map[string]interface{}) {
				role["token_max_ttl"] = int64(time.Minute / time.Second)
			},
		},
		{
			name: "missing explicit maximum TTL",
			mutate: func(role map[string]interface{}) {
				delete(role, "token_explicit_max_ttl")
			},
		},
		{
			name: "periodic token",
			mutate: func(role map[string]interface{}) {
				role["token_period"] = int64(time.Minute / time.Second)
			},
		},
		{
			name: "bound CIDR",
			mutate: func(role map[string]interface{}) {
				role["token_bound_cidrs"] = []string{"192.0.2.0/24"}
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			role := make(map[string]interface{}, len(resources.roleData))
			for key, value := range resources.roleData {
				role[key] = value
			}
			test.mutate(role)
			if sameRole(role, resources) {
				t.Fatal("sameRole() accepted conflicting role data")
			}
		})
	}
}

func TestEnableAccessFailsClosedOnConflictAndAuditsFailure(t *testing.T) {
	t.Parallel()

	controlAuthorization := randomOpaqueValue(t)
	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		if request.Header.Get("X-Vault-Token") != controlAuthorization {
			t.Error("request did not use the injected control-plane authorization")
		}
		switch {
		case request.Method == http.MethodGet &&
			strings.HasPrefix(request.URL.Path, "/v1/sys/policies/acl/"):
			writeTestVaultResponse(t, response, http.StatusOK, map[string]any{
				"data": map[string]any{
					"policy": `path "sys/*" { capabilities = ["sudo"] }`,
				},
			})
		case request.Method == http.MethodGet &&
			strings.HasPrefix(request.URL.Path, "/v1/auth/jwt/role/"):
			response.WriteHeader(http.StatusNotFound)
		default:
			t.Errorf("unexpected Vault request: %s %s", request.Method, request.URL.Path)
			response.WriteHeader(http.StatusNotFound)
		}
	}))
	t.Cleanup(server.Close)

	audits := &memoryAuditStore{}
	manager := newHTTPTestManager(t, server.URL, controlAuthorization, audits)
	descriptor, err := manager.EnableAccess(context.Background(), validBinding())
	if !errors.Is(err, ErrBindingConflict) {
		t.Fatalf("EnableAccess() error = %v, want %v", err, ErrBindingConflict)
	}
	if descriptor != (authz.RedemptionDescriptor{}) {
		t.Fatalf("EnableAccess() returned descriptor after conflict: %#v", descriptor)
	}
	records := audits.snapshot()
	if len(records) != 1 || records[0].EventType != audit.EventBindingFailed {
		t.Fatalf("failure audit records = %#v", records)
	}
	if records[0].Details["failure_kind"] != "binding_conflict" ||
		records[0].SPIFFEID != validBinding().SPIFFEID ||
		records[0].OnBehalfOf != validBinding().OnBehalfOf {
		t.Fatalf("failure audit metadata = %#v", records[0])
	}
}

func TestVaultResponseBodyIsNotReturnedOrAudited(t *testing.T) {
	t.Parallel()

	responseMarker := "do-not-return-this-vault-response"
	controlAuthorization := randomOpaqueValue(t)
	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) {
		writeTestVaultResponse(t, response, http.StatusInternalServerError, map[string]any{
			"errors": []string{responseMarker},
		})
	}))
	t.Cleanup(server.Close)

	audits := &memoryAuditStore{}
	manager := newHTTPTestManager(t, server.URL, controlAuthorization, audits)
	_, err := manager.EnableAccess(context.Background(), validBinding())
	if !errors.Is(err, ErrVaultOperation) {
		t.Fatalf("EnableAccess() error = %v, want %v", err, ErrVaultOperation)
	}
	if strings.Contains(err.Error(), responseMarker) ||
		strings.Contains(err.Error(), controlAuthorization) {
		t.Fatal("EnableAccess() exposed Vault response or authorization material")
	}
	var operationError *OperationError
	if !errors.As(err, &operationError) || operationError.StatusCode != http.StatusInternalServerError {
		t.Fatalf("EnableAccess() operation error = %#v", operationError)
	}
	encodedAudits, encodeErr := json.Marshal(audits.snapshot())
	if encodeErr != nil {
		t.Fatalf("marshal audit records: %v", encodeErr)
	}
	if strings.Contains(string(encodedAudits), responseMarker) ||
		strings.Contains(string(encodedAudits), controlAuthorization) {
		t.Fatal("audit record exposed Vault response or authorization material")
	}
}

func TestEnableAccessUsesBoundedRequestContext(t *testing.T) {
	t.Parallel()

	controlAuthorization := randomOpaqueValue(t)
	server := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, request *http.Request) {
		<-request.Context().Done()
	}))
	t.Cleanup(server.Close)

	audits := &memoryAuditStore{}
	config := validManagerConfig()
	config.VaultAddress = server.URL
	config.RequestTimeout = 50 * time.Millisecond
	config.AuditStore = audits
	config.ClientProvider = ClientProviderFunc(func(context.Context) (*hashicorpapi.Client, error) {
		clientConfig := hashicorpapi.DefaultConfig()
		clientConfig.Address = server.URL
		clientConfig.MaxRetries = 0
		client, err := hashicorpapi.NewClient(clientConfig)
		if err != nil {
			return nil, err
		}
		client.SetToken(controlAuthorization)
		return client, nil
	})
	manager, err := New(config)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	startedAt := time.Now()
	_, err = manager.EnableAccess(context.Background(), validBinding())
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("EnableAccess() error = %v, want %v", err, context.DeadlineExceeded)
	}
	if time.Since(startedAt) > time.Second {
		t.Fatal("EnableAccess() exceeded its bounded request timeout")
	}
	records := audits.snapshot()
	if len(records) != 1 || records[0].Details["failure_kind"] != "deadline_exceeded" {
		t.Fatalf("timeout audit records = %#v", records)
	}
}

func TestRevokeDeletesRoleBeforePolicyAndIsIdempotent(t *testing.T) {
	t.Parallel()

	controlAuthorization := randomOpaqueValue(t)
	var (
		requestsMu sync.Mutex
		requests   []string
	)
	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		requestsMu.Lock()
		requests = append(requests, request.Method+" "+request.URL.Path)
		requestsMu.Unlock()
		switch request.Method {
		case http.MethodDelete:
			response.WriteHeader(http.StatusNoContent)
		case http.MethodGet:
			response.WriteHeader(http.StatusNotFound)
		default:
			response.WriteHeader(http.StatusMethodNotAllowed)
		}
	}))
	t.Cleanup(server.Close)

	audits := &memoryAuditStore{}
	manager := newHTTPTestManager(t, server.URL, controlAuthorization, audits)
	for attempt := 0; attempt < 2; attempt++ {
		report, err := manager.Revoke(context.Background(), validBinding().RequestID)
		if err != nil {
			t.Fatalf("Revoke(attempt %d) error = %v", attempt+1, err)
		}
		if !report.RoleRemoved || !report.PolicyRemoved || report.LeasesRevoked ||
			!report.STSCredentialsMayRemain || len(report.Warnings) == 0 {
			t.Fatalf("Revoke(attempt %d) report = %#v", attempt+1, report)
		}
	}

	requestID := validBinding().RequestID
	rolePath := "/v1/auth/jwt/role/agentgate-role-" + requestID
	policyPath := "/v1/sys/policies/acl/agentgate-policy-" + requestID
	want := []string{
		"DELETE " + rolePath,
		"GET " + rolePath,
		"DELETE " + policyPath,
		"GET " + policyPath,
		"DELETE " + rolePath,
		"GET " + rolePath,
		"DELETE " + policyPath,
		"GET " + policyPath,
	}
	requestsMu.Lock()
	defer requestsMu.Unlock()
	if strings.Join(requests, "\n") != strings.Join(want, "\n") {
		t.Fatalf("Vault request order = %#v, want %#v", requests, want)
	}
	for _, request := range requests {
		if strings.Contains(request, "/sys/leases/") {
			t.Fatalf("Revoke() attempted unsafe broad lease revocation: %q", request)
		}
	}
	records := audits.snapshot()
	if len(records) != 2 {
		t.Fatalf("revocation audit records = %d, want 2", len(records))
	}
	for _, record := range records {
		if record.EventType != audit.EventRevocation ||
			record.Details["role_removed"] != "true" ||
			record.Details["policy_removed"] != "true" ||
			record.Details["leases_revoked"] != "false" ||
			record.Details["sts_may_remain"] != "true" {
			t.Fatalf("revocation audit record = %#v", record)
		}
	}
}

func validManagerConfig() Config {
	return Config{
		VaultAddress:   "https://vault.example.test",
		Namespace:      "",
		AuthMount:      "jwt",
		RolePrefix:     "agentgate-role-",
		PolicyPrefix:   "agentgate-policy-",
		AWSMount:       "aws",
		RequestTimeout: 2 * time.Second,
		Clock: func() time.Time {
			return time.Date(2030, time.January, 2, 15, 4, 5, 0, time.UTC)
		},
		ClientProvider: ClientProviderFunc(func(context.Context) (*hashicorpapi.Client, error) {
			return nil, errors.New("unused test client provider")
		}),
		AuditStore: &memoryAuditStore{},
	}
}

func validBinding() vaultmgr.AccessBinding {
	return vaultmgr.AccessBinding{
		RequestID:     "018f47f2-4d8a-7b22-98e0-9b638c715d22",
		SPIFFEID:      "spiffe://agentgate.test/ns/agents/sa/terraform-runner",
		VaultRole:     "terraform-sandbox",
		GrantedTTL:    15 * time.Minute,
		PolicyVersion: strings.Repeat("a", 64),
		OnBehalfOf:    "operator@example.test",
	}
}

func newHTTPTestManager(
	t *testing.T,
	address string,
	controlAuthorization string,
	audits audit.AuditStore,
) *Manager {
	t.Helper()
	config := validManagerConfig()
	config.VaultAddress = address
	config.AuditStore = audits
	config.ClientProvider = ClientProviderFunc(func(context.Context) (*hashicorpapi.Client, error) {
		clientConfig := hashicorpapi.DefaultConfig()
		clientConfig.Address = address
		clientConfig.MaxRetries = 0
		client, err := hashicorpapi.NewClient(clientConfig)
		if err != nil {
			return nil, err
		}
		client.SetToken(controlAuthorization)
		return client, nil
	})
	manager, err := New(config)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	return manager
}

func randomOpaqueValue(t *testing.T) string {
	t.Helper()
	value := make([]byte, 32)
	if _, err := rand.Read(value); err != nil {
		t.Fatalf("generate opaque test value: %v", err)
	}
	return base64.RawURLEncoding.EncodeToString(value)
}

func writeTestVaultResponse(
	t *testing.T,
	response http.ResponseWriter,
	status int,
	value any,
) {
	t.Helper()
	response.Header().Set("Content-Type", "application/json")
	response.WriteHeader(status)
	if err := json.NewEncoder(response).Encode(value); err != nil {
		t.Errorf("encode test Vault response: %v", err)
	}
}

type memoryAuditStore struct {
	mu        sync.Mutex
	records   []audit.AuditRecord
	appendErr error
	readErr   error
}

func (s *memoryAuditStore) Append(_ context.Context, record audit.AuditRecord) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.appendErr != nil {
		return s.appendErr
	}
	s.records = append(s.records, cloneAuditRecord(record))
	return nil
}

func (s *memoryAuditStore) ByRequestID(
	_ context.Context,
	requestID string,
) ([]audit.AuditRecord, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.readErr != nil {
		return nil, s.readErr
	}
	records := make([]audit.AuditRecord, 0)
	for _, record := range s.records {
		if record.RequestID == requestID {
			records = append(records, cloneAuditRecord(record))
		}
	}
	return records, nil
}

func (s *memoryAuditStore) List(
	_ context.Context,
	query audit.Query,
) ([]audit.AuditRecord, error) {
	return s.ByRequestID(context.Background(), query.RequestID)
}

func (s *memoryAuditStore) snapshot() []audit.AuditRecord {
	s.mu.Lock()
	defer s.mu.Unlock()
	records := make([]audit.AuditRecord, 0, len(s.records))
	for _, record := range s.records {
		records = append(records, cloneAuditRecord(record))
	}
	return records
}

func cloneAuditRecord(record audit.AuditRecord) audit.AuditRecord {
	cloned := record
	cloned.Details = make(map[string]string, len(record.Details))
	for key, value := range record.Details {
		cloned.Details[key] = value
	}
	if record.Decision != nil {
		decision := *record.Decision
		cloned.Decision = &decision
	}
	return cloned
}
