package authz

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/jaezeu/agentgate/internal/grant"
	policybundle "github.com/jaezeu/agentgate/policies"
)

func TestEmbeddedPolicyEngineEvaluatesTrustedAccessRequest(t *testing.T) {
	engine := newTestPolicyEngine(t)
	request := validAccessRequest()

	decision, err := engine.Evaluate(context.Background(), request)
	if err != nil {
		t.Fatalf("Evaluate() error = %v", err)
	}
	if decision.Kind != DecisionAllow {
		t.Fatalf("Decision.Kind = %q, want %q", decision.Kind, DecisionAllow)
	}
	if decision.Reason != "allow.scope_valid: workload identity and signed task scope are allowed" {
		t.Fatalf("Decision.Reason = %q", decision.Reason)
	}
	if decision.GrantedTTL != 10*time.Minute {
		t.Fatalf("Decision.GrantedTTL = %s, want %s", decision.GrantedTTL, 10*time.Minute)
	}
	if !decision.DecidedAt.Equal(request.RequestedAt) {
		t.Fatalf("Decision.DecidedAt = %s, want %s", decision.DecidedAt, request.RequestedAt)
	}

	expectedVersion := hashBundle(policybundle.AuthorizationBundle())
	if decision.PolicyVersion != expectedVersion {
		t.Fatalf("Decision.PolicyVersion = %q, want %q", decision.PolicyVersion, expectedVersion)
	}
}

func TestPolicyInputContainsOnlyRequiredCredentialFreeValues(t *testing.T) {
	request := validAccessRequest()
	input := policyInput(request)

	wantTopLevelKeys := []string{
		"current_time",
		"request_id",
		"requested_vault_role",
		"spiffe_id",
		"task_grant",
	}
	assertMapKeys(t, input, wantTopLevelKeys)

	taskGrant, ok := input["task_grant"].(map[string]any)
	if !ok {
		t.Fatalf("task_grant type = %T, want map[string]any", input["task_grant"])
	}
	wantGrantKeys := []string{
		"commit_sha",
		"environment",
		"issued_at",
		"nonce",
		"on_behalf_of",
		"operation",
		"repo",
		"request_id",
		"ticket_id",
		"ttl",
		"vault_role",
	}
	assertMapKeys(t, taskGrant, wantGrantKeys)

	if got := input["current_time"]; got != "2026-07-17T10:00:00.123456789Z" {
		t.Fatalf("current_time = %#v", got)
	}
	if got := taskGrant["issued_at"]; got != "2026-07-17T09:55:00.987654321Z" {
		t.Fatalf("task_grant.issued_at = %#v", got)
	}

	payload, err := json.Marshal(input)
	if err != nil {
		t.Fatalf("json.Marshal(policy input) error = %v", err)
	}
	for _, prohibited := range []string{
		"signature",
		"token",
		"lease",
		"access_key",
		"secret_key",
		"session_token",
		"credential",
	} {
		if strings.Contains(string(payload), prohibited) {
			t.Fatalf("policy input unexpectedly contains %q: %s", prohibited, payload)
		}
	}
}

func TestPolicyVersionIsSHA256OfExactEmbeddedBytes(t *testing.T) {
	source := policybundle.AuthorizationBundle()
	if source == "" {
		t.Fatal("AuthorizationBundle() is empty")
	}

	sum := sha256.Sum256([]byte(source))
	expected := hex.EncodeToString(sum[:])
	if got := hashBundle(source); got != expected {
		t.Fatalf("hashBundle() = %q, want %q", got, expected)
	}
	if got := hashBundle(source); len(got) != 64 || got != strings.ToLower(got) {
		t.Fatalf("hashBundle() = %q, want 64 lowercase hexadecimal characters", got)
	}

	engine := newTestPolicyEngine(t)
	decision, err := engine.Evaluate(context.Background(), validAccessRequest())
	if err != nil {
		t.Fatalf("Evaluate() error = %v", err)
	}
	if decision.PolicyVersion != expected {
		t.Fatalf("PolicyVersion = %q, want %q", decision.PolicyVersion, expected)
	}

	distinctSource := "# byte-distinct test bundle\n" + source
	distinctEngine, err := newEmbeddedPolicyEngine(context.Background(), distinctSource)
	if err != nil {
		t.Fatalf("newEmbeddedPolicyEngine(distinct source) error = %v", err)
	}
	distinctDecision, err := distinctEngine.Evaluate(context.Background(), validAccessRequest())
	if err != nil {
		t.Fatalf("Evaluate(distinct source) error = %v", err)
	}
	if distinctDecision.PolicyVersion != hashBundle(distinctSource) {
		t.Fatalf("distinct PolicyVersion = %q", distinctDecision.PolicyVersion)
	}
	if distinctDecision.PolicyVersion == decision.PolicyVersion {
		t.Fatal("byte-distinct bundles produced the same policy version")
	}
}

func TestEmbeddedPolicyEngineMapsAllDecisionKindsAndTTLs(t *testing.T) {
	engine := newTestPolicyEngine(t)

	tests := []struct {
		name       string
		mutate     func(*AccessRequest)
		wantKind   DecisionKind
		wantTTL    time.Duration
		wantReason string
	}{
		{
			name: "clamps an eligible request above fifteen minutes",
			mutate: func(request *AccessRequest) {
				request.TaskGrant.TTLSeconds = 1200
			},
			wantKind: DecisionAllow,
			wantTTL:  15 * time.Minute,
		},
		{
			name: "parks production apply only after scope validation",
			mutate: func(request *AccessRequest) {
				request.TaskGrant.Operation = grant.OperationTerraformApply
				request.TaskGrant.Environment = "prod"
				request.TaskGrant.TTLSeconds = 1200
			},
			wantKind: DecisionPendingApproval,
			wantTTL:  15 * time.Minute,
		},
		{
			name: "denies a request above sixty minutes",
			mutate: func(request *AccessRequest) {
				request.TaskGrant.TTLSeconds = 3601
			},
			wantKind:   DecisionDeny,
			wantReason: "deny.ttl_exceeds_maximum: signed task grant ttl must not exceed 3600 seconds",
		},
		{
			name: "denies correlation id mismatch",
			mutate: func(request *AccessRequest) {
				request.RequestID = "req-different"
			},
			wantKind:   DecisionDeny,
			wantReason: "deny.request_id_mismatch: access request_id must equal the signed task grant request_id",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			request := validAccessRequest()
			test.mutate(&request)

			decision, err := engine.Evaluate(context.Background(), request)
			if err != nil {
				t.Fatalf("Evaluate() error = %v", err)
			}
			if decision.Kind != test.wantKind {
				t.Fatalf("Decision.Kind = %q, want %q", decision.Kind, test.wantKind)
			}
			if decision.GrantedTTL != test.wantTTL {
				t.Fatalf("Decision.GrantedTTL = %s, want %s", decision.GrantedTTL, test.wantTTL)
			}
			if test.wantReason != "" && decision.Reason != test.wantReason {
				t.Fatalf("Decision.Reason = %q, want %q", decision.Reason, test.wantReason)
			}
			if decision.PolicyVersion == "" {
				t.Fatal("Decision.PolicyVersion is empty")
			}
		})
	}
}

func TestNewEmbeddedPolicyEngineFailsClosedOnBundleProblems(t *testing.T) {
	validDefault := `{
		"decision": "deny",
		"reason": "deny.default: test default",
		"granted_ttl_seconds": 0,
	}`

	tests := []struct {
		name   string
		source string
	}{
		{
			name:   "empty bundle",
			source: "",
		},
		{
			name:   "compile error",
			source: "package agentgate.authz\nthis is not valid rego",
		},
		{
			name: "missing required policy configuration",
			source: fmt.Sprintf(`
package agentgate.authz
import rego.v1
default decision := %s
`, validDefault),
		},
		{
			name: "malformed startup output",
			source: `
package agentgate.authz
import rego.v1
bundle_ready := true
default decision := {
	"decision": "allow",
	"reason": "allow.invalid: zero ttl",
	"granted_ttl_seconds": 0,
}
`,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			engine, err := newEmbeddedPolicyEngine(context.Background(), test.source)
			if err == nil {
				t.Fatalf("newEmbeddedPolicyEngine() = %#v, want error", engine)
			}
			if engine != nil {
				t.Fatalf("newEmbeddedPolicyEngine() engine = %#v, want nil", engine)
			}
		})
	}
}

func TestMalformedPolicyOutputFailsClosedWithPolicyVersion(t *testing.T) {
	tests := []struct {
		name   string
		output string
	}{
		{
			name:   "missing reason",
			output: `{"decision": "allow", "granted_ttl_seconds": 600}`,
		},
		{
			name:   "unsupported decision kind",
			output: `{"decision": "maybe", "reason": "invalid", "granted_ttl_seconds": 600}`,
		},
		{
			name:   "successful decision with zero ttl",
			output: `{"decision": "allow", "reason": "invalid", "granted_ttl_seconds": 0}`,
		},
		{
			name:   "deny decision with positive ttl",
			output: `{"decision": "deny", "reason": "invalid", "granted_ttl_seconds": 1}`,
		},
		{
			name:   "unknown output field",
			output: `{"decision": "allow", "reason": "invalid", "granted_ttl_seconds": 600, "token": "forbidden"}`,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			source := dynamicOutputPolicy(test.output)
			engine, err := newEmbeddedPolicyEngine(context.Background(), source)
			if err != nil {
				t.Fatalf("newEmbeddedPolicyEngine() error = %v", err)
			}

			decision, err := engine.Evaluate(context.Background(), validAccessRequest())
			if err == nil {
				t.Fatal("Evaluate() error = nil, want malformed output error")
			}
			if decision.Kind != DecisionDeny {
				t.Fatalf("Decision.Kind = %q, want %q", decision.Kind, DecisionDeny)
			}
			if decision.Reason != outputFailureReason {
				t.Fatalf("Decision.Reason = %q, want %q", decision.Reason, outputFailureReason)
			}
			if decision.GrantedTTL != 0 {
				t.Fatalf("Decision.GrantedTTL = %s, want 0", decision.GrantedTTL)
			}
			if decision.PolicyVersion != hashBundle(source) {
				t.Fatalf("Decision.PolicyVersion = %q", decision.PolicyVersion)
			}
		})
	}
}

func TestPolicyEvaluationErrorFailsClosedWithPolicyVersion(t *testing.T) {
	engine := newTestPolicyEngine(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	decision, err := engine.Evaluate(ctx, validAccessRequest())
	if err == nil {
		t.Fatal("Evaluate() error = nil, want cancellation error")
	}
	if decision.Kind != DecisionDeny {
		t.Fatalf("Decision.Kind = %q, want %q", decision.Kind, DecisionDeny)
	}
	if decision.Reason != evaluationFailureReason {
		t.Fatalf("Decision.Reason = %q, want %q", decision.Reason, evaluationFailureReason)
	}
	if decision.PolicyVersion != hashBundle(policybundle.AuthorizationBundle()) {
		t.Fatalf("Decision.PolicyVersion = %q", decision.PolicyVersion)
	}
}

func TestEmbeddedPolicyEngineSupportsConcurrentEvaluation(t *testing.T) {
	engine := newTestPolicyEngine(t)
	const evaluations = 100
	errors := make(chan error, evaluations)

	for index := 0; index < evaluations; index++ {
		index := index
		go func() {
			request := validAccessRequest()
			request.RequestID = fmt.Sprintf("req-policy-%03d", index)
			request.TaskGrant.RequestID = request.RequestID
			if index%2 == 1 {
				request.TaskGrant.TTLSeconds = 1200
			}

			decision, err := engine.Evaluate(context.Background(), request)
			if err != nil {
				errors <- err
				return
			}
			wantTTL := 10 * time.Minute
			if index%2 == 1 {
				wantTTL = 15 * time.Minute
			}
			if decision.Kind != DecisionAllow || decision.GrantedTTL != wantTTL {
				errors <- fmt.Errorf(
					"evaluation %d = (%s, %s), want (%s, %s)",
					index,
					decision.Kind,
					decision.GrantedTTL,
					DecisionAllow,
					wantTTL,
				)
				return
			}
			errors <- nil
		}()
	}

	for range evaluations {
		if err := <-errors; err != nil {
			t.Error(err)
		}
	}
}

func newTestPolicyEngine(t *testing.T) *EmbeddedPolicyEngine {
	t.Helper()
	engine, err := NewEmbeddedPolicyEngine(context.Background())
	if err != nil {
		t.Fatalf("NewEmbeddedPolicyEngine() error = %v", err)
	}
	return engine
}

func validAccessRequest() AccessRequest {
	return AccessRequest{
		RequestID: "req-policy-001",
		SPIFFEID:  "spiffe://sandbox.agentgate.test/ns/agentgate-sandbox/sa/terraform-runner",
		TaskGrant: grant.TaskGrant{
			RequestID:   "req-policy-001",
			Repo:        "github.com/agentgate-sandbox/terraform-demo",
			CommitSHA:   "0123456789abcdef0123456789abcdef01234567",
			Operation:   grant.OperationTerraformPlan,
			Environment: "dev",
			VaultRole:   "terraform-sandbox",
			TTLSeconds:  600,
			Nonce:       "nonce-policy-001",
			IssuedAt: time.Date(
				2026, time.July, 17, 9, 55, 0, 987654321, time.UTC,
			),
			OnBehalfOf: "student@example.test",
			TicketID:   "SANDBOX-101",
			Signature:  "verified-dispatcher-signature-is-not-policy-input",
		},
		RequestedVaultRole: "terraform-sandbox",
		RequestedAt: time.Date(
			2026, time.July, 17, 10, 0, 0, 123456789, time.UTC,
		),
	}
}

func assertMapKeys(t *testing.T, values map[string]any, want []string) {
	t.Helper()
	if len(values) != len(want) {
		t.Fatalf("map has %d keys, want %d: %#v", len(values), len(want), values)
	}
	for _, key := range want {
		if _, ok := values[key]; !ok {
			t.Errorf("map is missing key %q", key)
		}
	}
}

func dynamicOutputPolicy(output string) string {
	return fmt.Sprintf(`
package agentgate.authz

import rego.v1

bundle_ready := true

default decision := {
	"decision": "deny",
	"reason": "deny.default: test default",
	"granted_ttl_seconds": 0,
}

decision := %s if {
	input.spiffe_id == "spiffe://sandbox.agentgate.test/ns/agentgate-sandbox/sa/terraform-runner"
}
`, output)
}
