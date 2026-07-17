package authz

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/open-policy-agent/opa/v1/rego"

	policybundle "github.com/jaezeu/agentgate/policies"
)

const (
	bundleModuleName = "policies/authorization.rego"
	evaluationQuery  = `{"bundle_ready": data.agentgate.authz.bundle_ready, "decision": data.agentgate.authz.decision}`

	evaluationFailureReason = "deny.policy_evaluation_error: embedded policy evaluation failed closed"
	outputFailureReason     = "deny.malformed_policy_output: embedded policy output failed validation"
)

var errMalformedPolicyOutput = errors.New("malformed policy output")

// EmbeddedPolicyEngine evaluates the formatted Rego module compiled into the
// AgentGate binary.
type EmbeddedPolicyEngine struct {
	query         rego.PreparedEvalQuery
	policyVersion string
}

var _ PolicyEngine = (*EmbeddedPolicyEngine)(nil)

// NewEmbeddedPolicyEngine loads and prepares the embedded policy once.
func NewEmbeddedPolicyEngine(ctx context.Context) (*EmbeddedPolicyEngine, error) {
	return newEmbeddedPolicyEngine(ctx, policybundle.AuthorizationBundle())
}

func newEmbeddedPolicyEngine(ctx context.Context, bundle string) (*EmbeddedPolicyEngine, error) {
	if ctx == nil {
		return nil, errors.New("prepare embedded policy: context is required")
	}
	if bundle == "" {
		return nil, errors.New("prepare embedded policy: bundle is empty")
	}

	prepared, err := rego.New(
		rego.Query(evaluationQuery),
		rego.Module(bundleModuleName, bundle),
	).PrepareForEval(ctx)
	if err != nil {
		return nil, fmt.Errorf("prepare embedded policy: %w", err)
	}

	engine := &EmbeddedPolicyEngine{
		query:         prepared,
		policyVersion: hashBundle(bundle),
	}
	startupResult, err := engine.evaluate(ctx, map[string]any{})
	if err != nil {
		return nil, fmt.Errorf("validate embedded policy: %w", err)
	}
	if !startupResult.bundleReady {
		return nil, errors.New("validate embedded policy: required policy configuration is missing")
	}
	if startupResult.decision.kind != DecisionDeny {
		return nil, errors.New("validate embedded policy: empty input must be denied")
	}

	return engine, nil
}

// Evaluate maps trusted internal values to policy input and fails closed on any
// evaluation or output error.
func (e *EmbeddedPolicyEngine) Evaluate(ctx context.Context, request AccessRequest) (Decision, error) {
	decidedAt := request.RequestedAt.UTC()
	if e == nil {
		return Decision{
			Kind:      DecisionDeny,
			Reason:    evaluationFailureReason,
			DecidedAt: decidedAt,
		}, errors.New("evaluate embedded policy: engine is nil")
	}
	if ctx == nil {
		return e.failedDecision(decidedAt, evaluationFailureReason),
			errors.New("evaluate embedded policy: context is required")
	}

	result, err := e.evaluate(ctx, policyInput(request))
	if err != nil {
		reason := evaluationFailureReason
		if errors.Is(err, errMalformedPolicyOutput) {
			reason = outputFailureReason
		}
		return e.failedDecision(decidedAt, reason),
			fmt.Errorf("evaluate embedded policy: %w", err)
	}
	if !result.bundleReady {
		return e.failedDecision(decidedAt, outputFailureReason),
			errors.New("evaluate embedded policy: required policy configuration is missing")
	}

	return Decision{
		Kind:          result.decision.kind,
		Reason:        result.decision.reason,
		GrantedTTL:    time.Duration(result.decision.grantedTTLSeconds) * time.Second,
		PolicyVersion: e.policyVersion,
		DecidedAt:     decidedAt,
	}, nil
}

func (e *EmbeddedPolicyEngine) evaluate(ctx context.Context, input map[string]any) (policyEvaluation, error) {
	resultSet, err := e.query.Eval(ctx, rego.EvalInput(input))
	if err != nil {
		return policyEvaluation{}, err
	}
	if len(resultSet) != 1 {
		return policyEvaluation{}, fmt.Errorf(
			"%w: expected one policy result, got %d",
			errMalformedPolicyOutput,
			len(resultSet),
		)
	}
	if len(resultSet[0].Expressions) != 1 || resultSet[0].Expressions[0] == nil {
		return policyEvaluation{}, fmt.Errorf(
			"%w: expected one policy expression, got %d",
			errMalformedPolicyOutput,
			len(resultSet[0].Expressions),
		)
	}

	result, err := decodePolicyEvaluation(resultSet[0].Expressions[0].Value)
	if err != nil {
		return policyEvaluation{}, fmt.Errorf("%w: %w", errMalformedPolicyOutput, err)
	}
	return result, nil
}

func (e *EmbeddedPolicyEngine) failedDecision(at time.Time, reason string) Decision {
	return Decision{
		Kind:          DecisionDeny,
		Reason:        reason,
		PolicyVersion: e.policyVersion,
		DecidedAt:     at,
	}
}

func policyInput(request AccessRequest) map[string]any {
	return map[string]any{
		"request_id":           request.RequestID,
		"spiffe_id":            request.SPIFFEID,
		"requested_vault_role": request.RequestedVaultRole,
		"current_time":         formatPolicyTime(request.RequestedAt),
		"task_grant": map[string]any{
			"request_id":   request.TaskGrant.RequestID,
			"repo":         request.TaskGrant.Repo,
			"commit_sha":   request.TaskGrant.CommitSHA,
			"operation":    string(request.TaskGrant.Operation),
			"environment":  request.TaskGrant.Environment,
			"vault_role":   request.TaskGrant.VaultRole,
			"ttl":          request.TaskGrant.TTLSeconds,
			"nonce":        request.TaskGrant.Nonce,
			"issued_at":    formatPolicyTime(request.TaskGrant.IssuedAt),
			"on_behalf_of": request.TaskGrant.OnBehalfOf,
			"ticket_id":    request.TaskGrant.TicketID,
		},
	}
}

func formatPolicyTime(value time.Time) string {
	if value.IsZero() {
		return ""
	}
	return value.UTC().Format(time.RFC3339Nano)
}

func hashBundle(bundle string) string {
	sum := sha256.Sum256([]byte(bundle))
	return hex.EncodeToString(sum[:])
}

type policyEvaluation struct {
	bundleReady bool
	decision    policyDecision
}

type policyDecision struct {
	kind              DecisionKind
	reason            string
	grantedTTLSeconds int64
}

type rawPolicyEvaluation struct {
	BundleReady *bool              `json:"bundle_ready"`
	Decision    *rawPolicyDecision `json:"decision"`
}

type rawPolicyDecision struct {
	Kind              *string `json:"decision"`
	Reason            *string `json:"reason"`
	GrantedTTLSeconds *int64  `json:"granted_ttl_seconds"`
}

func decodePolicyEvaluation(value any) (policyEvaluation, error) {
	payload, err := json.Marshal(value)
	if err != nil {
		return policyEvaluation{}, fmt.Errorf("encode policy output: %w", err)
	}

	var raw rawPolicyEvaluation
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&raw); err != nil {
		return policyEvaluation{}, fmt.Errorf("decode policy output: %w", err)
	}
	if err := ensureJSONEnd(decoder); err != nil {
		return policyEvaluation{}, err
	}
	if raw.BundleReady == nil {
		return policyEvaluation{}, errors.New("policy output is missing bundle_ready")
	}
	if raw.Decision == nil {
		return policyEvaluation{}, errors.New("policy output is missing decision")
	}

	decision, err := validatePolicyDecision(*raw.Decision)
	if err != nil {
		return policyEvaluation{}, err
	}
	return policyEvaluation{
		bundleReady: *raw.BundleReady,
		decision:    decision,
	}, nil
}

func validatePolicyDecision(raw rawPolicyDecision) (policyDecision, error) {
	if raw.Kind == nil {
		return policyDecision{}, errors.New("policy decision is missing decision")
	}
	if raw.Reason == nil || strings.TrimSpace(*raw.Reason) == "" {
		return policyDecision{}, errors.New("policy decision is missing reason")
	}
	if raw.GrantedTTLSeconds == nil {
		return policyDecision{}, errors.New("policy decision is missing granted_ttl_seconds")
	}

	kind := DecisionKind(*raw.Kind)
	switch kind {
	case DecisionDeny:
		if *raw.GrantedTTLSeconds != 0 {
			return policyDecision{}, errors.New("deny decision must grant zero seconds")
		}
	case DecisionAllow, DecisionPendingApproval:
		if *raw.GrantedTTLSeconds <= 0 || *raw.GrantedTTLSeconds > 900 {
			return policyDecision{}, errors.New("successful policy decision ttl must be between 1 and 900 seconds")
		}
	default:
		return policyDecision{}, fmt.Errorf("policy decision has unsupported kind %q", kind)
	}

	return policyDecision{
		kind:              kind,
		reason:            *raw.Reason,
		grantedTTLSeconds: *raw.GrantedTTLSeconds,
	}, nil
}

func ensureJSONEnd(decoder *json.Decoder) error {
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		if err == nil {
			return errors.New("policy output contains multiple JSON values")
		}
		return fmt.Errorf("decode policy output trailer: %w", err)
	}
	return nil
}
