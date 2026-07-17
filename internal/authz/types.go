package authz

import (
	"context"
	"time"

	"github.com/jaezeu/agentgate/internal/grant"
)

// AccessRequest is the complete, credential-free input to an access decision.
type AccessRequest struct {
	RequestID          string          `json:"request_id"`
	SPIFFEID           string          `json:"spiffe_id"`
	TaskGrant          grant.TaskGrant `json:"task_grant"`
	RequestedVaultRole string          `json:"requested_vault_role"`
	RequestedAt        time.Time       `json:"requested_at"`
}

// DecisionKind is the terminal or parked result of policy evaluation.
type DecisionKind string

const (
	DecisionAllow           DecisionKind = "allow"
	DecisionDeny            DecisionKind = "deny"
	DecisionPendingApproval DecisionKind = "pending_approval"
)

// Decision records a policy result and the exact policy bundle that produced it.
type Decision struct {
	Kind          DecisionKind  `json:"decision"`
	Reason        string        `json:"reason"`
	GrantedTTL    time.Duration `json:"granted_ttl"`
	PolicyVersion string        `json:"policy_version"`
	DecidedAt     time.Time     `json:"decided_at"`
}

// RedemptionDescriptor tells an agent where and how to authenticate directly to Vault.
// It deliberately contains no token, lease, secret, or cloud credential material.
type RedemptionDescriptor struct {
	RequestID    string    `json:"request_id"`
	VaultAddress string    `json:"vault_address"`
	AuthMount    string    `json:"auth_mount"`
	AuthRole     string    `json:"auth_role"`
	SecretsPath  string    `json:"secrets_path"`
	Audience     string    `json:"audience"`
	ExpiresAt    time.Time `json:"expires_at"`
}

// PolicyEngine evaluates both workload identity and dispatcher-authenticated task context.
type PolicyEngine interface {
	Evaluate(context.Context, AccessRequest) (Decision, error)
}
