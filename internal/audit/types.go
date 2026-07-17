package audit

import (
	"context"
	"time"

	"github.com/jaezeu/agentgate/internal/approval"
	"github.com/jaezeu/agentgate/internal/authz"
	"github.com/jaezeu/agentgate/internal/grant"
)

// EventType identifies an immutable point in the request lifecycle.
type EventType string

const (
	EventGrantVerified     EventType = "grant_verified"
	EventDecisionRecorded  EventType = "decision_recorded"
	EventApprovalRequested EventType = "approval_requested"
	EventApprovalDecided   EventType = "approval_decided"
	EventBindingEnabled    EventType = "binding_enabled"
	EventBindingFailed     EventType = "binding_failed"
	EventRevocation        EventType = "revocation"
)

// AuditRecord links human intent, workload identity, policy, Vault binding, and cloud correlation.
// Details must never contain Vault tokens, leases, or cloud credential material.
type AuditRecord struct {
	EventID        string                 `json:"event_id"`
	RequestID      string                 `json:"request_id"`
	EventType      EventType              `json:"event_type"`
	OccurredAt     time.Time              `json:"occurred_at"`
	SPIFFEID       string                 `json:"spiffe_id"`
	OnBehalfOf     string                 `json:"on_behalf_of"`
	TicketID       string                 `json:"ticket_id"`
	TaskGrant      grant.TaskGrant        `json:"task_grant"`
	Decision       *authz.Decision        `json:"decision,omitempty"`
	ApprovalState  approval.ApprovalState `json:"approval_state,omitempty"`
	VaultAuthRole  string                 `json:"vault_auth_role,omitempty"`
	AWSSessionName string                 `json:"aws_role_session_name,omitempty"`
	Details        map[string]string      `json:"details,omitempty"`
}

// Query bounds dashboard and operational audit reads.
type Query struct {
	RequestID string
	Decision  authz.DecisionKind
	Limit     int
	Before    time.Time
}

// AuditStore persists and retrieves immutable correlation records.
type AuditStore interface {
	Append(context.Context, AuditRecord) error
	ByRequestID(context.Context, string) ([]AuditRecord, error)
	List(context.Context, Query) ([]AuditRecord, error)
}
