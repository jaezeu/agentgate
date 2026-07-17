package approval

import (
	"context"
	"errors"
	"time"

	"github.com/jaezeu/agentgate/internal/authz"
	"github.com/jaezeu/agentgate/internal/grant"
	"github.com/jaezeu/agentgate/internal/vaultmgr"
)

// ApprovalState is the separately authenticated human decision state.
type ApprovalState string

const (
	ApprovalNotRequired ApprovalState = "not_required"
	ApprovalPending     ApprovalState = "pending"
	ApprovalApproved    ApprovalState = "approved"
	ApprovalDenied      ApprovalState = "denied"
	ApprovalExpired     ApprovalState = "expired"
)

// Request is a parked policy decision awaiting a human approver.
type Request struct {
	RequestID   string        `json:"request_id"`
	State       ApprovalState `json:"state"`
	RequestedAt time.Time     `json:"requested_at"`
	DecidedAt   *time.Time    `json:"decided_at,omitempty"`
	DecidedBy   string        `json:"decided_by,omitempty"`
	Reason      string        `json:"reason,omitempty"`
	Version     int64         `json:"version"`
}

// CanTransition reports whether a state change is permitted by the approval state machine.
func (s ApprovalState) CanTransition(next ApprovalState) bool {
	if s == next {
		return true
	}
	return s == ApprovalPending && (next == ApprovalApproved || next == ApprovalDenied || next == ApprovalExpired)
}

// Transition returns a new approval snapshot without mutating the original.
func (r Request) Transition(next ApprovalState, actor, reason string, at time.Time) (Request, error) {
	if !r.State.CanTransition(next) {
		return Request{}, errors.New("invalid approval state transition")
	}
	if r.State == next {
		return r, nil
	}
	r.State = next
	r.DecidedAt = &at
	r.DecidedBy = actor
	r.Reason = reason
	r.Version++
	return r, nil
}

// ApprovalNotifier sends a credential-free notification for a parked request.
type ApprovalNotifier interface {
	NotifyPending(context.Context, Request) error
}

// BindingState tracks credential-blind Vault configuration, not credential issuance.
type BindingState string

const (
	BindingNotRequired BindingState = "not_required"
	BindingPending     BindingState = "pending"
	BindingEnabling    BindingState = "enabling"
	BindingEnabled     BindingState = "enabled"
	BindingFailed      BindingState = "failed"
	BindingRevoking    BindingState = "revoking"
	BindingRevoked     BindingState = "revoked"
)

// Record is the durable, credential-free snapshot of an access request.
// Grant.Signature is cleared before persistence.
type Record struct {
	AccessRequest authz.AccessRequest         `json:"access_request"`
	GrantHash     string                      `json:"-"`
	Decision      authz.Decision              `json:"decision"`
	Approval      Request                     `json:"approval"`
	BindingState  BindingState                `json:"binding_state"`
	BindingError  string                      `json:"binding_error,omitempty"`
	Descriptor    *authz.RedemptionDescriptor `json:"descriptor,omitempty"`
	Revocation    *vaultmgr.RevocationReport  `json:"revocation,omitempty"`
	RevokedAt     *time.Time                  `json:"revoked_at,omitempty"`
}

// NewRecord constructs a persistence-safe lifecycle snapshot.
func NewRecord(accessRequest authz.AccessRequest, decision authz.Decision, grantHash string) Record {
	accessRequest.TaskGrant.Signature = ""
	state := ApprovalNotRequired
	bindingState := BindingPending
	if decision.Kind == authz.DecisionPendingApproval {
		state = ApprovalPending
	}
	if decision.Kind == authz.DecisionDeny {
		bindingState = BindingNotRequired
	}
	return Record{
		AccessRequest: accessRequest,
		GrantHash:     grantHash,
		Decision:      decision,
		Approval: Request{
			RequestID:   accessRequest.RequestID,
			State:       state,
			RequestedAt: accessRequest.RequestedAt,
			Version:     1,
		},
		BindingState: bindingState,
	}
}

// ListFilter bounds and filters operational request reads.
type ListFilter struct {
	Decision      authz.DecisionKind
	Approval      ApprovalState
	Binding       BindingState
	Active        *bool
	SPIFFEID      string
	OnBehalfOf    string
	Environment   string
	Operation     grant.Operation
	Repo          string
	CreatedAfter  time.Time
	CreatedBefore time.Time
	Limit         int
	Offset        int
}

var (
	ErrNotFound       = errors.New("approval request not found")
	ErrConflict       = errors.New("approval request state conflict")
	ErrExpiredRequest = errors.New("approval request expired")
)

// Store owns durable request snapshots and atomic approval/binding transitions.
type Store interface {
	Create(context.Context, Record) (stored Record, created bool, err error)
	Get(context.Context, string) (Record, error)
	List(context.Context, ListFilter) ([]Record, error)
	Decide(context.Context, string, ApprovalState, string, string, time.Time) (stored Record, won bool, claimBinding bool, err error)
	ClaimBinding(context.Context, string) (stored Record, claimed bool, err error)
	CompleteBinding(context.Context, string, *authz.RedemptionDescriptor, string) (Record, error)
	ClaimExpiredBinding(context.Context, time.Time) (stored Record, claimed bool, err error)
	ReleaseExpiredBinding(context.Context, string, string, time.Time) error
	RecordRevocation(context.Context, string, vaultmgr.RevocationReport, time.Time) (Record, error)
	Ready(context.Context) error
}

// ReviewDetails contains only fields safe to send to an approval webhook.
type ReviewDetails struct {
	RequestID          string
	SPIFFEID           string
	OnBehalfOf         string
	TicketID           string
	Repo               string
	CommitSHA          string
	Operation          grant.Operation
	Environment        string
	RequestedVaultRole string
	TTLSeconds         int64
	PolicyReason       string
}
