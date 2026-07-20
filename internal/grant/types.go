package grant

import (
	"context"
	"time"
)

// Operation is an autonomous action authorized by a dispatcher.
type Operation string

const (
	OperationTerraformPlan     Operation = "terraform-plan"
	OperationTerraformApply    Operation = "terraform-apply"
	OperationKubernetesInspect Operation = "kubernetes-inspect"
)

// TaskGrant is dispatcher-signed task context. TTL is encoded in seconds.
type TaskGrant struct {
	RequestID   string    `json:"request_id"`
	Repo        string    `json:"repo"`
	CommitSHA   string    `json:"commit_sha"`
	Operation   Operation `json:"operation"`
	Environment string    `json:"environment"`
	VaultRole   string    `json:"vault_role"`
	TTLSeconds  int64     `json:"ttl"`
	Nonce       string    `json:"nonce"`
	IssuedAt    time.Time `json:"issued_at"`
	OnBehalfOf  string    `json:"on_behalf_of"`
	TicketID    string    `json:"ticket_id"`
	Signature   string    `json:"signature"`
}

// ExpiresAt returns the dispatcher-defined validity boundary.
func (g TaskGrant) ExpiresAt() time.Time {
	return g.IssuedAt.Add(time.Duration(g.TTLSeconds) * time.Second)
}

// GrantVerifier authenticates dispatcher task context and atomically prevents replay.
type GrantVerifier interface {
	Verify(context.Context, TaskGrant) error
}

// NonceStore atomically consumes a nonce until its grant expires. Expiry of a
// previously consumed nonce is judged against the caller-supplied now so the
// replay decision uses the same clock that validated the grant's time bounds.
type NonceStore interface {
	Use(ctx context.Context, nonce string, now, expiresAt time.Time) (bool, error)
}
