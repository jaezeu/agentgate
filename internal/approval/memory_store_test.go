package approval_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/jaezeu/agentgate/internal/approval"
	"github.com/jaezeu/agentgate/internal/vaultmgr"
)

func TestMemoryStoreDecideRejectsRevokedRecords(t *testing.T) {
	ctx := context.Background()
	now := time.Now().UTC().Truncate(time.Second)
	store := approval.NewMemoryStore()

	record := pendingRecord(
		"00000000-0000-4000-8000-000000000201",
		"memory-revoked-nonce-201",
		now,
	)
	if _, created, err := store.Create(ctx, record); err != nil || !created {
		t.Fatalf("Create() = created %v, error %v; want true, nil", created, err)
	}
	if _, err := store.RecordRevocation(
		ctx,
		record.AccessRequest.RequestID,
		vaultmgr.RevocationReport{RequestID: record.AccessRequest.RequestID},
		now.Add(time.Second),
	); err != nil {
		t.Fatalf("RecordRevocation() error = %v", err)
	}

	afterRevoke, won, claim, err := store.Decide(
		ctx,
		record.AccessRequest.RequestID,
		approval.ApprovalApproved,
		"approver@example.test",
		"approved after revocation",
		now.Add(2*time.Second),
	)
	if !errors.Is(err, approval.ErrConflict) || won || claim {
		t.Fatalf("Decide(after revocation) = won %v, claim %v, error %v; want conflict", won, claim, err)
	}
	if afterRevoke.BindingState != approval.BindingRevoked {
		t.Fatalf("binding state = %q, want revoked", afterRevoke.BindingState)
	}
}
