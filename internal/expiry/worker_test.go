package expiry

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"testing"
	"time"

	"github.com/jaezeu/agentgate/internal/approval"
	"github.com/jaezeu/agentgate/internal/authz"
	"github.com/jaezeu/agentgate/internal/vaultmgr"
)

type fakeVaultManager struct {
	report vaultmgr.RevocationReport
	err    error
	calls  []string
}

func (m *fakeVaultManager) EnableAccess(
	context.Context,
	vaultmgr.AccessBinding,
) (authz.RedemptionDescriptor, error) {
	return authz.RedemptionDescriptor{}, errors.New("unexpected enable access")
}

func (m *fakeVaultManager) Revoke(_ context.Context, requestID string) (vaultmgr.RevocationReport, error) {
	m.calls = append(m.calls, requestID)
	return m.report, m.err
}

func TestSweepRevokesExpiredBinding(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 3, 21, 12, 0, 0, 0, time.UTC)
	requestID := "00000000-0000-4000-8000-000000000006"
	store := approval.NewMemoryStore()
	createEnabledRecord(t, store, requestID, now.Add(-time.Second))
	manager := &fakeVaultManager{report: vaultmgr.RevocationReport{
		RequestID:     requestID,
		RoleRemoved:   true,
		PolicyRemoved: true,
	}}
	worker := newTestWorker(t, store, manager, now)

	worker.sweep(context.Background())

	record, err := store.Get(context.Background(), requestID)
	if err != nil {
		t.Fatalf("get swept record: %v", err)
	}
	if record.BindingState != approval.BindingRevoked || record.Revocation == nil {
		t.Fatalf("expected revoked record, got %#v", record)
	}
	if !record.Revocation.STSCredentialsMayRemain || len(record.Revocation.Warnings) == 0 {
		t.Fatalf("expected explicit STS caveat, got %#v", record.Revocation)
	}
	if len(manager.calls) != 1 || manager.calls[0] != requestID {
		t.Fatalf("unexpected Vault revocations: %#v", manager.calls)
	}
}

func TestSweepReleasesClaimAfterVaultFailure(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 3, 21, 12, 0, 0, 0, time.UTC)
	requestID := "00000000-0000-4000-8000-000000000007"
	store := approval.NewMemoryStore()
	createEnabledRecord(t, store, requestID, now.Add(-time.Second))
	manager := &fakeVaultManager{err: errors.New("Vault unavailable")}
	worker := newTestWorker(t, store, manager, now)

	worker.sweep(context.Background())

	record, err := store.Get(context.Background(), requestID)
	if err != nil {
		t.Fatalf("get released record: %v", err)
	}
	if record.BindingState != approval.BindingEnabled ||
		record.BindingError != expiryFailure ||
		record.Revocation != nil {
		t.Fatalf("expected retryable generic failure, got %#v", record)
	}
}

func TestSweepIgnoresUnexpiredBinding(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 3, 21, 12, 0, 0, 0, time.UTC)
	requestID := "00000000-0000-4000-8000-000000000008"
	store := approval.NewMemoryStore()
	createEnabledRecord(t, store, requestID, now.Add(31*time.Second))
	manager := &fakeVaultManager{}
	worker := newTestWorker(t, store, manager, now)

	worker.sweep(context.Background())

	record, err := store.Get(context.Background(), requestID)
	if err != nil {
		t.Fatalf("get unexpired record: %v", err)
	}
	if record.BindingState != approval.BindingEnabled || len(manager.calls) != 0 {
		t.Fatalf("unexpired binding was processed: %#v", record)
	}
}

func TestMemoryStoreRecoversStaleExpiryClaim(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 3, 21, 12, 0, 0, 0, time.UTC)
	store := approval.NewMemoryStore()
	createEnabledRecord(
		t,
		store,
		"00000000-0000-4000-8000-000000000009",
		now.Add(-time.Second),
	)

	if _, claimed, err := store.ClaimExpiredBinding(context.Background(), now); err != nil || !claimed {
		t.Fatalf("claim expired binding: claimed=%t err=%v", claimed, err)
	}
	if _, claimed, err := store.ClaimExpiredBinding(
		context.Background(),
		now.Add(30*time.Second-time.Nanosecond),
	); err != nil || claimed {
		t.Fatalf("premature stale claim: claimed=%t err=%v", claimed, err)
	}
	if _, claimed, err := store.ClaimExpiredBinding(
		context.Background(),
		now.Add(30*time.Second),
	); err != nil || !claimed {
		t.Fatalf("recover stale claim: claimed=%t err=%v", claimed, err)
	}
}

func newTestWorker(
	t *testing.T,
	store approval.Store,
	manager vaultmgr.VaultManager,
	now time.Time,
) *Worker {
	t.Helper()
	worker, err := NewWorker(
		store,
		manager,
		slog.New(slog.NewTextHandler(io.Discard, nil)),
	)
	if err != nil {
		t.Fatalf("create expiry worker: %v", err)
	}
	worker.clock = func() time.Time { return now }
	return worker
}

func createEnabledRecord(
	t *testing.T,
	store approval.Store,
	requestID string,
	expiresAt time.Time,
) {
	t.Helper()
	record := approval.Record{
		AccessRequest: authz.AccessRequest{RequestID: requestID},
		BindingState:  approval.BindingEnabled,
		Descriptor: &authz.RedemptionDescriptor{
			RequestID: requestID,
			ExpiresAt: expiresAt,
		},
	}
	if _, _, err := store.Create(context.Background(), record); err != nil {
		t.Fatalf("create enabled record: %v", err)
	}
}
