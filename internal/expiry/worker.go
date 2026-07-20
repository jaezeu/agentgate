package expiry

import (
	"context"
	"errors"
	"log/slog"
	"time"

	"github.com/jaezeu/agentgate/internal/approval"
	"github.com/jaezeu/agentgate/internal/vaultmgr"
)

const (
	defaultSweepInterval = 5 * time.Second
	defaultBatchSize     = 100
	expiryFailure        = "automatic expiry cleanup failed"
)

// Worker removes request-scoped Vault configuration just before its signed redemption window expires.
type Worker struct {
	store            approval.Store
	vaultManager     vaultmgr.VaultManager
	logger           *slog.Logger
	clock            func() time.Time
	sweepInterval    time.Duration
	operationTimeout time.Duration
}

// NewWorker validates and constructs an expiry worker.
func NewWorker(
	store approval.Store,
	vaultManager vaultmgr.VaultManager,
	logger *slog.Logger,
) (*Worker, error) {
	if store == nil {
		return nil, errors.New("expiry worker request store is required")
	}
	if vaultManager == nil {
		return nil, errors.New("expiry worker Vault manager is required")
	}
	if logger == nil {
		logger = slog.Default()
	}
	return &Worker{
		store:            store,
		vaultManager:     vaultManager,
		logger:           logger,
		clock:            func() time.Time { return time.Now().UTC() },
		sweepInterval:    defaultSweepInterval,
		operationTimeout: 20 * time.Second,
	}, nil
}

// Run performs an immediate sweep and then continues until the lifecycle context is canceled.
func (w *Worker) Run(ctx context.Context) {
	w.sweep(ctx)
	ticker := time.NewTicker(w.sweepInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			w.sweep(ctx)
		}
	}
}

func (w *Worker) sweep(ctx context.Context) {
	// Failed revocations keep their 'revoking' claim until the end of the
	// sweep: releasing immediately would make the same earliest-expiring
	// binding the first claim of every iteration, starving every later
	// expired binding behind one persistently failing revocation.
	var failed []string
	reachedLimit := true
	for range defaultBatchSize {
		if ctx.Err() != nil {
			reachedLimit = false
			break
		}
		at := w.clock().UTC()
		record, claimed, err := w.store.ClaimExpiredBinding(ctx, at)
		if err != nil {
			w.logger.Error("claim expired Vault binding", "component", "expiry_worker")
			reachedLimit = false
			break
		}
		if !claimed {
			reachedLimit = false
			break
		}
		requestID := record.AccessRequest.RequestID
		if err := w.revoke(ctx, requestID); err != nil {
			w.logger.Error(
				"remove expired Vault binding",
				"component", "expiry_worker",
				"request_id", requestID,
			)
			failed = append(failed, requestID)
		}
	}
	if reachedLimit {
		w.logger.Warn("expired Vault binding sweep reached batch limit", "component", "expiry_worker")
	}
	for _, requestID := range failed {
		if err := w.release(ctx, requestID); err != nil {
			w.logger.Error(
				"release failed expired binding claim",
				"component", "expiry_worker",
				"request_id", requestID,
			)
		}
	}
}

func (w *Worker) revoke(ctx context.Context, requestID string) error {
	operationContext, cancel := context.WithTimeout(ctx, w.operationTimeout)
	defer cancel()

	report, err := w.vaultManager.Revoke(operationContext, requestID)
	if err != nil {
		return err
	}
	report, err = vaultmgr.NormalizeRevocationReport(requestID, report)
	if err != nil {
		return err
	}
	_, err = w.store.RecordRevocation(
		operationContext,
		requestID,
		report,
		approval.BindingRevoking,
		w.clock().UTC(),
	)
	if errors.Is(err, approval.ErrConflict) {
		// Another actor recorded a revocation for this request first; the
		// binding is already terminal and the claim row no longer exists.
		return nil
	}
	return err
}

func (w *Worker) release(ctx context.Context, requestID string) error {
	releaseContext, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	return w.store.ReleaseExpiredBinding(
		releaseContext,
		requestID,
		expiryFailure,
		w.clock().UTC(),
	)
}
