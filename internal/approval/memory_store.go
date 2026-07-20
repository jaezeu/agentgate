package approval

import (
	"context"
	"sync"
	"time"

	"github.com/jaezeu/agentgate/internal/authz"
	"github.com/jaezeu/agentgate/internal/vaultmgr"
)

// MemoryStore is a deterministic workflow store for tests and single-process demos.
type MemoryStore struct {
	mu                   sync.Mutex
	records              map[string]Record
	expiredBindingClaims map[string]time.Time
}

func NewMemoryStore() *MemoryStore {
	return &MemoryStore{
		records:              make(map[string]Record),
		expiredBindingClaims: make(map[string]time.Time),
	}
}

func (s *MemoryStore) Create(_ context.Context, record Record) (Record, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if stored, ok := s.records[record.AccessRequest.RequestID]; ok {
		if !sameSubmission(stored, record) {
			return cloneRecord(stored), false, ErrConflict
		}
		return cloneRecord(stored), false, nil
	}
	record = cloneRecord(record)
	s.records[record.AccessRequest.RequestID] = record
	return cloneRecord(record), true, nil
}

func (s *MemoryStore) Get(_ context.Context, requestID string) (Record, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	record, ok := s.records[requestID]
	if !ok {
		return Record{}, ErrNotFound
	}
	return cloneRecord(record), nil
}

func (s *MemoryStore) List(_ context.Context, filter ListFilter) ([]Record, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	records := make([]Record, 0, len(s.records))
	now := time.Now().UTC()
	for _, record := range s.records {
		if filter.Decision != "" && record.Decision.Kind != filter.Decision ||
			filter.Approval != "" && record.Approval.State != filter.Approval ||
			filter.Binding != "" && record.BindingState != filter.Binding ||
			filter.SPIFFEID != "" && record.AccessRequest.SPIFFEID != filter.SPIFFEID ||
			filter.OnBehalfOf != "" && record.AccessRequest.TaskGrant.OnBehalfOf != filter.OnBehalfOf ||
			filter.Environment != "" && record.AccessRequest.TaskGrant.Environment != filter.Environment ||
			filter.Operation != "" && record.AccessRequest.TaskGrant.Operation != filter.Operation ||
			filter.Repo != "" && record.AccessRequest.TaskGrant.Repo != filter.Repo ||
			!filter.CreatedAfter.IsZero() && record.AccessRequest.RequestedAt.Before(filter.CreatedAfter) ||
			!filter.CreatedBefore.IsZero() && !record.AccessRequest.RequestedAt.Before(filter.CreatedBefore) {
			continue
		}
		if filter.Active != nil {
			expiresAt := record.AccessRequest.TaskGrant.ExpiresAt()
			if record.Descriptor != nil && record.Descriptor.ExpiresAt.Before(expiresAt) {
				expiresAt = record.Descriptor.ExpiresAt
			}
			active := record.RevokedAt == nil && now.Before(expiresAt)
			if active != *filter.Active {
				continue
			}
		}
		records = append(records, cloneRecord(record))
	}
	sortRecords(records)
	start := min(filter.Offset, len(records))
	end := len(records)
	if filter.Limit > 0 {
		end = min(start+filter.Limit, end)
	}
	return records[start:end], nil
}

func (s *MemoryStore) Decide(_ context.Context, requestID string, next ApprovalState, actor, reason string, at time.Time) (Record, bool, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	record, ok := s.records[requestID]
	if !ok {
		return Record{}, false, false, ErrNotFound
	}
	if record.RevokedAt != nil {
		return cloneRecord(record), false, false, ErrConflict
	}
	if record.Approval.State == next {
		return cloneRecord(record), false, false, nil
	}
	if record.Approval.State != ApprovalPending {
		return cloneRecord(record), false, false, ErrConflict
	}
	if next == ApprovalApproved && !at.Before(record.AccessRequest.TaskGrant.ExpiresAt()) {
		expired, err := record.Approval.Transition(ApprovalExpired, actor, "approval window expired", at)
		if err != nil {
			return Record{}, false, false, err
		}
		record.Approval = expired
		record.BindingState = BindingNotRequired
		s.records[requestID] = record
		return cloneRecord(record), true, false, ErrExpiredRequest
	}
	transitioned, err := record.Approval.Transition(next, actor, reason, at)
	if err != nil {
		return Record{}, false, false, err
	}
	record.Approval = transitioned
	claim := next == ApprovalApproved
	if claim {
		record.BindingState = BindingEnabling
	} else {
		record.BindingState = BindingNotRequired
	}
	s.records[requestID] = record
	return cloneRecord(record), true, claim, nil
}

func (s *MemoryStore) ClaimBinding(_ context.Context, requestID string) (Record, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	record, ok := s.records[requestID]
	if !ok {
		return Record{}, false, ErrNotFound
	}
	eligible := record.Decision.Kind == authz.DecisionAllow || record.Approval.State == ApprovalApproved
	if !eligible || (record.BindingState != BindingPending && record.BindingState != BindingFailed) {
		return cloneRecord(record), false, nil
	}
	record.BindingState = BindingEnabling
	record.BindingError = ""
	s.records[requestID] = record
	return cloneRecord(record), true, nil
}

func (s *MemoryStore) CompleteBinding(_ context.Context, requestID string, descriptor *authz.RedemptionDescriptor, failure string) (Record, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	record, ok := s.records[requestID]
	if !ok {
		return Record{}, ErrNotFound
	}
	if record.BindingState != BindingEnabling {
		return cloneRecord(record), ErrConflict
	}
	if failure != "" {
		record.BindingState = BindingFailed
		record.BindingError = failure
		record.Descriptor = nil
	} else if descriptor != nil {
		copyDescriptor := *descriptor
		record.BindingState = BindingEnabled
		record.BindingError = ""
		record.Descriptor = &copyDescriptor
	} else {
		return cloneRecord(record), ErrConflict
	}
	s.records[requestID] = record
	return cloneRecord(record), nil
}

func (s *MemoryStore) ClaimExpiredBinding(_ context.Context, at time.Time) (Record, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	var selectedID string
	for requestID, record := range s.records {
		if record.RevokedAt != nil || record.Descriptor == nil ||
			record.Descriptor.ExpiresAt.After(at.Add(bindingCleanupLead)) {
			continue
		}
		claimTime, claimed := s.expiredBindingClaims[requestID]
		eligible := record.BindingState == BindingEnabled ||
			(record.BindingState == BindingRevoking &&
				claimed && !claimTime.After(at.Add(-staleBindingClaim)))
		if !eligible {
			continue
		}
		if selectedID == "" ||
			record.Descriptor.ExpiresAt.Before(s.records[selectedID].Descriptor.ExpiresAt) ||
			(record.Descriptor.ExpiresAt.Equal(s.records[selectedID].Descriptor.ExpiresAt) &&
				requestID < selectedID) {
			selectedID = requestID
		}
	}
	if selectedID == "" {
		return Record{}, false, nil
	}

	record := s.records[selectedID]
	record.BindingState = BindingRevoking
	record.BindingError = ""
	s.records[selectedID] = record
	s.expiredBindingClaims[selectedID] = at
	return cloneRecord(record), true, nil
}

func (s *MemoryStore) ReleaseExpiredBinding(_ context.Context, requestID, failure string, _ time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	record, ok := s.records[requestID]
	if !ok {
		return ErrNotFound
	}
	if record.BindingState != BindingRevoking {
		return ErrConflict
	}
	record.BindingState = BindingEnabled
	record.BindingError = failure
	s.records[requestID] = record
	delete(s.expiredBindingClaims, requestID)
	return nil
}

// RecordRevocation mirrors the Postgres guard: the terminal revoked state is
// only stamped over the binding state the caller observed before revoking in
// Vault, and never over an in-flight enablement (the memory store tracks no
// claim timestamps, so every enablement claim counts as live).
func (s *MemoryStore) RecordRevocation(_ context.Context, requestID string, report vaultmgr.RevocationReport, expectedState BindingState, at time.Time) (Record, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	record, ok := s.records[requestID]
	if !ok {
		return Record{}, ErrNotFound
	}
	if record.RevokedAt != nil ||
		record.BindingState != expectedState ||
		record.BindingState == BindingEnabling {
		return cloneRecord(record), ErrConflict
	}
	copyReport := report
	copyReport.Warnings = append([]string(nil), report.Warnings...)
	record.Revocation = &copyReport
	record.RevokedAt = &at
	record.BindingState = BindingRevoked
	s.records[requestID] = record
	delete(s.expiredBindingClaims, requestID)
	return cloneRecord(record), nil
}

func (s *MemoryStore) Ready(context.Context) error {
	return nil
}

func cloneRecord(record Record) Record {
	if record.Approval.DecidedAt != nil {
		value := *record.Approval.DecidedAt
		record.Approval.DecidedAt = &value
	}
	if record.Descriptor != nil {
		value := *record.Descriptor
		record.Descriptor = &value
	}
	if record.Revocation != nil {
		value := *record.Revocation
		value.Warnings = append([]string(nil), record.Revocation.Warnings...)
		record.Revocation = &value
	}
	if record.RevokedAt != nil {
		value := *record.RevokedAt
		record.RevokedAt = &value
	}
	return record
}

func sortRecords(records []Record) {
	for i := 1; i < len(records); i++ {
		for j := i; j > 0; j-- {
			left, right := records[j-1], records[j]
			if left.AccessRequest.RequestedAt.After(right.AccessRequest.RequestedAt) ||
				left.AccessRequest.RequestedAt.Equal(right.AccessRequest.RequestedAt) &&
					left.AccessRequest.RequestID > right.AccessRequest.RequestID {
				break
			}
			records[j-1], records[j] = records[j], records[j-1]
		}
	}
}
