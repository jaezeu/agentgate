package grant

import (
	"context"
	"sync"
	"time"
)

// MemoryNonceStore is suitable for tests and single-process demos only.
// HA deployments must use a shared atomic store such as Postgres.
type MemoryNonceStore struct {
	mu     sync.Mutex
	nonces map[string]time.Time
}

// NewMemoryNonceStore constructs an empty nonce store.
func NewMemoryNonceStore() *MemoryNonceStore {
	return &MemoryNonceStore{nonces: make(map[string]time.Time)}
}

// Use atomically consumes a nonce and opportunistically removes entries that
// have expired according to the caller's clock.
func (s *MemoryNonceStore) Use(_ context.Context, nonce string, now, expiresAt time.Time) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	for storedNonce, expiry := range s.nonces {
		if !now.Before(expiry) {
			delete(s.nonces, storedNonce)
		}
	}
	if _, exists := s.nonces[nonce]; exists {
		return false, nil
	}
	s.nonces[nonce] = expiresAt
	return true, nil
}
