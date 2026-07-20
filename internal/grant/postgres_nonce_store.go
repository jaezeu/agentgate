package grant

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"
)

const maxNonceLength = 512

// PostgresNonceStore atomically prevents grant replay across AgentGate replicas.
type PostgresNonceStore struct {
	db *sql.DB
}

// NewPostgresNonceStore constructs a shared nonce store.
func NewPostgresNonceStore(db *sql.DB) *PostgresNonceStore {
	return &PostgresNonceStore{db: db}
}

// Use consumes a nonce unless an unexpired use already exists. The broker's
// clock, not the database's, decides whether a prior use has expired: the
// grant's own time bounds were checked against the broker clock, and letting
// a database clock that runs ahead reopen the row would create a replay
// window at the tail of every grant's lifetime.
func (s *PostgresNonceStore) Use(ctx context.Context, nonce string, now, expiresAt time.Time) (bool, error) {
	if s == nil || s.db == nil {
		return false, errors.New("postgres nonce store database is required")
	}
	if strings.TrimSpace(nonce) == "" || len(nonce) > maxNonceLength {
		return false, errors.New("grant nonce is invalid")
	}

	var used bool
	err := s.db.QueryRowContext(ctx, `
		INSERT INTO consumed_grant_nonces (nonce, expires_at)
		VALUES ($1, $3)
		ON CONFLICT (nonce) DO UPDATE
		SET expires_at = EXCLUDED.expires_at,
		    consumed_at = now()
		WHERE consumed_grant_nonces.expires_at <= $2
		RETURNING TRUE
	`, nonce, now.UTC(), expiresAt.UTC()).Scan(&used)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("consume grant nonce: %w", err)
	}
	return used, nil
}
