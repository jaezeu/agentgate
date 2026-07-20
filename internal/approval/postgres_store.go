package approval

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jaezeu/agentgate/internal/authz"
	"github.com/jaezeu/agentgate/internal/grant"
	"github.com/jaezeu/agentgate/internal/vaultmgr"
)

const (
	defaultListLimit = 50
	// maxListLimit is one above the API's maximum page size so the
	// transport layer can fetch an extra row as its has-more probe.
	maxListLimit     = 101
	maxListOffset    = 10_000
	maxActorLength   = 512
	maxReasonLength  = 4_096
	maxBindingError  = 512
	maxWarningCount  = 20
	maxWarningLength = 1_024
	// Vault operations are bounded below this interval; reclaiming recovers a crashed replica.
	staleBindingClaim = 30 * time.Second
	// Start cleanup before descriptor expiry so normal reconciliation latency cannot extend access.
	bindingCleanupLead = 30 * time.Second
)

// PostgresStore persists request and approval lifecycle state across replicas.
type PostgresStore struct {
	db *sql.DB
}

// NewPostgresStore constructs a durable approval store.
func NewPostgresStore(db *sql.DB) *PostgresStore {
	return &PostgresStore{db: db}
}

func (s *PostgresStore) Create(ctx context.Context, record Record) (Record, bool, error) {
	if err := s.validate(); err != nil {
		return Record{}, false, err
	}
	record.AccessRequest.TaskGrant.Signature = ""
	if err := validateNewRecord(record); err != nil {
		return Record{}, false, err
	}

	transaction, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return Record{}, false, fmt.Errorf("begin request transaction: %w", err)
	}
	defer func() { _ = transaction.Rollback() }()

	var grantedTTL any
	if record.Decision.GrantedTTL > 0 {
		grantedTTL = int64(record.Decision.GrantedTTL / time.Second)
	}
	result, err := transaction.ExecContext(ctx, `
		INSERT INTO access_requests (
			request_id,
			spiffe_id,
			on_behalf_of,
			ticket_id,
			repo,
			commit_sha,
			operation,
			environment,
			vault_role,
			requested_ttl_seconds,
			granted_ttl_seconds,
			decision,
			decision_reason,
			policy_version,
			grant_hash,
			grant_nonce,
			grant_issued_at,
			requested_at,
			decided_at,
			binding_state,
			binding_error,
			binding_updated_at,
			created_at,
			updated_at
		) VALUES (
			$1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12,
			$13, $14, $15, $16, $17, $18, $19, $20, $21, $18, $18, $18
		)
		ON CONFLICT (request_id) DO NOTHING
	`,
		record.AccessRequest.RequestID,
		record.AccessRequest.SPIFFEID,
		record.AccessRequest.TaskGrant.OnBehalfOf,
		record.AccessRequest.TaskGrant.TicketID,
		record.AccessRequest.TaskGrant.Repo,
		record.AccessRequest.TaskGrant.CommitSHA,
		string(record.AccessRequest.TaskGrant.Operation),
		record.AccessRequest.TaskGrant.Environment,
		record.AccessRequest.RequestedVaultRole,
		record.AccessRequest.TaskGrant.TTLSeconds,
		grantedTTL,
		string(record.Decision.Kind),
		record.Decision.Reason,
		record.Decision.PolicyVersion,
		record.GrantHash,
		record.AccessRequest.TaskGrant.Nonce,
		record.AccessRequest.TaskGrant.IssuedAt.UTC(),
		record.AccessRequest.RequestedAt.UTC(),
		record.Decision.DecidedAt.UTC(),
		string(record.BindingState),
		record.BindingError,
	)
	if err != nil {
		if isUniqueViolation(err) {
			return Record{}, false, ErrConflict
		}
		return Record{}, false, fmt.Errorf("insert access request: %w", err)
	}
	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return Record{}, false, fmt.Errorf("inspect access request insert: %w", err)
	}
	created := rowsAffected == 1

	if created && record.Approval.State == ApprovalPending {
		_, err = transaction.ExecContext(ctx, `
			INSERT INTO approvals (
				request_id, state, requested_at, reason, version
			) VALUES ($1, $2, $3, $4, $5)
		`,
			record.AccessRequest.RequestID,
			string(record.Approval.State),
			record.Approval.RequestedAt.UTC(),
			record.Approval.Reason,
			record.Approval.Version,
		)
		if err != nil {
			return Record{}, false, fmt.Errorf("insert approval request: %w", err)
		}
	}
	if err := transaction.Commit(); err != nil {
		return Record{}, false, fmt.Errorf("commit access request: %w", err)
	}

	stored, err := s.Get(ctx, record.AccessRequest.RequestID)
	if err != nil {
		return Record{}, false, err
	}
	if !created && !sameSubmission(stored, record) {
		return stored, false, ErrConflict
	}
	return stored, created, nil
}

func (s *PostgresStore) Get(ctx context.Context, requestID string) (Record, error) {
	if err := s.validate(); err != nil {
		return Record{}, err
	}
	record, err := scanRecord(s.db.QueryRowContext(ctx, recordSelect+`
		WHERE ar.request_id = $1
	`, requestID))
	if errors.Is(err, sql.ErrNoRows) {
		return Record{}, ErrNotFound
	}
	if err != nil {
		return Record{}, fmt.Errorf("get access request: %w", err)
	}
	return record, nil
}

func (s *PostgresStore) List(ctx context.Context, filter ListFilter) ([]Record, error) {
	if err := s.validate(); err != nil {
		return nil, err
	}
	query := strings.Builder{}
	query.WriteString(recordSelect)
	query.WriteString(" WHERE TRUE")
	arguments := make([]any, 0, 9)
	addFilter := func(clause string, value any) {
		arguments = append(arguments, value)
		query.WriteString(" AND ")
		query.WriteString(strings.Replace(
			clause,
			"%s",
			"$"+strconv.Itoa(len(arguments)),
			1,
		))
	}
	if filter.Decision != "" {
		addFilter("ar.decision = %s", string(filter.Decision))
	}
	if filter.Approval != "" {
		addFilter("COALESCE(ap.state, 'not_required') = %s", string(filter.Approval))
	}
	if filter.Binding != "" {
		addFilter("ar.binding_state = %s", string(filter.Binding))
	}
	if filter.Active != nil {
		addFilter(`(
			ar.revoked_at IS NULL
			AND now() < COALESCE(
				ar.redemption_expires_at,
				ar.grant_issued_at + ar.requested_ttl_seconds * interval '1 second'
			)
		) = %s`, *filter.Active)
	}
	if filter.SPIFFEID != "" {
		addFilter("ar.spiffe_id = %s", filter.SPIFFEID)
	}
	if filter.OnBehalfOf != "" {
		addFilter("ar.on_behalf_of = %s", filter.OnBehalfOf)
	}
	if filter.Environment != "" {
		addFilter("ar.environment = %s", filter.Environment)
	}
	if filter.Operation != "" {
		addFilter("ar.operation = %s", string(filter.Operation))
	}
	if filter.Repo != "" {
		addFilter("ar.repo = %s", filter.Repo)
	}
	if !filter.CreatedAfter.IsZero() {
		addFilter("ar.requested_at >= %s", filter.CreatedAfter.UTC())
	}
	if !filter.CreatedBefore.IsZero() {
		addFilter("ar.requested_at < %s", filter.CreatedBefore.UTC())
	}

	limit := filter.Limit
	if limit <= 0 {
		limit = defaultListLimit
	}
	limit = min(limit, maxListLimit)
	offset := max(filter.Offset, 0)
	offset = min(offset, maxListOffset)
	arguments = append(arguments, limit, offset)
	query.WriteString(" ORDER BY ar.requested_at DESC, ar.request_id DESC LIMIT $")
	query.WriteString(strconv.Itoa(len(arguments) - 1))
	query.WriteString(" OFFSET $")
	query.WriteString(strconv.Itoa(len(arguments)))

	rows, err := s.db.QueryContext(ctx, query.String(), arguments...)
	if err != nil {
		return nil, fmt.Errorf("list access requests: %w", err)
	}
	defer func() { _ = rows.Close() }()

	records := make([]Record, 0, limit)
	for rows.Next() {
		record, scanErr := scanRecord(rows)
		if scanErr != nil {
			return nil, fmt.Errorf("scan access request: %w", scanErr)
		}
		records = append(records, record)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate access requests: %w", err)
	}
	return records, nil
}

func (s *PostgresStore) Decide(
	ctx context.Context,
	requestID string,
	next ApprovalState,
	actor string,
	reason string,
	at time.Time,
) (Record, bool, bool, error) {
	if err := s.validate(); err != nil {
		return Record{}, false, false, err
	}
	if next != ApprovalApproved && next != ApprovalDenied && next != ApprovalExpired {
		return Record{}, false, false, errors.New("unsupported approval decision")
	}
	if strings.TrimSpace(actor) == "" || len(actor) > maxActorLength || len(reason) > maxReasonLength {
		return Record{}, false, false, errors.New("approval decision metadata is invalid")
	}

	transaction, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return Record{}, false, false, fmt.Errorf("begin approval transaction: %w", err)
	}
	defer func() { _ = transaction.Rollback() }()

	var current ApprovalState
	var version int64
	var grantIssuedAt time.Time
	var requestedTTL int64
	var revokedAt sql.NullTime
	err = transaction.QueryRowContext(ctx, `
		SELECT ap.state, ap.version, ar.grant_issued_at, ar.requested_ttl_seconds, ar.revoked_at
		FROM approvals ap
		JOIN access_requests ar ON ar.request_id = ap.request_id
		WHERE ap.request_id = $1
		FOR UPDATE OF ap, ar
	`, requestID).Scan(&current, &version, &grantIssuedAt, &requestedTTL, &revokedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return Record{}, false, false, ErrNotFound
	}
	if err != nil {
		return Record{}, false, false, fmt.Errorf("lock approval request: %w", err)
	}

	if revokedAt.Valid {
		if err := transaction.Commit(); err != nil {
			return Record{}, false, false, fmt.Errorf("commit revoked approval conflict: %w", err)
		}
		stored, getErr := s.Get(ctx, requestID)
		if getErr != nil {
			return Record{}, false, false, getErr
		}
		return stored, false, false, ErrConflict
	}

	if current == next {
		if err := transaction.Commit(); err != nil {
			return Record{}, false, false, fmt.Errorf("commit idempotent approval: %w", err)
		}
		stored, getErr := s.Get(ctx, requestID)
		return stored, false, false, getErr
	}
	if current != ApprovalPending {
		if err := transaction.Commit(); err != nil {
			return Record{}, false, false, fmt.Errorf("commit approval conflict: %w", err)
		}
		stored, getErr := s.Get(ctx, requestID)
		if getErr != nil {
			return Record{}, false, false, getErr
		}
		return stored, false, false, ErrConflict
	}

	effectiveNext := next
	effectiveReason := reason
	expired := next == ApprovalApproved &&
		!at.Before(grantIssuedAt.Add(time.Duration(requestedTTL)*time.Second))
	if expired {
		effectiveNext = ApprovalExpired
		effectiveReason = "approval window expired"
	}
	_, err = transaction.ExecContext(ctx, `
		UPDATE approvals
		SET state = $2,
		    decided_at = $3,
		    decided_by = $4,
		    reason = $5,
		    version = $6
		WHERE request_id = $1
	`, requestID, string(effectiveNext), at.UTC(), actor, effectiveReason, version+1)
	if err != nil {
		return Record{}, false, false, fmt.Errorf("update approval decision: %w", err)
	}

	bindingState := BindingNotRequired
	claimBinding := effectiveNext == ApprovalApproved
	if claimBinding {
		bindingState = BindingEnabling
	}
	_, err = transaction.ExecContext(ctx, `
		UPDATE access_requests
		SET binding_state = $2,
		    binding_error = '',
		    binding_updated_at = $3,
		    updated_at = $3
		WHERE request_id = $1
	`, requestID, string(bindingState), at.UTC())
	if err != nil {
		return Record{}, false, false, fmt.Errorf("update approval binding state: %w", err)
	}
	if err := transaction.Commit(); err != nil {
		return Record{}, false, false, fmt.Errorf("commit approval decision: %w", err)
	}

	stored, err := s.Get(ctx, requestID)
	if err != nil {
		return Record{}, false, false, err
	}
	if expired {
		return stored, true, false, ErrExpiredRequest
	}
	return stored, true, claimBinding, nil
}

func (s *PostgresStore) ClaimBinding(ctx context.Context, requestID string) (Record, bool, error) {
	if err := s.validate(); err != nil {
		return Record{}, false, err
	}
	transaction, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return Record{}, false, fmt.Errorf("begin binding transaction: %w", err)
	}
	defer func() { _ = transaction.Rollback() }()

	var decision authz.DecisionKind
	var approvalState ApprovalState
	var bindingState BindingState
	var bindingStale bool
	err = transaction.QueryRowContext(ctx, `
		SELECT
			ar.decision,
			COALESCE(ap.state, 'not_required'),
			ar.binding_state,
			ar.binding_updated_at <= now() - $2 * interval '1 second'
		FROM access_requests ar
		LEFT JOIN approvals ap ON ap.request_id = ar.request_id
		WHERE ar.request_id = $1
		FOR UPDATE OF ar
	`, requestID, int64(staleBindingClaim/time.Second)).Scan(
		&decision,
		&approvalState,
		&bindingState,
		&bindingStale,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return Record{}, false, ErrNotFound
	}
	if err != nil {
		return Record{}, false, fmt.Errorf("lock access binding: %w", err)
	}

	eligible := decision == authz.DecisionAllow || approvalState == ApprovalApproved
	claimed := eligible &&
		(bindingState == BindingPending ||
			bindingState == BindingFailed ||
			(bindingState == BindingEnabling && bindingStale))
	if claimed {
		_, err = transaction.ExecContext(ctx, `
			UPDATE access_requests
			SET binding_state = 'enabling',
			    binding_error = '',
			    binding_updated_at = now(),
			    updated_at = now()
			WHERE request_id = $1
		`, requestID)
		if err != nil {
			return Record{}, false, fmt.Errorf("claim access binding: %w", err)
		}
	}
	if err := transaction.Commit(); err != nil {
		return Record{}, false, fmt.Errorf("commit binding claim: %w", err)
	}
	stored, err := s.Get(ctx, requestID)
	return stored, claimed, err
}

func (s *PostgresStore) CompleteBinding(
	ctx context.Context,
	requestID string,
	descriptor *authz.RedemptionDescriptor,
	failure string,
) (Record, error) {
	if err := s.validate(); err != nil {
		return Record{}, err
	}
	if len(failure) > maxBindingError || (failure == "" && descriptor == nil) ||
		(failure != "" && descriptor != nil) {
		return Record{}, errors.New("binding result is invalid")
	}

	var result sql.Result
	var err error
	if failure != "" {
		result, err = s.db.ExecContext(ctx, `
			UPDATE access_requests
			SET binding_state = 'failed',
			    binding_error = $2,
			    vault_address = NULL,
			    vault_auth_mount = NULL,
			    vault_auth_role = NULL,
			    vault_secrets_path = NULL,
			    vault_audience = NULL,
			    redemption_expires_at = NULL,
			    binding_updated_at = now(),
			    updated_at = now()
			WHERE request_id = $1 AND binding_state = 'enabling'
		`, requestID, failure)
	} else {
		if descriptor.RequestID != requestID {
			return Record{}, errors.New("binding descriptor request ID does not match")
		}
		result, err = s.db.ExecContext(ctx, `
			UPDATE access_requests
			SET binding_state = 'enabled',
			    binding_error = '',
			    vault_address = $2,
			    vault_auth_mount = $3,
			    vault_auth_role = $4,
			    vault_secrets_path = $5,
			    vault_audience = $6,
			    redemption_expires_at = $7,
			    binding_updated_at = now(),
			    updated_at = now()
			WHERE request_id = $1 AND binding_state = 'enabling'
		`,
			requestID,
			descriptor.VaultAddress,
			descriptor.AuthMount,
			descriptor.AuthRole,
			descriptor.SecretsPath,
			descriptor.Audience,
			descriptor.ExpiresAt.UTC(),
		)
	}
	if err != nil {
		return Record{}, fmt.Errorf("complete access binding: %w", err)
	}
	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return Record{}, fmt.Errorf("inspect binding completion: %w", err)
	}
	if rowsAffected != 1 {
		stored, getErr := s.Get(ctx, requestID)
		if getErr != nil {
			return Record{}, getErr
		}
		return stored, ErrConflict
	}
	return s.Get(ctx, requestID)
}

func (s *PostgresStore) ClaimExpiredBinding(
	ctx context.Context,
	at time.Time,
) (Record, bool, error) {
	if err := s.validate(); err != nil {
		return Record{}, false, err
	}
	var requestID string
	err := s.db.QueryRowContext(ctx, `
		WITH candidate AS (
			SELECT request_id
			FROM access_requests
			WHERE revoked_at IS NULL
			  AND redemption_expires_at IS NOT NULL
			  AND redemption_expires_at <= $1::timestamptz + $3 * interval '1 second'
			  AND (
			      binding_state = 'enabled'
			      OR (
			          binding_state = 'revoking'
			          AND binding_updated_at <= $1::timestamptz - $2 * interval '1 second'
			      )
			  )
			ORDER BY redemption_expires_at, request_id
			FOR UPDATE SKIP LOCKED
			LIMIT 1
		)
		UPDATE access_requests ar
		SET binding_state = 'revoking',
		    binding_error = '',
		    binding_updated_at = $1::timestamptz,
		    updated_at = $1::timestamptz
		FROM candidate
		WHERE ar.request_id = candidate.request_id
		RETURNING ar.request_id
	`,
		at.UTC(),
		int64(staleBindingClaim/time.Second),
		int64(bindingCleanupLead/time.Second),
	).Scan(&requestID)
	if errors.Is(err, sql.ErrNoRows) {
		return Record{}, false, nil
	}
	if err != nil {
		return Record{}, false, fmt.Errorf("claim expired access binding: %w", err)
	}
	stored, err := s.Get(ctx, requestID)
	if err != nil {
		return Record{}, false, err
	}
	return stored, true, nil
}

func (s *PostgresStore) ReleaseExpiredBinding(
	ctx context.Context,
	requestID string,
	failure string,
	at time.Time,
) error {
	if err := s.validate(); err != nil {
		return err
	}
	if len(failure) > maxBindingError {
		return errors.New("binding failure is too long")
	}
	result, err := s.db.ExecContext(ctx, `
		UPDATE access_requests
		SET binding_state = 'enabled',
		    binding_error = $2,
		    binding_updated_at = $3,
		    updated_at = $3
		WHERE request_id = $1 AND binding_state = 'revoking'
	`, requestID, failure, at.UTC())
	if err != nil {
		return fmt.Errorf("release expired access binding: %w", err)
	}
	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("inspect expired binding release: %w", err)
	}
	if rowsAffected != 1 {
		stored, getErr := s.Get(ctx, requestID)
		if getErr != nil {
			return getErr
		}
		if stored.BindingState != BindingRevoking {
			return ErrConflict
		}
		return errors.New("expired binding release did not update request")
	}
	return nil
}

// RecordRevocation stamps the terminal revoked state only when the binding is
// still in the state the caller observed before revoking in Vault, and never
// over a live enablement claim that could still write to Vault (a stale claim
// from a crashed replica is allowed). Without the guard, a revoke racing an
// in-flight enablement would mark 'revoked' over a binding whose Vault role
// and policy outlive the recorded revocation, and revoked_at would then hide
// the row from the expiry sweeper forever.
func (s *PostgresStore) RecordRevocation(
	ctx context.Context,
	requestID string,
	report vaultmgr.RevocationReport,
	expectedState BindingState,
	at time.Time,
) (Record, error) {
	if err := s.validate(); err != nil {
		return Record{}, err
	}
	if report.RequestID != requestID || len(report.Warnings) > maxWarningCount {
		return Record{}, errors.New("revocation report is invalid")
	}
	for _, warning := range report.Warnings {
		if len(warning) > maxWarningLength {
			return Record{}, errors.New("revocation warning is too long")
		}
	}
	warningValues := report.Warnings
	if warningValues == nil {
		// The column check requires a JSON array; a nil slice encodes as null.
		warningValues = []string{}
	}
	warnings, err := json.Marshal(warningValues)
	if err != nil {
		return Record{}, fmt.Errorf("encode revocation warnings: %w", err)
	}
	result, err := s.db.ExecContext(ctx, `
		UPDATE access_requests
		SET binding_state = 'revoked',
		    binding_error = '',
		    revocation_role_removed = $2,
		    revocation_policy_removed = $3,
		    revocation_leases_revoked = $4,
		    revocation_sts_may_remain = $5,
		    revocation_warnings = $6,
		    revoked_at = $7,
		    binding_updated_at = $7,
		    updated_at = $7
		WHERE request_id = $1
		  AND revoked_at IS NULL
		  AND binding_state = $8
		  AND (
		      binding_state <> 'enabling'
		      OR binding_updated_at <= now() - $9 * interval '1 second'
		  )
	`,
		requestID,
		report.RoleRemoved,
		report.PolicyRemoved,
		report.LeasesRevoked,
		report.STSCredentialsMayRemain,
		warnings,
		at.UTC(),
		string(expectedState),
		int64(staleBindingClaim/time.Second),
	)
	if err != nil {
		return Record{}, fmt.Errorf("record revocation: %w", err)
	}
	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return Record{}, fmt.Errorf("inspect revocation update: %w", err)
	}
	if rowsAffected != 1 {
		stored, getErr := s.Get(ctx, requestID)
		if getErr != nil {
			return Record{}, getErr
		}
		return stored, ErrConflict
	}
	return s.Get(ctx, requestID)
}

func (s *PostgresStore) Ready(ctx context.Context) error {
	if err := s.validate(); err != nil {
		return err
	}
	if err := s.db.PingContext(ctx); err != nil {
		return fmt.Errorf("approval store is not ready: %w", err)
	}
	return nil
}

func (s *PostgresStore) validate() error {
	if s == nil || s.db == nil {
		return errors.New("postgres approval store database is required")
	}
	return nil
}

func validateNewRecord(record Record) error {
	request := record.AccessRequest
	taskGrant := request.TaskGrant
	if strings.TrimSpace(request.RequestID) == "" ||
		request.RequestID != taskGrant.RequestID ||
		strings.TrimSpace(request.SPIFFEID) == "" ||
		strings.TrimSpace(request.RequestedVaultRole) == "" ||
		request.RequestedVaultRole != taskGrant.VaultRole ||
		request.RequestedAt.IsZero() ||
		record.Decision.DecidedAt.IsZero() ||
		len(record.GrantHash) != 64 {
		return errors.New("access request record is invalid")
	}
	if record.Approval.RequestID != request.RequestID ||
		record.Approval.Version < 1 ||
		(record.Decision.Kind == authz.DecisionPendingApproval &&
			record.Approval.State != ApprovalPending) ||
		(record.Decision.Kind != authz.DecisionPendingApproval &&
			record.Approval.State != ApprovalNotRequired) {
		return errors.New("approval request record is invalid")
	}
	return nil
}

func sameSubmission(left Record, right Record) bool {
	return left.AccessRequest.RequestID == right.AccessRequest.RequestID &&
		left.AccessRequest.SPIFFEID == right.AccessRequest.SPIFFEID &&
		left.AccessRequest.RequestedVaultRole == right.AccessRequest.RequestedVaultRole &&
		left.GrantHash == right.GrantHash
}

func isUniqueViolation(err error) bool {
	var postgresError *pgconn.PgError
	return errors.As(err, &postgresError) && postgresError.Code == "23505"
}

type recordScanner interface {
	Scan(...any) error
}

func scanRecord(scanner recordScanner) (Record, error) {
	var (
		requestID          string
		spiffeID           string
		onBehalfOf         string
		ticketID           string
		repo               string
		commitSHA          string
		operation          string
		environment        string
		vaultRole          string
		requestedTTL       int64
		grantedTTL         sql.NullInt64
		decision           string
		decisionReason     string
		policyVersion      string
		grantHash          string
		grantNonce         string
		grantIssuedAt      time.Time
		requestedAt        time.Time
		decidedAt          time.Time
		bindingState       string
		bindingError       string
		vaultAddress       sql.NullString
		vaultAuthMount     sql.NullString
		vaultAuthRole      sql.NullString
		vaultSecretsPath   sql.NullString
		vaultAudience      sql.NullString
		redemptionExpiry   sql.NullTime
		roleRemoved        sql.NullBool
		policyRemoved      sql.NullBool
		leasesRevoked      sql.NullBool
		stsMayRemain       sql.NullBool
		revocationWarnings []byte
		revokedAt          sql.NullTime
		approvalState      string
		approvalRequested  time.Time
		approvalDecided    sql.NullTime
		approvalActor      string
		approvalReason     string
		approvalVersion    int64
	)
	err := scanner.Scan(
		&requestID,
		&spiffeID,
		&onBehalfOf,
		&ticketID,
		&repo,
		&commitSHA,
		&operation,
		&environment,
		&vaultRole,
		&requestedTTL,
		&grantedTTL,
		&decision,
		&decisionReason,
		&policyVersion,
		&grantHash,
		&grantNonce,
		&grantIssuedAt,
		&requestedAt,
		&decidedAt,
		&bindingState,
		&bindingError,
		&vaultAddress,
		&vaultAuthMount,
		&vaultAuthRole,
		&vaultSecretsPath,
		&vaultAudience,
		&redemptionExpiry,
		&roleRemoved,
		&policyRemoved,
		&leasesRevoked,
		&stsMayRemain,
		&revocationWarnings,
		&revokedAt,
		&approvalState,
		&approvalRequested,
		&approvalDecided,
		&approvalActor,
		&approvalReason,
		&approvalVersion,
	)
	if err != nil {
		return Record{}, err
	}

	record := Record{
		AccessRequest: authz.AccessRequest{
			RequestID: requestID,
			SPIFFEID:  spiffeID,
			TaskGrant: grant.TaskGrant{
				RequestID:   requestID,
				Repo:        repo,
				CommitSHA:   commitSHA,
				Operation:   grant.Operation(operation),
				Environment: environment,
				VaultRole:   vaultRole,
				TTLSeconds:  requestedTTL,
				Nonce:       grantNonce,
				IssuedAt:    grantIssuedAt,
				OnBehalfOf:  onBehalfOf,
				TicketID:    ticketID,
			},
			RequestedVaultRole: vaultRole,
			RequestedAt:        requestedAt,
		},
		GrantHash: grantHash,
		Decision: authz.Decision{
			Kind:          authz.DecisionKind(decision),
			Reason:        decisionReason,
			PolicyVersion: policyVersion,
			DecidedAt:     decidedAt,
		},
		Approval: Request{
			RequestID:   requestID,
			State:       ApprovalState(approvalState),
			RequestedAt: approvalRequested,
			DecidedBy:   approvalActor,
			Reason:      approvalReason,
			Version:     approvalVersion,
		},
		BindingState: BindingState(bindingState),
		BindingError: bindingError,
	}
	if grantedTTL.Valid {
		record.Decision.GrantedTTL = time.Duration(grantedTTL.Int64) * time.Second
	}
	if approvalDecided.Valid {
		value := approvalDecided.Time
		record.Approval.DecidedAt = &value
	}

	descriptorPresent := vaultAddress.Valid || vaultAuthMount.Valid || vaultAuthRole.Valid ||
		vaultSecretsPath.Valid || vaultAudience.Valid || redemptionExpiry.Valid
	if descriptorPresent {
		if !vaultAddress.Valid || !vaultAuthMount.Valid || !vaultAuthRole.Valid ||
			!vaultSecretsPath.Valid || !vaultAudience.Valid || !redemptionExpiry.Valid {
			return Record{}, errors.New("stored redemption descriptor is incomplete")
		}
		record.Descriptor = &authz.RedemptionDescriptor{
			RequestID:    requestID,
			VaultAddress: vaultAddress.String,
			AuthMount:    vaultAuthMount.String,
			AuthRole:     vaultAuthRole.String,
			SecretsPath:  vaultSecretsPath.String,
			Audience:     vaultAudience.String,
			ExpiresAt:    redemptionExpiry.Time,
		}
	}

	revocationPresent := roleRemoved.Valid || policyRemoved.Valid || leasesRevoked.Valid ||
		stsMayRemain.Valid || len(revocationWarnings) > 0 || revokedAt.Valid
	if revocationPresent {
		if !roleRemoved.Valid || !policyRemoved.Valid || !leasesRevoked.Valid || !stsMayRemain.Valid {
			return Record{}, errors.New("stored revocation report is incomplete")
		}
		var warnings []string
		if len(revocationWarnings) > 0 {
			if err := json.Unmarshal(revocationWarnings, &warnings); err != nil {
				return Record{}, fmt.Errorf("decode revocation warnings: %w", err)
			}
		}
		record.Revocation = &vaultmgr.RevocationReport{
			RequestID:               requestID,
			RoleRemoved:             roleRemoved.Bool,
			PolicyRemoved:           policyRemoved.Bool,
			LeasesRevoked:           leasesRevoked.Bool,
			STSCredentialsMayRemain: stsMayRemain.Bool,
			Warnings:                warnings,
		}
	}
	if revokedAt.Valid {
		value := revokedAt.Time
		record.RevokedAt = &value
	}
	return record, nil
}

const recordSelect = `
	SELECT
		ar.request_id::text,
		ar.spiffe_id,
		ar.on_behalf_of,
		ar.ticket_id,
		ar.repo,
		ar.commit_sha,
		ar.operation,
		ar.environment,
		ar.vault_role,
		ar.requested_ttl_seconds,
		ar.granted_ttl_seconds,
		ar.decision,
		ar.decision_reason,
		ar.policy_version,
		ar.grant_hash,
		ar.grant_nonce,
		ar.grant_issued_at,
		ar.requested_at,
		ar.decided_at,
		ar.binding_state,
		ar.binding_error,
		ar.vault_address,
		ar.vault_auth_mount,
		ar.vault_auth_role,
		ar.vault_secrets_path,
		ar.vault_audience,
		ar.redemption_expires_at,
		ar.revocation_role_removed,
		ar.revocation_policy_removed,
		ar.revocation_leases_revoked,
		ar.revocation_sts_may_remain,
		ar.revocation_warnings,
		ar.revoked_at,
		COALESCE(ap.state, 'not_required'),
		COALESCE(ap.requested_at, ar.requested_at),
		ap.decided_at,
		COALESCE(ap.decided_by, ''),
		COALESCE(ap.reason, ''),
		COALESCE(ap.version, 1)
	FROM access_requests ar
	LEFT JOIN approvals ap ON ap.request_id = ar.request_id
`
