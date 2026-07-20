package audit

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/jaezeu/agentgate/internal/approval"
	"github.com/jaezeu/agentgate/internal/authz"
	"github.com/jaezeu/agentgate/internal/grant"
)

const (
	defaultAuditLimit = 50
	maxAuditLimit     = 100
	maxRequestEvents  = 1_000
	maxDetailCount    = 32
	maxDetailLength   = 2_048
)

// PostgresStore persists immutable, credential-free correlation events.
type PostgresStore struct {
	db *sql.DB
}

// NewPostgresStore constructs an immutable audit store.
func NewPostgresStore(db *sql.DB) *PostgresStore {
	return &PostgresStore{db: db}
}

func (s *PostgresStore) Append(ctx context.Context, record AuditRecord) error {
	if s == nil || s.db == nil {
		return errors.New("postgres audit store database is required")
	}
	if strings.TrimSpace(record.EventID) == "" {
		var err error
		record.EventID, err = randomUUID()
		if err != nil {
			return err
		}
	}
	if err := s.hydrateCorrelation(ctx, &record); err != nil {
		return err
	}
	record.TaskGrant.Signature = ""
	if err := validateAuditRecord(record); err != nil {
		return err
	}

	taskGrantJSON, err := json.Marshal(record.TaskGrant)
	if err != nil {
		return fmt.Errorf("encode audit task grant: %w", err)
	}
	details, err := safeDetails(record.Details)
	if err != nil {
		return err
	}
	detailsJSON, err := json.Marshal(details)
	if err != nil {
		return fmt.Errorf("encode audit details: %w", err)
	}

	var (
		decisionKind     any
		decisionReason   any
		policyVersion    any
		decisionSnapshot any
		approvalState    any
		vaultAuthRole    any
		awsSessionName   any
	)
	if record.Decision != nil {
		decisionKind = string(record.Decision.Kind)
		decisionReason = record.Decision.Reason
		policyVersion = record.Decision.PolicyVersion
		decisionSnapshot, err = json.Marshal(record.Decision)
		if err != nil {
			return fmt.Errorf("encode audit decision: %w", err)
		}
	}
	if record.ApprovalState != "" && record.ApprovalState != approval.ApprovalNotRequired {
		approvalState = string(record.ApprovalState)
	}
	if record.VaultAuthRole != "" {
		vaultAuthRole = record.VaultAuthRole
	}
	if record.AWSSessionName != "" {
		awsSessionName = record.AWSSessionName
	}

	_, err = s.db.ExecContext(ctx, `
		INSERT INTO audit_events (
			event_id,
			request_id,
			event_type,
			occurred_at,
			spiffe_id,
			on_behalf_of,
			ticket_id,
			decision,
			decision_reason,
			policy_version,
			decision_snapshot,
			approval_state,
			vault_auth_role,
			aws_role_session_name,
			task_grant,
			details
		) VALUES (
			$1, $2, $3, $4, $5, $6, $7, $8,
			$9, $10, $11, $12, $13, $14, $15, $16
		)
	`,
		record.EventID,
		record.RequestID,
		string(record.EventType),
		record.OccurredAt.UTC(),
		record.SPIFFEID,
		record.OnBehalfOf,
		record.TicketID,
		decisionKind,
		decisionReason,
		policyVersion,
		decisionSnapshot,
		approvalState,
		vaultAuthRole,
		awsSessionName,
		taskGrantJSON,
		detailsJSON,
	)
	if err != nil {
		return fmt.Errorf("append audit event: %w", err)
	}
	return nil
}

func (s *PostgresStore) hydrateCorrelation(ctx context.Context, record *AuditRecord) error {
	if record.TaskGrant.RequestID != "" &&
		record.SPIFFEID != "" &&
		record.OnBehalfOf != "" &&
		record.TicketID != "" {
		return nil
	}
	var (
		spiffeID       string
		onBehalfOf     string
		ticketID       string
		repo           string
		commitSHA      string
		operation      string
		environment    string
		vaultRole      string
		ttlSeconds     int64
		nonce          string
		issuedAt       time.Time
		decisionKind   string
		decisionReason string
		grantedTTL     sql.NullInt64
		policyVersion  string
		decidedAt      time.Time
		approvalState  string
	)
	err := s.db.QueryRowContext(ctx, `
		SELECT
			ar.spiffe_id,
			ar.on_behalf_of,
			ar.ticket_id,
			ar.repo,
			ar.commit_sha,
			ar.operation,
			ar.environment,
			ar.vault_role,
			ar.requested_ttl_seconds,
			ar.grant_nonce,
			ar.grant_issued_at,
			ar.decision,
			ar.decision_reason,
			ar.granted_ttl_seconds,
			ar.policy_version,
			ar.decided_at,
			COALESCE(ap.state, 'not_required')
		FROM access_requests ar
		LEFT JOIN approvals ap ON ap.request_id = ar.request_id
		WHERE ar.request_id = $1
	`, record.RequestID).Scan(
		&spiffeID,
		&onBehalfOf,
		&ticketID,
		&repo,
		&commitSHA,
		&operation,
		&environment,
		&vaultRole,
		&ttlSeconds,
		&nonce,
		&issuedAt,
		&decisionKind,
		&decisionReason,
		&grantedTTL,
		&policyVersion,
		&decidedAt,
		&approvalState,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return errors.New("audit event has no durable request correlation")
	}
	if err != nil {
		return fmt.Errorf("hydrate audit event correlation: %w", err)
	}
	if record.SPIFFEID != "" && record.SPIFFEID != spiffeID ||
		record.OnBehalfOf != "" && record.OnBehalfOf != onBehalfOf ||
		record.TicketID != "" && record.TicketID != ticketID ||
		record.TaskGrant.RequestID != "" && record.TaskGrant.RequestID != record.RequestID {
		return errors.New("audit event correlation conflicts with durable request")
	}
	record.SPIFFEID = spiffeID
	record.OnBehalfOf = onBehalfOf
	record.TicketID = ticketID
	record.TaskGrant = grant.TaskGrant{
		RequestID:   record.RequestID,
		Repo:        repo,
		CommitSHA:   commitSHA,
		Operation:   grant.Operation(operation),
		Environment: environment,
		VaultRole:   vaultRole,
		TTLSeconds:  ttlSeconds,
		Nonce:       nonce,
		IssuedAt:    issuedAt,
		OnBehalfOf:  onBehalfOf,
		TicketID:    ticketID,
	}
	if record.Decision == nil {
		record.Decision = &authz.Decision{
			Kind:          authz.DecisionKind(decisionKind),
			Reason:        decisionReason,
			PolicyVersion: policyVersion,
			DecidedAt:     decidedAt,
		}
		if grantedTTL.Valid {
			record.Decision.GrantedTTL = time.Duration(grantedTTL.Int64) * time.Second
		}
	}
	if record.ApprovalState == "" {
		record.ApprovalState = approval.ApprovalState(approvalState)
	}
	return nil
}

func (s *PostgresStore) ByRequestID(ctx context.Context, requestID string) ([]AuditRecord, error) {
	if s == nil || s.db == nil {
		return nil, errors.New("postgres audit store database is required")
	}
	rows, err := s.db.QueryContext(ctx, auditSelect+`
		WHERE request_id = $1
		ORDER BY occurred_at ASC, id ASC
		LIMIT $2
	`, requestID, maxRequestEvents)
	if err != nil {
		return nil, fmt.Errorf("list request audit events: %w", err)
	}
	return collectAuditRecords(rows)
}

func (s *PostgresStore) List(ctx context.Context, query Query) ([]AuditRecord, error) {
	if s == nil || s.db == nil {
		return nil, errors.New("postgres audit store database is required")
	}
	statement := strings.Builder{}
	statement.WriteString(auditSelect)
	statement.WriteString(" WHERE TRUE")
	arguments := make([]any, 0, 4)
	addFilter := func(clause string, value any) {
		arguments = append(arguments, value)
		statement.WriteString(" AND ")
		statement.WriteString(strings.Replace(
			clause,
			"%s",
			"$"+strconv.Itoa(len(arguments)),
			1,
		))
	}
	if query.RequestID != "" {
		addFilter("request_id = %s", query.RequestID)
	}
	if query.Decision != "" {
		addFilter("decision = %s", string(query.Decision))
	}
	if !query.Before.IsZero() {
		if query.BeforeSequence > 0 {
			// Keyset cursor matching the (occurred_at DESC, id DESC) order:
			// a bare occurred_at comparison would skip every remaining
			// record sharing the boundary row's timestamp.
			arguments = append(arguments, query.Before.UTC(), query.BeforeSequence)
			fmt.Fprintf(
				&statement,
				" AND (occurred_at, id) < ($%d, $%d)",
				len(arguments)-1,
				len(arguments),
			)
		} else {
			addFilter("occurred_at < %s", query.Before.UTC())
		}
	}
	limit := query.Limit
	if limit <= 0 {
		limit = defaultAuditLimit
	}
	limit = min(limit, maxAuditLimit)
	arguments = append(arguments, limit)
	statement.WriteString(" ORDER BY occurred_at DESC, id DESC LIMIT $")
	statement.WriteString(strconv.Itoa(len(arguments)))

	rows, err := s.db.QueryContext(ctx, statement.String(), arguments...)
	if err != nil {
		return nil, fmt.Errorf("list audit events: %w", err)
	}
	return collectAuditRecords(rows)
}

func collectAuditRecords(rows *sql.Rows) ([]AuditRecord, error) {
	defer func() { _ = rows.Close() }()
	records := make([]AuditRecord, 0)
	for rows.Next() {
		record, err := scanAuditRecord(rows)
		if err != nil {
			return nil, fmt.Errorf("scan audit event: %w", err)
		}
		records = append(records, record)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate audit events: %w", err)
	}
	return records, nil
}

func scanAuditRecord(scanner interface{ Scan(...any) error }) (AuditRecord, error) {
	var (
		record         AuditRecord
		eventType      string
		decisionKind   sql.NullString
		decisionReason sql.NullString
		policyVersion  sql.NullString
		decisionJSON   []byte
		approvalState  sql.NullString
		vaultAuthRole  sql.NullString
		awsSessionName sql.NullString
		taskGrantJSON  []byte
		detailsJSON    []byte
	)
	err := scanner.Scan(
		&record.Sequence,
		&record.EventID,
		&record.RequestID,
		&eventType,
		&record.OccurredAt,
		&record.SPIFFEID,
		&record.OnBehalfOf,
		&record.TicketID,
		&decisionKind,
		&decisionReason,
		&policyVersion,
		&decisionJSON,
		&approvalState,
		&vaultAuthRole,
		&awsSessionName,
		&taskGrantJSON,
		&detailsJSON,
	)
	if err != nil {
		return AuditRecord{}, err
	}
	record.EventType = EventType(eventType)
	record.ApprovalState = approval.ApprovalState(approvalState.String)
	record.VaultAuthRole = vaultAuthRole.String
	record.AWSSessionName = awsSessionName.String
	if err := json.Unmarshal(taskGrantJSON, &record.TaskGrant); err != nil {
		return AuditRecord{}, fmt.Errorf("decode task grant: %w", err)
	}
	record.TaskGrant.Signature = ""
	if len(decisionJSON) > 0 {
		var decision authz.Decision
		if err := json.Unmarshal(decisionJSON, &decision); err != nil {
			return AuditRecord{}, fmt.Errorf("decode decision: %w", err)
		}
		record.Decision = &decision
	} else if decisionKind.Valid {
		record.Decision = &authz.Decision{
			Kind:          authz.DecisionKind(decisionKind.String),
			Reason:        decisionReason.String,
			PolicyVersion: policyVersion.String,
		}
	}
	if len(detailsJSON) > 0 {
		if err := json.Unmarshal(detailsJSON, &record.Details); err != nil {
			return AuditRecord{}, fmt.Errorf("decode details: %w", err)
		}
	}
	return record, nil
}

func validateAuditRecord(record AuditRecord) error {
	if strings.TrimSpace(record.RequestID) == "" ||
		record.TaskGrant.RequestID != record.RequestID ||
		strings.TrimSpace(record.SPIFFEID) == "" ||
		strings.TrimSpace(record.OnBehalfOf) == "" ||
		record.TaskGrant.OnBehalfOf != record.OnBehalfOf ||
		record.TaskGrant.Signature != "" ||
		record.OccurredAt.IsZero() {
		return errors.New("audit event correlation data is invalid")
	}
	switch record.EventType {
	case EventGrantVerified,
		EventDecisionRecorded,
		EventApprovalRequested,
		EventApprovalDecided,
		EventBindingEnabled,
		EventBindingFailed,
		EventRevocation:
	default:
		return errors.New("audit event type is invalid")
	}
	return nil
}

func safeDetails(details map[string]string) (map[string]string, error) {
	if len(details) > maxDetailCount {
		return nil, errors.New("audit details contain too many fields")
	}
	safe := make(map[string]string, len(details))
	for key, value := range details {
		normalizedKey := strings.ToLower(strings.NewReplacer(
			"-", "",
			"_", "",
			".", "",
		).Replace(key))
		if key == "" || len(key) > 128 || len(value) > maxDetailLength ||
			containsSensitiveName(normalizedKey) || containsCredentialMarker(value) {
			return nil, errors.New("audit details contain a prohibited field")
		}
		safe[key] = value
	}
	return safe, nil
}

func containsSensitiveName(key string) bool {
	for _, prohibited := range []string{
		"accesskey",
		"apikey",
		"authorization",
		"credential",
		"password",
		"privatekey",
		"secretkey",
		"sessiontoken",
		"signature",
		"token",
		"vaultlease",
	} {
		if strings.Contains(key, prohibited) {
			return true
		}
	}
	return false
}

func containsCredentialMarker(value string) bool {
	upper := strings.ToUpper(value)
	return strings.Contains(upper, "-----BEGIN PRIVATE KEY-----") ||
		strings.Contains(upper, "-----BEGIN RSA PRIVATE KEY-----") ||
		strings.Contains(upper, "BEARER ") ||
		strings.Contains(upper, "HVS.") ||
		strings.Contains(upper, "HVB.") ||
		strings.Contains(upper, "HVR.") ||
		containsAWSAccessKeyID(upper) ||
		containsAWSSecretKeyCandidate(value)
}

// containsAWSSecretKeyCandidate flags exactly-40-character runs of the AWS
// secret-key alphabet that mix upper case, lower case, and a digit or symbol.
// The case/digit requirement keeps 40-character lowercase hex values (git
// commit SHAs) from matching while catching real secret keys, which are
// random base64-like strings. It runs on the original value because
// containsCredentialMarker's upper-cased copy erases the case signal.
func containsAWSSecretKeyCandidate(value string) bool {
	isKeyByte := func(b byte) bool {
		return (b >= 'A' && b <= 'Z') || (b >= 'a' && b <= 'z') ||
			(b >= '0' && b <= '9') || b == '/' || b == '+' || b == '='
	}
	for start := 0; start < len(value); {
		if !isKeyByte(value[start]) {
			start++
			continue
		}
		end := start
		var hasUpper, hasLower, hasDigitOrSymbol bool
		for end < len(value) && isKeyByte(value[end]) {
			switch b := value[end]; {
			case b >= 'A' && b <= 'Z':
				hasUpper = true
			case b >= 'a' && b <= 'z':
				hasLower = true
			default:
				hasDigitOrSymbol = true
			}
			end++
		}
		if end-start == 40 && hasUpper && hasLower && hasDigitOrSymbol {
			return true
		}
		start = end
	}
	return false
}

func containsAWSAccessKeyID(value string) bool {
	for _, prefix := range []string{"AKIA", "ASIA"} {
		for start := strings.Index(value, prefix); start >= 0; {
			end := start + 20
			if end <= len(value) {
				matches := true
				for _, char := range value[start+len(prefix) : end] {
					if (char < 'A' || char > 'Z') && (char < '0' || char > '9') {
						matches = false
						break
					}
				}
				if matches {
					return true
				}
			}
			next := strings.Index(value[start+len(prefix):], prefix)
			if next < 0 {
				break
			}
			start += len(prefix) + next
		}
	}
	return false
}

func randomUUID() (string, error) {
	value := make([]byte, 16)
	if _, err := rand.Read(value); err != nil {
		return "", fmt.Errorf("generate audit event ID: %w", err)
	}
	value[6] = (value[6] & 0x0f) | 0x40
	value[8] = (value[8] & 0x3f) | 0x80
	return fmt.Sprintf(
		"%08x-%04x-%04x-%04x-%012x",
		value[0:4],
		value[4:6],
		value[6:8],
		value[8:10],
		value[10:16],
	), nil
}

const auditSelect = `
	SELECT
		id,
		event_id::text,
		request_id::text,
		event_type,
		occurred_at,
		spiffe_id,
		on_behalf_of,
		ticket_id,
		decision,
		decision_reason,
		policy_version,
		decision_snapshot,
		approval_state,
		vault_auth_role,
		aws_role_session_name,
		task_grant,
		details
	FROM audit_events
`
