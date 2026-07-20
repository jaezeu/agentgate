package approval_test

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net"
	"net/url"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	_ "github.com/jackc/pgx/v5/stdlib"
	"github.com/jaezeu/agentgate/internal/approval"
	"github.com/jaezeu/agentgate/internal/audit"
	"github.com/jaezeu/agentgate/internal/authz"
	"github.com/jaezeu/agentgate/internal/grant"
	"github.com/jaezeu/agentgate/internal/vaultmgr"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/wait"
)

const postgresTestImage = "postgres:17@sha256:a426e44bac0b759c95894d68e1a0ac03ecc20b619f498a91aae373bf06d8508d"

// testDatabaseURL prefers a configured database (as in CI) and otherwise
// starts a disposable PostgreSQL container so that these integration tests
// never silently skip when the required merge-bar dependencies are present.
func testDatabaseURL(t *testing.T) string {
	t.Helper()
	if databaseURL := os.Getenv("AGENTGATE_TEST_DATABASE_URL"); databaseURL != "" {
		return databaseURL
	}
	requirePostgresDocker(t)

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	container, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
		ContainerRequest: testcontainers.ContainerRequest{
			Image:        postgresTestImage,
			ExposedPorts: []string{"5432/tcp"},
			Env: map[string]string{
				"POSTGRES_DB":       "agentgate",
				"POSTGRES_USER":     "agentgate",
				"POSTGRES_PASSWORD": "agentgate",
			},
			WaitingFor: wait.ForLog("database system is ready to accept connections").
				WithOccurrence(2).
				WithStartupTimeout(2 * time.Minute),
		},
		Started: true,
	})
	testcontainers.CleanupContainer(t, container)
	if err != nil {
		t.Fatalf("start PostgreSQL test container: %v", err)
	}
	host, err := container.Host(ctx)
	if err != nil {
		t.Fatalf("resolve PostgreSQL test host: %v", err)
	}
	port, err := container.MappedPort(ctx, "5432/tcp")
	if err != nil {
		t.Fatalf("resolve PostgreSQL test port: %v", err)
	}
	return fmt.Sprintf(
		"postgres://agentgate:agentgate@%s/agentgate?sslmode=disable",
		net.JoinHostPort(host, port.Port()),
	)
}

func requirePostgresDocker(t *testing.T) {
	t.Helper()
	defer func() {
		if recovered := recover(); recovered != nil {
			handlePostgresUnavailable(t, fmt.Sprint(recovered))
		}
	}()
	provider, err := testcontainers.ProviderDocker.GetProvider()
	if err == nil {
		err = provider.Health(context.Background())
	}
	if err != nil {
		handlePostgresUnavailable(t, err.Error())
	}
}

func handlePostgresUnavailable(t *testing.T, reason string) {
	t.Helper()
	if os.Getenv("AGENTGATE_REQUIRE_DOCKER") == "true" {
		t.Fatalf("Docker is required for the PostgreSQL integration tests when AGENTGATE_TEST_DATABASE_URL is unset: %s", reason)
	}
	t.Skipf("AGENTGATE_TEST_DATABASE_URL is not set and Docker is unavailable: %s", reason)
}

func TestPostgresStoresLifecycleAndRace(t *testing.T) {
	databaseURL := testDatabaseURL(t)
	db := openTestDatabase(t, databaseURL)
	ctx := context.Background()
	now := time.Now().UTC().Truncate(time.Second)

	nonces := grant.NewPostgresNonceStore(db)
	used, err := nonces.Use(ctx, "shared-integration-nonce", now, now.Add(time.Minute))
	if err != nil || !used {
		t.Fatalf("first nonce use = %v, %v; want true, nil", used, err)
	}
	used, err = nonces.Use(ctx, "shared-integration-nonce", now, now.Add(time.Minute))
	if err != nil || used {
		t.Fatalf("second nonce use = %v, %v; want false, nil", used, err)
	}

	requests := approval.NewPostgresStore(db)
	record := pendingRecord(
		"00000000-0000-4000-8000-000000000101",
		"request-nonce-101",
		now,
	)
	stored, created, err := requests.Create(ctx, record)
	if err != nil || !created {
		t.Fatalf("Create() = created %v, error %v; want true, nil", created, err)
	}
	if stored.Approval.State != approval.ApprovalPending {
		t.Fatalf("approval state = %q, want pending", stored.Approval.State)
	}

	approved, won, claim, err := requests.Decide(
		ctx,
		record.AccessRequest.RequestID,
		approval.ApprovalApproved,
		"approver@example.test",
		"reviewed",
		now.Add(time.Second),
	)
	if err != nil || !won || !claim {
		t.Fatalf("Decide(approved) = won %v, claim %v, error %v", won, claim, err)
	}
	if approved.BindingState != approval.BindingEnabling {
		t.Fatalf("binding state = %q, want enabling", approved.BindingState)
	}
	_, won, claim, err = requests.Decide(
		ctx,
		record.AccessRequest.RequestID,
		approval.ApprovalApproved,
		"approver@example.test",
		"reviewed",
		now.Add(2*time.Second),
	)
	if err != nil || won || claim {
		t.Fatalf("idempotent Decide() = won %v, claim %v, error %v", won, claim, err)
	}

	// #nosec G101 -- this descriptor contains only credential-free routing metadata.
	descriptor := &authz.RedemptionDescriptor{ //nolint:gosec // Credential-free test routing metadata.
		RequestID:    record.AccessRequest.RequestID,
		VaultAddress: "https://vault.example.test",
		AuthMount:    "jwt",
		AuthRole:     "request-role",
		SecretsPath:  "aws/creds/request-role",
		Audience:     "vault",
		ExpiresAt:    now.Add(5 * time.Minute),
	}
	enabled, err := requests.CompleteBinding(
		ctx,
		record.AccessRequest.RequestID,
		descriptor,
		"",
	)
	if err != nil || enabled.BindingState != approval.BindingEnabled {
		t.Fatalf("CompleteBinding() state = %q, error %v", enabled.BindingState, err)
	}

	report := vaultmgr.RevocationReport{
		RequestID:               record.AccessRequest.RequestID,
		RoleRemoved:             true,
		PolicyRemoved:           true,
		STSCredentialsMayRemain: true,
		Warnings:                []string{"STS credentials may remain valid until expiry."},
	}
	revoked, err := requests.RecordRevocation(
		ctx,
		record.AccessRequest.RequestID,
		report,
		approval.BindingEnabled,
		now.Add(3*time.Second),
	)
	if err != nil || revoked.Revocation == nil || !revoked.Revocation.STSCredentialsMayRemain {
		t.Fatalf("RecordRevocation() = %#v, error %v", revoked.Revocation, err)
	}

	revokedPending := pendingRecord(
		"00000000-0000-4000-8000-000000000102",
		"request-nonce-102",
		now,
	)
	if _, created, err := requests.Create(ctx, revokedPending); err != nil || !created {
		t.Fatalf("Create(revoked pending) = created %v, error %v; want true, nil", created, err)
	}
	if _, err := requests.RecordRevocation(
		ctx,
		revokedPending.AccessRequest.RequestID,
		vaultmgr.RevocationReport{RequestID: revokedPending.AccessRequest.RequestID},
		approval.BindingPending,
		now.Add(4*time.Second),
	); err != nil {
		t.Fatalf("RecordRevocation(pending) error = %v", err)
	}
	afterRevoke, won, claim, err := requests.Decide(
		ctx,
		revokedPending.AccessRequest.RequestID,
		approval.ApprovalApproved,
		"approver@example.test",
		"approved after revocation",
		now.Add(5*time.Second),
	)
	if !errors.Is(err, approval.ErrConflict) || won || claim {
		t.Fatalf("Decide(after revocation) = won %v, claim %v, error %v; want conflict", won, claim, err)
	}
	if afterRevoke.BindingState != approval.BindingRevoked {
		t.Fatalf("binding state after revoked approval attempt = %q, want revoked", afterRevoke.BindingState)
	}

	audits := audit.NewPostgresStore(db)
	taskGrant := record.AccessRequest.TaskGrant
	taskGrant.Signature = "must-not-be-persisted"
	err = audits.Append(ctx, audit.AuditRecord{
		RequestID:     record.AccessRequest.RequestID,
		EventType:     audit.EventDecisionRecorded,
		OccurredAt:    now,
		SPIFFEID:      record.AccessRequest.SPIFFEID,
		OnBehalfOf:    taskGrant.OnBehalfOf,
		TicketID:      taskGrant.TicketID,
		TaskGrant:     taskGrant,
		Decision:      &record.Decision,
		ApprovalState: approval.ApprovalPending,
		Details:       map[string]string{"result": "pending"},
	})
	if err != nil {
		t.Fatalf("Append() error = %v", err)
	}
	events, err := audits.ByRequestID(ctx, record.AccessRequest.RequestID)
	if err != nil || len(events) != 1 {
		t.Fatalf("ByRequestID() length = %d, error %v", len(events), err)
	}
	if events[0].TaskGrant.Signature != "" || events[0].Decision == nil ||
		events[0].Decision.PolicyVersion != record.Decision.PolicyVersion {
		t.Fatalf("stored audit event = %#v", events[0])
	}
	err = audits.Append(ctx, audit.AuditRecord{
		RequestID:  record.AccessRequest.RequestID,
		EventType:  audit.EventBindingEnabled,
		OccurredAt: now.Add(time.Second),
		Details:    map[string]string{"status": "enabled"},
	})
	if err != nil {
		t.Fatalf("Append(partial manager event) error = %v", err)
	}
	events, err = audits.ByRequestID(ctx, record.AccessRequest.RequestID)
	if err != nil || len(events) != 2 {
		t.Fatalf("ByRequestID() hydrated length = %d, error %v", len(events), err)
	}
	if events[1].SPIFFEID != record.AccessRequest.SPIFFEID ||
		events[1].OnBehalfOf != record.AccessRequest.TaskGrant.OnBehalfOf ||
		events[1].TaskGrant.RequestID != record.AccessRequest.RequestID {
		t.Fatalf("manager audit event was not hydrated: %#v", events[1])
	}

	raceRecord := pendingRecord(
		"00000000-0000-4000-8000-000000000106",
		"request-nonce-106",
		now,
	)
	if _, _, err := requests.Create(ctx, raceRecord); err != nil {
		t.Fatalf("create race request: %v", err)
	}
	var winners atomic.Int32
	var waitGroup sync.WaitGroup
	for _, next := range []approval.ApprovalState{
		approval.ApprovalApproved,
		approval.ApprovalDenied,
	} {
		waitGroup.Add(1)
		go func(state approval.ApprovalState) {
			defer waitGroup.Done()
			_, won, _, decideErr := requests.Decide(
				ctx,
				raceRecord.AccessRequest.RequestID,
				state,
				"racing-approver@example.test",
				"race",
				now.Add(time.Second),
			)
			if won {
				winners.Add(1)
			}
			if decideErr != nil && !errors.Is(decideErr, approval.ErrConflict) {
				t.Errorf("Decide(%q) error = %v", state, decideErr)
			}
		}(next)
	}
	waitGroup.Wait()
	if winners.Load() != 1 {
		t.Fatalf("approval race winners = %d, want 1", winners.Load())
	}
	raceResult, err := requests.Get(ctx, raceRecord.AccessRequest.RequestID)
	if err != nil {
		t.Fatalf("Get(race) error = %v", err)
	}
	if raceResult.Approval.State != approval.ApprovalApproved &&
		raceResult.Approval.State != approval.ApprovalDenied {
		t.Fatalf("race state = %q", raceResult.Approval.State)
	}

	staleRecord := pendingRecord(
		"00000000-0000-4000-8000-000000000104",
		"request-nonce-104",
		now,
	)
	if _, _, err := requests.Create(ctx, staleRecord); err != nil {
		t.Fatalf("create stale binding request: %v", err)
	}
	if _, _, claim, err := requests.Decide(
		ctx,
		staleRecord.AccessRequest.RequestID,
		approval.ApprovalApproved,
		"approver@example.test",
		"reviewed",
		now.Add(time.Second),
	); err != nil || !claim {
		t.Fatalf("approve stale binding request: claim %v, error %v", claim, err)
	}
	if _, err := db.ExecContext(ctx, `
		UPDATE access_requests
		SET binding_updated_at = now() - interval '1 minute'
		WHERE request_id = $1
	`, staleRecord.AccessRequest.RequestID); err != nil {
		t.Fatalf("age binding claim: %v", err)
	}
	reclaimed, claim, err := requests.ClaimBinding(ctx, staleRecord.AccessRequest.RequestID)
	if err != nil || !claim || reclaimed.BindingState != approval.BindingEnabling {
		t.Fatalf(
			"ClaimBinding(stale) = state %q, claim %v, error %v",
			reclaimed.BindingState,
			claim,
			err,
		)
	}

	expiredRecord := pendingRecord(
		"00000000-0000-4000-8000-000000000103",
		"request-nonce-103",
		now.Add(-2*time.Minute),
	)
	expiredRecord.AccessRequest.TaskGrant.TTLSeconds = 60
	if _, _, err := requests.Create(ctx, expiredRecord); err != nil {
		t.Fatalf("create expired request: %v", err)
	}
	expired, _, claim, err := requests.Decide(
		ctx,
		expiredRecord.AccessRequest.RequestID,
		approval.ApprovalApproved,
		"approver@example.test",
		"late review",
		now,
	)
	if !errors.Is(err, approval.ErrExpiredRequest) || claim ||
		expired.Approval.State != approval.ApprovalExpired {
		t.Fatalf("expired Decide() = state %q, claim %v, error %v", expired.Approval.State, claim, err)
	}
}

func TestPostgresExpiredBindingClaimIsReplicaSafeAndRecoverable(t *testing.T) {
	databaseURL := testDatabaseURL(t)
	db := openTestDatabase(t, databaseURL)
	ctx := context.Background()
	now := time.Now().UTC().Truncate(time.Second)
	requestID := "00000000-0000-4000-8000-000000000105"
	requests := approval.NewPostgresStore(db)
	record := pendingRecord(requestID, "request-nonce-105", now.Add(-time.Minute))
	if _, _, err := requests.Create(ctx, record); err != nil {
		t.Fatalf("create expiry request: %v", err)
	}
	if _, _, _, err := requests.Decide(
		ctx,
		requestID,
		approval.ApprovalApproved,
		"approver@example.test",
		"reviewed",
		now.Add(-30*time.Second),
	); err != nil {
		t.Fatalf("approve expiry request: %v", err)
	}
	descriptor := &authz.RedemptionDescriptor{ //nolint:gosec // Credential-free test routing metadata.
		RequestID:    requestID,
		VaultAddress: "https://vault.example.test",
		AuthMount:    "jwt",
		AuthRole:     "request-role",
		SecretsPath:  "aws/creds/request-role",
		Audience:     "vault",
		ExpiresAt:    now.Add(-time.Second),
	}
	if _, err := requests.CompleteBinding(ctx, requestID, descriptor, ""); err != nil {
		t.Fatalf("enable expiry request: %v", err)
	}

	var winners atomic.Int32
	var waitGroup sync.WaitGroup
	for range 2 {
		waitGroup.Add(1)
		go func() {
			defer waitGroup.Done()
			_, claimed, err := approval.NewPostgresStore(db).ClaimExpiredBinding(ctx, now)
			if err != nil {
				t.Errorf("claim expired binding: %v", err)
				return
			}
			if claimed {
				winners.Add(1)
			}
		}()
	}
	waitGroup.Wait()
	if winners.Load() != 1 {
		t.Fatalf("expiry claim winners = %d, want 1", winners.Load())
	}

	if err := requests.ReleaseExpiredBinding(
		ctx,
		requestID,
		"automatic expiry cleanup failed",
		now.Add(time.Second),
	); err != nil {
		t.Fatalf("release expiry claim: %v", err)
	}
	if _, claimed, err := requests.ClaimExpiredBinding(ctx, now.Add(2*time.Second)); err != nil || !claimed {
		t.Fatalf("reclaim released binding: claimed=%t err=%v", claimed, err)
	}

	if _, err := db.ExecContext(ctx, `
		UPDATE access_requests
		SET binding_updated_at = $2
		WHERE request_id = $1
	`, requestID, now.Add(-31*time.Second)); err != nil {
		t.Fatalf("age expiry claim: %v", err)
	}
	restartedStore := approval.NewPostgresStore(db)
	recovered, claimed, err := restartedStore.ClaimExpiredBinding(ctx, now)
	if err != nil || !claimed {
		t.Fatalf("recover stale expiry claim: claimed=%t err=%v", claimed, err)
	}
	if recovered.BindingState != approval.BindingRevoking {
		t.Fatalf("recovered state = %q, want revoking", recovered.BindingState)
	}
}

func pendingRecord(requestID, nonce string, issuedAt time.Time) approval.Record {
	taskGrant := grant.TaskGrant{
		RequestID:   requestID,
		Repo:        "github.com/jaezeu/agentgate",
		CommitSHA:   strings.Repeat("a", 40),
		Operation:   grant.OperationTerraformApply,
		Environment: "prod",
		VaultRole:   "terraform-prod",
		TTLSeconds:  900,
		Nonce:       nonce,
		IssuedAt:    issuedAt,
		OnBehalfOf:  "requester@example.test",
		TicketID:    "CHANGE-123",
	}
	accessRequest := authz.AccessRequest{
		RequestID:          requestID,
		SPIFFEID:           "spiffe://agentgate.test/ns/agents/sa/runner",
		TaskGrant:          taskGrant,
		RequestedVaultRole: taskGrant.VaultRole,
		RequestedAt:        issuedAt,
	}
	return approval.NewRecord(accessRequest, authz.Decision{
		Kind:          authz.DecisionPendingApproval,
		Reason:        "production apply requires human approval",
		GrantedTTL:    5 * time.Minute,
		PolicyVersion: strings.Repeat("b", 64),
		DecidedAt:     issuedAt,
	}, strings.Repeat("c", 64))
}

func openTestDatabase(t *testing.T, databaseURL string) *sql.DB {
	t.Helper()
	parsedURL, err := url.Parse(databaseURL)
	if err != nil {
		t.Fatalf("parse test database URL: %v", err)
	}
	admin, err := sql.Open("pgx", databaseURL)
	if err != nil {
		t.Fatalf("open test database: %v", err)
	}
	t.Cleanup(func() { _ = admin.Close() })

	schema := fmt.Sprintf("agentgate_test_%d", time.Now().UnixNano())
	if _, err := admin.Exec("CREATE SCHEMA " + schema); err != nil {
		t.Fatalf("create test schema: %v", err)
	}
	t.Cleanup(func() {
		if _, dropErr := admin.Exec("DROP SCHEMA " + schema + " CASCADE"); dropErr != nil {
			t.Errorf("drop test schema: %v", dropErr)
		}
	})

	query := parsedURL.Query()
	query.Set("search_path", schema)
	parsedURL.RawQuery = query.Encode()
	db, err := sql.Open("pgx", parsedURL.String())
	if err != nil {
		t.Fatalf("open schema database: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })

	for _, path := range []string{
		"../audit/migrations/000001_foundation.up.sql",
		"../audit/migrations/000002_expiring_bindings.up.sql",
	} {
		migration, err := os.ReadFile(path) // #nosec G304 -- paths are fixed test migrations.
		if err != nil {
			t.Fatalf("read test migration %q: %v", path, err)
		}
		if _, err := db.Exec(string(migration)); err != nil {
			t.Fatalf("apply test migration %q: %v", path, err)
		}
	}
	return db
}
