package api

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jaezeu/agentgate/internal/approval"
	"github.com/jaezeu/agentgate/internal/audit"
	"github.com/jaezeu/agentgate/internal/authz"
	"github.com/jaezeu/agentgate/internal/grant"
	"github.com/jaezeu/agentgate/internal/svid"
	"github.com/jaezeu/agentgate/internal/vaultmgr"
)

const (
	testHumanToken = "runtime-only-human-token"
	testSPIFFEID   = "spiffe://agentgate.test/ns/agents/sa/runner"
)

func TestImmediateAllowReturnsDescriptorAndAudits(t *testing.T) {
	harness := newAPIHarness(t, authz.DecisionAllow)
	taskGrant := harness.taskGrant("00000000-0000-4000-8000-000000000201", "nonce-201")

	response := harness.submit(taskGrant, "")

	if response.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", response.Code, response.Body.String())
	}
	body := response.Body.String()
	if !strings.Contains(body, `"descriptor"`) ||
		!strings.Contains(body, `"audience":"vault"`) {
		t.Fatalf("allow response missing descriptor: %s", body)
	}
	if strings.Contains(body, taskGrant.Signature) || strings.Contains(body, taskGrant.Nonce) {
		t.Fatalf("allow response exposed signed grant material: %s", body)
	}
	if harness.vault.enableCallCount() != 1 {
		t.Fatalf("EnableAccess() calls = %d, want 1", harness.vault.enableCallCount())
	}
	eventTypes := harness.audits.eventTypes()
	for _, expected := range []audit.EventType{
		audit.EventGrantVerified,
		audit.EventDecisionRecorded,
		audit.EventBindingEnabled,
	} {
		if !containsEvent(eventTypes, expected) {
			t.Fatalf("audit events = %v, missing %q", eventTypes, expected)
		}
	}
	for _, event := range harness.audits.records() {
		if event.RequestID != taskGrant.RequestID || event.TaskGrant.Signature != "" {
			t.Fatalf("unsafe or uncorrelated audit event: %#v", event)
		}
		if event.EventType == audit.EventBindingEnabled &&
			event.AWSSessionName != taskGrant.RequestID {
			t.Fatalf("binding audit AWS session = %q, want request ID", event.AWSSessionName)
		}
	}
}

func TestInvalidGrantStopsBeforePolicyAndVault(t *testing.T) {
	harness := newAPIHarness(t, authz.DecisionAllow)
	harness.verifier.errors = []error{grant.ErrInvalidSignature}

	response := harness.submit(
		harness.taskGrant("00000000-0000-4000-8000-000000000202", "nonce-202"),
		"",
	)

	if response.Code != http.StatusUnauthorized ||
		!strings.Contains(response.Body.String(), "invalid_task_grant_signature") {
		t.Fatalf("response = %d %s", response.Code, response.Body.String())
	}
	if harness.policy.callCount() != 0 || harness.vault.enableCallCount() != 0 {
		t.Fatalf(
			"policy calls = %d, Vault calls = %d; want 0, 0",
			harness.policy.callCount(),
			harness.vault.enableCallCount(),
		)
	}
}

func TestPolicyDenyReturnsDistinctReasonWithoutVault(t *testing.T) {
	harness := newAPIHarness(t, authz.DecisionDeny)
	harness.policy.reason = "repository is outside the approved allowlist"

	response := harness.submit(
		harness.taskGrant("00000000-0000-4000-8000-000000000203", "nonce-203"),
		"",
	)

	if response.Code != http.StatusForbidden ||
		!strings.Contains(response.Body.String(), harness.policy.reason) {
		t.Fatalf("response = %d %s", response.Code, response.Body.String())
	}
	if harness.vault.enableCallCount() != 0 {
		t.Fatalf("EnableAccess() calls = %d, want 0", harness.vault.enableCallCount())
	}
}

func TestAllowedTTLIsClampedToSignedGrantExpiry(t *testing.T) {
	harness := newAPIHarness(t, authz.DecisionAllow)
	harness.policy.grantedTTL = 15 * time.Minute
	taskGrant := harness.taskGrant("00000000-0000-4000-8000-000000000220", "nonce-220")
	taskGrant.IssuedAt = harness.now.Add(-2 * time.Second)

	response := harness.submit(taskGrant, "")

	if response.Code != http.StatusOK {
		t.Fatalf("response = %d %s", response.Code, response.Body.String())
	}
	record, err := harness.store.Get(context.Background(), taskGrant.RequestID)
	if err != nil {
		t.Fatalf("Get() error = %v", err)
	}
	if record.Decision.GrantedTTL != 898*time.Second {
		t.Fatalf("granted TTL = %s, want 898s", record.Decision.GrantedTTL)
	}
}

func TestWorkloadAuthReplayAndCorrelationBoundaries(t *testing.T) {
	t.Run("missing SVID", func(t *testing.T) {
		harness := newAPIHarness(t, authz.DecisionAllow)
		request := harness.accessHTTPRequest(
			harness.taskGrant("00000000-0000-4000-8000-000000000204", "nonce-204"),
		)
		request.TLS = nil
		response := httptest.NewRecorder()
		harness.router.ServeHTTP(response, request)
		if response.Code != http.StatusUnauthorized || harness.verifier.callCount() != 0 {
			t.Fatalf("response = %d %s", response.Code, response.Body.String())
		}
	})

	t.Run("invalid SVID", func(t *testing.T) {
		harness := newAPIHarness(t, authz.DecisionAllow)
		harness.svid.validationError = errors.New("untrusted SVID")
		response := harness.submit(
			harness.taskGrant("00000000-0000-4000-8000-000000000205", "nonce-205"),
			"",
		)
		if response.Code != http.StatusUnauthorized || harness.verifier.callCount() != 0 {
			t.Fatalf("response = %d %s", response.Code, response.Body.String())
		}
	})

	t.Run("human token cannot authenticate workload", func(t *testing.T) {
		harness := newAPIHarness(t, authz.DecisionAllow)
		response := harness.submit(
			harness.taskGrant("00000000-0000-4000-8000-000000000206", "nonce-206"),
			testHumanToken,
		)
		if response.Code != http.StatusUnauthorized || harness.verifier.callCount() != 0 {
			t.Fatalf("response = %d %s", response.Code, response.Body.String())
		}
	})

	t.Run("replayed nonce", func(t *testing.T) {
		harness := newAPIHarness(t, authz.DecisionDeny)
		harness.verifier.errors = []error{nil, grant.ErrReplay}
		taskGrant := harness.taskGrant(
			"00000000-0000-4000-8000-000000000207",
			"nonce-207",
		)
		first := harness.submit(taskGrant, "")
		second := harness.submit(taskGrant, "")
		if first.Code != http.StatusForbidden ||
			second.Code != http.StatusConflict ||
			!strings.Contains(second.Body.String(), "replayed_task_grant") {
			t.Fatalf(
				"first = %d %s, second = %d %s",
				first.Code,
				first.Body.String(),
				second.Code,
				second.Body.String(),
			)
		}
		if harness.policy.callCount() != 1 {
			t.Fatalf("policy calls = %d, want 1", harness.policy.callCount())
		}
	})

	t.Run("transport request ID conflict", func(t *testing.T) {
		harness := newAPIHarness(t, authz.DecisionAllow)
		taskGrant := harness.taskGrant(
			"00000000-0000-4000-8000-000000000208",
			"nonce-208",
		)
		request := harness.accessHTTPRequest(taskGrant)
		request.Header.Set("X-Request-ID", "00000000-0000-4000-8000-000000000999")
		response := httptest.NewRecorder()
		harness.router.ServeHTTP(response, request)
		if response.Code != http.StatusConflict ||
			!strings.Contains(response.Body.String(), "request_id_conflict") {
			t.Fatalf("response = %d %s", response.Code, response.Body.String())
		}
		// The conflict must be detected before Verify so the mismatched
		// header cannot burn the grant's nonce.
		if harness.verifier.callCount() != 0 || harness.policy.callCount() != 0 {
			t.Fatalf(
				"verifier calls = %d, policy calls = %d",
				harness.verifier.callCount(),
				harness.policy.callCount(),
			)
		}
	})
}

func TestFullPendingApprovalFlowAndSeparateReadRails(t *testing.T) {
	harness := newAPIHarness(t, authz.DecisionPendingApproval)
	taskGrant := harness.taskGrant("00000000-0000-4000-8000-000000000209", "nonce-209")

	submitted := harness.submit(taskGrant, "")
	if submitted.Code != http.StatusAccepted ||
		!strings.Contains(submitted.Body.String(), `"approval_state":"pending"`) {
		t.Fatalf("submit = %d %s", submitted.Code, submitted.Body.String())
	}
	select {
	case notified := <-harness.notifier.notifications:
		if notified.RequestID != taskGrant.RequestID {
			t.Fatalf("notified request = %q", notified.RequestID)
		}
	case <-time.After(time.Second):
		t.Fatal("pending notification was not attempted")
	}
	if harness.vault.enableCallCount() != 0 {
		t.Fatalf("Vault called before approval")
	}

	pending := harness.workloadGet(taskGrant.RequestID)
	if pending.Code != http.StatusOK ||
		strings.Contains(pending.Body.String(), `"descriptor"`) {
		t.Fatalf("pending poll = %d %s", pending.Code, pending.Body.String())
	}

	approved := harness.humanPost(
		"/v1/requests/"+taskGrant.RequestID+"/approve",
		`{"reason":"change reviewed"}`,
		true,
	)
	if approved.Code != http.StatusOK {
		t.Fatalf("approve = %d %s", approved.Code, approved.Body.String())
	}
	if strings.Contains(approved.Body.String(), `"descriptor"`) {
		t.Fatalf("human approval response exposed workload descriptor: %s", approved.Body.String())
	}
	if harness.vault.enableCallCount() != 1 {
		t.Fatalf("EnableAccess() calls = %d, want 1", harness.vault.enableCallCount())
	}

	retrieved := harness.workloadGet(taskGrant.RequestID)
	if retrieved.Code != http.StatusOK ||
		!strings.Contains(retrieved.Body.String(), `"descriptor"`) {
		t.Fatalf("approved poll = %d %s", retrieved.Code, retrieved.Body.String())
	}
	if retrieved.Header().Get("X-Request-ID") != taskGrant.RequestID {
		t.Fatalf("response request ID = %q", retrieved.Header().Get("X-Request-ID"))
	}

	harness.svid.setSPIFFEID("spiffe://agentgate.test/ns/agents/sa/other")
	wrongWorkload := harness.workloadGet(taskGrant.RequestID)
	if wrongWorkload.Code != http.StatusForbidden ||
		strings.Contains(wrongWorkload.Body.String(), `"descriptor"`) {
		t.Fatalf(
			"wrong workload response = %d %s",
			wrongWorkload.Code,
			wrongWorkload.Body.String(),
		)
	}

	humanRead := harness.humanGet("/v1/requests/" + taskGrant.RequestID)
	if humanRead.Code != http.StatusOK ||
		strings.Contains(humanRead.Body.String(), `"descriptor"`) {
		t.Fatalf("human read = %d %s", humanRead.Code, humanRead.Body.String())
	}

	revoked := harness.humanPost(
		"/v1/requests/"+taskGrant.RequestID+"/revoke",
		`{}`,
		true,
	)
	if revoked.Code != http.StatusOK ||
		!strings.Contains(revoked.Body.String(), `"sts_credentials_may_remain":true`) ||
		!strings.Contains(strings.ToLower(revoked.Body.String()), "until their expiry") {
		t.Fatalf("revoke = %d %s", revoked.Code, revoked.Body.String())
	}
}

func TestApprovalTransitionsAreAtomicIdempotentAndRetryable(t *testing.T) {
	t.Run("concurrent approvals call Vault once", func(t *testing.T) {
		harness := newAPIHarness(t, authz.DecisionPendingApproval)
		taskGrant := harness.taskGrant(
			"00000000-0000-4000-8000-000000000210",
			"nonce-210",
		)
		if response := harness.submit(taskGrant, ""); response.Code != http.StatusAccepted {
			t.Fatalf("submit = %d %s", response.Code, response.Body.String())
		}

		const requestCount = 16
		var waitGroup sync.WaitGroup
		statuses := make(chan int, requestCount)
		for range requestCount {
			waitGroup.Add(1)
			go func() {
				defer waitGroup.Done()
				response := harness.humanPost(
					"/v1/requests/"+taskGrant.RequestID+"/approve",
					`{"reason":"concurrent review"}`,
					true,
				)
				statuses <- response.Code
			}()
		}
		waitGroup.Wait()
		close(statuses)
		for status := range statuses {
			if status != http.StatusOK && status != http.StatusAccepted {
				t.Fatalf("concurrent approval status = %d", status)
			}
		}
		if harness.vault.enableCallCount() != 1 {
			t.Fatalf("EnableAccess() calls = %d, want 1", harness.vault.enableCallCount())
		}
		if decisions := harness.audits.eventCount(audit.EventApprovalDecided); decisions != 1 {
			t.Fatalf("approval decision audit events = %d, want 1", decisions)
		}
		if bindings := harness.audits.eventCount(audit.EventBindingEnabled); bindings != 1 {
			t.Fatalf("binding enabled audit events = %d, want 1", bindings)
		}
	})

	t.Run("approve versus deny has one winner", func(t *testing.T) {
		harness := newAPIHarness(t, authz.DecisionPendingApproval)
		taskGrant := harness.taskGrant(
			"00000000-0000-4000-8000-000000000211",
			"nonce-211",
		)
		if response := harness.submit(taskGrant, ""); response.Code != http.StatusAccepted {
			t.Fatalf("submit = %d %s", response.Code, response.Body.String())
		}

		var waitGroup sync.WaitGroup
		statuses := make(chan int, 2)
		for _, action := range []string{"approve", "deny"} {
			waitGroup.Add(1)
			go func(action string) {
				defer waitGroup.Done()
				response := harness.humanPost(
					"/v1/requests/"+taskGrant.RequestID+"/"+action,
					`{"reason":"race review"}`,
					true,
				)
				statuses <- response.Code
			}(action)
		}
		waitGroup.Wait()
		close(statuses)
		successes := 0
		conflicts := 0
		for status := range statuses {
			switch status {
			case http.StatusOK:
				successes++
			case http.StatusConflict:
				conflicts++
			default:
				t.Fatalf("race status = %d", status)
			}
		}
		if successes != 1 || conflicts != 1 || harness.vault.enableCallCount() > 1 {
			t.Fatalf(
				"successes = %d, conflicts = %d, Vault calls = %d",
				successes,
				conflicts,
				harness.vault.enableCallCount(),
			)
		}
		if decisions := harness.audits.eventCount(audit.EventApprovalDecided); decisions != 1 {
			t.Fatalf("approval decision audit events = %d, want 1", decisions)
		}
	})

	t.Run("denial never writes binding", func(t *testing.T) {
		harness := newAPIHarness(t, authz.DecisionPendingApproval)
		taskGrant := harness.taskGrant(
			"00000000-0000-4000-8000-000000000212",
			"nonce-212",
		)
		_ = harness.submit(taskGrant, "")
		denied := harness.humanPost(
			"/v1/requests/"+taskGrant.RequestID+"/deny",
			`{"reason":"not approved"}`,
			true,
		)
		if denied.Code != http.StatusOK || harness.vault.enableCallCount() != 0 {
			t.Fatalf(
				"deny = %d %s, Vault calls = %d",
				denied.Code,
				denied.Body.String(),
				harness.vault.enableCallCount(),
			)
		}
	})

	t.Run("failed binding can be retried idempotently", func(t *testing.T) {
		harness := newAPIHarness(t, authz.DecisionPendingApproval)
		harness.vault.enableErrors = []error{errors.New("temporary Vault failure"), nil}
		taskGrant := harness.taskGrant(
			"00000000-0000-4000-8000-000000000213",
			"nonce-213",
		)
		_ = harness.submit(taskGrant, "")
		first := harness.humanPost(
			"/v1/requests/"+taskGrant.RequestID+"/approve",
			`{}`,
			true,
		)
		second := harness.humanPost(
			"/v1/requests/"+taskGrant.RequestID+"/approve",
			`{}`,
			true,
		)
		if first.Code != http.StatusBadGateway || second.Code != http.StatusOK {
			t.Fatalf(
				"first = %d %s, second = %d %s",
				first.Code,
				first.Body.String(),
				second.Code,
				second.Body.String(),
			)
		}
		if harness.vault.enableCallCount() != 2 {
			t.Fatalf("EnableAccess() calls = %d, want 2", harness.vault.enableCallCount())
		}
		for eventType, want := range map[audit.EventType]int{
			audit.EventApprovalDecided: 1,
			audit.EventBindingFailed:   1,
			audit.EventBindingEnabled:  1,
		} {
			if got := harness.audits.eventCount(eventType); got != want {
				t.Fatalf("%s audit events = %d, want %d", eventType, got, want)
			}
		}
	})
}

func TestExpiredPendingCannotBeApproved(t *testing.T) {
	harness := newAPIHarness(t, authz.DecisionPendingApproval)
	taskGrant := harness.taskGrant("00000000-0000-4000-8000-000000000214", "nonce-214")
	taskGrant.IssuedAt = harness.now.Add(-2 * time.Minute)
	taskGrant.TTLSeconds = 60
	accessRequest := authz.AccessRequest{
		RequestID:          taskGrant.RequestID,
		SPIFFEID:           testSPIFFEID,
		TaskGrant:          taskGrant,
		RequestedVaultRole: taskGrant.VaultRole,
		RequestedAt:        taskGrant.IssuedAt,
	}
	record := approval.NewRecord(accessRequest, authz.Decision{
		Kind:          authz.DecisionPendingApproval,
		Reason:        "approval required",
		GrantedTTL:    time.Minute,
		PolicyVersion: strings.Repeat("a", 64),
		DecidedAt:     taskGrant.IssuedAt,
	}, strings.Repeat("b", 64))
	if _, _, err := harness.store.Create(context.Background(), record); err != nil {
		t.Fatalf("seed pending record: %v", err)
	}

	response := harness.humanPost(
		"/v1/requests/"+taskGrant.RequestID+"/approve",
		`{}`,
		true,
	)

	if response.Code != http.StatusGone ||
		!strings.Contains(response.Body.String(), `"state":"expired"`) ||
		harness.vault.enableCallCount() != 0 {
		t.Fatalf("response = %d %s", response.Code, response.Body.String())
	}
}

func TestWebhookFailureLeavesPendingAndHumanRailRejectsWorkload(t *testing.T) {
	harness := newAPIHarness(t, authz.DecisionPendingApproval)
	harness.notifier.err = errors.New("webhook unavailable")
	taskGrant := harness.taskGrant("00000000-0000-4000-8000-000000000215", "nonce-215")

	response := harness.submit(taskGrant, "")
	if response.Code != http.StatusAccepted {
		t.Fatalf("submit = %d %s", response.Code, response.Body.String())
	}
	select {
	case <-harness.notifier.notifications:
	case <-time.After(time.Second):
		t.Fatal("webhook delivery was not attempted")
	}
	record, err := harness.store.Get(context.Background(), taskGrant.RequestID)
	if err != nil || record.Approval.State != approval.ApprovalPending {
		t.Fatalf("pending record = %#v, error %v", record.Approval, err)
	}

	workloadOnly := httptest.NewRequest(
		http.MethodPost,
		"/v1/requests/"+taskGrant.RequestID+"/approve",
		strings.NewReader(`{}`),
	)
	workloadOnly.Header.Set("Content-Type", "application/json")
	workloadOnly.TLS = testTLSState()
	rejected := httptest.NewRecorder()
	harness.router.ServeHTTP(rejected, workloadOnly)
	if rejected.Code != http.StatusUnauthorized || harness.vault.enableCallCount() != 0 {
		t.Fatalf("workload approval = %d %s", rejected.Code, rejected.Body.String())
	}
}

func TestListFiltersBoundsAndStableCredentialFreeResponses(t *testing.T) {
	harness := newAPIHarness(t, authz.DecisionDeny)
	first := harness.taskGrant("00000000-0000-4000-8000-000000000216", "nonce-216")
	second := harness.taskGrant("00000000-0000-4000-8000-000000000217", "nonce-217")
	_ = harness.submit(first, "")
	_ = harness.submit(second, "")

	listed := harness.humanGet("/v1/requests?decision=deny&limit=1&offset=0")
	if listed.Code != http.StatusOK ||
		!strings.Contains(listed.Body.String(), `"limit":1`) ||
		!strings.Contains(listed.Body.String(), `"has_more":true`) ||
		strings.Contains(listed.Body.String(), `"signature"`) ||
		strings.Contains(listed.Body.String(), `"nonce"`) ||
		strings.Contains(listed.Body.String(), `"descriptor"`) {
		t.Fatalf("list = %d %s", listed.Code, listed.Body.String())
	}
	invalid := harness.humanGet("/v1/requests?limit=101")
	if invalid.Code != http.StatusBadRequest {
		t.Fatalf("invalid list = %d %s", invalid.Code, invalid.Body.String())
	}
}

func TestListReportsHasMoreAtMaximumPageSize(t *testing.T) {
	harness := newAPIHarness(t, authz.DecisionPendingApproval)
	for i := 0; i < 101; i++ {
		taskGrant := harness.taskGrant(
			fmt.Sprintf("00000000-0000-4000-8000-%012d", 300+i),
			fmt.Sprintf("nonce-page-%03d", i),
		)
		accessRequest := authz.AccessRequest{
			RequestID:          taskGrant.RequestID,
			SPIFFEID:           testSPIFFEID,
			TaskGrant:          taskGrant,
			RequestedVaultRole: taskGrant.VaultRole,
			RequestedAt:        harness.now.Add(time.Duration(i) * time.Second),
		}
		record := approval.NewRecord(accessRequest, authz.Decision{
			Kind:          authz.DecisionPendingApproval,
			Reason:        "approval required",
			GrantedTTL:    time.Minute,
			PolicyVersion: strings.Repeat("a", 64),
			DecidedAt:     harness.now,
		}, strings.Repeat("b", 64))
		if _, _, err := harness.store.Create(context.Background(), record); err != nil {
			t.Fatalf("seed record %d: %v", i, err)
		}
	}

	listed := harness.humanGet("/v1/requests?limit=100")
	if listed.Code != http.StatusOK ||
		!strings.Contains(listed.Body.String(), `"has_more":true`) {
		t.Fatalf("list at max page size = %d %s", listed.Code, listed.Body.String())
	}
}

func TestHumanDashboardDetailAndExtendedFilters(t *testing.T) {
	harness := newAPIHarness(t, authz.DecisionPendingApproval)
	taskGrant := harness.taskGrant("00000000-0000-4000-8000-000000000219", "nonce-219")
	if response := harness.submit(taskGrant, ""); response.Code != http.StatusAccepted {
		t.Fatalf("submit = %d %s", response.Code, response.Body.String())
	}
	approved := harness.humanPost(
		"/v1/requests/"+taskGrant.RequestID+"/approve",
		`{"reason":"dashboard review"}`,
		true,
	)
	if approved.Code != http.StatusOK {
		t.Fatalf("approve = %d %s", approved.Code, approved.Body.String())
	}

	query := url.Values{
		"binding":     {"enabled"},
		"environment": {taskGrant.Environment},
		"operation":   {string(taskGrant.Operation)},
		"repo":        {taskGrant.Repo},
		"limit":       {"25"},
		"offset":      {"0"},
	}
	listed := harness.humanGet("/v1/requests?" + query.Encode())
	if listed.Code != http.StatusOK ||
		!strings.Contains(listed.Body.String(), taskGrant.RequestID) ||
		!strings.Contains(listed.Body.String(), `"grant_issued_at"`) ||
		!strings.Contains(listed.Body.String(), `"vault_auth_role"`) ||
		!strings.Contains(listed.Body.String(), `"aws_role_session_name":"`+taskGrant.RequestID+`"`) {
		t.Fatalf("extended list = %d %s", listed.Code, listed.Body.String())
	}

	revoked := harness.humanPost(
		"/v1/requests/"+taskGrant.RequestID+"/revoke",
		`{}`,
		true,
	)
	if revoked.Code != http.StatusOK {
		t.Fatalf("revoke = %d %s", revoked.Code, revoked.Body.String())
	}
	repeated := harness.humanPost(
		"/v1/requests/"+taskGrant.RequestID+"/revoke",
		`{}`,
		true,
	)
	if repeated.Code != http.StatusOK ||
		harness.vault.revokeCallCount() != 1 ||
		harness.audits.eventCount(audit.EventRevocation) != 1 {
		t.Fatalf(
			"repeated revoke = %d %s, Vault calls = %d, audit events = %d",
			repeated.Code,
			repeated.Body.String(),
			harness.vault.revokeCallCount(),
			harness.audits.eventCount(audit.EventRevocation),
		)
	}
	detail := harness.humanGet("/v1/requests/" + taskGrant.RequestID)
	body := detail.Body.String()
	if detail.Code != http.StatusOK ||
		!strings.Contains(body, `"events"`) ||
		!strings.Contains(body, `"event_type":"approval_decided"`) ||
		!strings.Contains(body, `"event_type":"revocation"`) ||
		!strings.Contains(body, `"sts_credentials_may_remain":true`) {
		t.Fatalf("dashboard detail = %d %s", detail.Code, body)
	}
	for _, prohibited := range []string{`"descriptor"`, `"task_grant"`, `"nonce"`, `"signature"`} {
		if strings.Contains(body, prohibited) {
			t.Fatalf("dashboard detail exposed prohibited field %s: %s", prohibited, body)
		}
	}
}

func TestLogsAuditAndJSONDoNotCarryCredentialMaterial(t *testing.T) {
	harness := newAPIHarness(t, authz.DecisionAllow)
	// #nosec G101 -- this is a public AWS documentation marker used to test redaction.
	credentialMarker := "AKIAIOSFODNN7EXAMPLE"
	harness.vault.enableErrors = []error{errors.New(credentialMarker)}
	taskGrant := harness.taskGrant("00000000-0000-4000-8000-000000000218", "nonce-218")

	response := harness.submit(taskGrant, "")
	if response.Code != http.StatusBadGateway {
		t.Fatalf("response = %d %s", response.Code, response.Body.String())
	}
	combined := response.Body.String() + harness.logs.String()
	for _, prohibited := range []string{
		credentialMarker,
		testHumanToken,
		taskGrant.Signature,
	} {
		if strings.Contains(combined, prohibited) {
			t.Fatalf("output contained prohibited marker %q: %s", prohibited, combined)
		}
	}
	for _, event := range harness.audits.records() {
		encoded, err := json.Marshal(event)
		if err != nil {
			t.Fatalf("encode audit event: %v", err)
		}
		if bytes.Contains(encoded, []byte(credentialMarker)) ||
			bytes.Contains(encoded, []byte(taskGrant.Signature)) {
			t.Fatalf("audit event contained credential material: %s", encoded)
		}
	}
}

func TestPoCStaticHumanAuthRequiresExplicitGate(t *testing.T) {
	if _, err := NewPoCStaticTokenAuthenticator(false, testHumanToken, "poc"); err == nil {
		t.Fatal("static token auth initialized outside explicit PoC mode")
	}
	authenticator, err := NewPoCStaticTokenAuthenticator(true, testHumanToken, "poc")
	if err != nil {
		t.Fatalf("initialize PoC auth: %v", err)
	}
	if _, err := authenticator.Authenticate(context.Background(), "wrong"); !errors.Is(err, ErrHumanUnauthorized) {
		t.Fatalf("wrong token error = %v", err)
	}
	identity, err := authenticator.Authenticate(context.Background(), testHumanToken)
	if err != nil || identity.Subject != "poc" {
		t.Fatalf("valid token identity = %#v, error %v", identity, err)
	}
}

func TestAccessRequestBodiesAreBoundedAndCannotSupplyIdentity(t *testing.T) {
	harness := newAPIHarness(t, authz.DecisionAllow)

	t.Run("content type is required", func(t *testing.T) {
		request := httptest.NewRequest(
			http.MethodPost,
			"/v1/access-requests",
			strings.NewReader(`{}`),
		)
		request.TLS = testTLSState()
		response := httptest.NewRecorder()
		harness.router.ServeHTTP(response, request)
		if response.Code != http.StatusUnsupportedMediaType {
			t.Fatalf("response = %d %s", response.Code, response.Body.String())
		}
	})

	t.Run("caller supplied SPIFFE ID is rejected", func(t *testing.T) {
		taskGrant := harness.taskGrant(
			"00000000-0000-4000-8000-000000000219",
			"nonce-219",
		)
		encodedGrant, err := json.Marshal(taskGrant)
		if err != nil {
			t.Fatalf("encode task grant: %v", err)
		}
		body := `{"spiffe_id":"spiffe://attacker.test/workload","task_grant":` +
			string(encodedGrant) + `,"requested_vault_role":"terraform-prod"}`
		request := httptest.NewRequest(
			http.MethodPost,
			"/v1/access-requests",
			strings.NewReader(body),
		)
		request.Header.Set("Content-Type", "application/json")
		request.TLS = testTLSState()
		response := httptest.NewRecorder()
		harness.router.ServeHTTP(response, request)
		if response.Code != http.StatusBadRequest || harness.verifier.callCount() != 0 {
			t.Fatalf("response = %d %s", response.Code, response.Body.String())
		}
	})

	t.Run("oversized body is rejected", func(t *testing.T) {
		request := httptest.NewRequest(
			http.MethodPost,
			"/v1/access-requests",
			strings.NewReader(strings.Repeat(" ", int(defaultMaxBodyBytes)+1)),
		)
		request.Header.Set("Content-Type", "application/json")
		request.TLS = testTLSState()
		response := httptest.NewRecorder()
		harness.router.ServeHTTP(response, request)
		if response.Code != http.StatusRequestEntityTooLarge {
			t.Fatalf("response = %d %s", response.Code, response.Body.String())
		}
	})
}

func TestReadinessFailsGenericallyWhenDependencyIsUnavailable(t *testing.T) {
	harness := newAPIHarness(t, authz.DecisionAllow)
	humanAuth, err := NewPoCStaticTokenAuthenticator(
		true,
		testHumanToken,
		"approver@example.test",
	)
	if err != nil {
		t.Fatalf("create human authenticator: %v", err)
	}
	router, err := NewRouter(Config{
		Version: "test",
		Clock:   func() time.Time { return harness.now },
		Logger:  slog.New(slog.NewJSONHandler(io.Discard, nil)),
	}, Dependencies{
		SVIDValidator:      harness.svid,
		GrantVerifier:      harness.verifier,
		PolicyEngine:       harness.policy,
		VaultManager:       harness.vault,
		AuditStore:         harness.audits,
		RequestStore:       failingReadyStore{Store: harness.store},
		ApprovalNotifier:   harness.notifier,
		HumanAuthenticator: humanAuth,
	})
	if err != nil {
		t.Fatalf("NewRouter() error = %v", err)
	}
	request := httptest.NewRequest(http.MethodGet, "/readyz", nil)
	response := httptest.NewRecorder()
	router.ServeHTTP(response, request)
	if response.Code != http.StatusServiceUnavailable ||
		!strings.Contains(response.Body.String(), `"status":"unavailable"`) ||
		strings.Contains(response.Body.String(), "database password") {
		t.Fatalf("readiness response = %d %s", response.Code, response.Body.String())
	}
}

type apiHarness struct {
	t        *testing.T
	now      time.Time
	router   http.Handler
	store    *approval.MemoryStore
	svid     *fakeSVIDValidator
	verifier *fakeGrantVerifier
	policy   *fakePolicyEngine
	vault    *fakeVaultManager
	audits   *fakeAuditStore
	notifier *fakeApprovalNotifier
	logs     *lockedBuffer
}

func newAPIHarness(t *testing.T, decisionKind authz.DecisionKind) *apiHarness {
	t.Helper()
	now := time.Date(2030, time.January, 2, 15, 4, 5, 0, time.UTC)
	store := approval.NewMemoryStore()
	svidValidator := &fakeSVIDValidator{identity: svid.Identity{
		SPIFFEID:    testSPIFFEID,
		TrustDomain: "agentgate.test",
		ExpiresAt:   now.Add(time.Hour),
	}}
	verifier := &fakeGrantVerifier{}
	policy := &fakePolicyEngine{
		kind:          decisionKind,
		reason:        "test policy decision",
		grantedTTL:    5 * time.Minute,
		policyVersion: strings.Repeat("a", 64),
		decidedAt:     now,
	}
	audits := &fakeAuditStore{}
	vault := &fakeVaultManager{
		now: now,
		revokeReport: vaultmgr.RevocationReport{
			RoleRemoved:   true,
			PolicyRemoved: true,
		},
		audits: audits,
	}
	notifier := &fakeApprovalNotifier{notifications: make(chan approval.Request, 32)}
	humanAuth, err := NewPoCStaticTokenAuthenticator(
		true,
		testHumanToken,
		"approver@example.test",
	)
	if err != nil {
		t.Fatalf("create human authenticator: %v", err)
	}
	logs := &lockedBuffer{}
	logger := slog.New(slog.NewJSONHandler(logs, nil))
	router, err := NewRouter(Config{
		Version:             "test",
		Clock:               func() time.Time { return now },
		Logger:              logger,
		NotificationTimeout: time.Second,
	}, Dependencies{
		SVIDValidator:      svidValidator,
		GrantVerifier:      verifier,
		PolicyEngine:       policy,
		VaultManager:       vault,
		AuditStore:         audits,
		RequestStore:       store,
		ApprovalNotifier:   notifier,
		HumanAuthenticator: humanAuth,
	})
	if err != nil {
		t.Fatalf("NewRouter() error = %v", err)
	}
	return &apiHarness{
		t:        t,
		now:      now,
		router:   router,
		store:    store,
		svid:     svidValidator,
		verifier: verifier,
		policy:   policy,
		vault:    vault,
		audits:   audits,
		notifier: notifier,
		logs:     logs,
	}
}

func (h *apiHarness) taskGrant(requestID, nonce string) grant.TaskGrant {
	h.t.Helper()
	return grant.TaskGrant{
		RequestID:   requestID,
		Repo:        "github.com/jaezeu/agentgate",
		CommitSHA:   strings.Repeat("a", 40),
		Operation:   grant.OperationTerraformApply,
		Environment: "prod",
		VaultRole:   "terraform-prod",
		TTLSeconds:  900,
		Nonce:       nonce,
		IssuedAt:    h.now,
		OnBehalfOf:  "requester@example.test",
		TicketID:    "CHANGE-123",
		Signature:   "signed-task-grant",
	}
}

func (h *apiHarness) accessHTTPRequest(taskGrant grant.TaskGrant) *http.Request {
	h.t.Helper()
	body, err := json.Marshal(AccessRequestPayload{
		TaskGrant:          taskGrant,
		RequestedVaultRole: taskGrant.VaultRole,
	})
	if err != nil {
		h.t.Fatalf("encode access request: %v", err)
	}
	request := httptest.NewRequest(http.MethodPost, "/v1/access-requests", bytes.NewReader(body))
	request.Header.Set("Content-Type", "application/json")
	request.TLS = testTLSState()
	return request
}

func (h *apiHarness) submit(taskGrant grant.TaskGrant, humanToken string) *httptest.ResponseRecorder {
	h.t.Helper()
	request := h.accessHTTPRequest(taskGrant)
	if humanToken != "" {
		request.Header.Set("Authorization", "Bearer "+humanToken)
	}
	response := httptest.NewRecorder()
	h.router.ServeHTTP(response, request)
	return response
}

func (h *apiHarness) humanPost(path, body string, authenticated bool) *httptest.ResponseRecorder {
	h.t.Helper()
	request := httptest.NewRequest(http.MethodPost, path, strings.NewReader(body))
	request.Header.Set("Content-Type", "application/json")
	if authenticated {
		request.Header.Set("Authorization", "Bearer "+testHumanToken)
	}
	response := httptest.NewRecorder()
	h.router.ServeHTTP(response, request)
	return response
}

func (h *apiHarness) humanGet(path string) *httptest.ResponseRecorder {
	h.t.Helper()
	request := httptest.NewRequest(http.MethodGet, path, nil)
	request.Header.Set("Authorization", "Bearer "+testHumanToken)
	response := httptest.NewRecorder()
	h.router.ServeHTTP(response, request)
	return response
}

func (h *apiHarness) workloadGet(requestID string) *httptest.ResponseRecorder {
	h.t.Helper()
	request := httptest.NewRequest(http.MethodGet, "/v1/requests/"+requestID, nil)
	request.TLS = testTLSState()
	response := httptest.NewRecorder()
	h.router.ServeHTTP(response, request)
	return response
}

func testTLSState() *tls.ConnectionState {
	return &tls.ConnectionState{PeerCertificates: []*x509.Certificate{{}}}
}

type fakeSVIDValidator struct {
	mu              sync.Mutex
	identity        svid.Identity
	validationError error
}

func (v *fakeSVIDValidator) Validate(
	_ context.Context,
	_ []*x509.Certificate,
) (svid.Identity, error) {
	v.mu.Lock()
	defer v.mu.Unlock()
	return v.identity, v.validationError
}

func (v *fakeSVIDValidator) setSPIFFEID(spiffeID string) {
	v.mu.Lock()
	defer v.mu.Unlock()
	v.identity.SPIFFEID = spiffeID
}

type fakeGrantVerifier struct {
	mu     sync.Mutex
	calls  int
	errors []error
}

func (v *fakeGrantVerifier) Verify(context.Context, grant.TaskGrant) error {
	v.mu.Lock()
	defer v.mu.Unlock()
	index := v.calls
	v.calls++
	if index < len(v.errors) {
		return v.errors[index]
	}
	return nil
}

func (v *fakeGrantVerifier) callCount() int {
	v.mu.Lock()
	defer v.mu.Unlock()
	return v.calls
}

type fakePolicyEngine struct {
	mu            sync.Mutex
	calls         int
	kind          authz.DecisionKind
	reason        string
	grantedTTL    time.Duration
	policyVersion string
	decidedAt     time.Time
}

func (e *fakePolicyEngine) Evaluate(context.Context, authz.AccessRequest) (authz.Decision, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.calls++
	grantedTTL := e.grantedTTL
	if e.kind == authz.DecisionDeny {
		grantedTTL = 0
	}
	return authz.Decision{
		Kind:          e.kind,
		Reason:        e.reason,
		GrantedTTL:    grantedTTL,
		PolicyVersion: e.policyVersion,
		DecidedAt:     e.decidedAt,
	}, nil
}

func (e *fakePolicyEngine) callCount() int {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.calls
}

type fakeVaultManager struct {
	mu           sync.Mutex
	now          time.Time
	enableCalls  []vaultmgr.AccessBinding
	enableErrors []error
	revokeCalls  int
	revokeReport vaultmgr.RevocationReport
	revokeError  error
	audits       *fakeAuditStore
}

func (m *fakeVaultManager) EnableAccess(
	ctx context.Context,
	binding vaultmgr.AccessBinding,
) (authz.RedemptionDescriptor, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	index := len(m.enableCalls)
	m.enableCalls = append(m.enableCalls, binding)
	if index < len(m.enableErrors) && m.enableErrors[index] != nil {
		m.appendBindingAudit(ctx, binding, audit.EventBindingFailed, "failed")
		return authz.RedemptionDescriptor{}, m.enableErrors[index]
	}
	authRole := "request-" + binding.RequestID
	m.appendBindingAudit(ctx, binding, audit.EventBindingEnabled, "enabled")
	// #nosec G101 -- redemption descriptors contain routing metadata, never credentials.
	return authz.RedemptionDescriptor{
		RequestID:    binding.RequestID,
		VaultAddress: "https://vault.example.test",
		AuthMount:    "jwt",
		AuthRole:     authRole,
		SecretsPath:  "aws/creds/terraform-prod",
		Audience:     "vault",
		ExpiresAt:    m.now.Add(binding.GrantedTTL),
	}, nil
}

func (m *fakeVaultManager) Revoke(
	ctx context.Context,
	requestID string,
) (vaultmgr.RevocationReport, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.revokeCalls++
	report := m.revokeReport
	report.RequestID = requestID
	if m.audits != nil {
		_ = m.audits.Append(ctx, audit.AuditRecord{
			RequestID:  requestID,
			EventType:  audit.EventRevocation,
			OccurredAt: m.now,
			Details: map[string]string{
				"status":         "revoked",
				"sts_may_remain": "true",
			},
		})
	}
	return report, m.revokeError
}

func (m *fakeVaultManager) appendBindingAudit(
	ctx context.Context,
	binding vaultmgr.AccessBinding,
	eventType audit.EventType,
	status string,
) {
	if m.audits == nil {
		return
	}
	record := audit.AuditRecord{
		RequestID:     binding.RequestID,
		EventType:     eventType,
		OccurredAt:    m.now,
		SPIFFEID:      binding.SPIFFEID,
		OnBehalfOf:    binding.OnBehalfOf,
		VaultAuthRole: "request-" + binding.RequestID,
		Details:       map[string]string{"status": status},
	}
	if eventType == audit.EventBindingEnabled {
		record.AWSSessionName = binding.RequestID
	}
	_ = m.audits.Append(ctx, record)
}

func (m *fakeVaultManager) enableCallCount() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.enableCalls)
}

func (m *fakeVaultManager) revokeCallCount() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.revokeCalls
}

type fakeAuditStore struct {
	mu     sync.Mutex
	events []audit.AuditRecord
}

func (s *fakeAuditStore) Append(_ context.Context, record audit.AuditRecord) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if record.TaskGrant.Signature != "" {
		return errors.New("audit event contained a signature")
	}
	s.events = append(s.events, record)
	return nil
}

func (s *fakeAuditStore) ByRequestID(
	_ context.Context,
	requestID string,
) ([]audit.AuditRecord, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	records := make([]audit.AuditRecord, 0)
	for _, record := range s.events {
		if record.RequestID == requestID {
			records = append(records, record)
		}
	}
	return records, nil
}

func (s *fakeAuditStore) List(context.Context, audit.Query) ([]audit.AuditRecord, error) {
	return s.records(), nil
}

func (s *fakeAuditStore) records() []audit.AuditRecord {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]audit.AuditRecord(nil), s.events...)
}

func (s *fakeAuditStore) eventTypes() []audit.EventType {
	records := s.records()
	eventTypes := make([]audit.EventType, 0, len(records))
	for _, record := range records {
		eventTypes = append(eventTypes, record.EventType)
	}
	return eventTypes
}

func (s *fakeAuditStore) eventCount(eventType audit.EventType) int {
	count := 0
	for _, candidate := range s.eventTypes() {
		if candidate == eventType {
			count++
		}
	}
	return count
}

type fakeApprovalNotifier struct {
	notifications chan approval.Request
	err           error
}

func (n *fakeApprovalNotifier) NotifyPending(
	_ context.Context,
	request approval.Request,
) error {
	n.notifications <- request
	return n.err
}

type lockedBuffer struct {
	mu     sync.Mutex
	buffer bytes.Buffer
}

func (b *lockedBuffer) Write(value []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buffer.Write(value)
}

func (b *lockedBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buffer.String()
}

type failingReadyStore struct {
	approval.Store
}

func (failingReadyStore) Ready(context.Context) error {
	return errors.New("database password must not be disclosed")
}

func containsEvent(events []audit.EventType, expected audit.EventType) bool {
	for _, event := range events {
		if event == expected {
			return true
		}
	}
	return false
}

var _ io.Writer = (*lockedBuffer)(nil)
