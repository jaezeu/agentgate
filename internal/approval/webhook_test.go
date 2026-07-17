package approval

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jaezeu/agentgate/internal/authz"
	"github.com/jaezeu/agentgate/internal/grant"
)

func TestHTTPNotifierRetriesCredentialFreeSlackPayload(t *testing.T) {
	t.Parallel()

	var (
		mu              sync.Mutex
		attempts        int
		payloads        []string
		idempotencyKeys []string
		attemptHeaders  []string
	)
	webhook := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		body, err := io.ReadAll(io.LimitReader(request.Body, defaultMaxWebhookPayloadBytes+1))
		if err != nil {
			t.Errorf("read webhook body: %v", err)
		}
		mu.Lock()
		attempts++
		currentAttempt := attempts
		payloads = append(payloads, string(body))
		idempotencyKeys = append(idempotencyKeys, request.Header.Get("Idempotency-Key"))
		attemptHeaders = append(attemptHeaders, request.Header.Get("X-AgentGate-Delivery-Attempt"))
		mu.Unlock()
		if currentAttempt < 3 {
			http.Error(response, "retry", http.StatusServiceUnavailable)
			return
		}
		response.WriteHeader(http.StatusNoContent)
	}))
	defer webhook.Close()

	store := NewMemoryStore()
	record := webhookPendingRecord()
	stored, _, err := store.Create(context.Background(), record)
	if err != nil {
		t.Fatalf("seed pending request: %v", err)
	}
	notifier, err := NewHTTPNotifier(WebhookConfig{
		URL:            webhook.URL,
		PublicBaseURL:  "https://agentgate.example.test",
		Client:         &http.Client{Timeout: time.Second},
		MaxAttempts:    3,
		InitialBackoff: time.Millisecond,
	}, store)
	if err != nil {
		t.Fatalf("NewHTTPNotifier() error = %v", err)
	}

	if err := notifier.NotifyPending(context.Background(), stored.Approval); err != nil {
		t.Fatalf("NotifyPending() error = %v", err)
	}

	mu.Lock()
	defer mu.Unlock()
	if attempts != 3 {
		t.Fatalf("attempts = %d, want 3", attempts)
	}
	for index, payload := range payloads {
		if !strings.Contains(payload, `"text"`) ||
			!strings.Contains(payload, record.AccessRequest.RequestID) ||
			!strings.Contains(payload, `"spiffe_id"`) ||
			!strings.Contains(payload, `"on_behalf_of"`) ||
			!strings.Contains(payload, `"approve"`) ||
			!strings.Contains(payload, `"deny"`) {
			t.Fatalf("payload %d missing review fields: %s", index, payload)
		}
		for _, prohibited := range []string{
			"signature",
			record.AccessRequest.TaskGrant.Nonce,
			"vault_address",
			"access_key",
			"session_token",
		} {
			if strings.Contains(strings.ToLower(payload), strings.ToLower(prohibited)) {
				t.Fatalf("payload %d contained prohibited value %q: %s", index, prohibited, payload)
			}
		}
		if idempotencyKeys[index] != idempotencyKeys[0] {
			t.Fatalf("idempotency keys changed: %v", idempotencyKeys)
		}
		if attemptHeaders[index] != strconv.Itoa(index+1) {
			t.Fatalf("attempt headers = %v", attemptHeaders)
		}
	}
}

func TestHTTPNotifierReturnsStructuredNonRetryableFailure(t *testing.T) {
	t.Parallel()

	var attempts int
	webhook := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) {
		attempts++
		response.WriteHeader(http.StatusBadRequest)
	}))
	defer webhook.Close()

	store := NewMemoryStore()
	record := webhookPendingRecord()
	stored, _, err := store.Create(context.Background(), record)
	if err != nil {
		t.Fatalf("seed pending request: %v", err)
	}
	notifier, err := NewHTTPNotifier(WebhookConfig{
		URL:            webhook.URL,
		PublicBaseURL:  "https://agentgate.example.test",
		MaxAttempts:    3,
		InitialBackoff: time.Millisecond,
	}, store)
	if err != nil {
		t.Fatalf("NewHTTPNotifier() error = %v", err)
	}

	err = notifier.NotifyPending(context.Background(), stored.Approval)
	var deliveryError *DeliveryError
	if !errors.As(err, &deliveryError) {
		t.Fatalf("NotifyPending() error = %v, want DeliveryError", err)
	}
	if deliveryError.Attempts != 1 ||
		deliveryError.StatusCode != http.StatusBadRequest ||
		deliveryError.Retryable ||
		attempts != 1 {
		t.Fatalf("delivery error = %#v, attempts = %d", deliveryError, attempts)
	}
	current, err := store.Get(context.Background(), record.AccessRequest.RequestID)
	if err != nil || current.Approval.State != ApprovalPending {
		t.Fatalf("webhook failure changed authorization state: %#v, %v", current, err)
	}
}

func TestHTTPNotifierConfigurationIsBounded(t *testing.T) {
	t.Parallel()

	store := NewMemoryStore()
	tests := []WebhookConfig{
		// #nosec G101 -- fake user info verifies that credential-bearing URLs are rejected.
		{URL: "https://user:secret@example.test", PublicBaseURL: "https://agentgate.example.test"},
		{URL: "https://hooks.example.test", PublicBaseURL: "file:///tmp/agentgate"},
		{
			URL:           "https://hooks.example.test",
			PublicBaseURL: "https://agentgate.example.test",
			Client:        &http.Client{Timeout: 11 * time.Second},
		},
		{
			URL:           "https://hooks.example.test",
			PublicBaseURL: "https://agentgate.example.test",
			MaxAttempts:   maxWebhookAttempts + 1,
		},
	}
	for _, config := range tests {
		if _, err := NewHTTPNotifier(config, store); err == nil {
			t.Fatalf("NewHTTPNotifier(%#v) succeeded, want error", config)
		}
	}
}

func webhookPendingRecord() Record {
	now := time.Date(2030, time.January, 2, 15, 4, 5, 0, time.UTC)
	taskGrant := grant.TaskGrant{
		RequestID:   "00000000-0000-4000-8000-000000000301",
		Repo:        "github.com/jaezeu/agentgate",
		CommitSHA:   strings.Repeat("a", 40),
		Operation:   grant.OperationTerraformApply,
		Environment: "prod",
		VaultRole:   "terraform-prod",
		TTLSeconds:  900,
		Nonce:       "webhook-nonce-must-not-be-sent",
		IssuedAt:    now,
		OnBehalfOf:  "requester@example.test",
		TicketID:    "CHANGE-301",
		Signature:   "signature-must-not-be-sent",
	}
	accessRequest := authz.AccessRequest{
		RequestID:          taskGrant.RequestID,
		SPIFFEID:           "spiffe://agentgate.test/ns/agents/sa/runner",
		TaskGrant:          taskGrant,
		RequestedVaultRole: taskGrant.VaultRole,
		RequestedAt:        now,
	}
	return NewRecord(accessRequest, authz.Decision{
		Kind:          authz.DecisionPendingApproval,
		Reason:        "production apply requires approval",
		GrantedTTL:    5 * time.Minute,
		PolicyVersion: strings.Repeat("b", 64),
		DecidedAt:     now,
	}, strings.Repeat("c", 64))
}
