package approval

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

const (
	defaultWebhookTimeout    = 5 * time.Second
	maxWebhookTimeout        = 10 * time.Second
	defaultWebhookAttempts   = 3
	maxWebhookAttempts       = 5
	defaultWebhookBackoff    = 200 * time.Millisecond
	maxWebhookResponseBytes  = int64(4 << 10)
	maxWebhookEndpointLength = 2_048
)

// WebhookConfig bounds credential-free approval notification delivery.
type WebhookConfig struct {
	URL            string
	PublicBaseURL  string
	Client         *http.Client
	Logger         *slog.Logger
	MaxAttempts    int
	InitialBackoff time.Duration
}

// HTTPNotifier delivers Slack-compatible approval notifications.
type HTTPNotifier struct {
	store          Store
	endpoint       *url.URL
	publicBaseURL  *url.URL
	client         *http.Client
	logger         *slog.Logger
	maxAttempts    int
	initialBackoff time.Duration
}

// DeliveryError reports a bounded webhook failure without response content.
type DeliveryError struct {
	Attempts   int
	StatusCode int
	Retryable  bool
}

func (e *DeliveryError) Error() string {
	if e.StatusCode != 0 {
		return fmt.Sprintf(
			"approval webhook failed after %d attempt(s) with HTTP status %d",
			e.Attempts,
			e.StatusCode,
		)
	}
	return fmt.Sprintf("approval webhook failed after %d attempt(s)", e.Attempts)
}

// NewHTTPNotifier validates webhook routing and retry bounds.
func NewHTTPNotifier(config WebhookConfig, store Store) (*HTTPNotifier, error) {
	if store == nil {
		return nil, errors.New("approval request store is required")
	}
	endpoint, err := parseWebhookURL(config.URL)
	if err != nil {
		return nil, fmt.Errorf("invalid approval webhook URL: %w", err)
	}
	publicBaseURL, err := parseWebhookURL(config.PublicBaseURL)
	if err != nil {
		return nil, fmt.Errorf("invalid public AgentGate URL: %w", err)
	}

	client := config.Client
	if client == nil {
		client = &http.Client{Timeout: defaultWebhookTimeout}
	} else {
		copyClient := *client
		client = &copyClient
		if client.Timeout <= 0 {
			client.Timeout = defaultWebhookTimeout
		}
	}
	client.CheckRedirect = func(_ *http.Request, _ []*http.Request) error {
		return errors.New("approval webhook redirects are disabled")
	}
	if client.Timeout > maxWebhookTimeout {
		return nil, fmt.Errorf("approval webhook timeout exceeds %s", maxWebhookTimeout)
	}
	attempts := config.MaxAttempts
	if attempts == 0 {
		attempts = defaultWebhookAttempts
	}
	if attempts < 1 || attempts > maxWebhookAttempts {
		return nil, fmt.Errorf("approval webhook attempts must be between 1 and %d", maxWebhookAttempts)
	}
	backoff := config.InitialBackoff
	if backoff == 0 {
		backoff = defaultWebhookBackoff
	}
	if backoff < 0 || backoff > time.Second {
		return nil, errors.New("approval webhook initial backoff must be between zero and one second")
	}
	logger := config.Logger
	if logger == nil {
		logger = slog.Default()
	}
	return &HTTPNotifier{
		store:          store,
		endpoint:       endpoint,
		publicBaseURL:  publicBaseURL,
		client:         client,
		logger:         logger,
		maxAttempts:    attempts,
		initialBackoff: backoff,
	}, nil
}

func (n *HTTPNotifier) NotifyPending(ctx context.Context, request Request) error {
	if n == nil {
		return errors.New("approval webhook notifier is required")
	}
	record, err := n.store.Get(ctx, request.RequestID)
	if err != nil {
		return fmt.Errorf("load approval review details: %w", err)
	}
	if record.Approval.State != ApprovalPending ||
		request.State != ApprovalPending ||
		record.Approval.Version != request.Version {
		return ErrConflict
	}
	payload, idempotencyKey, err := n.payload(record)
	if err != nil {
		return err
	}

	var lastStatus int
	for attempt := 1; attempt <= n.maxAttempts; attempt++ {
		status, retryable, deliveryErr := n.deliver(
			ctx,
			payload,
			idempotencyKey,
			attempt,
		)
		lastStatus = status
		if deliveryErr == nil {
			n.logger.InfoContext(
				ctx,
				"approval webhook delivered",
				"event",
				"approval_webhook_delivered",
				"request_id",
				request.RequestID,
				"attempt",
				attempt,
				"status",
				status,
			)
			return nil
		}
		if !retryable || attempt == n.maxAttempts {
			return &DeliveryError{
				Attempts:   attempt,
				StatusCode: lastStatus,
				Retryable:  retryable,
			}
		}
		n.logger.WarnContext(
			ctx,
			"approval webhook delivery will retry",
			"event",
			"approval_webhook_retry",
			"request_id",
			request.RequestID,
			"attempt",
			attempt,
			"status",
			status,
		)
		if err := waitForRetry(ctx, n.initialBackoff, attempt); err != nil {
			return &DeliveryError{
				Attempts:   attempt,
				StatusCode: lastStatus,
				Retryable:  true,
			}
		}
	}
	return &DeliveryError{
		Attempts:   n.maxAttempts,
		StatusCode: lastStatus,
		Retryable:  true,
	}
}

func (n *HTTPNotifier) deliver(
	ctx context.Context,
	payload []byte,
	idempotencyKey string,
	attempt int,
) (int, bool, error) {
	request, err := http.NewRequestWithContext(
		ctx,
		http.MethodPost,
		n.endpoint.String(),
		bytes.NewReader(payload),
	)
	if err != nil {
		return 0, false, errors.New("create approval webhook request")
	}
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Idempotency-Key", idempotencyKey)
	request.Header.Set("X-AgentGate-Delivery-Attempt", strconv.Itoa(attempt))

	response, err := n.client.Do(request)
	if err != nil {
		return 0, true, errors.New("send approval webhook")
	}
	_, copyErr := io.Copy(
		io.Discard,
		io.LimitReader(response.Body, maxWebhookResponseBytes),
	)
	closeErr := response.Body.Close()
	if copyErr != nil || closeErr != nil {
		return response.StatusCode, true, errors.New("discard approval webhook response")
	}
	if response.StatusCode >= http.StatusOK && response.StatusCode < http.StatusMultipleChoices {
		return response.StatusCode, false, nil
	}
	return response.StatusCode, retryableWebhookStatus(response.StatusCode), errors.New("approval webhook rejected delivery")
}

func (n *HTTPNotifier) payload(record Record) ([]byte, string, error) {
	taskGrant := record.AccessRequest.TaskGrant
	details := ReviewDetails{
		RequestID:          record.AccessRequest.RequestID,
		SPIFFEID:           record.AccessRequest.SPIFFEID,
		OnBehalfOf:         taskGrant.OnBehalfOf,
		TicketID:           taskGrant.TicketID,
		Repo:               taskGrant.Repo,
		CommitSHA:          taskGrant.CommitSHA,
		Operation:          taskGrant.Operation,
		Environment:        taskGrant.Environment,
		RequestedVaultRole: record.AccessRequest.RequestedVaultRole,
		TTLSeconds:         int64(record.Decision.GrantedTTL / time.Second),
		PolicyReason:       record.Decision.Reason,
	}
	for _, field := range []string{
		details.RequestID,
		details.SPIFFEID,
		details.OnBehalfOf,
		details.TicketID,
		details.Repo,
		details.CommitSHA,
		details.Environment,
		details.RequestedVaultRole,
		details.PolicyReason,
	} {
		if containsWebhookCredentialMarker(field) {
			return nil, "", errors.New("approval webhook review contains prohibited material")
		}
	}
	idempotencyKey := fmt.Sprintf(
		"agentgate:%s:pending:%d",
		record.AccessRequest.RequestID,
		record.Approval.Version,
	)
	base := strings.TrimRight(n.publicBaseURL.String(), "/")
	payload := struct {
		Text           string `json:"text"`
		RequestID      string `json:"request_id"`
		IdempotencyKey string `json:"idempotency_key"`
		Review         struct {
			SPIFFEID           string `json:"spiffe_id"`
			OnBehalfOf         string `json:"on_behalf_of"`
			TicketID           string `json:"ticket_id"`
			Repo               string `json:"repo"`
			CommitSHA          string `json:"commit_sha"`
			Operation          string `json:"operation"`
			Environment        string `json:"environment"`
			RequestedVaultRole string `json:"requested_vault_role"`
			TTLSeconds         int64  `json:"ttl_seconds"`
			PolicyReason       string `json:"policy_reason"`
		} `json:"review"`
		Actions struct {
			Approve string `json:"approve"`
			Deny    string `json:"deny"`
		} `json:"actions"`
	}{
		Text:           "AgentGate access request " + details.RequestID + " requires human approval.",
		RequestID:      details.RequestID,
		IdempotencyKey: idempotencyKey,
	}
	payload.Review.SPIFFEID = details.SPIFFEID
	payload.Review.OnBehalfOf = details.OnBehalfOf
	payload.Review.TicketID = details.TicketID
	payload.Review.Repo = details.Repo
	payload.Review.CommitSHA = details.CommitSHA
	payload.Review.Operation = string(details.Operation)
	payload.Review.Environment = details.Environment
	payload.Review.RequestedVaultRole = details.RequestedVaultRole
	payload.Review.TTLSeconds = details.TTLSeconds
	payload.Review.PolicyReason = details.PolicyReason
	escapedID := url.PathEscape(details.RequestID)
	payload.Actions.Approve = base + "/v1/requests/" + escapedID + "/approve"
	payload.Actions.Deny = base + "/v1/requests/" + escapedID + "/deny"

	serialized, err := json.Marshal(payload)
	if err != nil {
		return nil, "", fmt.Errorf("encode approval webhook payload: %w", err)
	}
	if int64(len(serialized)) > defaultMaxWebhookPayloadBytes {
		return nil, "", errors.New("approval webhook payload exceeds size limit")
	}
	return serialized, idempotencyKey, nil
}

func parseWebhookURL(rawURL string) (*url.URL, error) {
	if rawURL == "" || len(rawURL) > maxWebhookEndpointLength {
		return nil, errors.New("URL is required")
	}
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return nil, errors.New("URL cannot be parsed")
	}
	if (parsed.Scheme != "http" && parsed.Scheme != "https") ||
		parsed.Host == "" ||
		parsed.User != nil ||
		parsed.Fragment != "" {
		return nil, errors.New("URL must be an absolute HTTP(S) URL without user info or fragment")
	}
	return parsed, nil
}

func retryableWebhookStatus(status int) bool {
	return status == http.StatusRequestTimeout ||
		status == http.StatusTooEarly ||
		status == http.StatusTooManyRequests ||
		status >= http.StatusInternalServerError
}

func waitForRetry(ctx context.Context, initial time.Duration, attempt int) error {
	delay := initial * time.Duration(1<<(attempt-1))
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

func containsWebhookCredentialMarker(value string) bool {
	upper := strings.ToUpper(value)
	return strings.Contains(upper, "-----BEGIN PRIVATE KEY-----") ||
		strings.Contains(upper, "BEARER ") ||
		strings.Contains(upper, "AKIA")
}

const defaultMaxWebhookPayloadBytes = int64(32 << 10)
