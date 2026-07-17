package api

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/jaezeu/agentgate/internal/approval"
	"github.com/jaezeu/agentgate/internal/audit"
	"github.com/jaezeu/agentgate/internal/authz"
	"github.com/jaezeu/agentgate/internal/grant"
	"github.com/jaezeu/agentgate/internal/vaultmgr"
)

const (
	maxRequestIDLength = 36
	maxSPIFFEIDLength  = 2_048
	maxRepoLength      = 2_048
	maxIdentityLength  = 512
	maxTicketLength    = 512
	maxRoleLength      = 512
	maxReasonLength    = 4_096
	maxFieldLength     = 512
	maxGrantTTL        = 24 * time.Hour
	maxPageSize        = 100
	defaultPageSize    = 50
	maxPageOffset      = 10_000
)

var errBindingEnablement = errors.New("access binding enablement failed")

// AccessRequestPayload is the canonical workload access-request transport.
type AccessRequestPayload struct {
	TaskGrant          grant.TaskGrant `json:"task_grant"`
	RequestedVaultRole string          `json:"requested_vault_role"`
}

type decisionRequestPayload struct {
	Reason string `json:"reason"`
}

// AccessDecisionResponse is the canonical response to a workload access request.
type AccessDecisionResponse struct {
	RequestID    string                      `json:"request_id"`
	Decision     authz.Decision              `json:"decision"`
	Approval     approval.ApprovalState      `json:"approval_state"`
	BindingState approval.BindingState       `json:"binding_state"`
	Descriptor   *authz.RedemptionDescriptor `json:"descriptor,omitempty"`
	Error        *APIError                   `json:"error,omitempty"`
}

// RequestView is the canonical credential-free request transport.
type RequestView struct {
	RequestID          string                      `json:"request_id"`
	SPIFFEID           string                      `json:"spiffe_id"`
	OnBehalfOf         string                      `json:"on_behalf_of"`
	TicketID           string                      `json:"ticket_id"`
	Repo               string                      `json:"repo"`
	CommitSHA          string                      `json:"commit_sha"`
	Operation          grant.Operation             `json:"operation"`
	Environment        string                      `json:"environment"`
	RequestedVaultRole string                      `json:"requested_vault_role"`
	RequestedTTL       int64                       `json:"requested_ttl_seconds"`
	GrantIssuedAt      time.Time                   `json:"grant_issued_at"`
	RequestedAt        time.Time                   `json:"requested_at"`
	ExpiresAt          time.Time                   `json:"expires_at"`
	Decision           authz.Decision              `json:"decision"`
	Approval           approval.Request            `json:"approval"`
	BindingState       approval.BindingState       `json:"binding_state"`
	BindingError       string                      `json:"binding_error,omitempty"`
	VaultAuthRole      string                      `json:"vault_auth_role,omitempty"`
	AWSSessionName     string                      `json:"aws_role_session_name,omitempty"`
	Descriptor         *authz.RedemptionDescriptor `json:"descriptor,omitempty"`
	Revocation         *vaultmgr.RevocationReport  `json:"revocation,omitempty"`
	RevokedAt          *time.Time                  `json:"revoked_at,omitempty"`
}

// RequestEventView is the canonical credential-free audit event transport.
type RequestEventView struct {
	EventID        string                     `json:"event_id"`
	RequestID      string                     `json:"request_id"`
	EventType      audit.EventType            `json:"event_type"`
	OccurredAt     time.Time                  `json:"occurred_at"`
	SPIFFEID       string                     `json:"spiffe_id"`
	OnBehalfOf     string                     `json:"on_behalf_of"`
	TicketID       string                     `json:"ticket_id"`
	Decision       authz.DecisionKind         `json:"decision,omitempty"`
	DecisionReason string                     `json:"decision_reason,omitempty"`
	PolicyVersion  string                     `json:"policy_version,omitempty"`
	ApprovalState  approval.ApprovalState     `json:"approval_state,omitempty"`
	Actor          string                     `json:"actor,omitempty"`
	Reason         string                     `json:"reason,omitempty"`
	VaultAuthRole  string                     `json:"vault_auth_role,omitempty"`
	AWSSessionName string                     `json:"aws_role_session_name,omitempty"`
	Revocation     *vaultmgr.RevocationReport `json:"revocation,omitempty"`
}

// RequestResponse is the canonical response for one request.
type RequestResponse struct {
	Request RequestView        `json:"request"`
	Events  []RequestEventView `json:"events,omitempty"`
	Error   *APIError          `json:"error,omitempty"`
}

// RequestListResponse is the canonical paginated request response.
type RequestListResponse struct {
	Requests []RequestView `json:"requests"`
	Limit    int           `json:"limit"`
	Offset   int           `json:"offset"`
	HasMore  bool          `json:"has_more"`
}

// RevocationResponse is the canonical credential-free revocation response.
type RevocationResponse struct {
	RequestID  string                    `json:"request_id"`
	Revocation vaultmgr.RevocationReport `json:"revocation"`
}

func (s *server) handleAccessRequest(response http.ResponseWriter, request *http.Request) {
	principal, ok := principalFromContext(request.Context())
	if !ok || principal.kind != principalWorkload {
		s.writeError(
			response,
			request,
			http.StatusUnauthorized,
			"workload_auth_required",
			"workload X509-SVID authentication is required",
		)
		return
	}

	var payload AccessRequestPayload
	if decodeError := s.decodeJSON(response, request, &payload, false); decodeError != nil {
		s.writeError(
			response,
			request,
			decodeError.status,
			decodeError.code,
			decodeError.message,
		)
		return
	}
	if err := validateAccessPayload(payload); err != nil {
		s.writeError(
			response,
			request,
			http.StatusBadRequest,
			"invalid_access_request",
			"access request is structurally invalid",
		)
		return
	}
	if err := s.dependencies.GrantVerifier.Verify(request.Context(), payload.TaskGrant); err != nil {
		status, code, message := grantErrorResponse(err)
		s.config.Logger.WarnContext(
			request.Context(),
			"task grant rejected",
			"event",
			"grant_rejected",
			"reason",
			code,
		)
		s.writeError(response, request, status, code, message)
		return
	}

	correlation := correlationFromContext(request.Context())
	if correlation.transportProvided && correlation.id != payload.TaskGrant.RequestID {
		s.writeError(
			response,
			request,
			http.StatusConflict,
			"request_id_conflict",
			"X-Request-ID conflicts with the signed task grant",
		)
		return
	}
	correlation.id = payload.TaskGrant.RequestID
	request = request.WithContext(withCorrelation(request.Context(), correlation))
	response.Header().Set("X-Request-ID", payload.TaskGrant.RequestID)

	requestedAt := s.config.Clock().UTC()
	accessRequest := authz.AccessRequest{
		RequestID:          payload.TaskGrant.RequestID,
		SPIFFEID:           principal.workload.SPIFFEID,
		TaskGrant:          payload.TaskGrant,
		RequestedVaultRole: payload.RequestedVaultRole,
		RequestedAt:        requestedAt,
	}
	grantHash, err := hashGrant(payload.TaskGrant)
	if err != nil {
		s.writeError(
			response,
			request,
			http.StatusInternalServerError,
			"internal_error",
			"task grant correlation could not be recorded",
		)
		return
	}
	if err := s.appendAudit(request.Context(), audit.EventGrantVerified, accessRequest, nil, "", nil); err != nil {
		s.auditFailure(response, request)
		return
	}

	decision, err := s.dependencies.PolicyEngine.Evaluate(request.Context(), accessRequest)
	if err == nil {
		decision, err = normalizeDecisionTTL(accessRequest, decision)
	}
	if err != nil || validateDecision(accessRequest, decision) != nil {
		s.config.Logger.ErrorContext(
			request.Context(),
			"policy evaluation failed",
			"event",
			"policy_evaluation_failed",
			"request_id",
			accessRequest.RequestID,
		)
		s.writeError(
			response,
			request,
			http.StatusInternalServerError,
			"policy_evaluation_failed",
			"authorization policy could not produce a valid decision",
		)
		return
	}

	record, created, err := s.dependencies.RequestStore.Create(
		request.Context(),
		approval.NewRecord(accessRequest, decision, grantHash),
	)
	if errors.Is(err, approval.ErrConflict) {
		s.writeError(
			response,
			request,
			http.StatusConflict,
			"request_conflict",
			"request ID is already associated with different task context",
		)
		return
	}
	if err != nil {
		s.internalStoreFailure(response, request, "request_persistence_failed")
		return
	}
	if !created {
		s.writeError(
			response,
			request,
			http.StatusConflict,
			"duplicate_request",
			"the signed task grant has already been submitted",
		)
		return
	}
	if err := s.appendAudit(
		request.Context(),
		audit.EventDecisionRecorded,
		record.AccessRequest,
		&record.Decision,
		record.Approval.State,
		map[string]string{"result": string(record.Decision.Kind)},
	); err != nil {
		s.auditFailure(response, request)
		return
	}

	switch decision.Kind {
	case authz.DecisionDeny:
		writeJSON(response, http.StatusForbidden, AccessDecisionResponse{
			RequestID:    record.AccessRequest.RequestID,
			Decision:     record.Decision,
			Approval:     record.Approval.State,
			BindingState: record.BindingState,
			Error: &APIError{
				Code:    "policy_denied",
				Message: record.Decision.Reason,
			},
		})
	case authz.DecisionPendingApproval:
		if err := s.appendAudit(
			request.Context(),
			audit.EventApprovalRequested,
			record.AccessRequest,
			&record.Decision,
			record.Approval.State,
			nil,
		); err != nil {
			s.auditFailure(response, request)
			return
		}
		s.notifyPending(request.Context(), record.Approval)
		writeJSON(response, http.StatusAccepted, AccessDecisionResponse{
			RequestID:    record.AccessRequest.RequestID,
			Decision:     record.Decision,
			Approval:     record.Approval.State,
			BindingState: record.BindingState,
		})
	case authz.DecisionAllow:
		record, claimed, err := s.dependencies.RequestStore.ClaimBinding(
			request.Context(),
			record.AccessRequest.RequestID,
		)
		if err != nil {
			s.internalStoreFailure(response, request, "binding_claim_failed")
			return
		}
		if !claimed {
			s.writeError(
				response,
				request,
				http.StatusConflict,
				"binding_conflict",
				"access binding could not be claimed",
			)
			return
		}
		record, err = s.enableBinding(request.Context(), record)
		if err != nil {
			writeJSON(response, http.StatusBadGateway, AccessDecisionResponse{
				RequestID:    record.AccessRequest.RequestID,
				Decision:     record.Decision,
				Approval:     record.Approval.State,
				BindingState: record.BindingState,
				Error: &APIError{
					Code:    "binding_enablement_failed",
					Message: "credential-blind Vault binding enablement failed",
				},
			})
			return
		}
		writeJSON(response, http.StatusOK, AccessDecisionResponse{
			RequestID:    record.AccessRequest.RequestID,
			Decision:     record.Decision,
			Approval:     record.Approval.State,
			BindingState: record.BindingState,
			Descriptor:   record.Descriptor,
		})
	}
}

func (s *server) handleGetRequest(response http.ResponseWriter, request *http.Request) {
	requestID, request, ok := s.pathRequestID(response, request)
	if !ok {
		return
	}
	record, err := s.dependencies.RequestStore.Get(request.Context(), requestID)
	if errors.Is(err, approval.ErrNotFound) {
		s.writeError(response, request, http.StatusNotFound, "request_not_found", "request not found")
		return
	}
	if err != nil {
		s.internalStoreFailure(response, request, "request_read_failed")
		return
	}

	principal, authenticated := principalFromContext(request.Context())
	if !authenticated {
		s.writeError(response, request, http.StatusUnauthorized, "authentication_required", "authentication is required")
		return
	}
	includeDescriptor := false
	includeEvents := false
	switch principal.kind {
	case principalWorkload:
		if principal.workload.SPIFFEID != record.AccessRequest.SPIFFEID {
			s.writeError(
				response,
				request,
				http.StatusForbidden,
				"workload_identity_mismatch",
				"request belongs to a different workload identity",
			)
			return
		}
		includeDescriptor = record.BindingState == approval.BindingEnabled &&
			(record.Decision.Kind == authz.DecisionAllow ||
				record.Approval.State == approval.ApprovalApproved)
	case principalHuman:
		includeEvents = true
	default:
		s.writeError(response, request, http.StatusUnauthorized, "authentication_required", "authentication is required")
		return
	}
	result := RequestResponse{Request: viewRecord(record, includeDescriptor)}
	if includeEvents {
		events, auditErr := s.dependencies.AuditStore.ByRequestID(request.Context(), requestID)
		if auditErr != nil {
			s.config.Logger.ErrorContext(
				request.Context(),
				"request audit timeline read failed",
				"event",
				"audit_timeline_read_failed",
				"request_id",
				requestID,
			)
			s.writeError(
				response,
				request,
				http.StatusInternalServerError,
				"audit_timeline_read_failed",
				"request audit timeline could not be read",
			)
			return
		}
		result.Events = make([]RequestEventView, 0, len(events))
		for _, event := range events {
			result.Events = append(result.Events, viewAuditEvent(event, record))
		}
	}
	writeJSON(response, http.StatusOK, result)
}

func (s *server) handleListRequests(response http.ResponseWriter, request *http.Request) {
	filter, err := parseListFilter(request.URL.Query())
	if err != nil {
		s.writeError(
			response,
			request,
			http.StatusBadRequest,
			"invalid_list_filter",
			"request list filter is invalid",
		)
		return
	}
	limit := filter.Limit
	if limit <= 0 {
		limit = defaultPageSize
	}
	storeFilter := filter
	if limit < maxPageSize {
		storeFilter.Limit = limit + 1
	}
	records, err := s.dependencies.RequestStore.List(request.Context(), storeFilter)
	if err != nil {
		s.internalStoreFailure(response, request, "request_list_failed")
		return
	}
	hasMore := len(records) > limit
	if hasMore {
		records = records[:limit]
	}
	views := make([]RequestView, 0, len(records))
	for _, record := range records {
		views = append(views, viewRecord(record, false))
	}
	writeJSON(response, http.StatusOK, RequestListResponse{
		Requests: views,
		Limit:    limit,
		Offset:   filter.Offset,
		HasMore:  hasMore,
	})
}

func (s *server) handleApprove(response http.ResponseWriter, request *http.Request) {
	s.handleApprovalDecision(response, request, approval.ApprovalApproved)
}

func (s *server) handleDeny(response http.ResponseWriter, request *http.Request) {
	s.handleApprovalDecision(response, request, approval.ApprovalDenied)
}

func (s *server) handleApprovalDecision(
	response http.ResponseWriter,
	request *http.Request,
	next approval.ApprovalState,
) {
	requestID, request, ok := s.pathRequestID(response, request)
	if !ok {
		return
	}
	var payload decisionRequestPayload
	if decodeError := s.decodeJSON(response, request, &payload, true); decodeError != nil {
		s.writeError(
			response,
			request,
			decodeError.status,
			decodeError.code,
			decodeError.message,
		)
		return
	}
	if len(payload.Reason) > maxReasonLength || containsCredentialMarker(payload.Reason) {
		s.writeError(
			response,
			request,
			http.StatusBadRequest,
			"invalid_decision_reason",
			"approval decision reason is too long",
		)
		return
	}
	principal, authenticated := principalFromContext(request.Context())
	if !authenticated || principal.kind != principalHuman {
		s.writeError(
			response,
			request,
			http.StatusUnauthorized,
			"human_auth_required",
			"human authentication is required",
		)
		return
	}
	if strings.TrimSpace(payload.Reason) == "" {
		payload.Reason = string(next)
	}

	record, won, claimBinding, err := s.dependencies.RequestStore.Decide(
		request.Context(),
		requestID,
		next,
		principal.human.Subject,
		payload.Reason,
		s.config.Clock().UTC(),
	)
	if errors.Is(err, approval.ErrNotFound) {
		s.writeError(response, request, http.StatusNotFound, "request_not_found", "request not found")
		return
	}
	if errors.Is(err, approval.ErrExpiredRequest) {
		if won {
			if auditErr := s.appendApprovalDecisionAudit(request.Context(), record); auditErr != nil {
				s.auditFailure(response, request)
				return
			}
		}
		s.writeRequestError(
			response,
			http.StatusGone,
			record,
			"approval_expired",
			"approval window has expired",
		)
		return
	}
	if errors.Is(err, approval.ErrConflict) {
		s.writeRequestError(
			response,
			http.StatusConflict,
			record,
			"approval_conflict",
			"request has already reached a different approval state",
		)
		return
	}
	if err != nil {
		s.internalStoreFailure(response, request, "approval_transition_failed")
		return
	}

	if won {
		if err := s.appendApprovalDecisionAudit(request.Context(), record); err != nil {
			if claimBinding {
				s.completeBindingFailure(request.Context(), requestID, "approval audit recording failed")
			}
			s.auditFailure(response, request)
			return
		}
	}
	if next == approval.ApprovalDenied {
		writeJSON(response, http.StatusOK, RequestResponse{Request: viewRecord(record, false)})
		return
	}

	if !claimBinding &&
		(record.BindingState == approval.BindingFailed ||
			record.BindingState == approval.BindingEnabling) {
		record, claimBinding, err = s.dependencies.RequestStore.ClaimBinding(
			request.Context(),
			requestID,
		)
		if err != nil {
			s.internalStoreFailure(response, request, "binding_claim_failed")
			return
		}
	}
	if !claimBinding {
		status := http.StatusOK
		if record.BindingState == approval.BindingEnabling {
			status = http.StatusAccepted
		}
		writeJSON(response, status, RequestResponse{Request: viewRecord(record, false)})
		return
	}

	record, err = s.enableBinding(request.Context(), record)
	if err != nil {
		s.writeRequestError(
			response,
			http.StatusBadGateway,
			record,
			"binding_enablement_failed",
			"credential-blind Vault binding enablement failed",
		)
		return
	}
	writeJSON(response, http.StatusOK, RequestResponse{Request: viewRecord(record, false)})
}

func (s *server) handleRevoke(response http.ResponseWriter, request *http.Request) {
	requestID, request, ok := s.pathRequestID(response, request)
	if !ok {
		return
	}
	var payload struct{}
	if decodeError := s.decodeJSON(response, request, &payload, true); decodeError != nil {
		s.writeError(
			response,
			request,
			decodeError.status,
			decodeError.code,
			decodeError.message,
		)
		return
	}
	record, err := s.dependencies.RequestStore.Get(request.Context(), requestID)
	if errors.Is(err, approval.ErrNotFound) {
		s.writeError(response, request, http.StatusNotFound, "request_not_found", "request not found")
		return
	}
	if err != nil {
		s.internalStoreFailure(response, request, "request_read_failed")
		return
	}
	if record.Revocation != nil {
		writeJSON(response, http.StatusOK, RevocationResponse{
			RequestID:  requestID,
			Revocation: *record.Revocation,
		})
		return
	}

	report, err := s.dependencies.VaultManager.Revoke(request.Context(), requestID)
	if err != nil {
		s.config.Logger.ErrorContext(
			request.Context(),
			"Vault revocation failed",
			"event",
			"revocation_failed",
			"request_id",
			requestID,
		)
		s.writeError(
			response,
			request,
			http.StatusBadGateway,
			"revocation_failed",
			"credential-blind Vault revocation failed",
		)
		return
	}
	report, err = vaultmgr.NormalizeRevocationReport(requestID, report)
	if err != nil {
		s.writeError(
			response,
			request,
			http.StatusBadGateway,
			"invalid_revocation_report",
			"Vault manager returned an invalid revocation report",
		)
		return
	}
	persistenceCtx, cancelPersistence := newPersistenceContext(request.Context())
	defer cancelPersistence()
	_, err = s.dependencies.RequestStore.RecordRevocation(
		persistenceCtx,
		requestID,
		report,
		s.config.Clock().UTC(),
	)
	if err != nil {
		s.internalStoreFailure(response, request, "revocation_persistence_failed")
		return
	}
	writeJSON(response, http.StatusOK, RevocationResponse{
		RequestID:  requestID,
		Revocation: report,
	})
}

func (s *server) enableBinding(ctx context.Context, record approval.Record) (approval.Record, error) {
	now := s.config.Clock().UTC()
	expiryLimit := record.AccessRequest.RequestedAt.Add(record.Decision.GrantedTTL)
	if grantExpiry := record.AccessRequest.TaskGrant.ExpiresAt(); grantExpiry.Before(expiryLimit) {
		expiryLimit = grantExpiry
	}
	remainingTTL := expiryLimit.Sub(now).Truncate(time.Second)
	if remainingTTL <= 0 {
		failed := s.completeBindingFailure(ctx, record.AccessRequest.RequestID, "access binding window expired")
		s.appendBindingAuditAfterFailure(ctx, failed)
		return failed, errBindingEnablement
	}
	binding := vaultmgr.AccessBinding{
		RequestID:     record.AccessRequest.RequestID,
		SPIFFEID:      record.AccessRequest.SPIFFEID,
		Operation:     string(record.AccessRequest.TaskGrant.Operation),
		VaultRole:     record.AccessRequest.RequestedVaultRole,
		GrantedTTL:    remainingTTL,
		PolicyVersion: record.Decision.PolicyVersion,
		OnBehalfOf:    record.AccessRequest.TaskGrant.OnBehalfOf,
	}
	descriptor, err := s.dependencies.VaultManager.EnableAccess(ctx, binding)
	if err != nil {
		s.config.Logger.ErrorContext(
			ctx,
			"Vault binding enablement failed",
			"event",
			"binding_enablement_failed",
			"request_id",
			record.AccessRequest.RequestID,
		)
		failed := s.completeBindingFailure(ctx, record.AccessRequest.RequestID, "Vault binding enablement failed")
		return failed, errBindingEnablement
	}
	if err := validateDescriptor(record, descriptor, s.config.Clock().UTC()); err != nil {
		failed := s.completeBindingFailure(ctx, record.AccessRequest.RequestID, "Vault returned invalid redemption metadata")
		s.appendBindingAuditAfterFailure(ctx, failed)
		return failed, errBindingEnablement
	}

	persistenceCtx, cancelPersistence := newPersistenceContext(ctx)
	defer cancelPersistence()
	completed, err := s.dependencies.RequestStore.CompleteBinding(
		persistenceCtx,
		record.AccessRequest.RequestID,
		&descriptor,
		"",
	)
	if err != nil {
		return record, errBindingEnablement
	}
	return completed, nil
}

func (s *server) completeBindingFailure(
	ctx context.Context,
	requestID string,
	message string,
) approval.Record {
	persistenceCtx, cancelPersistence := newPersistenceContext(ctx)
	defer cancelPersistence()
	record, err := s.dependencies.RequestStore.CompleteBinding(
		persistenceCtx,
		requestID,
		nil,
		message,
	)
	if err != nil {
		s.config.Logger.ErrorContext(
			ctx,
			"binding failure state could not be persisted",
			"event",
			"binding_failure_persistence_failed",
			"request_id",
			requestID,
		)
		return approval.Record{AccessRequest: authz.AccessRequest{RequestID: requestID}}
	}
	return record
}

func (s *server) appendBindingAuditAfterFailure(ctx context.Context, record approval.Record) {
	if record.AccessRequest.RequestID == "" {
		return
	}
	persistenceCtx, cancelPersistence := newPersistenceContext(ctx)
	defer cancelPersistence()
	if err := s.appendBindingAudit(persistenceCtx, audit.EventBindingFailed, record); err != nil {
		s.config.Logger.ErrorContext(
			ctx,
			"binding failure audit could not be persisted",
			"event",
			"binding_failure_audit_failed",
			"request_id",
			record.AccessRequest.RequestID,
		)
	}
}

func (s *server) appendApprovalDecisionAudit(
	ctx context.Context,
	record approval.Record,
) error {
	details := map[string]string{
		"actor":   record.Approval.DecidedBy,
		"reason":  record.Approval.Reason,
		"version": strconv.FormatInt(record.Approval.Version, 10),
	}
	return s.appendAudit(
		ctx,
		audit.EventApprovalDecided,
		record.AccessRequest,
		&record.Decision,
		record.Approval.State,
		details,
	)
}

func (s *server) appendBindingAudit(
	ctx context.Context,
	eventType audit.EventType,
	record approval.Record,
) error {
	details := map[string]string{"result": string(record.BindingState)}
	return s.appendAudit(
		ctx,
		eventType,
		record.AccessRequest,
		&record.Decision,
		record.Approval.State,
		details,
	)
}

func (s *server) appendAudit(
	ctx context.Context,
	eventType audit.EventType,
	request authz.AccessRequest,
	decision *authz.Decision,
	approvalState approval.ApprovalState,
	details map[string]string,
) error {
	eventID, err := randomRequestID()
	if err != nil {
		return err
	}
	taskGrant := request.TaskGrant
	taskGrant.Signature = ""
	record := audit.AuditRecord{
		EventID:       eventID,
		RequestID:     request.RequestID,
		EventType:     eventType,
		OccurredAt:    s.config.Clock().UTC(),
		SPIFFEID:      request.SPIFFEID,
		OnBehalfOf:    taskGrant.OnBehalfOf,
		TicketID:      taskGrant.TicketID,
		TaskGrant:     taskGrant,
		Decision:      decision,
		ApprovalState: approvalState,
		Details:       details,
	}
	if eventType == audit.EventBindingEnabled {
		record.AWSSessionName = request.RequestID
	}
	return s.dependencies.AuditStore.Append(ctx, record)
}

func (s *server) notifyPending(ctx context.Context, request approval.Request) {
	go func() {
		notificationContext, cancel := context.WithTimeout(
			context.WithoutCancel(ctx),
			s.config.NotificationTimeout,
		)
		defer cancel()
		err := s.dependencies.ApprovalNotifier.NotifyPending(notificationContext, request)
		if err != nil {
			s.config.Logger.WarnContext(
				notificationContext,
				"approval notification delivery failed",
				"event",
				"approval_notification_failed",
				"request_id",
				request.RequestID,
			)
			return
		}
		s.config.Logger.InfoContext(
			notificationContext,
			"approval notification delivered",
			"event",
			"approval_notification_delivered",
			"request_id",
			request.RequestID,
		)
	}()
}

func (s *server) pathRequestID(
	response http.ResponseWriter,
	request *http.Request,
) (string, *http.Request, bool) {
	requestID := chi.URLParam(request, "id")
	if len(requestID) > maxRequestIDLength || !validUUID(requestID) {
		s.writeError(
			response,
			request,
			http.StatusBadRequest,
			"invalid_request_id",
			"request ID must be a UUID",
		)
		return "", request, false
	}
	correlation := correlationFromContext(request.Context())
	if correlation.transportProvided && correlation.id != requestID {
		s.writeError(
			response,
			request,
			http.StatusConflict,
			"request_id_conflict",
			"X-Request-ID conflicts with the signed request ID",
		)
		return "", request, false
	}
	correlation.id = requestID
	request = request.WithContext(withCorrelation(request.Context(), correlation))
	response.Header().Set("X-Request-ID", requestID)
	return requestID, request, true
}

type decodeError struct {
	status  int
	code    string
	message string
}

func (s *server) decodeJSON(
	response http.ResponseWriter,
	request *http.Request,
	target any,
	allowEmpty bool,
) *decodeError {
	contentType := request.Header.Get("Content-Type")
	if contentType == "" {
		if allowEmpty && request.ContentLength == 0 {
			return nil
		}
		return &decodeError{
			status:  http.StatusUnsupportedMediaType,
			code:    "json_content_type_required",
			message: "Content-Type must be application/json",
		}
	}
	mediaType, _, err := mime.ParseMediaType(contentType)
	if err != nil || mediaType != "application/json" {
		return &decodeError{
			status:  http.StatusUnsupportedMediaType,
			code:    "json_content_type_required",
			message: "Content-Type must be application/json",
		}
	}

	request.Body = http.MaxBytesReader(response, request.Body, s.config.MaxBodyBytes)
	decoder := json.NewDecoder(request.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		var maxBytesError *http.MaxBytesError
		if errors.As(err, &maxBytesError) {
			return &decodeError{
				status:  http.StatusRequestEntityTooLarge,
				code:    "request_body_too_large",
				message: "request body exceeds the configured limit",
			}
		}
		if allowEmpty && errors.Is(err, io.EOF) {
			return nil
		}
		return &decodeError{
			status:  http.StatusBadRequest,
			code:    "invalid_json",
			message: "request body must be one valid JSON object",
		}
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return &decodeError{
			status:  http.StatusBadRequest,
			code:    "invalid_json",
			message: "request body must contain only one JSON object",
		}
	}
	return nil
}

func validateAccessPayload(payload AccessRequestPayload) error {
	taskGrant := payload.TaskGrant
	if !validUUID(taskGrant.RequestID) ||
		taskGrant.RequestID == "" ||
		len(taskGrant.RequestID) > maxRequestIDLength ||
		taskGrant.Repo == "" ||
		len(taskGrant.Repo) > maxRepoLength ||
		len(taskGrant.CommitSHA) != 40 ||
		!isLowerHex(taskGrant.CommitSHA) ||
		!supportedOperation(taskGrant.Operation) ||
		taskGrant.Environment == "" ||
		len(taskGrant.Environment) > maxFieldLength ||
		taskGrant.VaultRole == "" ||
		len(taskGrant.VaultRole) > maxRoleLength ||
		payload.RequestedVaultRole != taskGrant.VaultRole ||
		taskGrant.TTLSeconds <= 0 ||
		taskGrant.TTLSeconds > int64(maxGrantTTL/time.Second) ||
		taskGrant.Nonce == "" ||
		len(taskGrant.Nonce) > maxFieldLength ||
		taskGrant.IssuedAt.IsZero() ||
		taskGrant.OnBehalfOf == "" ||
		len(taskGrant.OnBehalfOf) > maxIdentityLength ||
		taskGrant.TicketID == "" ||
		len(taskGrant.TicketID) > maxTicketLength ||
		taskGrant.Signature == "" ||
		len(taskGrant.Signature) > maxFieldLength ||
		containsCredentialMarker(taskGrant.Repo) ||
		containsCredentialMarker(taskGrant.Environment) ||
		containsCredentialMarker(taskGrant.VaultRole) ||
		containsCredentialMarker(taskGrant.OnBehalfOf) ||
		containsCredentialMarker(taskGrant.TicketID) {
		return errors.New("invalid access request")
	}
	return nil
}

func validateDecision(request authz.AccessRequest, decision authz.Decision) error {
	if decision.Kind != authz.DecisionAllow &&
		decision.Kind != authz.DecisionDeny &&
		decision.Kind != authz.DecisionPendingApproval {
		return errors.New("unsupported policy decision")
	}
	if strings.TrimSpace(decision.Reason) == "" ||
		len(decision.Reason) > maxReasonLength ||
		len(decision.PolicyVersion) != sha256.Size*2 ||
		!isLowerHex(decision.PolicyVersion) ||
		decision.DecidedAt.IsZero() {
		return errors.New("invalid policy decision metadata")
	}
	if decision.Kind == authz.DecisionDeny {
		return nil
	}
	if decision.GrantedTTL <= 0 ||
		decision.GrantedTTL%time.Second != 0 ||
		decision.GrantedTTL > time.Duration(request.TaskGrant.TTLSeconds)*time.Second {
		return errors.New("policy granted an invalid TTL")
	}
	return nil
}

func normalizeDecisionTTL(
	request authz.AccessRequest,
	decision authz.Decision,
) (authz.Decision, error) {
	if decision.Kind == authz.DecisionDeny {
		return decision, nil
	}
	remaining := request.TaskGrant.ExpiresAt().Sub(request.RequestedAt).Truncate(time.Second)
	if remaining <= 0 {
		return authz.Decision{}, errors.New("task grant has no remaining whole-second lifetime")
	}
	if decision.GrantedTTL > remaining {
		decision.GrantedTTL = remaining
	}
	return decision, nil
}

func validateDescriptor(
	record approval.Record,
	descriptor authz.RedemptionDescriptor,
	now time.Time,
) error {
	expiryLimit := record.AccessRequest.RequestedAt.Add(record.Decision.GrantedTTL)
	grantExpiry := record.AccessRequest.TaskGrant.ExpiresAt()
	if grantExpiry.Before(expiryLimit) {
		expiryLimit = grantExpiry
	}
	parsedAddress, err := url.Parse(descriptor.VaultAddress)
	if err != nil {
		return errors.New("invalid Vault address")
	}
	if descriptor.RequestID != record.AccessRequest.RequestID ||
		parsedAddress.Scheme == "" ||
		parsedAddress.Host == "" ||
		descriptor.AuthMount == "" ||
		descriptor.AuthRole == "" ||
		descriptor.SecretsPath == "" ||
		descriptor.Audience != "vault" ||
		!descriptor.ExpiresAt.After(now) ||
		descriptor.ExpiresAt.After(expiryLimit) {
		return errors.New("invalid redemption descriptor")
	}
	return nil
}

func grantErrorResponse(err error) (int, string, string) {
	switch {
	case errors.Is(err, grant.ErrReplay):
		return http.StatusConflict, "replayed_task_grant", "task grant nonce has already been used"
	case errors.Is(err, grant.ErrExpired):
		return http.StatusUnauthorized, "expired_task_grant", "task grant has expired"
	case errors.Is(err, grant.ErrFutureIssued):
		return http.StatusUnauthorized, "future_task_grant", "task grant issue time is invalid"
	case errors.Is(err, grant.ErrInvalidSignature):
		return http.StatusUnauthorized, "invalid_task_grant_signature", "task grant signature is invalid"
	case errors.Is(err, grant.ErrMissingOnBehalfOf), errors.Is(err, grant.ErrMissingClaim):
		return http.StatusBadRequest, "invalid_task_grant", "task grant is missing required signed context"
	default:
		return http.StatusUnauthorized, "invalid_task_grant", "task grant verification failed"
	}
}

func hashGrant(taskGrant grant.TaskGrant) (string, error) {
	serialized, err := json.Marshal(taskGrant)
	if err != nil {
		return "", fmt.Errorf("encode task grant hash input: %w", err)
	}
	digest := sha256.Sum256(serialized)
	return hex.EncodeToString(digest[:]), nil
}

func containsCredentialMarker(value string) bool {
	upper := strings.ToUpper(value)
	return strings.Contains(upper, "-----BEGIN PRIVATE KEY-----") ||
		strings.Contains(upper, "-----BEGIN RSA PRIVATE KEY-----") ||
		strings.Contains(upper, "BEARER ") ||
		containsAWSAccessKeyID(upper)
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

func viewRecord(record approval.Record, includeDescriptor bool) RequestView {
	expiresAt := record.AccessRequest.TaskGrant.ExpiresAt()
	if record.Descriptor != nil && record.Descriptor.ExpiresAt.Before(expiresAt) {
		expiresAt = record.Descriptor.ExpiresAt
	}
	view := RequestView{
		RequestID:          record.AccessRequest.RequestID,
		SPIFFEID:           record.AccessRequest.SPIFFEID,
		OnBehalfOf:         record.AccessRequest.TaskGrant.OnBehalfOf,
		TicketID:           record.AccessRequest.TaskGrant.TicketID,
		Repo:               record.AccessRequest.TaskGrant.Repo,
		CommitSHA:          record.AccessRequest.TaskGrant.CommitSHA,
		Operation:          record.AccessRequest.TaskGrant.Operation,
		Environment:        record.AccessRequest.TaskGrant.Environment,
		RequestedVaultRole: record.AccessRequest.RequestedVaultRole,
		RequestedTTL:       record.AccessRequest.TaskGrant.TTLSeconds,
		GrantIssuedAt:      record.AccessRequest.TaskGrant.IssuedAt,
		RequestedAt:        record.AccessRequest.RequestedAt,
		ExpiresAt:          expiresAt,
		Decision:           record.Decision,
		Approval:           record.Approval,
		BindingState:       record.BindingState,
		BindingError:       record.BindingError,
		Revocation:         record.Revocation,
		RevokedAt:          record.RevokedAt,
	}
	if record.Descriptor != nil {
		view.VaultAuthRole = record.Descriptor.AuthRole
		view.AWSSessionName = record.AccessRequest.RequestID
	}
	if includeDescriptor && record.Descriptor != nil {
		descriptor := *record.Descriptor
		view.Descriptor = &descriptor
	}
	return view
}

func viewAuditEvent(event audit.AuditRecord, record approval.Record) RequestEventView {
	view := RequestEventView{
		EventID:        event.EventID,
		RequestID:      event.RequestID,
		EventType:      event.EventType,
		OccurredAt:     event.OccurredAt,
		SPIFFEID:       event.SPIFFEID,
		OnBehalfOf:     event.OnBehalfOf,
		TicketID:       event.TicketID,
		ApprovalState:  event.ApprovalState,
		Actor:          event.Details["actor"],
		Reason:         event.Details["reason"],
		VaultAuthRole:  event.VaultAuthRole,
		AWSSessionName: event.AWSSessionName,
	}
	if view.SPIFFEID == "" {
		view.SPIFFEID = record.AccessRequest.SPIFFEID
	}
	if view.OnBehalfOf == "" {
		view.OnBehalfOf = record.AccessRequest.TaskGrant.OnBehalfOf
	}
	if view.TicketID == "" {
		view.TicketID = record.AccessRequest.TaskGrant.TicketID
	}
	if event.Decision != nil {
		view.Decision = event.Decision.Kind
		view.DecisionReason = event.Decision.Reason
		view.PolicyVersion = event.Decision.PolicyVersion
	}
	if event.EventType == audit.EventRevocation && record.Revocation != nil {
		report := *record.Revocation
		report.Warnings = append([]string(nil), record.Revocation.Warnings...)
		view.Revocation = &report
	}
	return view
}

func parseListFilter(values url.Values) (approval.ListFilter, error) {
	allowed := map[string]struct{}{
		"decision":       {},
		"approval":       {},
		"binding":        {},
		"active":         {},
		"spiffe_id":      {},
		"on_behalf_of":   {},
		"environment":    {},
		"operation":      {},
		"repo":           {},
		"created_after":  {},
		"created_before": {},
		"limit":          {},
		"offset":         {},
	}
	for key, entries := range values {
		if _, ok := allowed[key]; !ok || len(entries) != 1 {
			return approval.ListFilter{}, errors.New("unsupported or repeated list filter")
		}
	}

	filter := approval.ListFilter{Limit: defaultPageSize}
	if value := values.Get("decision"); value != "" {
		filter.Decision = authz.DecisionKind(value)
		if filter.Decision != authz.DecisionAllow &&
			filter.Decision != authz.DecisionDeny &&
			filter.Decision != authz.DecisionPendingApproval {
			return approval.ListFilter{}, errors.New("invalid decision filter")
		}
	}
	if value := values.Get("approval"); value != "" {
		filter.Approval = approval.ApprovalState(value)
		switch filter.Approval {
		case approval.ApprovalNotRequired,
			approval.ApprovalPending,
			approval.ApprovalApproved,
			approval.ApprovalDenied,
			approval.ApprovalExpired:
		default:
			return approval.ListFilter{}, errors.New("invalid approval filter")
		}
	}
	if value := values.Get("binding"); value != "" {
		filter.Binding = approval.BindingState(value)
		switch filter.Binding {
		case approval.BindingNotRequired,
			approval.BindingPending,
			approval.BindingEnabling,
			approval.BindingEnabled,
			approval.BindingFailed,
			approval.BindingRevoking,
			approval.BindingRevoked:
		default:
			return approval.ListFilter{}, errors.New("invalid binding filter")
		}
	}
	if value := values.Get("active"); value != "" {
		active, err := strconv.ParseBool(value)
		if err != nil {
			return approval.ListFilter{}, errors.New("invalid active filter")
		}
		filter.Active = &active
	}
	filter.SPIFFEID = values.Get("spiffe_id")
	filter.OnBehalfOf = values.Get("on_behalf_of")
	filter.Environment = values.Get("environment")
	filter.Repo = values.Get("repo")
	if value := values.Get("operation"); value != "" {
		filter.Operation = grant.Operation(value)
		if !supportedOperation(filter.Operation) {
			return approval.ListFilter{}, errors.New("invalid operation filter")
		}
	}
	if len(filter.SPIFFEID) > maxSPIFFEIDLength ||
		len(filter.OnBehalfOf) > maxIdentityLength ||
		len(filter.Environment) > maxFieldLength ||
		len(filter.Repo) > maxRepoLength ||
		containsCredentialMarker(filter.Environment) ||
		containsCredentialMarker(filter.Repo) {
		return approval.ListFilter{}, errors.New("list filter is invalid")
	}
	var err error
	if value := values.Get("created_after"); value != "" {
		filter.CreatedAfter, err = time.Parse(time.RFC3339, value)
		if err != nil {
			return approval.ListFilter{}, errors.New("invalid created_after filter")
		}
	}
	if value := values.Get("created_before"); value != "" {
		filter.CreatedBefore, err = time.Parse(time.RFC3339, value)
		if err != nil {
			return approval.ListFilter{}, errors.New("invalid created_before filter")
		}
	}
	if !filter.CreatedAfter.IsZero() && !filter.CreatedBefore.IsZero() &&
		!filter.CreatedAfter.Before(filter.CreatedBefore) {
		return approval.ListFilter{}, errors.New("invalid time window")
	}
	if value := values.Get("limit"); value != "" {
		filter.Limit, err = strconv.Atoi(value)
		if err != nil || filter.Limit < 1 || filter.Limit > maxPageSize {
			return approval.ListFilter{}, errors.New("invalid limit")
		}
	}
	if value := values.Get("offset"); value != "" {
		filter.Offset, err = strconv.Atoi(value)
		if err != nil || filter.Offset < 0 || filter.Offset > maxPageOffset {
			return approval.ListFilter{}, errors.New("invalid offset")
		}
	}
	return filter, nil
}

// supportedOperation is the transport-level operation allowlist. Whether an
// operation is permitted for a given workload, and which Vault secrets mount
// serves it, are decided later by policy and the manager's access profiles.
func supportedOperation(operation grant.Operation) bool {
	switch operation {
	case grant.OperationTerraformPlan,
		grant.OperationTerraformApply,
		grant.OperationKubernetesInspect:
		return true
	default:
		return false
	}
}

func isLowerHex(value string) bool {
	if value == "" {
		return false
	}
	for _, character := range value {
		if !strings.ContainsRune("0123456789abcdef", character) {
			return false
		}
	}
	return true
}

func newPersistenceContext(ctx context.Context) (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
}

func (s *server) writeRequestError(
	response http.ResponseWriter,
	status int,
	record approval.Record,
	code string,
	message string,
) {
	writeJSON(response, status, RequestResponse{
		Request: viewRecord(record, false),
		Error:   &APIError{Code: code, Message: message},
	})
}

func (s *server) auditFailure(response http.ResponseWriter, request *http.Request) {
	s.config.Logger.ErrorContext(
		request.Context(),
		"audit event persistence failed",
		"event",
		"audit_persistence_failed",
		"request_id",
		requestIDFromContext(request.Context()),
	)
	s.writeError(
		response,
		request,
		http.StatusInternalServerError,
		"audit_persistence_failed",
		"request lifecycle audit could not be recorded",
	)
}

func (s *server) internalStoreFailure(
	response http.ResponseWriter,
	request *http.Request,
	event string,
) {
	s.config.Logger.ErrorContext(
		request.Context(),
		"request store operation failed",
		"event",
		event,
		"request_id",
		requestIDFromContext(request.Context()),
	)
	s.writeError(
		response,
		request,
		http.StatusInternalServerError,
		"request_store_failed",
		"request lifecycle state could not be persisted",
	)
}
