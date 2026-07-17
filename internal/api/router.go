package api

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"runtime/debug"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/jaezeu/agentgate/internal/approval"
	"github.com/jaezeu/agentgate/internal/audit"
	"github.com/jaezeu/agentgate/internal/authz"
	"github.com/jaezeu/agentgate/internal/grant"
	"github.com/jaezeu/agentgate/internal/svid"
	"github.com/jaezeu/agentgate/internal/vaultmgr"
)

const (
	defaultMaxBodyBytes       = int64(64 << 10)
	defaultReadinessTimeout   = 2 * time.Second
	defaultNotificationWindow = 15 * time.Second
)

// Config controls bounded HTTP behavior without carrying secret configuration.
type Config struct {
	Version             string
	MaxBodyBytes        int64
	ReadinessTimeout    time.Duration
	NotificationTimeout time.Duration
	Clock               func() time.Time
	Logger              *slog.Logger
}

// Dependencies are the existing domain contracts consumed by the API workflow.
type Dependencies struct {
	SVIDValidator      svid.SVIDValidator
	GrantVerifier      grant.GrantVerifier
	PolicyEngine       authz.PolicyEngine
	VaultManager       vaultmgr.VaultManager
	AuditStore         audit.AuditStore
	RequestStore       approval.Store
	ApprovalNotifier   approval.ApprovalNotifier
	HumanAuthenticator HumanAuthenticator
	ReadinessChecks    []func(context.Context) error
}

type server struct {
	config       Config
	dependencies Dependencies
}

// NewRouter builds the complete API with separate workload and human auth rails.
func NewRouter(config Config, dependencies Dependencies) (http.Handler, error) {
	if dependencies.SVIDValidator == nil ||
		dependencies.GrantVerifier == nil ||
		dependencies.PolicyEngine == nil ||
		dependencies.VaultManager == nil ||
		dependencies.AuditStore == nil ||
		dependencies.RequestStore == nil ||
		dependencies.ApprovalNotifier == nil ||
		dependencies.HumanAuthenticator == nil {
		return nil, errors.New("all API dependencies are required")
	}
	if config.MaxBodyBytes <= 0 {
		config.MaxBodyBytes = defaultMaxBodyBytes
	}
	if config.MaxBodyBytes > defaultMaxBodyBytes {
		return nil, fmt.Errorf("maximum request body exceeds %d bytes", defaultMaxBodyBytes)
	}
	if config.ReadinessTimeout <= 0 {
		config.ReadinessTimeout = defaultReadinessTimeout
	}
	if config.NotificationTimeout <= 0 {
		config.NotificationTimeout = defaultNotificationWindow
	}
	if config.Clock == nil {
		config.Clock = func() time.Time { return time.Now().UTC() }
	}
	if config.Logger == nil {
		config.Logger = slog.Default()
	}
	api := &server{config: config, dependencies: dependencies}

	router := chi.NewRouter()
	router.Use(api.recoverPanics)
	router.Use(api.requestLogger)
	router.Get("/livez", api.handleLive)
	router.Get("/readyz", api.handleReady)
	router.Route("/v1", func(router chi.Router) {
		router.With(api.requireWorkload).Post("/access-requests", api.handleAccessRequest)
		router.With(api.requireReadPrincipal).Get("/requests/{id}", api.handleGetRequest)

		router.Group(func(router chi.Router) {
			router.Use(api.requireHuman)
			router.Get("/requests", api.handleListRequests)
			router.Post("/requests/{id}/approve", api.handleApprove)
			router.Post("/requests/{id}/deny", api.handleDeny)
			router.Post("/requests/{id}/revoke", api.handleRevoke)
		})
	})
	router.NotFound(func(response http.ResponseWriter, request *http.Request) {
		api.writeError(response, request, http.StatusNotFound, "not_found", "route not found")
	})
	router.MethodNotAllowed(func(response http.ResponseWriter, request *http.Request) {
		api.writeError(
			response,
			request,
			http.StatusMethodNotAllowed,
			"method_not_allowed",
			"method not allowed",
		)
	})
	return router, nil
}

// NewFoundationRouter retains the process-health-only foundation surface.
func NewFoundationRouter(version string) http.Handler {
	router := chi.NewRouter()
	router.Get("/livez", healthHandler(version))
	router.Get("/readyz", healthHandler(version))
	return router
}

func healthHandler(version string) http.HandlerFunc {
	return func(response http.ResponseWriter, _ *http.Request) {
		writeJSON(response, http.StatusOK, map[string]string{
			"status":  "ok",
			"version": version,
		})
	}
}

func (s *server) handleLive(response http.ResponseWriter, _ *http.Request) {
	writeJSON(response, http.StatusOK, map[string]string{
		"status":  "ok",
		"version": s.config.Version,
	})
}

func (s *server) handleReady(response http.ResponseWriter, request *http.Request) {
	ctx, cancel := context.WithTimeout(request.Context(), s.config.ReadinessTimeout)
	defer cancel()
	if err := s.dependencies.RequestStore.Ready(ctx); err != nil {
		s.config.Logger.WarnContext(
			request.Context(),
			"readiness check failed",
			"event",
			"readiness_failed",
			"dependency",
			"request_store",
		)
		writeJSON(response, http.StatusServiceUnavailable, map[string]string{
			"status":  "unavailable",
			"version": s.config.Version,
		})
		return
	}
	for _, check := range s.dependencies.ReadinessChecks {
		if check == nil {
			continue
		}
		if err := check(ctx); err != nil {
			s.config.Logger.WarnContext(
				request.Context(),
				"readiness check failed",
				"event",
				"readiness_failed",
				"dependency",
				"configured",
			)
			writeJSON(response, http.StatusServiceUnavailable, map[string]string{
				"status":  "unavailable",
				"version": s.config.Version,
			})
			return
		}
	}
	writeJSON(response, http.StatusOK, map[string]string{
		"status":  "ok",
		"version": s.config.Version,
	})
}

func (s *server) requireWorkload(next http.Handler) http.Handler {
	return http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		if request.Header.Get("Authorization") != "" {
			s.writeError(
				response,
				request,
				http.StatusUnauthorized,
				"workload_auth_required",
				"workload X509-SVID authentication is required",
			)
			return
		}
		if request.TLS == nil || len(request.TLS.PeerCertificates) == 0 {
			s.writeError(
				response,
				request,
				http.StatusUnauthorized,
				"workload_auth_required",
				"workload X509-SVID authentication is required",
			)
			return
		}
		identity, err := s.dependencies.SVIDValidator.Validate(
			request.Context(),
			request.TLS.PeerCertificates,
		)
		if err != nil {
			s.config.Logger.WarnContext(
				request.Context(),
				"workload authentication rejected",
				"event",
				"workload_auth_rejected",
			)
			s.writeError(
				response,
				request,
				http.StatusUnauthorized,
				"invalid_workload_svid",
				"workload X509-SVID is invalid",
			)
			return
		}
		ctx := withPrincipal(request.Context(), authenticatedPrincipal{
			kind:     principalWorkload,
			workload: identity,
		})
		next.ServeHTTP(response, request.WithContext(ctx))
	})
}

func (s *server) requireHuman(next http.Handler) http.Handler {
	return http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		token, err := parseBearerToken(request)
		if err != nil {
			s.writeError(
				response,
				request,
				http.StatusUnauthorized,
				"human_auth_required",
				"human bearer authentication is required",
			)
			return
		}
		identity, err := s.dependencies.HumanAuthenticator.Authenticate(request.Context(), token)
		if err != nil || strings.TrimSpace(identity.Subject) == "" {
			s.config.Logger.WarnContext(
				request.Context(),
				"human authentication rejected",
				"event",
				"human_auth_rejected",
			)
			s.writeError(
				response,
				request,
				http.StatusUnauthorized,
				"invalid_human_auth",
				"human authentication failed",
			)
			return
		}
		ctx := withPrincipal(request.Context(), authenticatedPrincipal{
			kind:  principalHuman,
			human: identity,
		})
		next.ServeHTTP(response, request.WithContext(ctx))
	})
}

func (s *server) requireReadPrincipal(next http.Handler) http.Handler {
	return http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		if len(request.Header.Values("Authorization")) > 0 {
			s.requireHuman(next).ServeHTTP(response, request)
			return
		}
		s.requireWorkload(next).ServeHTTP(response, request)
	})
}

func (s *server) requestLogger(next http.Handler) http.Handler {
	return http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		correlationID := request.Header.Get("X-Request-ID")
		provided := correlationID != ""
		if provided && !validUUID(correlationID) {
			s.writeError(
				response,
				request,
				http.StatusBadRequest,
				"invalid_request_id",
				"X-Request-ID must be a UUID",
			)
			return
		}
		if !provided {
			var err error
			correlationID, err = randomRequestID()
			if err != nil {
				s.writeError(
					response,
					request,
					http.StatusInternalServerError,
					"internal_error",
					"request correlation could not be initialized",
				)
				return
			}
		}
		request = request.WithContext(withCorrelation(
			request.Context(),
			requestCorrelation{id: correlationID, transportProvided: provided},
		))
		response.Header().Set("X-Request-ID", correlationID)
		wrapped := middleware.NewWrapResponseWriter(response, request.ProtoMajor)
		startedAt := time.Now()
		next.ServeHTTP(wrapped, request)
		s.config.Logger.InfoContext(
			request.Context(),
			"HTTP request completed",
			"event",
			"http_request_completed",
			"request_id",
			wrapped.Header().Get("X-Request-ID"),
			"method",
			request.Method,
			"route",
			routePattern(request),
			"status",
			wrapped.Status(),
			"duration_ms",
			time.Since(startedAt).Milliseconds(),
			"response_bytes",
			wrapped.BytesWritten(),
		)
	})
}

func (s *server) recoverPanics(next http.Handler) http.Handler {
	return http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		defer func() {
			if recovered := recover(); recovered != nil {
				s.config.Logger.ErrorContext(
					request.Context(),
					"HTTP handler panic",
					"event",
					"http_handler_panic",
					"request_id",
					requestIDFromContext(request.Context()),
					"stack_bytes",
					len(debug.Stack()),
				)
				s.writeError(
					response,
					request,
					http.StatusInternalServerError,
					"internal_error",
					"internal server error",
				)
			}
		}()
		next.ServeHTTP(response, request)
	})
}

func routePattern(request *http.Request) string {
	pattern := chi.RouteContext(request.Context()).RoutePattern()
	if pattern == "" {
		return "unmatched"
	}
	return pattern
}

type requestCorrelation struct {
	id                string
	transportProvided bool
}

type correlationContextKey struct{}

func withCorrelation(ctx context.Context, correlation requestCorrelation) context.Context {
	return context.WithValue(ctx, correlationContextKey{}, correlation)
}

func correlationFromContext(ctx context.Context) requestCorrelation {
	correlation, _ := ctx.Value(correlationContextKey{}).(requestCorrelation)
	return correlation
}

func requestIDFromContext(ctx context.Context) string {
	return correlationFromContext(ctx).id
}

func (s *server) writeError(
	response http.ResponseWriter,
	request *http.Request,
	status int,
	code string,
	message string,
) {
	writeJSON(response, status, ErrorResponse{
		RequestID: requestIDFromContext(request.Context()),
		Error: APIError{
			Code:    code,
			Message: message,
		},
	})
}

func writeJSON(response http.ResponseWriter, status int, value any) {
	response.Header().Set("Content-Type", "application/json")
	response.Header().Set("X-Content-Type-Options", "nosniff")
	response.WriteHeader(status)
	_ = json.NewEncoder(response).Encode(value)
}

// APIError is the canonical credential-free transport error.
type APIError struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

// ErrorResponse is the canonical API error response.
type ErrorResponse struct {
	RequestID string   `json:"request_id,omitempty"`
	Error     APIError `json:"error"`
}

func randomRequestID() (string, error) {
	value := make([]byte, 16)
	if _, err := rand.Read(value); err != nil {
		return "", fmt.Errorf("generate request ID: %w", err)
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

func validUUID(value string) bool {
	if len(value) != 36 {
		return false
	}
	for index, character := range value {
		switch index {
		case 8, 13, 18, 23:
			if character != '-' {
				return false
			}
		default:
			if !strings.ContainsRune("0123456789abcdefABCDEF", character) {
				return false
			}
		}
	}
	return true
}
