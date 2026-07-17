package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"

	gateapi "github.com/jaezeu/agentgate/internal/api"
	"github.com/jaezeu/agentgate/internal/approval"
	"github.com/jaezeu/agentgate/internal/authz"
	"github.com/jaezeu/agentgate/internal/grant"
	"github.com/spiffe/go-spiffe/v2/bundle/x509bundle"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/go-spiffe/v2/spiffetls/tlsconfig"
	"github.com/spiffe/go-spiffe/v2/svid/x509svid"
)

const maxAgentGateResponseBytes = 64 << 10

var (
	vaultNamePattern = regexp.MustCompile(`^[A-Za-z0-9_-]+$`)
	lowerHexPattern  = regexp.MustCompile(`^[0-9a-f]+$`)
)

func newAgentGateTransport(
	svidSource x509svid.Source,
	bundleSource x509bundle.Source,
	serverID spiffeid.ID,
) http.RoundTripper {
	clientTLS := tlsconfig.MTLSClientConfig(
		svidSource,
		bundleSource,
		tlsconfig.AuthorizeID(serverID),
	)
	clientTLS.MinVersion = tls.VersionTLS12
	return &http.Transport{
		Proxy: nil,
		DialContext: (&net.Dialer{
			Timeout:   5 * time.Second,
			KeepAlive: 30 * time.Second,
		}).DialContext,
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          4,
		IdleConnTimeout:       30 * time.Second,
		TLSHandshakeTimeout:   5 * time.Second,
		ResponseHeaderTimeout: 10 * time.Second,
		TLSClientConfig:       clientTLS,
	}
}

func rejectRedirect(_ *http.Request, _ []*http.Request) error {
	return http.ErrUseLastResponse
}

func closeHTTPTransport(transport http.RoundTripper) {
	if closer, ok := transport.(interface{ CloseIdleConnections() }); ok {
		closer.CloseIdleConnections()
	}
}

func validateAgentGateURL(raw string) (*url.URL, error) {
	endpoint, err := url.Parse(raw)
	if err != nil ||
		endpoint.Scheme != "https" ||
		endpoint.Host == "" ||
		endpoint.User != nil ||
		endpoint.RawQuery != "" ||
		endpoint.Fragment != "" ||
		endpoint.Path != "/v1/access-requests" {
		return nil, errors.New("agentgate-url must be an HTTPS /v1/access-requests endpoint")
	}
	return endpoint, nil
}

func obtainRedemptionDescriptor(
	ctx context.Context,
	client *http.Client,
	rawEndpoint string,
	taskGrant grant.TaskGrant,
	pollInterval time.Duration,
	now func() time.Time,
) (gateapi.AccessDecisionResponse, authz.RedemptionDescriptor, error) {
	endpoint, err := validateAgentGateURL(rawEndpoint)
	if err != nil {
		return gateapi.AccessDecisionResponse{}, authz.RedemptionDescriptor{}, err
	}
	response, status, err := submitAccessRequest(ctx, client, endpoint, taskGrant)
	if err != nil {
		return gateapi.AccessDecisionResponse{}, authz.RedemptionDescriptor{}, err
	}
	if err := validateAccessDecision(response, status, taskGrant.RequestID); err != nil {
		return gateapi.AccessDecisionResponse{}, authz.RedemptionDescriptor{}, err
	}

	switch status {
	case http.StatusOK:
		if response.Descriptor == nil {
			return gateapi.AccessDecisionResponse{}, authz.RedemptionDescriptor{}, errors.New("allowed response omitted redemption descriptor")
		}
		if err := validateRedemptionDescriptor(
			*response.Descriptor,
			taskGrant,
			now().UTC(),
		); err != nil {
			return gateapi.AccessDecisionResponse{}, authz.RedemptionDescriptor{}, err
		}
		return response, *response.Descriptor, nil
	case http.StatusAccepted:
		return pollForRedemptionDescriptor(
			ctx,
			client,
			endpoint,
			taskGrant,
			response,
			pollInterval,
			now,
		)
	case http.StatusForbidden:
		code := "policy_denied"
		if response.Error != nil && validErrorCode(response.Error.Code) {
			code = response.Error.Code
		}
		return gateapi.AccessDecisionResponse{}, authz.RedemptionDescriptor{},
			fmt.Errorf("AgentGate denied the signed request: %s", code)
	default:
		return gateapi.AccessDecisionResponse{}, authz.RedemptionDescriptor{},
			fmt.Errorf("AgentGate returned unexpected HTTP status %d", status)
	}
}

func submitAccessRequest(
	ctx context.Context,
	client *http.Client,
	endpoint *url.URL,
	taskGrant grant.TaskGrant,
) (gateapi.AccessDecisionResponse, int, error) {
	body, err := json.Marshal(gateapi.AccessRequestPayload{
		TaskGrant:          taskGrant,
		RequestedVaultRole: taskGrant.VaultRole,
	})
	if err != nil {
		return gateapi.AccessDecisionResponse{}, 0, errors.New("encode access request")
	}
	request, err := http.NewRequestWithContext(
		ctx,
		http.MethodPost,
		endpoint.String(),
		bytes.NewReader(body),
	)
	if err != nil {
		return gateapi.AccessDecisionResponse{}, 0, errors.New("create access request")
	}
	request.Header.Set("Accept", "application/json")
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("X-Request-ID", taskGrant.RequestID)

	httpResponse, err := client.Do(request)
	if err != nil {
		return gateapi.AccessDecisionResponse{}, 0, errors.New("submit access request to AgentGate")
	}
	defer func() { _ = httpResponse.Body.Close() }()
	if httpResponse.Header.Get("X-Request-ID") != taskGrant.RequestID {
		return gateapi.AccessDecisionResponse{}, 0, errors.New("AgentGate response request correlation mismatch")
	}

	if httpResponse.StatusCode != http.StatusOK &&
		httpResponse.StatusCode != http.StatusAccepted &&
		httpResponse.StatusCode != http.StatusForbidden {
		apiError, decodeErr := decodeErrorResponse(httpResponse.Body)
		if decodeErr != nil {
			return gateapi.AccessDecisionResponse{}, 0,
				fmt.Errorf("AgentGate returned HTTP status %d", httpResponse.StatusCode)
		}
		code := "request_failed"
		if validErrorCode(apiError.Error.Code) {
			code = apiError.Error.Code
		}
		return gateapi.AccessDecisionResponse{}, 0,
			fmt.Errorf("AgentGate returned HTTP status %d: %s", httpResponse.StatusCode, code)
	}

	var response gateapi.AccessDecisionResponse
	if err := decodeBoundedJSON(httpResponse.Body, &response); err != nil {
		return gateapi.AccessDecisionResponse{}, 0, errors.New("decode AgentGate access response")
	}
	return response, httpResponse.StatusCode, nil
}

func pollForRedemptionDescriptor(
	ctx context.Context,
	client *http.Client,
	endpoint *url.URL,
	taskGrant grant.TaskGrant,
	initial gateapi.AccessDecisionResponse,
	pollInterval time.Duration,
	now func() time.Time,
) (gateapi.AccessDecisionResponse, authz.RedemptionDescriptor, error) {
	pollURL := *endpoint
	pollURL.Path = "/v1/requests/" + taskGrant.RequestID

	timer := time.NewTimer(0)
	defer timer.Stop()
	for {
		select {
		case <-ctx.Done():
			return gateapi.AccessDecisionResponse{}, authz.RedemptionDescriptor{},
				errors.New("approval polling ended before access was enabled")
		case <-timer.C:
		}

		record, err := getWorkloadRequest(ctx, client, &pollURL, taskGrant.RequestID)
		if err != nil {
			return gateapi.AccessDecisionResponse{}, authz.RedemptionDescriptor{}, err
		}
		currentTime := now().UTC()
		if !record.ExpiresAt.After(currentTime) {
			return gateapi.AccessDecisionResponse{}, authz.RedemptionDescriptor{},
				errors.New("signed access window expired before approval")
		}
		switch {
		case record.Decision.Kind == authz.DecisionDeny:
			return gateapi.AccessDecisionResponse{}, authz.RedemptionDescriptor{},
				errors.New("AgentGate denied the signed request")
		case record.Approval.State == approval.ApprovalDenied:
			return gateapi.AccessDecisionResponse{}, authz.RedemptionDescriptor{},
				errors.New("human approver denied the signed request")
		case record.Approval.State == approval.ApprovalExpired:
			return gateapi.AccessDecisionResponse{}, authz.RedemptionDescriptor{},
				errors.New("approval window expired")
		case record.BindingState == approval.BindingFailed:
			return gateapi.AccessDecisionResponse{}, authz.RedemptionDescriptor{},
				errors.New("credential-blind Vault binding enablement failed")
		case record.BindingState == approval.BindingRevoking:
			return gateapi.AccessDecisionResponse{}, authz.RedemptionDescriptor{},
				errors.New("expired request-scoped Vault binding is being removed")
		case record.BindingState == approval.BindingRevoked:
			return gateapi.AccessDecisionResponse{}, authz.RedemptionDescriptor{},
				errors.New("access was revoked before redemption")
		case record.Descriptor != nil && record.BindingState != approval.BindingEnabled:
			return gateapi.AccessDecisionResponse{}, authz.RedemptionDescriptor{},
				errors.New("AgentGate exposed a descriptor before binding enablement")
		case record.BindingState == approval.BindingEnabled &&
			record.Approval.State == approval.ApprovalApproved:
			if record.Descriptor == nil {
				return gateapi.AccessDecisionResponse{}, authz.RedemptionDescriptor{},
					errors.New("enabled workload response omitted redemption descriptor")
			}
			if err := validateRedemptionDescriptor(*record.Descriptor, taskGrant, currentTime); err != nil {
				return gateapi.AccessDecisionResponse{}, authz.RedemptionDescriptor{}, err
			}
			initial.Approval = record.Approval.State
			initial.BindingState = record.BindingState
			initial.Descriptor = record.Descriptor
			return initial, *record.Descriptor, nil
		}
		timer.Reset(pollInterval)
	}
}

func getWorkloadRequest(
	ctx context.Context,
	client *http.Client,
	endpoint *url.URL,
	requestID string,
) (gateapi.RequestView, error) {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint.String(), nil)
	if err != nil {
		return gateapi.RequestView{}, errors.New("create approval poll request")
	}
	request.Header.Set("Accept", "application/json")
	request.Header.Set("X-Request-ID", requestID)
	response, err := client.Do(request)
	if err != nil {
		return gateapi.RequestView{}, errors.New("poll AgentGate approval state")
	}
	defer func() { _ = response.Body.Close() }()
	if response.Header.Get("X-Request-ID") != requestID {
		return gateapi.RequestView{}, errors.New("AgentGate poll response request correlation mismatch")
	}
	if response.StatusCode != http.StatusOK {
		return gateapi.RequestView{},
			fmt.Errorf("AgentGate approval poll returned HTTP status %d", response.StatusCode)
	}
	var payload gateapi.RequestResponse
	if err := decodeBoundedJSON(response.Body, &payload); err != nil {
		return gateapi.RequestView{}, errors.New("decode AgentGate approval poll response")
	}
	if payload.Request.RequestID != requestID {
		return gateapi.RequestView{}, errors.New("AgentGate approval poll body correlation mismatch")
	}
	return payload.Request, nil
}

func validateAccessDecision(
	response gateapi.AccessDecisionResponse,
	status int,
	requestID string,
) error {
	if response.RequestID != requestID {
		return errors.New("AgentGate access response body correlation mismatch")
	}
	if response.Descriptor != nil && response.Descriptor.RequestID != requestID {
		return errors.New("AgentGate descriptor correlation mismatch")
	}
	switch status {
	case http.StatusOK:
		if response.Decision.Kind != authz.DecisionAllow ||
			response.Approval != approval.ApprovalNotRequired ||
			response.BindingState != approval.BindingEnabled ||
			response.Error != nil {
			return errors.New("AgentGate returned an inconsistent allow response")
		}
	case http.StatusAccepted:
		if response.Decision.Kind != authz.DecisionPendingApproval ||
			response.Approval != approval.ApprovalPending ||
			response.BindingState != approval.BindingPending ||
			response.Descriptor != nil ||
			response.Error != nil {
			return errors.New("AgentGate returned an inconsistent pending response")
		}
	case http.StatusForbidden:
		if response.Decision.Kind != authz.DecisionDeny ||
			response.BindingState != approval.BindingNotRequired ||
			response.Descriptor != nil ||
			response.Error == nil {
			return errors.New("AgentGate returned an inconsistent deny response")
		}
	}
	if response.Decision.DecidedAt.IsZero() ||
		strings.TrimSpace(response.Decision.Reason) == "" ||
		len(response.Decision.PolicyVersion) != 64 ||
		!lowerHexPattern.MatchString(response.Decision.PolicyVersion) {
		return errors.New("AgentGate returned invalid decision metadata")
	}
	if response.Decision.Kind != authz.DecisionDeny &&
		(response.Decision.GrantedTTL <= 0 ||
			response.Decision.GrantedTTL > 15*time.Minute ||
			response.Decision.GrantedTTL%time.Second != 0) {
		return errors.New("AgentGate returned an invalid granted TTL")
	}
	return nil
}

func validateRedemptionDescriptor(
	descriptor authz.RedemptionDescriptor,
	taskGrant grant.TaskGrant,
	now time.Time,
) error {
	vaultURL, err := url.Parse(descriptor.VaultAddress)
	if err != nil ||
		vaultURL.Scheme != "https" ||
		vaultURL.Host == "" ||
		vaultURL.User != nil ||
		vaultURL.RawQuery != "" ||
		vaultURL.Fragment != "" ||
		(vaultURL.Path != "" && vaultURL.Path != "/") {
		return errors.New("AgentGate returned an invalid Vault address")
	}
	expectedPath := "aws/creds/" + taskGrant.VaultRole
	switch {
	case descriptor.RequestID != taskGrant.RequestID:
		return errors.New("vault descriptor request correlation mismatch")
	case descriptor.Audience != "vault":
		return errors.New("vault descriptor audience must be vault")
	case !vaultNamePattern.MatchString(descriptor.AuthMount):
		return errors.New("vault descriptor auth mount is invalid")
	case !vaultNamePattern.MatchString(descriptor.AuthRole) ||
		!strings.HasSuffix(descriptor.AuthRole, taskGrant.RequestID):
		return errors.New("vault descriptor auth role is not request-scoped")
	case descriptor.SecretsPath != expectedPath:
		return errors.New("vault descriptor secrets path does not match the signed role")
	case !descriptor.ExpiresAt.After(now):
		return errors.New("vault descriptor is expired")
	case descriptor.ExpiresAt.After(taskGrant.ExpiresAt()):
		return errors.New("vault descriptor exceeds the signed grant expiry")
	case descriptor.ExpiresAt.After(now.Add(15 * time.Minute)):
		return errors.New("vault descriptor exceeds the 15-minute access ceiling")
	default:
		return nil
	}
}

func decodeErrorResponse(reader io.Reader) (gateapi.ErrorResponse, error) {
	var response gateapi.ErrorResponse
	err := decodeBoundedJSON(reader, &response)
	return response, err
}

func decodeBoundedJSON(reader io.Reader, target any) error {
	body, err := io.ReadAll(io.LimitReader(reader, maxAgentGateResponseBytes+1))
	if err != nil {
		return err
	}
	if len(body) > maxAgentGateResponseBytes {
		return errors.New("response exceeds size limit")
	}
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return err
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return errors.New("response must contain one JSON object")
	}
	return nil
}

func validErrorCode(value string) bool {
	if value == "" || len(value) > 128 {
		return false
	}
	for _, character := range value {
		if (character < 'a' || character > 'z') &&
			(character < '0' || character > '9') &&
			character != '_' {
			return false
		}
	}
	return true
}
