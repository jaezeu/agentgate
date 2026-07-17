package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	gateapi "github.com/jaezeu/agentgate/internal/api"
	"github.com/jaezeu/agentgate/internal/approval"
	"github.com/jaezeu/agentgate/internal/authz"
	"github.com/jaezeu/agentgate/internal/grant"
)

func TestObtainRedemptionDescriptorImmediateAllow(t *testing.T) {
	now := time.Date(2030, time.January, 2, 3, 4, 5, 0, time.UTC)
	taskGrant := agentTaskGrant(now)
	descriptor := agentDescriptor(taskGrant, now.Add(10*time.Minute))
	server := httptest.NewTLSServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		if request.Method != http.MethodPost ||
			request.URL.Path != "/v1/access-requests" ||
			request.Header.Get("X-Request-ID") != taskGrant.RequestID ||
			request.Header.Get("Authorization") != "" {
			t.Fatalf("unexpected AgentGate request: %s %s", request.Method, request.URL.String())
		}
		var payload gateapi.AccessRequestPayload
		if err := json.NewDecoder(request.Body).Decode(&payload); err != nil {
			t.Fatalf("decode request: %v", err)
		}
		if payload.TaskGrant.RequestID != taskGrant.RequestID ||
			payload.RequestedVaultRole != taskGrant.VaultRole {
			t.Fatalf("payload = %#v", payload)
		}
		response.Header().Set("Content-Type", "application/json")
		response.Header().Set("X-Request-ID", taskGrant.RequestID)
		_ = json.NewEncoder(response).Encode(gateapi.AccessDecisionResponse{
			RequestID: taskGrant.RequestID,
			Decision: authz.Decision{
				Kind:          authz.DecisionAllow,
				Reason:        "bounded plan allowed",
				GrantedTTL:    10 * time.Minute,
				PolicyVersion: strings.Repeat("a", 64),
				DecidedAt:     now,
			},
			Approval:     approval.ApprovalNotRequired,
			BindingState: approval.BindingEnabled,
			Descriptor:   &descriptor,
		})
	}))
	defer server.Close()

	decision, actual, err := obtainRedemptionDescriptor(
		context.Background(),
		server.Client(),
		server.URL+"/v1/access-requests",
		taskGrant,
		time.Millisecond,
		func() time.Time { return now },
	)
	if err != nil {
		t.Fatalf("obtain descriptor: %v", err)
	}
	if actual != descriptor ||
		decision.RequestID != taskGrant.RequestID ||
		decision.BindingState != approval.BindingEnabled {
		t.Fatalf("decision = %#v, descriptor = %#v", decision, actual)
	}
}

func TestObtainRedemptionDescriptorPollsApprovedWorkloadRoute(t *testing.T) {
	now := time.Date(2030, time.January, 2, 3, 4, 5, 0, time.UTC)
	taskGrant := agentTaskGrant(now)
	descriptor := agentDescriptor(taskGrant, now.Add(8*time.Minute))
	var polls atomic.Int32
	server := httptest.NewTLSServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		response.Header().Set("Content-Type", "application/json")
		response.Header().Set("X-Request-ID", taskGrant.RequestID)
		switch {
		case request.Method == http.MethodPost && request.URL.Path == "/v1/access-requests":
			response.WriteHeader(http.StatusAccepted)
			_ = json.NewEncoder(response).Encode(gateapi.AccessDecisionResponse{
				RequestID: taskGrant.RequestID,
				Decision: authz.Decision{
					Kind:          authz.DecisionPendingApproval,
					Reason:        "human approval required",
					GrantedTTL:    8 * time.Minute,
					PolicyVersion: strings.Repeat("b", 64),
					DecidedAt:     now,
				},
				Approval:     approval.ApprovalPending,
				BindingState: approval.BindingPending,
			})
		case request.Method == http.MethodGet &&
			request.URL.Path == "/v1/requests/"+taskGrant.RequestID:
			count := polls.Add(1)
			view := gateapi.RequestView{
				RequestID:    taskGrant.RequestID,
				ExpiresAt:    taskGrant.ExpiresAt(),
				Decision:     authz.Decision{Kind: authz.DecisionPendingApproval},
				Approval:     approval.Request{RequestID: taskGrant.RequestID, State: approval.ApprovalPending},
				BindingState: approval.BindingPending,
			}
			if count > 1 {
				view.Approval.State = approval.ApprovalApproved
				view.BindingState = approval.BindingEnabled
				view.Descriptor = &descriptor
			}
			_ = json.NewEncoder(response).Encode(gateapi.RequestResponse{Request: view})
		default:
			http.NotFound(response, request)
		}
	}))
	defer server.Close()

	decision, actual, err := obtainRedemptionDescriptor(
		context.Background(),
		server.Client(),
		server.URL+"/v1/access-requests",
		taskGrant,
		time.Millisecond,
		func() time.Time { return now },
	)
	if err != nil {
		t.Fatalf("obtain descriptor: %v", err)
	}
	if polls.Load() != 2 ||
		actual != descriptor ||
		decision.Approval != approval.ApprovalApproved ||
		decision.BindingState != approval.BindingEnabled {
		t.Fatalf("polls = %d, decision = %#v, descriptor = %#v", polls.Load(), decision, actual)
	}
}

func TestValidateRedemptionDescriptorRejectsCrossRequestAndPathDrift(t *testing.T) {
	now := time.Date(2030, time.January, 2, 3, 4, 5, 0, time.UTC)
	taskGrant := agentTaskGrant(now)
	testCases := []struct {
		name   string
		mutate func(*authz.RedemptionDescriptor)
	}{
		{
			name: "request ID",
			mutate: func(descriptor *authz.RedemptionDescriptor) {
				descriptor.RequestID = "00000000-0000-4000-8000-000000000999"
			},
		},
		{
			name: "credential path",
			mutate: func(descriptor *authz.RedemptionDescriptor) {
				descriptor.SecretsPath = "aws/creds/another-role"
			},
		},
		{
			name: "audience",
			mutate: func(descriptor *authz.RedemptionDescriptor) {
				descriptor.Audience = "not-vault"
			},
		},
		{
			name: "expiry ceiling",
			mutate: func(descriptor *authz.RedemptionDescriptor) {
				descriptor.ExpiresAt = now.Add(16 * time.Minute)
			},
		},
	}
	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			descriptor := agentDescriptor(taskGrant, now.Add(10*time.Minute))
			testCase.mutate(&descriptor)
			if err := validateRedemptionDescriptor(descriptor, taskGrant, now); err == nil {
				t.Fatal("descriptor validation unexpectedly succeeded")
			}
		})
	}
}

func agentTaskGrant(now time.Time) grant.TaskGrant {
	return grant.TaskGrant{
		RequestID:   "00000000-0000-4000-8000-000000000601",
		Repo:        "github.com/agentgate-sandbox/terraform-demo",
		CommitSHA:   strings.Repeat("a", 40),
		Operation:   grant.OperationTerraformPlan,
		Environment: "sandbox",
		VaultRole:   "terraform-sandbox",
		TTLSeconds:  900,
		Nonce:       "nonce-601",
		IssuedAt:    now,
		OnBehalfOf:  "student@example.test",
		TicketID:    "LAB-601",
		Signature:   "signed-grant",
	}
}

func agentDescriptor(taskGrant grant.TaskGrant, expiresAt time.Time) authz.RedemptionDescriptor {
	return authz.RedemptionDescriptor{
		RequestID:    taskGrant.RequestID,
		VaultAddress: "https://vault.vault.svc.cluster.local:8200",
		AuthMount:    "spire-jwt",
		AuthRole:     "agentgate-" + taskGrant.RequestID,
		SecretsPath:  "aws/creds/" + taskGrant.VaultRole,
		Audience:     "vault",
		ExpiresAt:    expiresAt,
	}
}
