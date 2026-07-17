package vaultapi

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"strconv"
	"time"

	"github.com/jaezeu/agentgate/internal/audit"
	"github.com/jaezeu/agentgate/internal/vaultmgr"
)

const stsRevocationWarning = "AgentGate has no request-specific lease identifier; issued AWS STS credentials may remain valid until expiry"

type auditMetadata struct {
	spiffeID      string
	onBehalfOf    string
	vaultRole     string
	policyVersion string
	authRole      string
}

func (m *Manager) appendBindingAudit(
	ctx context.Context,
	resources bindingResources,
	status string,
	operationErr error,
) error {
	details := map[string]string{
		"status":              status,
		"vault_policy_name":   resources.policyName,
		"vault_role":          resources.binding.VaultRole,
		"secrets_path":        resources.secretsPath,
		"policy_version":      resources.binding.PolicyVersion,
		"granted_ttl_seconds": strconv.FormatInt(int64(resources.binding.GrantedTTL/time.Second), 10),
		"audience":            "vault",
	}
	if operationErr != nil {
		details["failure_kind"] = failureKind(operationErr)
		var vaultError *OperationError
		if errors.As(operationErr, &vaultError) && vaultError.StatusCode != 0 {
			details["vault_status_code"] = strconv.Itoa(vaultError.StatusCode)
		}
	}
	eventType := audit.EventBindingEnabled
	if operationErr != nil {
		eventType = audit.EventBindingFailed
	}
	record := audit.AuditRecord{
		RequestID:     resources.binding.RequestID,
		EventType:     eventType,
		OccurredAt:    m.clock().UTC(),
		SPIFFEID:      resources.binding.SPIFFEID,
		OnBehalfOf:    resources.binding.OnBehalfOf,
		VaultAuthRole: resources.roleName,
		Details:       details,
	}
	if operationErr == nil {
		record.AWSSessionName = resources.binding.RequestID
	}
	return m.appendAudit(ctx, record)
}

func (m *Manager) revocationMetadata(ctx context.Context, requestID string) (auditMetadata, error) {
	records, err := m.auditStore.ByRequestID(ctx, requestID)
	if err != nil {
		return auditMetadata{}, fmt.Errorf("read binding audit metadata: %w", err)
	}
	var selected audit.AuditRecord
	found := false
	for _, record := range records {
		if record.EventType != audit.EventBindingEnabled || record.Details["status"] != "enabled" {
			continue
		}
		if !found || record.OccurredAt.After(selected.OccurredAt) {
			selected = record
			found = true
		}
	}
	if !found {
		return auditMetadata{authRole: m.rolePrefix + requestID}, nil
	}
	return auditMetadata{
		spiffeID:      selected.SPIFFEID,
		onBehalfOf:    selected.OnBehalfOf,
		vaultRole:     selected.Details["vault_role"],
		policyVersion: selected.Details["policy_version"],
		authRole:      selected.VaultAuthRole,
	}, nil
}

func (m *Manager) appendRevocationAudit(
	ctx context.Context,
	requestID string,
	metadata auditMetadata,
	report vaultmgr.RevocationReport,
	status string,
	operationErr error,
) error {
	details := map[string]string{
		"status":            status,
		"vault_policy_name": m.policyPrefix + requestID,
		"vault_role":        metadata.vaultRole,
		"policy_version":    metadata.policyVersion,
		"role_removed":      strconv.FormatBool(report.RoleRemoved),
		"policy_removed":    strconv.FormatBool(report.PolicyRemoved),
		"leases_revoked":    strconv.FormatBool(report.LeasesRevoked),
		"sts_may_remain":    strconv.FormatBool(report.STSCredentialsMayRemain),
	}
	if operationErr != nil {
		details["failure_kind"] = failureKind(operationErr)
		var vaultError *OperationError
		if errors.As(operationErr, &vaultError) && vaultError.StatusCode != 0 {
			details["vault_status_code"] = strconv.Itoa(vaultError.StatusCode)
		}
	}
	record := audit.AuditRecord{
		RequestID:     requestID,
		EventType:     audit.EventRevocation,
		OccurredAt:    m.clock().UTC(),
		SPIFFEID:      metadata.spiffeID,
		OnBehalfOf:    metadata.onBehalfOf,
		VaultAuthRole: metadata.authRole,
		Details:       details,
	}
	return m.appendAudit(ctx, record)
}

func (m *Manager) appendRevocationOutcome(
	ctx context.Context,
	requestID string,
	report vaultmgr.RevocationReport,
	status string,
	operationErr error,
) error {
	metadata, metadataErr := m.revocationMetadata(ctx, requestID)
	auditErr := m.appendRevocationAudit(
		ctx,
		requestID,
		metadata,
		report,
		status,
		operationErr,
	)
	return errors.Join(metadataErr, auditErr)
}

func (m *Manager) appendAudit(ctx context.Context, record audit.AuditRecord) error {
	eventID, err := newEventID()
	if err != nil {
		return fmt.Errorf("generate audit event ID: %w", err)
	}
	record.EventID = eventID
	auditContext, cancel := context.WithTimeout(context.WithoutCancel(ctx), m.requestTimeout)
	defer cancel()
	if err := m.auditStore.Append(auditContext, record); err != nil {
		return fmt.Errorf("append %s audit event: %w", record.EventType, err)
	}
	return nil
}

func newEventID() (string, error) {
	var value [16]byte
	if _, err := rand.Read(value[:]); err != nil {
		return "", err
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

func failureKind(err error) string {
	switch {
	case errors.Is(err, ErrBindingConflict):
		return "binding_conflict"
	case errors.Is(err, context.DeadlineExceeded):
		return "deadline_exceeded"
	case errors.Is(err, context.Canceled):
		return "canceled"
	case errors.Is(err, ErrVaultOperation):
		return "vault_operation"
	default:
		return "internal"
	}
}
