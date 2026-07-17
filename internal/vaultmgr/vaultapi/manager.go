package vaultapi

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"reflect"
	"strconv"
	"strings"
	"time"

	hashicorpapi "github.com/hashicorp/vault/api"
	"github.com/jaezeu/agentgate/internal/audit"
	"github.com/jaezeu/agentgate/internal/authz"
	"github.com/jaezeu/agentgate/internal/vaultmgr"
)

var _ vaultmgr.VaultManager = (*Manager)(nil)

// Manager implements request-scoped Vault control-plane configuration.
type Manager struct {
	address        string
	namespace      string
	authMount      string
	rolePrefix     string
	policyPrefix   string
	awsMount       string
	requestTimeout time.Duration
	clock          func() time.Time
	clientProvider ClientProvider
	auditStore     audit.AuditStore
	operationLock  chan struct{}
}

// EnableAccess creates or reconciles one exact-subject JWT role and one-path policy.
func (m *Manager) EnableAccess(
	ctx context.Context,
	binding vaultmgr.AccessBinding,
) (authz.RedemptionDescriptor, error) {
	resources, err := m.resourcesFor(binding)
	if err != nil {
		return authz.RedemptionDescriptor{}, err
	}
	enabledAt := m.clock().UTC()
	operationContext, cancel := context.WithTimeout(ctx, m.requestTimeout)
	defer cancel()
	if err := m.lock(operationContext); err != nil {
		return authz.RedemptionDescriptor{}, err
	}
	defer m.unlock()

	client, err := m.managementClient(operationContext)
	if err != nil {
		auditErr := m.appendBindingAudit(ctx, resources, "failed", err)
		return authz.RedemptionDescriptor{}, errors.Join(err, auditErr)
	}
	defer client.ClearToken()
	if err := m.reconcileBinding(operationContext, client, resources); err != nil {
		auditErr := m.appendBindingAudit(ctx, resources, "failed", err)
		return authz.RedemptionDescriptor{}, errors.Join(err, auditErr)
	}

	descriptor := authz.RedemptionDescriptor{
		RequestID:    binding.RequestID,
		VaultAddress: m.address,
		AuthMount:    m.authMount,
		AuthRole:     resources.roleName,
		SecretsPath:  resources.secretsPath,
		Audience:     "vault",
		ExpiresAt:    enabledAt.Add(binding.GrantedTTL),
	}
	if err := m.appendBindingAudit(ctx, resources, "enabled", nil); err != nil {
		return authz.RedemptionDescriptor{}, err
	}
	return descriptor, nil
}

// Revoke removes request-scoped login configuration before removing its policy.
func (m *Manager) Revoke(ctx context.Context, requestID string) (vaultmgr.RevocationReport, error) {
	if !vaultNamePartPattern.MatchString(requestID) {
		return vaultmgr.RevocationReport{}, fieldError(
			ErrInvalidBinding,
			"request_id",
			"must contain only letters, digits, hyphens, and underscores",
		)
	}
	if len(m.rolePrefix+requestID) > maxVaultNameLength || len(m.policyPrefix+requestID) > maxVaultNameLength {
		return vaultmgr.RevocationReport{}, fieldError(ErrInvalidBinding, "request_id", "produces a Vault resource name that is too long")
	}

	operationContext, cancel := context.WithTimeout(ctx, m.requestTimeout)
	defer cancel()
	if err := m.lock(operationContext); err != nil {
		return vaultmgr.RevocationReport{}, err
	}
	defer m.unlock()

	report := vaultmgr.RevocationReport{
		RequestID:               requestID,
		STSCredentialsMayRemain: true,
		Warnings:                []string{stsRevocationWarning},
	}
	client, err := m.managementClient(operationContext)
	if err != nil {
		auditErr := m.appendRevocationOutcome(ctx, requestID, report, "failed", err)
		return report, errors.Join(err, auditErr)
	}
	defer client.ClearToken()

	roleName := m.rolePrefix + requestID
	rolePath := "auth/" + m.authMount + "/role/" + roleName
	if _, err := client.Logical().DeleteWithContext(operationContext, rolePath); err != nil {
		operationErr := newOperationError("delete JWT auth role", roleName, err)
		auditErr := m.appendRevocationOutcome(ctx, requestID, report, "failed", operationErr)
		return report, errors.Join(operationErr, auditErr)
	}
	role, err := client.Logical().ReadWithContext(operationContext, rolePath)
	if err != nil {
		operationErr := newOperationError("verify JWT auth role removal", roleName, err)
		auditErr := m.appendRevocationOutcome(ctx, requestID, report, "failed", operationErr)
		return report, errors.Join(operationErr, auditErr)
	}
	if role != nil {
		operationErr := newOperationError("verify JWT auth role removal", roleName, nil)
		auditErr := m.appendRevocationOutcome(ctx, requestID, report, "failed", operationErr)
		return report, errors.Join(operationErr, auditErr)
	}
	report.RoleRemoved = true

	policyName := m.policyPrefix + requestID
	if err := client.Sys().DeletePolicyWithContext(operationContext, policyName); err != nil {
		operationErr := newOperationError("delete ACL policy", policyName, err)
		auditErr := m.appendRevocationOutcome(ctx, requestID, report, "partial", operationErr)
		return report, errors.Join(operationErr, auditErr)
	}
	policy, err := client.Sys().GetPolicyWithContext(operationContext, policyName)
	if err != nil {
		operationErr := newOperationError("verify ACL policy removal", policyName, err)
		auditErr := m.appendRevocationOutcome(ctx, requestID, report, "partial", operationErr)
		return report, errors.Join(operationErr, auditErr)
	}
	if policy != "" {
		operationErr := newOperationError("verify ACL policy removal", policyName, nil)
		auditErr := m.appendRevocationOutcome(ctx, requestID, report, "partial", operationErr)
		return report, errors.Join(operationErr, auditErr)
	}
	report.PolicyRemoved = true

	auditErr := m.appendRevocationOutcome(ctx, requestID, report, "revoked", nil)
	return report, auditErr
}

func (m *Manager) managementClient(ctx context.Context) (*hashicorpapi.Client, error) {
	client, err := m.clientProvider.Client(ctx)
	if err != nil {
		return nil, newOperationError("obtain management client", "client", err)
	}
	if client == nil {
		return nil, newOperationError("obtain management client", "client", nil)
	}
	clientAddress, err := canonicalVaultAddress(client.Address())
	if err != nil || clientAddress != m.address {
		client.ClearToken()
		return nil, fieldError(ErrInvalidConfiguration, "client_provider", "returned a client for a different Vault address")
	}
	clientNamespace, err := canonicalOptionalVaultPath(strings.Trim(client.Namespace(), "/"))
	if err != nil || clientNamespace != m.namespace {
		client.ClearToken()
		return nil, fieldError(ErrInvalidConfiguration, "client_provider", "returned a client for a different Vault namespace")
	}
	return client, nil
}

func (m *Manager) reconcileBinding(
	ctx context.Context,
	client *hashicorpapi.Client,
	resources bindingResources,
) error {
	existingPolicy, err := client.Sys().GetPolicyWithContext(ctx, resources.policyName)
	if err != nil {
		return newOperationError("read ACL policy", resources.policyName, err)
	}
	existingRole, err := client.Logical().ReadWithContext(ctx, resources.rolePath)
	if err != nil {
		return newOperationError("read JWT auth role", resources.roleName, err)
	}
	if existingPolicy != "" && !samePolicy(existingPolicy, resources.policy) {
		return &ConflictError{RequestID: resources.binding.RequestID, Resource: resources.policyName}
	}
	if existingRole != nil && !sameRole(existingRole.Data, resources) {
		return &ConflictError{RequestID: resources.binding.RequestID, Resource: resources.roleName}
	}

	if existingPolicy == "" {
		if err := client.Sys().PutPolicyWithContext(ctx, resources.policyName, resources.policy); err != nil {
			return newOperationError("write ACL policy", resources.policyName, err)
		}
	}
	if existingRole == nil {
		if _, err := client.Logical().WriteWithContext(ctx, resources.rolePath, resources.roleData); err != nil {
			return newOperationError("write JWT auth role", resources.roleName, err)
		}
	}

	verifiedPolicy, err := client.Sys().GetPolicyWithContext(ctx, resources.policyName)
	if err != nil {
		return newOperationError("verify ACL policy", resources.policyName, err)
	}
	if !samePolicy(verifiedPolicy, resources.policy) {
		return &ConflictError{RequestID: resources.binding.RequestID, Resource: resources.policyName}
	}
	verifiedRole, err := client.Logical().ReadWithContext(ctx, resources.rolePath)
	if err != nil {
		return newOperationError("verify JWT auth role", resources.roleName, err)
	}
	if verifiedRole == nil || !sameRole(verifiedRole.Data, resources) {
		return &ConflictError{RequestID: resources.binding.RequestID, Resource: resources.roleName}
	}
	return nil
}

func samePolicy(actual, expected string) bool {
	return strings.TrimSpace(actual) == strings.TrimSpace(expected)
}

func sameRole(actual map[string]interface{}, resources bindingResources) bool {
	if actual == nil {
		return false
	}
	ttlSeconds := int64(resources.binding.GrantedTTL / time.Second)
	if !stringFieldEquals(actual, "role_type", "jwt") ||
		!stringFieldEquals(actual, "user_claim", "sub") ||
		!stringFieldEquals(actual, "bound_subject", resources.binding.SPIFFEID) ||
		!stringSliceFieldEquals(actual, "bound_audiences", []string{"vault"}) ||
		!stringSliceFieldEquals(actual, "token_policies", []string{resources.policyName}) ||
		!boolFieldEquals(actual, "token_no_default_policy", true) ||
		!integerFieldEquals(actual, "token_ttl", ttlSeconds) ||
		!integerFieldEquals(actual, "token_max_ttl", ttlSeconds) ||
		!integerFieldEquals(actual, "token_explicit_max_ttl", ttlSeconds) {
		return false
	}
	if value, exists := actual["verbose_oidc_logging"]; exists && !boolValueEquals(value, false) {
		return false
	}
	if value, exists := actual["token_period"]; exists && !integerValueEquals(value, 0) {
		return false
	}
	for _, field := range []string{"bound_claims", "token_bound_cidrs"} {
		if value, exists := actual[field]; exists && !isEmptyValue(value) {
			return false
		}
	}
	return true
}

func stringFieldEquals(data map[string]interface{}, field, expected string) bool {
	value, ok := data[field].(string)
	return ok && value == expected
}

func boolFieldEquals(data map[string]interface{}, field string, expected bool) bool {
	value, exists := data[field]
	return exists && boolValueEquals(value, expected)
}

func boolValueEquals(value interface{}, expected bool) bool {
	actual, ok := value.(bool)
	return ok && actual == expected
}

func integerFieldEquals(data map[string]interface{}, field string, expected int64) bool {
	value, exists := data[field]
	return exists && integerValueEquals(value, expected)
}

func integerValueEquals(value interface{}, expected int64) bool {
	actual, ok := integerValue(value)
	return ok && actual == expected
}

func integerValue(value interface{}) (int64, bool) {
	switch typed := value.(type) {
	case json.Number:
		parsed, err := typed.Int64()
		return parsed, err == nil
	case float64:
		if typed != math.Trunc(typed) || typed > math.MaxInt64 || typed < math.MinInt64 {
			return 0, false
		}
		return int64(typed), true
	case int:
		return int64(typed), true
	case int64:
		return typed, true
	case int32:
		return int64(typed), true
	case string:
		parsed, err := strconv.ParseInt(typed, 10, 64)
		return parsed, err == nil
	default:
		return 0, false
	}
}

func stringSliceFieldEquals(data map[string]interface{}, field string, expected []string) bool {
	value, exists := data[field]
	if !exists {
		return false
	}
	var actual []string
	switch typed := value.(type) {
	case []string:
		actual = typed
	case []interface{}:
		actual = make([]string, 0, len(typed))
		for _, item := range typed {
			text, ok := item.(string)
			if !ok {
				return false
			}
			actual = append(actual, text)
		}
	default:
		return false
	}
	return reflect.DeepEqual(actual, expected)
}

func isEmptyValue(value interface{}) bool {
	if value == nil {
		return true
	}
	reflected := reflect.ValueOf(value)
	switch reflected.Kind() {
	case reflect.Array, reflect.Map, reflect.Slice, reflect.String:
		return reflected.Len() == 0
	default:
		return false
	}
}

func (m *Manager) lock(ctx context.Context) error {
	select {
	case m.operationLock <- struct{}{}:
		return nil
	case <-ctx.Done():
		return fmt.Errorf("wait for Vault manager operation: %w", ctx.Err())
	}
}

func (m *Manager) unlock() {
	<-m.operationLock
}
