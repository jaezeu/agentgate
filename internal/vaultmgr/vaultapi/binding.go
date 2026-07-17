package vaultapi

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/jaezeu/agentgate/internal/vaultmgr"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
)

const (
	maxGrantedTTL       = time.Hour
	maxSPIFFEIDLength   = 2_048
	maxVaultRoleLength  = 128
	maxOnBehalfOfLength = 512
)

type bindingResources struct {
	binding     vaultmgr.AccessBinding
	roleName    string
	policyName  string
	rolePath    string
	secretsPath string
	policy      string
	roleData    map[string]interface{}
}

func (m *Manager) resourcesFor(binding vaultmgr.AccessBinding) (bindingResources, error) {
	if err := validateBinding(binding); err != nil {
		return bindingResources{}, err
	}
	roleName := m.rolePrefix + binding.RequestID
	policyName := m.policyPrefix + binding.RequestID
	if len(roleName) > maxVaultNameLength {
		return bindingResources{}, fieldError(ErrInvalidBinding, "request_id", "produces a Vault role name that is too long")
	}
	if len(policyName) > maxVaultNameLength {
		return bindingResources{}, fieldError(ErrInvalidBinding, "request_id", "produces a Vault policy name that is too long")
	}

	secretsMount, configured := m.secretsMounts[binding.Operation]
	if !configured {
		return bindingResources{}, fieldError(ErrInvalidBinding, "operation", "has no configured secrets mount profile")
	}
	secretsPath := secretsMount + "/creds/" + binding.VaultRole
	ttlSeconds := int64(binding.GrantedTTL / time.Second)
	fingerprint := bindingFingerprint(binding)
	policy := fmt.Sprintf(
		"# Managed by AgentGate. request_id=%s binding_sha256=%s\npath %q {\n  capabilities = [\"read\"]\n}\n",
		binding.RequestID,
		fingerprint,
		secretsPath,
	)
	return bindingResources{
		binding:     binding,
		roleName:    roleName,
		policyName:  policyName,
		rolePath:    "auth/" + m.authMount + "/role/" + roleName,
		secretsPath: secretsPath,
		policy:      policy,
		roleData: map[string]interface{}{
			"role_type":               "jwt",
			"user_claim":              "sub",
			"bound_subject":           binding.SPIFFEID,
			"bound_audiences":         []string{"vault"},
			"token_policies":          []string{policyName},
			"token_no_default_policy": true,
			"token_ttl":               ttlSeconds,
			"token_max_ttl":           ttlSeconds,
			"token_explicit_max_ttl":  ttlSeconds,
			"verbose_oidc_logging":    false,
		},
	}, nil
}

func validateBinding(binding vaultmgr.AccessBinding) error {
	if !vaultNamePartPattern.MatchString(binding.RequestID) {
		return fieldError(ErrInvalidBinding, "request_id", "must contain only letters, digits, hyphens, and underscores")
	}
	if !operationPattern.MatchString(binding.Operation) {
		return fieldError(ErrInvalidBinding, "operation", "must be a lowercase operation name")
	}
	if len(binding.SPIFFEID) > maxSPIFFEIDLength ||
		strings.ContainsAny(binding.SPIFFEID, "*?[]") {
		return fieldError(ErrInvalidBinding, "spiffe_id", "wildcards are forbidden")
	}
	id, err := spiffeid.FromString(binding.SPIFFEID)
	if err != nil || id.String() != binding.SPIFFEID {
		return fieldError(ErrInvalidBinding, "spiffe_id", "must be one canonical SPIFFE ID")
	}
	if len(binding.VaultRole) > maxVaultRoleLength ||
		!vaultNamePartPattern.MatchString(binding.VaultRole) {
		return fieldError(ErrInvalidBinding, "vault_role", "must be one Vault-safe path segment")
	}
	if binding.GrantedTTL <= 0 || binding.GrantedTTL > maxGrantedTTL {
		return fieldError(ErrInvalidBinding, "granted_ttl", "must be greater than zero and no more than one hour")
	}
	if binding.GrantedTTL%time.Second != 0 {
		return fieldError(ErrInvalidBinding, "granted_ttl", "must use whole seconds")
	}
	if len(binding.PolicyVersion) != sha256.Size*2 {
		return fieldError(ErrInvalidBinding, "policy_version", "must be a lowercase SHA-256 digest")
	}
	if decoded, err := hex.DecodeString(binding.PolicyVersion); err != nil || hex.EncodeToString(decoded) != binding.PolicyVersion {
		return fieldError(ErrInvalidBinding, "policy_version", "must be a lowercase SHA-256 digest")
	}
	if binding.OnBehalfOf == "" ||
		len(binding.OnBehalfOf) > maxOnBehalfOfLength ||
		strings.TrimSpace(binding.OnBehalfOf) != binding.OnBehalfOf {
		return fieldError(ErrInvalidBinding, "on_behalf_of", "must be non-empty without surrounding whitespace")
	}
	return nil
}

func bindingFingerprint(binding vaultmgr.AccessBinding) string {
	hash := sha256.New()
	for _, value := range []string{
		binding.RequestID,
		binding.SPIFFEID,
		binding.Operation,
		binding.VaultRole,
		strconv.FormatInt(int64(binding.GrantedTTL), 10),
		binding.PolicyVersion,
		binding.OnBehalfOf,
	} {
		_, _ = hash.Write([]byte(value))
		_, _ = hash.Write([]byte{0})
	}
	return hex.EncodeToString(hash.Sum(nil))
}
