package vaultmgr

import (
	"context"
	"errors"
	"strings"
	"time"

	"github.com/jaezeu/agentgate/internal/authz"
)

// AccessBinding is the least-privilege Vault configuration derived from an allowed request.
type AccessBinding struct {
	RequestID     string
	SPIFFEID      string
	VaultRole     string
	GrantedTTL    time.Duration
	PolicyVersion string
	OnBehalfOf    string
}

// RevocationReport distinguishes configuration removal from best-effort lease cleanup.
type RevocationReport struct {
	RequestID               string   `json:"request_id"`
	RoleRemoved             bool     `json:"role_removed"`
	PolicyRemoved           bool     `json:"policy_removed"`
	LeasesRevoked           bool     `json:"leases_revoked"`
	STSCredentialsMayRemain bool     `json:"sts_credentials_may_remain"`
	Warnings                []string `json:"warnings,omitempty"`
}

// NormalizeRevocationReport enforces the credential-free, best-effort STS revocation contract.
func NormalizeRevocationReport(
	requestID string,
	report RevocationReport,
) (RevocationReport, error) {
	if report.RequestID != requestID || len(report.Warnings) > 20 {
		return RevocationReport{}, errors.New("invalid revocation report")
	}
	const warning = "Issued AWS STS credentials may remain valid until their expiry."
	report.STSCredentialsMayRemain = true
	foundWarning := false
	for _, candidate := range report.Warnings {
		normalized := strings.ToUpper(candidate)
		if len(candidate) > 1_024 ||
			strings.Contains(normalized, "-----BEGIN PRIVATE KEY-----") ||
			strings.Contains(normalized, "-----BEGIN RSA PRIVATE KEY-----") ||
			strings.Contains(normalized, "BEARER ") ||
			containsAWSAccessKeyID(normalized) {
			return RevocationReport{}, errors.New("unsafe revocation warning")
		}
		lower := strings.ToLower(candidate)
		if strings.Contains(lower, "sts") && strings.Contains(lower, "remain") {
			foundWarning = true
		}
	}
	if !foundWarning {
		report.Warnings = append(report.Warnings, warning)
	}
	return report, nil
}

func containsAWSAccessKeyID(value string) bool {
	for _, prefix := range []string{"AKIA", "ASIA"} {
		for start := strings.Index(value, prefix); start >= 0; {
			end := start + 20
			if end <= len(value) {
				matches := true
				for _, character := range value[start+len(prefix) : end] {
					if (character < 'A' || character > 'Z') &&
						(character < '0' || character > '9') {
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

// VaultManager configures access and owns audit of each Vault control-plane attempt.
// It cannot read, transport, or return workload credentials.
type VaultManager interface {
	EnableAccess(context.Context, AccessBinding) (authz.RedemptionDescriptor, error)
	Revoke(context.Context, string) (RevocationReport, error)
}
