package vaultmgr

import (
	"strings"
	"testing"
)

func TestNormalizeRevocationReportEnforcesSTSCaveat(t *testing.T) {
	t.Parallel()
	report, err := NormalizeRevocationReport("request-1", RevocationReport{
		RequestID:     "request-1",
		RoleRemoved:   true,
		PolicyRemoved: true,
	})
	if err != nil {
		t.Fatalf("normalize report: %v", err)
	}
	if !report.STSCredentialsMayRemain || len(report.Warnings) != 1 ||
		!strings.Contains(report.Warnings[0], "STS") {
		t.Fatalf("missing STS caveat: %#v", report)
	}
}

func TestNormalizeRevocationReportRejectsUnsafeWarnings(t *testing.T) {
	t.Parallel()
	for name, warning := range map[string]string{
		"private key": "-----BEGIN PRIVATE KEY-----",
		"bearer":      "Bearer test-only-token-value",
		"AWS key":     "ASIAABCDEFGHIJKLMNOP",
		"too long":    strings.Repeat("x", 1_025),
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			if _, err := NormalizeRevocationReport("request-1", RevocationReport{
				RequestID: "request-1",
				Warnings:  []string{warning},
			}); err == nil {
				t.Fatal("unsafe warning was accepted")
			}
		})
	}
}

func TestNormalizeRevocationReportRejectsWrongRequest(t *testing.T) {
	t.Parallel()
	if _, err := NormalizeRevocationReport("request-1", RevocationReport{
		RequestID: "request-2",
	}); err == nil {
		t.Fatal("mismatched request ID was accepted")
	}
}
