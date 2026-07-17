package main

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestTerraformRunnerLimitsEnvironmentScrubsOutputAndClearsCredentials(t *testing.T) {
	if os.PathSeparator != '/' {
		t.Skip("test helper uses a POSIX shell")
	}
	const (
		accessKeyID  = "ASIAABCDEFGHIJKLMNOP"
		secretKey    = "runtime-only-secret-access-key-0123456789"
		sessionToken = "runtime-only-session-token-with-more-than-32-characters"
	)
	helper := filepath.Join(t.TempDir(), "terraform")
	script := `#!/bin/sh
set -eu
case "$1" in
  init)
    test -z "${AWS_ACCESS_KEY_ID:-}"
    test -z "${AWS_SECRET_ACCESS_KEY:-}"
    test -z "${AWS_SESSION_TOKEN:-}"
    test -z "${VAULT_TOKEN:-}"
    echo "init complete"
    ;;
  plan)
    test "${AWS_ACCESS_KEY_ID:-}" = "` + accessKeyID + `"
    test "${AWS_SECRET_ACCESS_KEY:-}" = "` + secretKey + `"
    test "${AWS_SESSION_TOKEN:-}" = "` + sessionToken + `"
    test -z "${VAULT_TOKEN:-}"
    test -z "${TF_LOG:-}"
    echo "AWS_ACCESS_KEY_ID=${AWS_ACCESS_KEY_ID}"
    echo "AWS_SECRET_ACCESS_KEY=${AWS_SECRET_ACCESS_KEY}"
    echo "AWS_SESSION_TOKEN=${AWS_SESSION_TOKEN}"
    exit 2
    ;;
  *)
    exit 9
    ;;
esac
`
	// #nosec G306 -- this test fixture must be executable by the test owner.
	if err := os.WriteFile(helper, []byte(script), 0o700); err != nil {
		t.Fatalf("write Terraform helper: %v", err)
	}
	t.Setenv("AWS_ACCESS_KEY_ID", "ASIAINHERITED000000")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "inherited-secret")
	t.Setenv("AWS_SESSION_TOKEN", "inherited-session")
	t.Setenv("VAULT_TOKEN", "hvs.inherited-vault-token")
	t.Setenv("TF_LOG", "TRACE")

	var output bytes.Buffer
	runner := terraformRunner{binary: helper, output: &output}
	workDirectory, cleanup, err := runner.prepare()
	if err != nil {
		t.Fatalf("prepare: %v", err)
	}
	defer cleanup()
	if err := runner.initialize(context.Background(), workDirectory); err != nil {
		t.Fatalf("initialize: %v\n%s", err, output.String())
	}
	credentials := &awsCredentials{
		accessKeyID:     accessKeyID,
		secretAccessKey: secretKey,
		sessionToken:    sessionToken,
	}
	result, err := runner.plan(context.Background(), workDirectory, terraformInputs{
		AWSRegion:  "us-west-2",
		DemoBucket: "agentgate-demo-test",
		DemoPrefix: "governed/",
		RequestID:  "00000000-0000-4000-8000-000000000601",
	}, credentials)
	if err != nil {
		t.Fatalf("plan: %v\n%s", err, output.String())
	}
	if !result.Initialized || !result.PlanCompleted || !result.ChangesPresent {
		t.Fatalf("result = %#v", result)
	}
	for _, prohibited := range []string{
		accessKeyID,
		secretKey,
		sessionToken,
		"ASIAINHERITED000000",
		"inherited-secret",
		"inherited-session",
		"hvs.inherited-vault-token",
	} {
		if strings.Contains(output.String(), prohibited) {
			t.Fatalf("scrubbed output contained %q: %s", prohibited, output.String())
		}
	}
	if !strings.Contains(output.String(), "[REDACTED]") {
		t.Fatalf("output did not report redaction: %s", output.String())
	}
	if credentials.accessKeyID != "" ||
		credentials.secretAccessKey != "" ||
		credentials.sessionToken != "" {
		t.Fatal("Terraform runner retained STS credential references")
	}
}

func TestScrubTerraformOutputCatchesCredentialShapedValues(t *testing.T) {
	raw := []byte(
		"ASIAABCDEFGHIJKLMNOP\n" +
			"eyJhbGciOiJFUzI1NiJ9.eyJhdWQiOiJ2YXVsdCJ9.signaturevalue\n" +
			"hvs.runtimeVaultToken\n",
	)
	scrubbed := string(scrubTerraformOutput(raw, nil))
	if strings.Contains(scrubbed, "ASIA") ||
		strings.Contains(scrubbed, "eyJ") ||
		strings.Contains(scrubbed, "hvs.") {
		t.Fatalf("credential-shaped output was not scrubbed: %s", scrubbed)
	}
}
