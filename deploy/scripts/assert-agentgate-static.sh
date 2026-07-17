#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck disable=SC1091
source "${SCRIPT_DIR}/lib/common.sh"

root="${DEPLOY_ROOT}/agentgate"

[[ "$(grep -c 'suspend[[:space:]]*=[[:space:]]*true' "${root}/demo_jobs.tf")" -eq 2 ]] ||
  die "both demo Jobs must remain suspended in Terraform"
grep -q 'spiffe://sandbox.agentgate.test/ns/agentgate-sandbox/sa/terraform-runner' \
  "${root}/locals.tf" ||
  die "runner SPIFFE ID does not match the embedded policy"
grep -q "\"k8s:sa:\${var.runner_service_account_name}\"" "${root}/identity.tf" ||
  die "runner service-account workload selector is missing"
grep -q 'automount_service_account_token = false' "${root}/namespaces.tf" ||
  die "service-account token automount is not disabled"
grep -q 'read_only_root_filesystem  = true' "${root}/agentgate.tf" ||
  die "AgentGate read-only root filesystem is missing"
grep -q 'resource "kubernetes_pod_disruption_budget_v1"' "${root}/agentgate.tf" ||
  die "AgentGate PodDisruptionBudget is missing"
grep -q 'resource "kubernetes_network_policy_v1" "runner_default_deny"' "${root}/network.tf" ||
  die "runner default-deny network policy is missing"
grep -q -- '"--listen=:8443"' "${root}/locals.tf" ||
  die "AgentGate mTLS listener flag is missing"
grep -q -- '"--vault-management-role=agentgate-manager"' "${root}/locals.tf" ||
  die "AgentGate Vault management identity is not wired"
grep -q 'spiffe-helper@sha256:2759b3a699bb63b91cc5896f46cd6f70b9e3dfed9f7f4355a3a0a4e702984f9c' \
  "${root}/locals.tf" ||
  die "AgentGate SPIFFE Helper image is not pinned to the reviewed digest"
grep -q 'scheme = "HTTPS"' "${root}/agentgate.tf" ||
  die "AgentGate HTTPS probes are missing"
grep -q 'listener_enabled = true' "${root}/config.tf" ||
  die "AgentGate SPIFFE Helper health endpoint is missing"
grep -q -- '"--terraform-bin=/usr/local/bin/terraform"' "${root}/demo_jobs.tf" ||
  die "demo runner does not invoke the packaged Terraform binary"
grep -Fq -- "\"--vault-tls-server-name=\${local.vault_server_name}\"" "${root}/demo_jobs.tf" ||
  die "demo runner does not verify the Vault TLS server name"
grep -Fq -- "\"--aws-region=\${local.aws_region}\"" "${root}/demo_jobs.tf" ||
  die "demo runner is not wired to the governed AWS region"
grep -Fq -- "\"--demo-bucket=\${local.demo_bucket_name}\"" "${root}/demo_jobs.tf" ||
  die "demo runner is not wired to the governed sandbox bucket"
grep -Fq -- "\"--demo-prefix=\${local.demo_bucket_prefix}\"" "${root}/demo_jobs.tf" ||
  die "demo runner is not wired to the governed sandbox prefix"
grep -q 'sizeLimit = "2Gi"' "${root}/demo_jobs.tf" ||
  die "demo runner has no bounded writable Terraform workspace"
if grep -Eq '(pid_file_name|renew_signal)' "${root}/config.tf"; then
  die "AgentGate file-watching SPIFFE Helper must not signal the application"
fi

if grep -RInE \
  '(AWS_ACCESS_KEY_ID|AWS_SECRET_ACCESS_KEY|AWS_SESSION_TOKEN|VAULT_TOKEN|aws/creds/)' \
  "${root}" \
  --exclude-dir=.terraform >/dev/null; then
  die "AgentGate root contains a prohibited credential-bearing path or environment variable"
fi

note "AgentGate static security assertions passed."
