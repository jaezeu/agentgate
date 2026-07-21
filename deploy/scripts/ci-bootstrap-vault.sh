#!/usr/bin/env bash
set -euo pipefail

# Runs inside the deploy workflow after the first platform pass. It makes the
# Vault bootstrap fully unattended:
#
#   1. port-forwards in-cluster Vault over TLS;
#   2. initializes Vault if needed, storing the recovery keys and initial
#      root token in AWS Secrets Manager (never printed, never persisted on
#      the runner beyond this job);
#   3. runs bootstrap-vault.sh with that root token to configure the
#      terraform-platform policy and the GitHub OIDC deployment trust.
#
# Re-runs are idempotent: an initialized Vault reuses the stored root token.
# If the operator has deleted the stored secret after retiring the root
# token, the (already configured) trust is left untouched.

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck disable=SC1091
source "${SCRIPT_DIR}/lib/common.sh"

for command_name in aws curl jq kubectl vault; do
  require_command "${command_name}"
done
require_env AGENTGATE_AWS_REGION

vault_namespace="${AGENTGATE_VAULT_NAMESPACE:-vault}"
spire_namespace="${AGENTGATE_SPIRE_NAMESPACE:-spire-system}"
vault_tls_name="vault.${vault_namespace}.svc.cluster.local"
secret_name="${AGENTGATE_VAULT_INIT_SECRET:-agentgate-sandbox/vault-init}"

tmp_dir="$(mktemp -d)"
chmod 0700 "${tmp_dir}"
port_forward_pid=""
cleanup() {
  [[ -n "${port_forward_pid}" ]] && kill "${port_forward_pid}" 2>/dev/null || true
  rm -rf "${tmp_dir}"
}
trap cleanup EXIT

ca_file="${tmp_dir}/spire-ca.pem"
kubectl get configmap spire-bundle \
  --namespace "${spire_namespace}" \
  -o jsonpath='{.data.bundle\.crt}' >"${ca_file}"
[[ -s "${ca_file}" ]] || die "SPIRE trust bundle is empty"

kubectl port-forward \
  --namespace "${vault_namespace}" \
  service/vault 8200:8200 >/dev/null 2>&1 &
port_forward_pid="$!"

export VAULT_ADDR="https://127.0.0.1:8200"
export VAULT_CACERT="${ca_file}"
export VAULT_TLS_SERVER_NAME="${vault_tls_name}"

# 501 = not initialized, 503 = sealed; both mean Vault is reachable.
vault_reachable=""
for _ in $(seq 1 60); do
  if curl --silent --output /dev/null \
    --cacert "${ca_file}" \
    --connect-to "${vault_tls_name}:8200:127.0.0.1:8200" \
    "https://${vault_tls_name}:8200/v1/sys/health?standbyok=true&uninitcode=200&sealedcode=200"; then
    vault_reachable="yes"
    break
  fi
  sleep 2
done
[[ -n "${vault_reachable}" ]] || die "Vault did not become reachable through the port-forward"

token_file="${tmp_dir}/root-token"
touch "${token_file}"
chmod 0600 "${token_file}"

if [[ "$(vault status -format=json | jq -r '.initialized')" != "true" ]]; then
  note "Initializing Vault; recovery keys and root token go to Secrets Manager ${secret_name}."
  init_file="${tmp_dir}/init.json"
  touch "${init_file}"
  chmod 0600 "${init_file}"
  vault operator init -format=json >"${init_file}"

  if ! aws secretsmanager create-secret \
    --region "${AGENTGATE_AWS_REGION}" \
    --name "${secret_name}" \
    --description "AgentGate sandbox Vault recovery keys and initial root token" \
    --secret-string "file://${init_file}" >/dev/null 2>&1; then
    aws secretsmanager put-secret-value \
      --region "${AGENTGATE_AWS_REGION}" \
      --secret-id "${secret_name}" \
      --secret-string "file://${init_file}" >/dev/null
  fi
  jq -r '.root_token' "${init_file}" >"${token_file}"
  rm -f "${init_file}"

  # KMS auto-unseal completes on its own moments after initialization.
  for _ in $(seq 1 30); do
    if [[ "$(vault status -format=json | jq -r '.sealed')" == "false" ]]; then
      break
    fi
    sleep 2
  done
  [[ "$(vault status -format=json | jq -r '.sealed')" == "false" ]] ||
    die "Vault stayed sealed after initialization; check the KMS unseal key and IRSA role"
elif aws secretsmanager get-secret-value \
  --region "${AGENTGATE_AWS_REGION}" \
  --secret-id "${secret_name}" \
  --query SecretString --output text 2>/dev/null |
  jq -r '.root_token' >"${token_file}" && [[ -s "${token_file}" ]]; then
  note "Vault is already initialized; reusing the stored root token."
else
  note "Vault is initialized and ${secret_name} is absent (root token retired);"
  note "leaving the existing deployment trust unchanged."
  exit 0
fi

[[ -z "${GITHUB_ACTIONS:-}" ]] || echo "::add-mask::$(<"${token_file}")"

VAULT_TOKEN_FILE="${token_file}" \
  AGENTGATE_GITHUB_REPOSITORY="${AGENTGATE_GITHUB_REPOSITORY:-${GITHUB_REPOSITORY:-}}" \
  "${SCRIPT_DIR}/bootstrap-vault.sh"

note "Unattended Vault bootstrap complete."
