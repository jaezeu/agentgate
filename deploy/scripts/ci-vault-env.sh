#!/usr/bin/env bash
set -euo pipefail

# Runs inside the GitHub Actions deploy workflow before a platform pass that
# includes Vault configuration. It port-forwards in-cluster Vault over TLS,
# exchanges the job's GitHub OIDC identity token for a short-lived Vault token
# scoped to the terraform-platform policy, and exports Vault environment for
# the Terraform provider. No long-lived Vault credential is stored anywhere.

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck disable=SC1091
source "${SCRIPT_DIR}/lib/common.sh"

for command_name in curl jq kubectl; do
  require_command "${command_name}"
done

require_env ACTIONS_ID_TOKEN_REQUEST_URL
require_env ACTIONS_ID_TOKEN_REQUEST_TOKEN
require_env GITHUB_ENV
require_env RUNNER_TEMP

vault_namespace="${AGENTGATE_VAULT_NAMESPACE:-vault}"
spire_namespace="${AGENTGATE_SPIRE_NAMESPACE:-spire-system}"
vault_tls_name="vault.${vault_namespace}.svc.cluster.local"
vault_audience="${AGENTGATE_VAULT_AUDIENCE:-agentgate-vault}"
vault_role="${AGENTGATE_VAULT_CI_ROLE:-terraform-platform}"

ca_file="${RUNNER_TEMP}/spire-ca.pem"
kubectl get configmap spire-bundle \
  --namespace "${spire_namespace}" \
  -o jsonpath='{.data.bundle\.crt}' >"${ca_file}"
[[ -s "${ca_file}" ]] || die "SPIRE trust bundle is empty"

kubectl port-forward \
  --namespace "${vault_namespace}" \
  service/vault 8200:8200 >/dev/null 2>&1 &
port_forward_pid="$!"

vault_ready=""
for _ in $(seq 1 30); do
  if curl --silent --fail --output /dev/null \
    --cacert "${ca_file}" \
    --connect-to "${vault_tls_name}:8200:127.0.0.1:8200" \
    "https://${vault_tls_name}:8200/v1/sys/health?standbyok=true"; then
    vault_ready="yes"
    break
  fi
  sleep 2
done
[[ -n "${vault_ready}" ]] || {
  kill "${port_forward_pid}" 2>/dev/null || true
  die "Vault did not become reachable through the port-forward"
}

id_token="$(
  curl --silent --fail \
    --header "Authorization: bearer ${ACTIONS_ID_TOKEN_REQUEST_TOKEN}" \
    "${ACTIONS_ID_TOKEN_REQUEST_URL}&audience=${vault_audience}" |
    jq -r '.value'
)"
[[ -n "${id_token}" && "${id_token}" != "null" ]] ||
  die "could not obtain a GitHub OIDC identity token"

login_payload="$(jq -n --arg role "${vault_role}" --arg jwt "${id_token}" \
  '{role: $role, jwt: $jwt}')"
vault_token="$(
  curl --silent --fail \
    --cacert "${ca_file}" \
    --connect-to "${vault_tls_name}:8200:127.0.0.1:8200" \
    --request POST \
    --data "${login_payload}" \
    "https://${vault_tls_name}:8200/v1/auth/jwt-deployer/login" |
    jq -r '.auth.client_token'
)"
unset id_token login_payload
[[ -n "${vault_token}" && "${vault_token}" != "null" ]] ||
  die "Vault JWT login for the deploy workflow failed"

echo "::add-mask::${vault_token}"
{
  printf 'VAULT_ADDR=https://127.0.0.1:8200\n'
  printf 'VAULT_CACERT=%s\n' "${ca_file}"
  printf 'VAULT_TLS_SERVER_NAME=%s\n' "${vault_tls_name}"
  printf 'VAULT_TOKEN=%s\n' "${vault_token}"
} >>"${GITHUB_ENV}"
unset vault_token

note "Vault provider environment exported; port-forward pid ${port_forward_pid} stays up for this job."
