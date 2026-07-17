#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck disable=SC1091
source "${SCRIPT_DIR}/lib/common.sh"

for command_name in base64 cmp cp jq kubectl openssl tr; do
  require_command "${command_name}"
done
verify_aws_identity
verify_kubernetes_context

secret_dir="${AGENTGATE_SECRET_DIR:-}"
[[ -n "${secret_dir}" ]] ||
  die "set AGENTGATE_SECRET_DIR to a protected directory outside the repository"
mkdir -p "${secret_dir}"
chmod 0700 "${secret_dir}"

case "${secret_dir}" in
  "${REPOSITORY_ROOT}" | "${REPOSITORY_ROOT}"/*)
    die "AGENTGATE_SECRET_DIR must be outside the repository"
    ;;
esac

for namespace in agentgate agentgate-sandbox agentgate-platform; do
  kubectl get namespace "${namespace}" >/dev/null ||
    die "namespace ${namespace} is missing; apply the required Terraform layer first"
done

tmp_dir="$(mktemp -d)"
trap 'rm -rf "${tmp_dir}"' EXIT
chmod 0700 "${tmp_dir}"

database_password_file="${tmp_dir}/password"
kubectl get secret agentgate-postgresql \
  --namespace agentgate-platform \
  -o jsonpath='{.data.password}' |
  base64 --decode >"${database_password_file}"
[[ -s "${database_password_file}" ]] ||
  die "platform PostgreSQL Secret has no non-empty password key"
assert_file_mode_private "${database_password_file}"
database_password="$(<"${database_password_file}")"
[[ "${database_password}" =~ ^[0-9a-f]{64}$ ]] ||
  die "platform PostgreSQL password does not match the bootstrap contract"
database_url_file="${tmp_dir}/database-url"
printf \
  'postgres://agentgate:%s@agentgate-postgresql.agentgate-platform.svc.cluster.local:5432/agentgate?sslmode=disable' \
  "${database_password}" >"${database_url_file}"
unset database_password
assert_file_mode_private "${database_url_file}"

private_key_file="${secret_dir}/dispatcher-private.pem"
public_key_file="${secret_dir}/dispatcher-public.pem"
cluster_private_key_file="${tmp_dir}/dispatcher-private.pem"
if kubectl get secret agentgate-dispatcher-private-key \
  --namespace agentgate-sandbox >/dev/null 2>&1; then
  kubectl get secret agentgate-dispatcher-private-key \
    --namespace agentgate-sandbox \
    -o jsonpath='{.data.dispatcher-private\.pem}' |
    base64 --decode >"${cluster_private_key_file}"
  [[ -s "${cluster_private_key_file}" ]] ||
    die "existing dispatcher Secret has no non-empty dispatcher-private.pem key"
  assert_file_mode_private "${cluster_private_key_file}"

  if [[ -f "${private_key_file}" ]]; then
    cmp -s "${private_key_file}" "${cluster_private_key_file}" ||
      die "local and cluster dispatcher private keys differ; restore the original pair instead of rotating silently"
  else
    cp "${cluster_private_key_file}" "${private_key_file}"
  fi
  openssl pkey -in "${private_key_file}" -pubout -out "${public_key_file}"
elif [[ ! -f "${private_key_file}" && ! -f "${public_key_file}" ]]; then
  openssl genpkey -algorithm ED25519 -out "${private_key_file}"
  openssl pkey -in "${private_key_file}" -pubout -out "${public_key_file}"
elif [[ ! -f "${private_key_file}" || ! -f "${public_key_file}" ]]; then
  die "dispatcher key pair is incomplete in ${secret_dir}; restore both files instead of rotating one side"
fi
assert_file_mode_private "${private_key_file}"
chmod 0644 "${public_key_file}"

normalize_approver_token_file() {
  local path="$1"
  local token
  token="$(<"${path}")"
  [[ -n "${token}" && "${token}" != *$'\n'* ]] ||
    die "PoC approver token must be one non-empty line"
  printf '%s' "${token}" >"${path}"
  unset token
  assert_file_mode_private "${path}"
}

normalize_webhook_url_file() {
  local path="$1"
  local webhook_url
  webhook_url="$(<"${path}")"
  [[ "${webhook_url}" =~ ^https://[^/@[:space:]]+([/?][^[:space:]]*)?$ &&
    "${webhook_url}" != *$'\n'* &&
    "${webhook_url}" != *'#'* &&
    "${#webhook_url}" -le 2048 ]] ||
    die "approval webhook URL must be one HTTPS URL without user info or a fragment"
  printf '%s' "${webhook_url}" >"${path}"
  unset webhook_url
  assert_file_mode_private "${path}"
}

approver_token_file="${secret_dir}/approver-token"
approval_webhook_url_file="${secret_dir}/approval-webhook-url"
cluster_approver_token_file="${tmp_dir}/approver-token"
cluster_approval_webhook_url_file="${tmp_dir}/approval-webhook-url"
if kubectl get secret agentgate-approver-token \
  --namespace agentgate >/dev/null 2>&1; then
  kubectl get secret agentgate-approver-token \
    --namespace agentgate \
    -o json |
    jq -r '.data.token // empty' |
    base64 --decode >"${cluster_approver_token_file}"
  [[ -s "${cluster_approver_token_file}" ]] ||
    die "existing approver Secret has no non-empty token key"
  normalize_approver_token_file "${cluster_approver_token_file}"

  if [[ -f "${approver_token_file}" ]]; then
    normalize_approver_token_file "${approver_token_file}"
    cmp -s "${approver_token_file}" "${cluster_approver_token_file}" ||
      die "local and cluster approver tokens differ; restore the original token instead of rotating silently"
  else
    cp "${cluster_approver_token_file}" "${approver_token_file}"
  fi

  kubectl get secret agentgate-approver-token \
    --namespace agentgate \
    -o json |
    jq -r '.data["webhook-url"] // empty' |
    base64 --decode >"${cluster_approval_webhook_url_file}"
  if [[ -s "${cluster_approval_webhook_url_file}" ]]; then
    normalize_webhook_url_file "${cluster_approval_webhook_url_file}"
    if [[ -f "${approval_webhook_url_file}" ]]; then
      normalize_webhook_url_file "${approval_webhook_url_file}"
      cmp -s "${approval_webhook_url_file}" "${cluster_approval_webhook_url_file}" ||
        die "local and cluster approval webhook URLs differ; reconcile them explicitly instead of rotating silently"
    else
      cp "${cluster_approval_webhook_url_file}" "${approval_webhook_url_file}"
    fi
  fi
elif [[ ! -f "${approver_token_file}" ]]; then
  openssl rand -base64 48 | tr -d '\n' >"${approver_token_file}"
fi
normalize_approver_token_file "${approver_token_file}"

[[ -f "${approval_webhook_url_file}" ]] ||
  die "create ${approval_webhook_url_file} as a protected file containing the sandbox HTTPS approval webhook URL"
normalize_webhook_url_file "${approval_webhook_url_file}"

kubectl create secret generic agentgate-postgresql \
  --namespace agentgate \
  --from-file="database-url=${database_url_file}" \
  --dry-run=client \
  -o yaml |
  kubectl apply -f - >/dev/null

kubectl create secret generic agentgate-approver-token \
  --namespace agentgate \
  --from-file="token=${approver_token_file}" \
  --from-file="webhook-url=${approval_webhook_url_file}" \
  --dry-run=client \
  -o yaml |
  kubectl apply -f - >/dev/null

kubectl create configmap agentgate-dispatcher-public-key \
  --namespace agentgate \
  --from-file="dispatcher-public.pem=${public_key_file}" \
  --dry-run=client \
  -o yaml |
  kubectl apply -f - >/dev/null

kubectl create secret generic agentgate-dispatcher-private-key \
  --namespace agentgate-sandbox \
  --from-file="dispatcher-private.pem=${private_key_file}" \
  --dry-run=client \
  -o yaml |
  kubectl apply -f - >/dev/null

kubectl rollout restart deployment/agentgate \
  --namespace agentgate >/dev/null

note "AgentGate runtime references, approval settings, and PoC dispatcher keys are ready."
note "The dispatcher private key exists only in the protected local directory and dispatcher namespace Secret."
