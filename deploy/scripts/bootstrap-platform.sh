#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck disable=SC1091
source "${SCRIPT_DIR}/lib/common.sh"

for command_name in base64 cmp cp kubectl openssl tr wc; do
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

apply_namespace "agentgate-platform" "restricted"
apply_namespace "spire-system" "privileged"
apply_namespace "vault" "restricted"
apply_namespace "hcp-terraform-agent" "restricted"

password_file="${secret_dir}/postgresql-password"
tmp_dir="$(mktemp -d)"
trap 'rm -rf "${tmp_dir}"' EXIT
chmod 0700 "${tmp_dir}"

normalize_password_file() {
  local path="$1"
  local byte_count password
  byte_count="$(wc -c <"${path}")"
  password="$(<"${path}")"
  [[ ("${byte_count}" -eq 64 || "${byte_count}" -eq 65) && "${password}" =~ ^[0-9a-f]{64}$ ]] ||
    die "PostgreSQL password must contain exactly 64 lowercase hexadecimal characters"
  printf '%s' "${password}" >"${path}"
  unset password
  assert_file_mode_private "${path}"
}

cluster_password_file="${tmp_dir}/postgresql-password"
if kubectl get secret agentgate-postgresql \
  --namespace agentgate-platform >/dev/null 2>&1; then
  kubectl get secret agentgate-postgresql \
    --namespace agentgate-platform \
    -o jsonpath='{.data.password}' |
    base64 --decode >"${cluster_password_file}"
  [[ -s "${cluster_password_file}" ]] ||
    die "existing platform PostgreSQL Secret has no non-empty password key"
  normalize_password_file "${cluster_password_file}"

  if [[ -f "${password_file}" ]]; then
    normalize_password_file "${password_file}"
    cmp -s "${password_file}" "${cluster_password_file}" ||
      die "local and cluster PostgreSQL passwords differ; restore the original local file instead of rotating an initialized database"
  else
    cp "${cluster_password_file}" "${password_file}"
  fi
elif [[ ! -f "${password_file}" ]]; then
  openssl rand -hex 32 | tr -d '\n' >"${password_file}"
fi
normalize_password_file "${password_file}"

kubectl create secret generic agentgate-postgresql \
  --namespace agentgate-platform \
  --from-file="password=${password_file}" \
  --from-file="postgres-password=${password_file}" \
  --dry-run=client \
  -o yaml |
  kubectl apply -f - >/dev/null

kubectl create secret generic agentgate-postgresql \
  --namespace spire-system \
  --from-file="password=${password_file}" \
  --dry-run=client \
  -o yaml |
  kubectl apply -f - >/dev/null

note "Platform namespaces and PostgreSQL runtime Secret are ready."
note "Secret material remains in ${secret_dir}; back it up securely or remove it after bootstrap."
