#!/usr/bin/env bash
set -euo pipefail
umask 077

COMMON_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DEPLOY_ROOT="$(cd "${COMMON_DIR}/../.." && pwd)"
REPOSITORY_ROOT="$(cd "${DEPLOY_ROOT}/.." && pwd)"
# shellcheck disable=SC2034
readonly COMMON_DIR DEPLOY_ROOT REPOSITORY_ROOT

die() {
  printf 'error: %s\n' "$*" >&2
  exit 1
}

note() {
  printf '%s\n' "$*"
}

require_command() {
  command -v "$1" >/dev/null 2>&1 || die "required command not found: $1"
}

require_env() {
  local value
  value="$(printenv "$1" 2>/dev/null || true)"
  [[ -n "${value}" ]] || die "required environment variable is not set: $1"
}

require_digest_reference() {
  local reference="$1"
  [[ "${reference}" =~ ^[^[:space:]@]+@sha256:[0-9a-f]{64}$ ]] ||
    die "image reference must be pinned by sha256 digest: ${reference}"
}

verify_aws_identity() {
  require_env AGENTGATE_AWS_ACCOUNT_ID
  require_env AGENTGATE_AWS_REGION

  local identity actual_account configured_region
  identity="$(aws sts get-caller-identity --output json)"
  actual_account="$(jq -r '.Account' <<<"${identity}")"
  [[ "${actual_account}" == "${AGENTGATE_AWS_ACCOUNT_ID}" ]] ||
    die "AWS account mismatch: expected ${AGENTGATE_AWS_ACCOUNT_ID}, got ${actual_account}"

  configured_region="${AWS_REGION:-${AWS_DEFAULT_REGION:-}}"
  if [[ -n "${configured_region}" && "${configured_region}" != "${AGENTGATE_AWS_REGION}" ]]; then
    die "AWS region mismatch: expected ${AGENTGATE_AWS_REGION}, got ${configured_region}"
  fi
}

verify_kubernetes_context() {
  require_env AGENTGATE_CLUSTER_NAME

  local current_context cluster_server
  current_context="$(kubectl config current-context)"
  cluster_server="$(kubectl config view --minify -o jsonpath='{.clusters[0].cluster.server}')"
  [[ -n "${cluster_server}" ]] || die "current Kubernetes context has no cluster server"

  kubectl get namespace kube-system >/dev/null
  note "Kubernetes context verified for ${AGENTGATE_CLUSTER_NAME}: ${current_context}"
}

apply_namespace() {
  local namespace="$1"
  local enforce_level="$2"

  kubectl create namespace "${namespace}" --dry-run=client -o yaml |
    kubectl apply -f - >/dev/null
  kubectl label namespace "${namespace}" \
    "pod-security.kubernetes.io/enforce=${enforce_level}" \
    "pod-security.kubernetes.io/enforce-version=v1.36" \
    "pod-security.kubernetes.io/audit=restricted" \
    "pod-security.kubernetes.io/audit-version=v1.36" \
    "pod-security.kubernetes.io/warn=restricted" \
    "pod-security.kubernetes.io/warn-version=v1.36" \
    --overwrite >/dev/null
}

assert_file_mode_private() {
  local path="$1"
  [[ -f "${path}" ]] || die "required file not found: ${path}"
  chmod 0600 "${path}"
}

sha256_file() {
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$1" | awk '{print $1}'
  else
    shasum -a 256 "$1" | awk '{print $1}'
  fi
}
