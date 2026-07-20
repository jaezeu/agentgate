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
  require_env AGENTGATE_AWS_REGION

  local current_context cluster_server expected_endpoint
  current_context="$(kubectl config current-context)"
  cluster_server="$(kubectl config view --minify -o jsonpath='{.clusters[0].cluster.server}')"
  [[ -n "${cluster_server}" ]] || die "current Kubernetes context has no cluster server"

  # The guard exists to stop secrets from landing on whatever cluster the
  # kubeconfig happens to point at, so the current context's server must be
  # the named EKS cluster's actual endpoint, not merely reachable.
  expected_endpoint="$(aws eks describe-cluster \
    --name "${AGENTGATE_CLUSTER_NAME}" \
    --region "${AGENTGATE_AWS_REGION}" \
    --query 'cluster.endpoint' \
    --output text)"
  [[ -n "${expected_endpoint}" && "${expected_endpoint}" != "None" ]] ||
    die "could not resolve the EKS endpoint for cluster ${AGENTGATE_CLUSTER_NAME}"
  local normalized_server normalized_endpoint
  normalized_server="$(tr '[:upper:]' '[:lower:]' <<<"${cluster_server%/}")"
  normalized_endpoint="$(tr '[:upper:]' '[:lower:]' <<<"${expected_endpoint%/}")"
  [[ "${normalized_server}" == "${normalized_endpoint}" ]] ||
    die "current Kubernetes context ${current_context} does not point at cluster ${AGENTGATE_CLUSTER_NAME} (${cluster_server} != ${expected_endpoint})"

  kubectl get namespace kube-system >/dev/null
  note "Kubernetes context verified for ${AGENTGATE_CLUSTER_NAME}: ${current_context}"
}

# Resolves AGENTGATE_SECRET_DIR to a physical path (following symlinks and
# relative segments) and refuses any location inside the repository, so the
# outside-the-repo contract cannot be bypassed with a relative path or a
# symlink that points back into the checkout. Prints the canonical path.
resolve_secret_dir() {
  local secret_dir="${AGENTGATE_SECRET_DIR:-}"
  [[ -n "${secret_dir}" ]] ||
    die "set AGENTGATE_SECRET_DIR to a protected directory outside the repository"
  mkdir -p "${secret_dir}"
  chmod 0700 "${secret_dir}"
  secret_dir="$(cd "${secret_dir}" && pwd -P)" ||
    die "AGENTGATE_SECRET_DIR could not be resolved"
  local repository_root_physical
  repository_root_physical="$(cd "${REPOSITORY_ROOT}" && pwd -P)"
  case "${secret_dir}" in
    "${repository_root_physical}" | "${repository_root_physical}"/*)
      die "AGENTGATE_SECRET_DIR must be outside the repository"
      ;;
  esac
  printf '%s\n' "${secret_dir}"
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
