#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck disable=SC1091
source "${SCRIPT_DIR}/lib/common.sh"

for command_name in aws jq kubectl terraform; do
  require_command "${command_name}"
done

require_env AGENTGATE_STATE_BUCKET
require_env AGENTGATE_AWS_ACCOUNT_ID
require_env AGENTGATE_AWS_REGION
require_env AGENTGATE_CONFIRM_DESTROY
require_env AGENTGATE_DEPLOYER_ROLE_ARN
require_env AGENTGATE_EKS_PUBLIC_ACCESS_CIDRS
[[ "${AGENTGATE_CONFIRM_DESTROY}" == "destroy-${AGENTGATE_AWS_ACCOUNT_ID}" ]] ||
  die "set AGENTGATE_CONFIRM_DESTROY=destroy-${AGENTGATE_AWS_ACCOUNT_ID} to confirm reverse teardown"
[[ "${AGENTGATE_DEPLOYER_ROLE_ARN}" =~ ^arn:[^:]+:iam::${AGENTGATE_AWS_ACCOUNT_ID}:role/.+ ]] ||
  die "AGENTGATE_DEPLOYER_ROLE_ARN does not belong to the confirmed sandbox account"

# Destroying the platform root removes Vault provider resources, so Vault must
# be reachable exactly as during the configuration pass (TLS port-forward plus
# a token holding the terraform-platform policy).
require_env VAULT_ADDR
require_env VAULT_CACERT
[[ "${VAULT_ADDR}" == https://* ]] || die "VAULT_ADDR must use HTTPS"
[[ -n "${VAULT_TOKEN:-}" ]] ||
  die "export VAULT_TOKEN (terraform-platform scoped) before destroying the platform root"

if [[ -n "${AWS_ACCESS_KEY_ID:-}" && -z "${AWS_SESSION_TOKEN:-}" ]]; then
  die "static AWS access keys are prohibited; use AWS SSO locally and GitHub OIDC in CI"
fi

verify_aws_identity
verify_kubernetes_context

export TF_VAR_state_bucket="${AGENTGATE_STATE_BUCKET}"
export TF_VAR_state_bucket_region="${AGENTGATE_AWS_REGION}"
export TF_VAR_deployer_role_arn="${AGENTGATE_DEPLOYER_ROLE_ARN}"
export TF_VAR_cluster_endpoint_public_access_cidrs="${AGENTGATE_EKS_PUBLIC_ACCESS_CIDRS}"
export TF_VAR_allow_public_cluster_endpoint="${AGENTGATE_ALLOW_PUBLIC_CLUSTER_ENDPOINT:-false}"
# Destroy never launches the application; the digest placeholder only
# satisfies variable validation.
export TF_VAR_application_image="${AGENTGATE_APPLICATION_IMAGE:-destroyed@sha256:0000000000000000000000000000000000000000000000000000000000000000}"

destroy_root() {
  local root="$1"
  note "Destroying deploy/${root} against s3://${AGENTGATE_STATE_BUCKET}/${root}.tfstate ..."
  "${SCRIPT_DIR}/init-root.sh" "${root}" >/dev/null
  terraform -chdir="${DEPLOY_ROOT}/${root}" destroy -input=false -auto-approve
}

destroy_root agentgate
destroy_root platform

for namespace in vault agentgate-platform; do
  kubectl delete pvc --all --namespace "${namespace}" --ignore-not-found --wait=true
done
kubectl delete namespace \
  vault \
  spire-system \
  agentgate-platform \
  --ignore-not-found \
  --wait=true

remaining_pvs="$(kubectl get pv -o json | jq '[.items[] | select(.spec.csi.driver == "ebs.csi.aws.com")] | length')"
[[ "${remaining_pvs}" -eq 0 ]] ||
  die "${remaining_pvs} EBS-backed persistent volumes remain; do not destroy infra until they are removed"

destroy_root infra

note "Reverse destroy completed: agentgate, platform, then infra."
note "The state bucket, OIDC provider, and deployer role remain."
note "To remove them: empty s3://${AGENTGATE_STATE_BUCKET}, then run"
note "  terraform -chdir=deploy/bootstrap destroy"
note "Review AWS Resource Groups/Tag Editor and billing for residual AgentGate-tagged resources."
