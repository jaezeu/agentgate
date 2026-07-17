#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck disable=SC1091
source "${SCRIPT_DIR}/lib/common.sh"

for command_name in aws curl jq kubectl terraform; do
  require_command "${command_name}"
done

require_env TF_CLOUD_ORGANIZATION
require_env TFC_TOKEN
require_env AGENTGATE_AWS_ACCOUNT_ID
require_env AGENTGATE_AWS_REGION
require_env AGENTGATE_CONFIRM_DESTROY
require_env AGENTGATE_INFRA_RUN_ROLE_ARN
require_env AGENTGATE_HCP_AWS_OIDC_PROVIDER_ARN
require_env AGENTGATE_HCP_OIDC_PROVIDER_OWNERSHIP
[[ "${AGENTGATE_CONFIRM_DESTROY}" == "destroy-${AGENTGATE_AWS_ACCOUNT_ID}" ]] ||
  die "set AGENTGATE_CONFIRM_DESTROY=destroy-${AGENTGATE_AWS_ACCOUNT_ID} to confirm reverse teardown"
[[ "${AGENTGATE_HCP_OIDC_PROVIDER_OWNERSHIP}" == "dedicated" ||
  "${AGENTGATE_HCP_OIDC_PROVIDER_OWNERSHIP}" == "shared" ]] ||
  die "AGENTGATE_HCP_OIDC_PROVIDER_OWNERSHIP must be dedicated or shared"
[[ "${AGENTGATE_INFRA_RUN_ROLE_ARN}" =~ ^arn:[^:]+:iam::${AGENTGATE_AWS_ACCOUNT_ID}:role/.+ ]] ||
  die "AGENTGATE_INFRA_RUN_ROLE_ARN does not belong to the confirmed sandbox account"
[[ "${AGENTGATE_HCP_AWS_OIDC_PROVIDER_ARN}" =~ ^arn:[^:]+:iam::${AGENTGATE_AWS_ACCOUNT_ID}:oidc-provider/app\.terraform\.io$ ]] ||
  die "AGENTGATE_HCP_AWS_OIDC_PROVIDER_ARN does not identify the confirmed sandbox account"

if [[ -n "${AWS_ACCESS_KEY_ID:-}" || -n "${AWS_SECRET_ACCESS_KEY:-}" || -n "${AWS_SESSION_TOKEN:-}" ]]; then
  die "exported AWS credential variables are prohibited; use AWS SSO locally and HCP dynamic credentials for runs"
fi

verify_aws_identity
verify_kubernetes_context

destroy_root() {
  local root="$1"
  note "Destroying deploy/${root} through its HCP Terraform workspace..."
  TF_CLOUD_ORGANIZATION="${TF_CLOUD_ORGANIZATION}" \
    terraform -chdir="${DEPLOY_ROOT}/${root}" init -input=false >/dev/null
  TF_CLOUD_ORGANIZATION="${TF_CLOUD_ORGANIZATION}" \
    terraform -chdir="${DEPLOY_ROOT}/${root}" destroy -input=false -auto-approve
}

destroy_root agentgate
destroy_root platform

for namespace in vault agentgate-platform; do
  kubectl delete pvc --all --namespace "${namespace}" --ignore-not-found --wait=true
done
kubectl delete namespace \
  hcp-terraform-agent \
  vault \
  spire-system \
  agentgate-platform \
  --ignore-not-found \
  --wait=true

remaining_pvs="$(kubectl get pv -o json | jq '[.items[] | select(.spec.csi.driver == "ebs.csi.aws.com")] | length')"
[[ "${remaining_pvs}" -eq 0 ]] ||
  die "${remaining_pvs} EBS-backed persistent volumes remain; do not destroy infra until they are removed"

destroy_root infra

infra_run_role_name="${AGENTGATE_INFRA_RUN_ROLE_ARN##*/}"
if aws iam get-role --role-name "${infra_run_role_name}" >/dev/null 2>&1; then
  aws iam list-attached-role-policies \
    --role-name "${infra_run_role_name}" \
    --output json |
    jq -r '.AttachedPolicies[].PolicyArn' |
    while read -r policy_arn; do
      aws iam detach-role-policy \
        --role-name "${infra_run_role_name}" \
        --policy-arn "${policy_arn}"
    done

  aws iam list-role-policies \
    --role-name "${infra_run_role_name}" \
    --output json |
    jq -r '.PolicyNames[]' |
    while read -r policy_name; do
      aws iam delete-role-policy \
        --role-name "${infra_run_role_name}" \
        --policy-name "${policy_name}"
    done

  aws iam delete-role --role-name "${infra_run_role_name}"
fi

if [[ "${AGENTGATE_HCP_OIDC_PROVIDER_OWNERSHIP}" == "dedicated" ]]; then
  if aws iam get-open-id-connect-provider \
    --open-id-connect-provider-arn "${AGENTGATE_HCP_AWS_OIDC_PROVIDER_ARN}" \
    >/dev/null 2>&1; then
    aws iam delete-open-id-connect-provider \
      --open-id-connect-provider-arn "${AGENTGATE_HCP_AWS_OIDC_PROVIDER_ARN}"
  fi
else
  note "Retaining explicitly shared HCP Terraform OIDC provider."
fi

tmp_dir="$(mktemp -d)"
trap 'rm -rf "${tmp_dir}"' EXIT
chmod 0700 "${tmp_dir}"
curl_config="${tmp_dir}/curl.conf"
{
  printf 'silent\n'
  printf 'show-error\n'
  printf 'header = "Authorization: Bearer %s"\n' "${TFC_TOKEN}"
  printf 'header = "Content-Type: application/vnd.api+json"\n'
} >"${curl_config}"
chmod 0600 "${curl_config}"

for workspace in agentgate-agentgate agentgate-platform agentgate-infra; do
  status="$(
    curl --config "${curl_config}" \
      --request DELETE \
      --output /dev/null \
      --write-out '%{http_code}' \
      "https://app.terraform.io/api/v2/organizations/${TF_CLOUD_ORGANIZATION}/workspaces/${workspace}"
  )"
  [[ "${status}" == "204" || "${status}" == "404" ]] ||
    die "failed to remove HCP Terraform workspace ${workspace}: HTTP ${status}"
done

if [[ -n "${HCP_TERRAFORM_AGENT_POOL_ID:-}" ]]; then
  status="$(
    curl --config "${curl_config}" \
      --request DELETE \
      --output /dev/null \
      --write-out '%{http_code}' \
      "https://app.terraform.io/api/v2/agent-pools/${HCP_TERRAFORM_AGENT_POOL_ID}"
  )"
  [[ "${status}" == "204" || "${status}" == "404" ]] ||
    die "failed to remove HCP Terraform agent pool: HTTP ${status}"
fi

note "Reverse destroy completed: agentgate, platform, infra, then HCP workspaces."
note "Review AWS Resource Groups/Tag Editor and billing for residual AgentGate-tagged resources."
