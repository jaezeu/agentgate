#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck disable=SC1091
source "${SCRIPT_DIR}/lib/common.sh"

for command_name in curl jq; do
  require_command "${command_name}"
done

require_env TFC_TOKEN
require_env TF_CLOUD_ORGANIZATION
require_env AGENTGATE_INFRA_RUN_ROLE_ARN
require_env AGENTGATE_HCP_AWS_OIDC_PROVIDER_ARN
require_env AGENTGATE_EKS_PUBLIC_ACCESS_CIDRS

[[ "${TF_CLOUD_ORGANIZATION}" =~ ^[A-Za-z0-9][A-Za-z0-9_-]{2,39}$ ]] ||
  die "TF_CLOUD_ORGANIZATION contains unsupported characters"
[[ "${AGENTGATE_INFRA_RUN_ROLE_ARN}" =~ ^arn:[^:]+:iam::[0-9]{12}:role/.+ ]] ||
  die "AGENTGATE_INFRA_RUN_ROLE_ARN must be an IAM role ARN"
[[ "${AGENTGATE_HCP_AWS_OIDC_PROVIDER_ARN}" =~ ^arn:[^:]+:iam::[0-9]{12}:oidc-provider/app\.terraform\.io$ ]] ||
  die "AGENTGATE_HCP_AWS_OIDC_PROVIDER_ARN must identify app.terraform.io"

jq -e '
  type == "array" and
  length > 0 and
  all(.[]; type == "string" and test("^[0-9./]+$") and . != "0.0.0.0/0")
' <<<"${AGENTGATE_EKS_PUBLIC_ACCESS_CIDRS}" >/dev/null ||
  die "AGENTGATE_EKS_PUBLIC_ACCESS_CIDRS must be a JSON array of narrow IPv4 CIDRs"

project_name="${HCP_TERRAFORM_PROJECT:-AgentGate Sandbox}"
api_base="https://app.terraform.io/api/v2"
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

api_request() {
  local method="$1"
  local path="$2"
  local body_file="${3:-}"
  local response_file="${tmp_dir}/response.json"
  local status
  local -a arguments

  arguments=(
    --config "${curl_config}"
    --request "${method}"
    --output "${response_file}"
    --write-out '%{http_code}'
  )
  if [[ -n "${body_file}" ]]; then
    arguments+=(--data-binary "@${body_file}")
  fi
  arguments+=("${api_base}${path}")

  status="$(curl "${arguments[@]}")"
  if [[ "${status}" == "404" ]]; then
    return 4
  fi
  [[ "${status}" =~ ^2[0-9][0-9]$ ]] ||
    die "HCP Terraform API ${method} ${path} failed with HTTP ${status}"
  cat "${response_file}"
}

payload_file="${tmp_dir}/payload.json"
projects_response="$(api_request GET "/organizations/${TF_CLOUD_ORGANIZATION}/projects?page%5Bsize%5D=100")"
project_id="$(
  jq -r --arg name "${project_name}" \
    '.data[] | select(.attributes.name == $name) | .id' <<<"${projects_response}" |
    head -n 1
)"
if [[ -z "${project_id}" ]]; then
  jq -n --arg name "${project_name}" '{
    data: {
      type: "projects",
      attributes: {name: $name}
    }
  }' >"${payload_file}"
  project_id="$(api_request POST "/organizations/${TF_CLOUD_ORGANIZATION}/projects" "${payload_file}" | jq -r '.data.id')"
  note "Created HCP Terraform project ${project_name}."
else
  note "HCP Terraform project ${project_name} already exists."
fi

workspace_id() {
  local name="$1"
  local response status
  if response="$(api_request GET "/organizations/${TF_CLOUD_ORGANIZATION}/workspaces/${name}")"; then
    jq -r '.data.id' <<<"${response}"
    return
  else
    status="$?"
  fi
  [[ "${status}" -eq 4 ]] || die "failed to inspect workspace ${name}"

  jq -n \
    --arg name "${name}" \
    --arg project_id "${project_id}" \
    '{
      data: {
        type: "workspaces",
        attributes: {
          name: $name,
          "auto-apply": false,
          "execution-mode": "remote",
          "terraform-version": "1.15.6"
        },
        relationships: {
          project: {
            data: {type: "projects", id: $project_id}
          }
        }
      }
    }' >"${payload_file}"
  api_request POST "/organizations/${TF_CLOUD_ORGANIZATION}/workspaces" "${payload_file}" |
    jq -r '.data.id'
}

upsert_variable() {
  local workspace_id_value="$1"
  local key="$2"
  local value="$3"
  local category="$4"
  local hcl="$5"
  local variables_response variable_id

  variables_response="$(api_request GET "/workspaces/${workspace_id_value}/vars")"
  variable_id="$(
    jq -r \
      --arg key "${key}" \
      --arg category "${category}" \
      '.data[] | select(.attributes.key == $key and .attributes.category == $category) | .id' \
      <<<"${variables_response}" |
      head -n 1
  )"

  jq -n \
    --arg key "${key}" \
    --arg value "${value}" \
    --arg category "${category}" \
    --argjson hcl "${hcl}" \
    '{
      data: {
        type: "vars",
        attributes: {
          key: $key,
          value: $value,
          category: $category,
          hcl: $hcl,
          sensitive: false
        }
      }
    }' >"${payload_file}"

  if [[ -n "${variable_id}" ]]; then
      jq --arg id "${variable_id}" '.data.id = $id' \
        "${payload_file}" >"${payload_file}.update"
      mv "${payload_file}.update" "${payload_file}"
      api_request PATCH "/vars/${variable_id}" "${payload_file}" >/dev/null
    else
    api_request POST "/workspaces/${workspace_id_value}/vars" "${payload_file}" >/dev/null
  fi
}

configure_agent_execution() {
  local workspace_id_value="$1"
  local agent_pool_id="$2"

  jq -n --arg pool_id "${agent_pool_id}" '{
    data: {
      type: "workspaces",
      attributes: {
        "execution-mode": "agent",
        "agent-pool-id": $pool_id
      }
    }
  }' >"${payload_file}"
  api_request PATCH "/workspaces/${workspace_id_value}" "${payload_file}" >/dev/null
}

replace_remote_state_consumers() {
  local producer_workspace_id="$1"
  shift
  local consumer_id
  local payload='{"data":[]}'

  for consumer_id in "$@"; do
    payload="$(
      jq \
        --arg id "${consumer_id}" \
        '.data += [{type: "workspaces", id: $id}]' \
        <<<"${payload}"
    )"
  done
  printf '%s\n' "${payload}" >"${payload_file}"
  api_request PATCH \
    "/workspaces/${producer_workspace_id}/relationships/remote-state-consumers" \
    "${payload_file}" >/dev/null
}

infra_workspace_id="$(workspace_id "agentgate-infra")"
platform_workspace_id="$(workspace_id "agentgate-platform")"
agentgate_workspace_id="$(workspace_id "agentgate-agentgate")"

replace_remote_state_consumers \
  "${infra_workspace_id}" \
  "${platform_workspace_id}" \
  "${agentgate_workspace_id}"
replace_remote_state_consumers \
  "${platform_workspace_id}" \
  "${agentgate_workspace_id}"

for workspace in "${infra_workspace_id}" "${platform_workspace_id}" "${agentgate_workspace_id}"; do
  upsert_variable "${workspace}" "TF_VAR_hcp_terraform_organization" "${TF_CLOUD_ORGANIZATION}" "env" "false"
  upsert_variable "${workspace}" "TFC_AWS_PROVIDER_AUTH" "true" "env" "false"
done

upsert_variable "${infra_workspace_id}" "TFC_AWS_RUN_ROLE_ARN" "${AGENTGATE_INFRA_RUN_ROLE_ARN}" "env" "false"
upsert_variable "${infra_workspace_id}" "TF_VAR_hcp_aws_oidc_provider_arn" "${AGENTGATE_HCP_AWS_OIDC_PROVIDER_ARN}" "env" "false"
upsert_variable "${infra_workspace_id}" "TF_VAR_cluster_endpoint_public_access_cidrs" "${AGENTGATE_EKS_PUBLIC_ACCESS_CIDRS}" "env" "false"

if [[ -n "${AGENTGATE_OPERATOR_PRINCIPAL_ARNS:-}" ]]; then
  jq -e 'type == "array" and all(.[]; type == "string")' \
    <<<"${AGENTGATE_OPERATOR_PRINCIPAL_ARNS}" >/dev/null ||
    die "AGENTGATE_OPERATOR_PRINCIPAL_ARNS must be a JSON array"
  upsert_variable "${infra_workspace_id}" \
    "TF_VAR_operator_access_principal_arns" \
    "${AGENTGATE_OPERATOR_PRINCIPAL_ARNS}" \
    "env" \
    "false"
fi

if [[ -n "${AGENTGATE_PLATFORM_RUN_ROLE_ARN:-}" ]]; then
  upsert_variable "${platform_workspace_id}" \
    "TFC_AWS_RUN_ROLE_ARN" \
    "${AGENTGATE_PLATFORM_RUN_ROLE_ARN}" \
    "env" \
    "false"
fi

if [[ -n "${AGENTGATE_AGENTGATE_RUN_ROLE_ARN:-}" ]]; then
  upsert_variable "${agentgate_workspace_id}" \
    "TFC_AWS_RUN_ROLE_ARN" \
    "${AGENTGATE_AGENTGATE_RUN_ROLE_ARN}" \
    "env" \
    "false"
fi

if [[ -n "${AGENTGATE_APPLICATION_IMAGE:-}" ]]; then
  require_digest_reference "${AGENTGATE_APPLICATION_IMAGE}"
  upsert_variable "${agentgate_workspace_id}" \
    "TF_VAR_application_image" \
    "${AGENTGATE_APPLICATION_IMAGE}" \
    "env" \
    "false"
fi

if [[ -n "${HCP_TERRAFORM_AGENT_POOL_ID:-}" ]]; then
  configure_agent_execution "${platform_workspace_id}" "${HCP_TERRAFORM_AGENT_POOL_ID}"
  configure_agent_execution "${agentgate_workspace_id}" "${HCP_TERRAFORM_AGENT_POOL_ID}"
fi

if [[ "${AGENTGATE_ENABLE_HCP_VAULT_AUTH:-no}" == "yes" ]]; then
  require_env AGENTGATE_VAULT_CA_CERT_BASE64
  upsert_variable "${platform_workspace_id}" "TFC_VAULT_PROVIDER_AUTH" "true" "env" "false"
  upsert_variable "${platform_workspace_id}" "TFC_VAULT_ADDR" "https://vault.vault.svc.cluster.local:8200" "env" "false"
  upsert_variable "${platform_workspace_id}" "TFC_VAULT_RUN_ROLE" "hcp-terraform-platform" "env" "false"
  upsert_variable "${platform_workspace_id}" "TFC_VAULT_AUTH_PATH" "jwt-hcp-terraform" "env" "false"
  upsert_variable "${platform_workspace_id}" "TFC_VAULT_WORKLOAD_IDENTITY_AUDIENCE" "vault.workload.identity" "env" "false"
  upsert_variable "${platform_workspace_id}" "TFC_VAULT_ENCODED_CACERT" "${AGENTGATE_VAULT_CA_CERT_BASE64}" "env" "false"
  upsert_variable "${platform_workspace_id}" "TF_VAR_vault_configuration_enabled" "true" "env" "false"
fi

note "HCP Terraform workspaces and non-secret dynamic credential references are configured."
note "Re-run this script after infra apply with downstream role ARNs and after Vault bootstrap with AGENTGATE_ENABLE_HCP_VAULT_AUTH=yes."
