#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck disable=SC1091
source "${SCRIPT_DIR}/lib/common.sh"

for command_name in jq vault; do
  require_command "${command_name}"
done

require_env TF_CLOUD_ORGANIZATION
require_env VAULT_ADDR
require_env VAULT_CACERT
require_env VAULT_TOKEN_FILE
[[ "${VAULT_ADDR}" == https://* ]] || die "VAULT_ADDR must use HTTPS"
assert_file_mode_private "${VAULT_TOKEN_FILE}"
[[ -f "${VAULT_CACERT}" ]] || die "VAULT_CACERT does not exist: ${VAULT_CACERT}"

project_name="${HCP_TERRAFORM_PROJECT:-AgentGate Sandbox}"
workspace_name="agentgate-platform"

vault_status_file="$(mktemp)"
tmp_dir="$(mktemp -d)"
trap 'unset VAULT_TOKEN; rm -f "${vault_status_file}"; rm -rf "${tmp_dir}"' EXIT
chmod 0600 "${vault_status_file}"
chmod 0700 "${tmp_dir}"

set +e
vault status -format=json >"${vault_status_file}" 2>/dev/null
vault_status_code="$?"
set -e

if [[ "${vault_status_code}" -ne 0 && "${vault_status_code}" -ne 2 ]]; then
  die "cannot reach Vault; verify the TLS port-forward and VAULT_TLS_SERVER_NAME"
fi
if [[ "$(jq -r '.initialized' "${vault_status_file}")" != "true" ]]; then
  die "Vault is not initialized; follow the manual initialization boundary in docs/DEPLOY.md"
fi
if [[ "$(jq -r '.sealed' "${vault_status_file}")" != "false" ]]; then
  die "Vault is sealed; unseal it manually before configuring HCP dynamic credentials"
fi

VAULT_TOKEN="$(<"${VAULT_TOKEN_FILE}")"
export VAULT_TOKEN

policy_file="${tmp_dir}/hcp-terraform-platform.hcl"
cat >"${policy_file}" <<'HCL'
path "auth/token/lookup-self" {
  capabilities = ["read"]
}

path "auth/token/renew-self" {
  capabilities = ["update"]
}

path "auth/token/revoke-self" {
  capabilities = ["update"]
}

path "sys/audit" {
  capabilities = ["read", "sudo"]
}

path "sys/audit/*" {
  capabilities = ["create", "read", "update", "delete", "sudo"]
}

path "sys/auth" {
  capabilities = ["read", "sudo"]
}

path "sys/auth/spire-jwt" {
  capabilities = ["create", "read", "update", "delete", "sudo"]
}

path "sys/auth/spire-jwt/*" {
  capabilities = ["create", "read", "update", "delete", "sudo"]
}

path "auth/spire-jwt/config" {
  capabilities = ["create", "read", "update", "delete"]
}

path "auth/spire-jwt/role/agentgate-manager" {
  capabilities = ["create", "read", "update", "delete"]
}

path "sys/mounts" {
  capabilities = ["read", "sudo"]
}

path "sys/mounts/aws" {
  capabilities = ["create", "read", "update", "delete", "sudo"]
}

path "sys/mounts/aws/*" {
  capabilities = ["create", "read", "update", "delete", "sudo"]
}

path "aws/config/root" {
  capabilities = ["create", "read", "update", "delete"]
}

path "aws/roles/terraform-sandbox" {
  capabilities = ["create", "read", "update", "delete"]
}

path "sys/policies/acl/agentgate-management" {
  capabilities = ["create", "read", "update", "delete"]
}
HCL
chmod 0600 "${policy_file}"

if grep -q 'aws/creds/' "${policy_file}"; then
  die "bootstrap policy must not contain an AWS credential read path"
fi

vault policy write hcp-terraform-platform "${policy_file}" >/dev/null

if ! vault auth list -format=json |
  jq -e 'has("jwt-hcp-terraform/")' >/dev/null; then
  vault auth enable -path=jwt-hcp-terraform jwt >/dev/null
fi

vault write auth/jwt-hcp-terraform/config \
  oidc_discovery_url="https://app.terraform.io" \
  bound_issuer="https://app.terraform.io" >/dev/null

role_file="${tmp_dir}/hcp-terraform-platform.json"
jq -n \
  --arg subject "organization:${TF_CLOUD_ORGANIZATION}:project:${project_name}:workspace:${workspace_name}:run_phase:*" \
  '{
    role_type: "jwt",
    policies: ["hcp-terraform-platform"],
    bound_audiences: ["vault.workload.identity"],
    bound_claims_type: "glob",
    bound_claims: {sub: $subject},
    user_claim: "terraform_full_workspace",
    token_ttl: "15m",
    token_max_ttl: "30m",
    token_no_default_policy: true
  }' >"${role_file}"
chmod 0600 "${role_file}"

vault write auth/jwt-hcp-terraform/role/hcp-terraform-platform \
  "@${role_file}" >/dev/null

unset VAULT_TOKEN
note "Vault now trusts only the exact HCP Terraform platform workspace subject."
note "Enable HCP Vault workspace variables, apply platform configuration, and retire the initial root token per docs/DEPLOY.md."
