#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck disable=SC1091
source "${SCRIPT_DIR}/lib/common.sh"

for command_name in jq vault; do
  require_command "${command_name}"
done

require_env VAULT_ADDR
require_env VAULT_CACERT
require_env VAULT_TOKEN_FILE
[[ "${VAULT_ADDR}" == https://* ]] || die "VAULT_ADDR must use HTTPS"
assert_file_mode_private "${VAULT_TOKEN_FILE}"
[[ -f "${VAULT_CACERT}" ]] || die "VAULT_CACERT does not exist: ${VAULT_CACERT}"

# Optional CI trust: when the GitHub repository is provided, Vault also
# trusts the repository's exact deploy environments through GitHub's OIDC
# issuer so the deploy workflow can run the platform configuration pass
# without any stored Vault token.
github_repository="${AGENTGATE_GITHUB_REPOSITORY:-}"
plan_environment="${AGENTGATE_GITHUB_PLAN_ENVIRONMENT:-sandbox-plan}"
apply_environment="${AGENTGATE_GITHUB_APPLY_ENVIRONMENT:-sandbox}"
if [[ -n "${github_repository}" ]]; then
  [[ "${github_repository}" =~ ^[A-Za-z0-9][A-Za-z0-9._-]*/[A-Za-z0-9._-]+$ ]] ||
    die "AGENTGATE_GITHUB_REPOSITORY must be an owner/name repository slug"
fi

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
  die "Vault is sealed; check the KMS auto-unseal (IRSA role and key access) before configuring deployment trust"
fi

VAULT_TOKEN="$(<"${VAULT_TOKEN_FILE}")"
export VAULT_TOKEN

policy_file="${tmp_dir}/terraform-platform.hcl"
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

vault policy write terraform-platform "${policy_file}" >/dev/null
note "Vault policy terraform-platform manages only platform configuration paths."

if [[ -n "${github_repository}" ]]; then
  if ! vault auth list -format=json |
    jq -e 'has("jwt-deployer/")' >/dev/null; then
    vault auth enable -path=jwt-deployer jwt >/dev/null
  fi

  vault write auth/jwt-deployer/config \
    oidc_discovery_url="https://token.actions.githubusercontent.com" \
    bound_issuer="https://token.actions.githubusercontent.com" >/dev/null

  role_file="${tmp_dir}/terraform-platform.json"
  jq -n \
    --arg plan_subject "repo:${github_repository}:environment:${plan_environment}" \
    --arg apply_subject "repo:${github_repository}:environment:${apply_environment}" \
    '{
      role_type: "jwt",
      policies: ["terraform-platform"],
      bound_audiences: ["agentgate-vault"],
      bound_claims_type: "string",
      bound_claims: {sub: [$plan_subject, $apply_subject]},
      user_claim: "sub",
      token_ttl: "15m",
      token_max_ttl: "30m",
      token_no_default_policy: true
    }' >"${role_file}"
  chmod 0600 "${role_file}"

  vault write auth/jwt-deployer/role/terraform-platform \
    "@${role_file}" >/dev/null

  note "Vault now trusts only the ${github_repository} ${plan_environment}/${apply_environment} GitHub environments."
else
  note "AGENTGATE_GITHUB_REPOSITORY is unset; skipped GitHub OIDC trust. Local applies mint a scoped token instead."
fi

unset VAULT_TOKEN
note "Mint a local scoped token with: vault token create -policy=terraform-platform -ttl=30m -orphan"
note "Apply the platform configuration pass and retire the initial root token per docs/DEPLOY.md."
