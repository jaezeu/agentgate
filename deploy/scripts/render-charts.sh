#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck disable=SC1091
source "${SCRIPT_DIR}/lib/common.sh"

require_command helm

output_dir="${1:-}"
[[ -n "${output_dir}" ]] || die "usage: $0 OUTPUT_DIRECTORY"
mkdir -p "${output_dir}"

helm_home="$(mktemp -d)"
trap 'rm -rf "${helm_home}"' EXIT
export HELM_CONFIG_HOME="${helm_home}/config"
export HELM_CACHE_HOME="${helm_home}/cache"
export HELM_DATA_HOME="${helm_home}/data"
chart_dir="${helm_home}/charts"
mkdir -p "${HELM_CONFIG_HOME}" "${HELM_CACHE_HOME}" "${HELM_DATA_HOME}" "${chart_dir}"

helm repo add spiffe https://spiffe.github.io/helm-charts-hardened >/dev/null
helm repo add hashicorp https://helm.releases.hashicorp.com >/dev/null
helm repo update >/dev/null

helm pull spiffe/spire --version 0.29.0 --destination "${chart_dir}"
helm pull hashicorp/vault --version 0.34.0 --destination "${chart_dir}"
postgresql_pull="$(
  helm pull oci://registry-1.docker.io/bitnamicharts/postgresql \
    --version 18.8.0 \
    --destination "${chart_dir}" 2>&1
)"
grep -q 'Digest: sha256:43f4d74fff2c12b93b542f10ff52c5f89d0de5ad64473cf88964cdfb76f5dc8c' \
  <<<"${postgresql_pull}" ||
  die "PostgreSQL OCI chart manifest digest does not match the reviewed pin"

[[ "$(sha256_file "${chart_dir}/spire-0.29.0.tgz")" == "b73205c87c5edfdaa5dcb6d6de16685950e02a5b8f843cdc6e101d127ef7a7be" ]] ||
  die "SPIRE chart archive digest does not match the reviewed pin"
[[ "$(sha256_file "${chart_dir}/vault-0.34.0.tgz")" == "a716f4fa8bb80e450ce7c0f9de7b475183c47437a162eee744cd40bf991244e9" ]] ||
  die "Vault chart archive digest does not match the reviewed pin"
[[ "$(sha256_file "${chart_dir}/postgresql-18.8.0.tgz")" == "fe14c233d3544f04a6d20831896273984e7ead129404f5205890deeebe5f18d9" ]] ||
  die "PostgreSQL chart archive digest does not match the reviewed pin"

helm template spire "${chart_dir}/spire-0.29.0.tgz" \
  --namespace spire-system \
  --include-crds \
  --values "${DEPLOY_ROOT}/platform/helm-values/spire.yaml" \
  >"${output_dir}/spire.yaml"

# Render the Terraform values template with the same placeholder identifiers
# the platform root injects at apply time.
vault_values="$(mktemp)"
# The patterns match literal templatefile placeholders.
# shellcheck disable=SC2016
sed \
  -e 's/\${aws_region}/ap-southeast-1/g' \
  -e 's|\${unseal_kms_key_arn}|arn:aws:kms:ap-southeast-1:111122223333:key/00000000-0000-0000-0000-000000000000|g' \
  "${DEPLOY_ROOT}/platform/helm-values/vault.yaml.tftpl" >"${vault_values}"

helm template vault "${chart_dir}/vault-0.34.0.tgz" \
  --namespace vault \
  --values "${vault_values}" \
  --set-string 'server.serviceAccount.annotations.eks\.amazonaws\.com/role-arn=arn:aws:iam::111122223333:role/agentgate-sandbox-vault-broker' \
  >"${output_dir}/vault.yaml"
rm -f "${vault_values}"

helm template agentgate-postgresql "${chart_dir}/postgresql-18.8.0.tgz" \
  --namespace agentgate-platform \
  --values "${DEPLOY_ROOT}/platform/helm-values/postgresql.yaml" \
  >"${output_dir}/postgresql.yaml"

"${SCRIPT_DIR}/assert-rendered-manifests.sh" "${output_dir}"
note "Rendered chart manifests passed static assertions in ${output_dir}."
