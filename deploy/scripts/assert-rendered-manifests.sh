#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck disable=SC1091
source "${SCRIPT_DIR}/lib/common.sh"

render_dir="${1:-}"
[[ -n "${render_dir}" ]] || die "usage: $0 RENDER_DIRECTORY"

spire_manifest="${render_dir}/spire.yaml"
vault_manifest="${render_dir}/vault.yaml"
postgresql_manifest="${render_dir}/postgresql.yaml"
vault_terraform="${DEPLOY_ROOT}/platform/vault.tf"
for manifest in "${spire_manifest}" "${vault_manifest}" "${postgresql_manifest}"; do
  [[ -s "${manifest}" ]] || die "rendered manifest is missing or empty: ${manifest}"
done

[[ "$(grep -c '^kind:' "${spire_manifest}")" -eq 48 ]] ||
  die "SPIRE render did not contain the reviewed 48 resources"
[[ "$(grep -c '^kind:' "${vault_manifest}")" -eq 10 ]] ||
  die "Vault render did not contain the reviewed 10 resources"
[[ "$(grep -c '^kind:' "${postgresql_manifest}")" -eq 6 ]] ||
  die "PostgreSQL render did not contain the reviewed 6 resources"

grep -q 'ghcr.io/spiffe/spire-agent:1.15.1' "${spire_manifest}" ||
  die "SPIRE agent image pin is missing"
grep -q 'ghcr.io/spiffe/spire-server:1.15.1' "${spire_manifest}" ||
  die "SPIRE server image pin is missing"
grep -q '"log_format": "json"' "${spire_manifest}" ||
  die "SPIRE JSON logging is not rendered"
grep -q 'runAsNonRoot: true' "${spire_manifest}" ||
  die "SPIRE non-root security context is not rendered"
grep -q 'k8s:sa:vault' "${spire_manifest}" ||
  die "exact Vault service-account selector is missing"

grep -q 'image: hashicorp/vault:2.0.3' "${vault_manifest}" ||
  die "Vault image pin is missing"
[[ "$(grep -c 'image: ghcr.io/spiffe/spiffe-helper@sha256:2759b3a699bb63b91cc5896f46cd6f70b9e3dfed9f7f4355a3a0a4e702984f9c' "${vault_manifest}")" -eq 2 ]] ||
  die "both Vault SPIFFE Helper containers must use the reviewed image digest"
grep -q 'name: helper-health' "${vault_manifest}" ||
  die "Vault SPIFFE Helper health endpoint is missing"
grep -q '/etc/spiffe-helper/helper-init.conf' "${vault_manifest}" ||
  die "Vault init container does not use its one-shot SPIFFE Helper configuration"

vault_helper_init_config="$(
  awk '
    /"helper-init.conf" = <<-HCL/ { capture = 1; next }
    capture && /^[[:space:]]*HCL$/ { exit }
    capture { print }
  ' "${vault_terraform}"
)"
if grep -Eq '(pid_file_name|renew_signal)' <<<"${vault_helper_init_config}"; then
  die "Vault one-shot SPIFFE Helper configuration contains daemon-only settings"
fi
grep -q 'pid_file_name = "/vault/tls/vault.pid"' "${vault_terraform}" ||
  die "Vault daemon SPIFFE Helper configuration does not signal the Vault PID"
grep -q 'kubernetes.io/metadata.name: agentgate-sandbox' "${vault_manifest}" ||
  die "Vault ingress does not include the exact runner namespace"
grep -q 'kubernetes.io/metadata.name: hcp-terraform-agent' "${vault_manifest}" ||
  die "Vault ingress does not include the HCP agent namespace"
[[ "$(grep -c -- '- name: home' "${vault_manifest}")" -eq 2 ]] ||
  die "Vault render has an unexpected duplicate or missing home volume/mount"
grep -q 'readOnlyRootFilesystem: true' "${vault_manifest}" ||
  die "Vault read-only root filesystem is not rendered"
grep -q 'readinessProbe:' "${vault_manifest}" ||
  die "Vault readiness probe is missing"
grep -q 'livenessProbe:' "${vault_manifest}" ||
  die "Vault liveness probe is missing"

grep -q 'registry-1.docker.io/bitnami/postgresql@sha256:db2312d9b243afa8c3b3f5496e478d17d0dff9791d06f3b93b9567abd86ae92f' \
  "${postgresql_manifest}" ||
  die "PostgreSQL image digest pin is missing"
grep -q 'readinessProbe:' "${postgresql_manifest}" ||
  die "PostgreSQL readiness probe is missing"
grep -q 'kind: NetworkPolicy' "${postgresql_manifest}" ||
  die "PostgreSQL network policy is missing"

if grep -Eq '(^|[[:space:]])(AWS_ACCESS_KEY_ID|AWS_SECRET_ACCESS_KEY|AWS_SESSION_TOKEN|VAULT_TOKEN):' \
  "${spire_manifest}" "${vault_manifest}" "${postgresql_manifest}"; then
  die "rendered manifests contain a prohibited credential environment variable"
fi
