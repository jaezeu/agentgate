#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck disable=SC1091
source "${SCRIPT_DIR}/lib/common.sh"

for command_name in jq kubectl; do
  require_command "${command_name}"
done
verify_aws_identity
verify_kubernetes_context

namespace="agentgate-sandbox"
job_name="agentgate-demo-dispatcher"
grant_secret="agentgate-demo-grant"

job_json="$(kubectl get job "${job_name}" --namespace "${namespace}" -o json)" ||
  die "dispatcher Job is absent; apply deploy/agentgate first"

if [[ "$(jq -r '.status.succeeded // 0' <<<"${job_json}")" -gt 0 ]]; then
  die "dispatcher Job already completed; run terraform apply -replace=kubernetes_manifest.dispatcher_demo in deploy/agentgate before preparing another grant"
fi
if [[ "$(jq -r '.spec.suspend // false' <<<"${job_json}")" != "true" ]]; then
  die "dispatcher Job is not safely suspended; inspect it before retrying"
fi

kubectl patch job "${job_name}" \
  --namespace "${namespace}" \
  --type merge \
  --patch '{"spec":{"suspend":false}}' >/dev/null
kubectl wait job "${job_name}" \
  --namespace "${namespace}" \
  --for=condition=complete \
  --timeout=180s >/dev/null

tmp_dir="$(mktemp -d)"
trap 'rm -rf "${tmp_dir}"' EXIT
chmod 0700 "${tmp_dir}"
grant_file="${tmp_dir}/grant.json"
kubectl logs "job/${job_name}" --namespace "${namespace}" >"${grant_file}"
chmod 0600 "${grant_file}"

jq -e '
  type == "object" and
  (.request_id | type == "string" and length > 0) and
  (.signature | type == "string" and length > 0) and
  .vault_role == "terraform-sandbox" and
  .ttl > 0 and .ttl <= 900
' "${grant_file}" >/dev/null ||
  die "dispatcher output was not a valid bounded demo grant"

if grep -Eqi '(access[_-]?key|secret[_-]?key|session[_-]?token|vault[_-]?token)' "${grant_file}"; then
  die "dispatcher output unexpectedly contains a credential-shaped field"
fi

kubectl create secret generic "${grant_secret}" \
  --namespace "${namespace}" \
  --from-file="grant.json=${grant_file}" \
  --dry-run=client \
  -o yaml |
  kubectl apply -f - >/dev/null

request_id="$(jq -r '.request_id' "${grant_file}")"
note "Prepared signed demo grant for request_id ${request_id}."
note "The runner remains suspended for operator review. Follow docs/DEPLOY.md to release the governed Terraform plan."
