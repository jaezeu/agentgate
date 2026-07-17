#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck disable=SC1091
source "${SCRIPT_DIR}/lib/common.sh"

mode="${1:---local}"
[[ "${mode}" == "--local" || "${mode}" == "--cluster" ]] ||
  die "usage: $0 [--local|--cluster]"

for command_name in aws curl helm jq kubectl openssl shellcheck terraform; do
  require_command "${command_name}"
done

terraform_version="$(terraform version -json | jq -r '.terraform_version')"
[[ "${terraform_version}" == "1.15.6" ]] ||
  die "Terraform 1.15.6 is required; found ${terraform_version}"

helm_version="$(helm version --template '{{.Version}}')"
[[ "${helm_version}" =~ ^v(3|4)\. ]] ||
  die "Helm 3.x or 4.x is required; found ${helm_version}"

kubectl_version="$(kubectl version --client -o json | jq -r '.clientVersion.gitVersion')"
[[ "${kubectl_version}" =~ ^v1\.36\. ]] ||
  die "kubectl 1.36.x is required; found ${kubectl_version}"

aws_version="$(aws --version 2>&1)"
[[ "${aws_version}" == aws-cli/2.* ]] ||
  die "AWS CLI v2 is required; found ${aws_version%% *}"

require_env TF_CLOUD_ORGANIZATION
require_env AGENTGATE_AWS_ACCOUNT_ID
require_env AGENTGATE_AWS_REGION
require_env AGENTGATE_ACKNOWLEDGE_COSTS
[[ "${AGENTGATE_ACKNOWLEDGE_COSTS}" == "yes" ]] ||
  die "set AGENTGATE_ACKNOWLEDGE_COSTS=yes after reviewing the cost warning in docs/DEPLOY.md"

if [[ -n "${AWS_ACCESS_KEY_ID:-}" || -n "${AWS_SECRET_ACCESS_KEY:-}" || -n "${AWS_SESSION_TOKEN:-}" ]]; then
  die "static or exported AWS credential variables are prohibited; use AWS SSO locally and HCP dynamic provider credentials for runs"
fi

verify_aws_identity

if [[ "${mode}" == "--cluster" ]]; then
  verify_kubernetes_context
fi

if grep -RInE \
  '(AKIA[0-9A-Z]{16}|ASIA[0-9A-Z]{16}|aws_access_key_id|aws_secret_access_key)' \
  "${DEPLOY_ROOT}/infra" \
  "${DEPLOY_ROOT}/platform" \
  "${DEPLOY_ROOT}/agentgate" \
  --exclude-dir=.terraform \
  --exclude='*.lock.hcl' >/dev/null; then
  die "deployment tree contains a static AWS credential pattern"
fi

note "Preflight passed without static AWS credential environment variables."
