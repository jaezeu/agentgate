#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck disable=SC1091
source "${SCRIPT_DIR}/lib/common.sh"

root="${1:-}"
[[ "${root}" == "bootstrap" || "${root}" == "infra" || "${root}" == "platform" || "${root}" == "agentgate" ]] ||
  die "usage: $0 <bootstrap|infra|platform|agentgate>"

require_command terraform
require_env AGENTGATE_STATE_BUCKET
require_env AGENTGATE_AWS_REGION

[[ "${AGENTGATE_STATE_BUCKET}" =~ ^[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]$ ]] ||
  die "AGENTGATE_STATE_BUCKET is not a valid S3 bucket name"

terraform -chdir="${DEPLOY_ROOT}/${root}" init \
  -input=false \
  -reconfigure \
  -backend-config="bucket=${AGENTGATE_STATE_BUCKET}" \
  -backend-config="region=${AGENTGATE_AWS_REGION}"

note "Initialized deploy/${root} against s3://${AGENTGATE_STATE_BUCKET}/${root}.tfstate"
