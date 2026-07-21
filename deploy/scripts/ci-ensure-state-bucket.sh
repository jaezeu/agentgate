#!/usr/bin/env bash
set -euo pipefail

# Idempotently ensures the Terraform state bucket exists with versioning,
# encryption, and public access blocked. Runs as the first step of the
# bootstrap stage so a completely fresh account needs no manual preparation.

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck disable=SC1091
source "${SCRIPT_DIR}/lib/common.sh"

require_command aws
require_env AGENTGATE_STATE_BUCKET
require_env AGENTGATE_AWS_REGION

bucket="${AGENTGATE_STATE_BUCKET}"
region="${AGENTGATE_AWS_REGION}"

[[ "${bucket}" =~ ^[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]$ ]] ||
  die "AGENTGATE_STATE_BUCKET is not a valid S3 bucket name"

if aws s3api head-bucket --bucket "${bucket}" 2>/dev/null; then
  note "State bucket s3://${bucket} already exists."
  exit 0
fi

if [[ "${region}" == "us-east-1" ]]; then
  aws s3api create-bucket --bucket "${bucket}" --region "${region}"
else
  aws s3api create-bucket \
    --bucket "${bucket}" \
    --region "${region}" \
    --create-bucket-configuration "LocationConstraint=${region}"
fi

aws s3api put-bucket-versioning \
  --bucket "${bucket}" \
  --versioning-configuration Status=Enabled
aws s3api put-bucket-encryption \
  --bucket "${bucket}" \
  --server-side-encryption-configuration \
  '{"Rules":[{"ApplyServerSideEncryptionByDefault":{"SSEAlgorithm":"aws:kms"},"BucketKeyEnabled":true}]}'
aws s3api put-public-access-block \
  --bucket "${bucket}" \
  --public-access-block-configuration \
  'BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true'

note "Created state bucket s3://${bucket} (versioned, encrypted, private)."
