provider "aws" {
  region = var.aws_region

  default_tags {
    tags = local.common_tags
  }
}

data "aws_caller_identity" "current" {}

data "aws_partition" "current" {}

locals {
  common_tags = merge(
    {
      Application = "AgentGate"
      Environment = "sandbox"
      ManagedBy   = "Terraform"
      Owner       = "AgentGate"
      CostCenter  = "sandbox"
    },
    var.additional_tags,
  )

  state_bucket_name = "${var.name_prefix}-${data.aws_caller_identity.current.account_id}-${var.aws_region}-tfstate"

  github_oidc_host = "token.actions.githubusercontent.com"

  # Only these exact GitHub Actions environment subjects may assume the
  # deployer role. Pushes, pull requests, and other repositories cannot.
  github_subjects = [
    "repo:${var.github_repository}:environment:${var.github_plan_environment}",
    "repo:${var.github_repository}:environment:${var.github_apply_environment}",
  ]

  github_oidc_provider_arn = (
    var.create_github_oidc_provider ?
    aws_iam_openid_connect_provider.github[0].arn :
    var.existing_github_oidc_provider_arn
  )
}

module "state_key" {
  source  = "terraform-aws-modules/kms/aws"
  version = "~> 4.2"

  description             = "Encrypts AgentGate sandbox Terraform state objects."
  enable_key_rotation     = true
  deletion_window_in_days = 7

  aliases = ["${var.name_prefix}-tfstate"]
}

module "state_bucket" {
  source  = "terraform-aws-modules/s3-bucket/aws"
  version = "~> 5.14"

  bucket = local.state_bucket_name

  # Recoverable, encrypted, private, TLS-only. Public access block arguments
  # default to true in this module and stay explicit here as documentation.
  versioning = {
    enabled = true
  }

  server_side_encryption_configuration = {
    rule = {
      bucket_key_enabled = true
      apply_server_side_encryption_by_default = {
        sse_algorithm     = "aws:kms"
        kms_master_key_id = module.state_key.key_arn
      }
    }
  }

  attach_deny_insecure_transport_policy = true

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true

  lifecycle_rule = [
    {
      id      = "expire-noncurrent-state-versions"
      enabled = true
      filter  = {}
      noncurrent_version_expiration = {
        days = var.state_noncurrent_version_retention_days
      }
    }
  ]
}

# The GitHub OIDC trust below is the security boundary of the whole
# deployment model, so it stays as explicit resources rather than a module:
# every claim condition is reviewable in place.

resource "aws_iam_openid_connect_provider" "github" {
  count = var.create_github_oidc_provider ? 1 : 0

  url            = "https://${local.github_oidc_host}"
  client_id_list = ["sts.amazonaws.com"]

  # AWS validates GitHub's certificate chain against trusted root CAs and
  # ignores these values for this issuer; the argument remains required.
  thumbprint_list = [
    "6938fd4d98bab03faadb97b34396831e3780aea1",
    "1c58a3a8518e8759bf075b76b750d4f2df264fcd",
  ]
}

data "aws_iam_policy_document" "deployer_assume" {
  statement {
    actions = ["sts:AssumeRoleWithWebIdentity"]
    effect  = "Allow"

    principals {
      type        = "Federated"
      identifiers = [local.github_oidc_provider_arn]
    }

    condition {
      test     = "StringEquals"
      variable = "${local.github_oidc_host}:aud"
      values   = ["sts.amazonaws.com"]
    }

    condition {
      test     = "StringEquals"
      variable = "${local.github_oidc_host}:sub"
      values   = local.github_subjects
    }
  }
}

resource "aws_iam_role" "deployer" {
  name                 = "${var.name_prefix}-deployer"
  description          = "GitHub Actions deployment role for the disposable AgentGate sandbox account."
  assume_role_policy   = data.aws_iam_policy_document.deployer_assume.json
  max_session_duration = 3600
}

# Sandbox-account scope: this reference deploys a VPC, EKS, IAM, KMS, and S3
# from a dedicated disposable account, so the deployer keeps the reviewed
# broad policy the same way an operator bootstrap role would. Splitting a
# read-only plan role from the apply role and replacing AdministratorAccess
# with a permission boundary are the first production hardening steps; see
# docs/adr/0001-deployment-control-plane.md.
resource "aws_iam_role_policy_attachment" "deployer_administrator" {
  role       = aws_iam_role.deployer.name
  policy_arn = "arn:${data.aws_partition.current.partition}:iam::aws:policy/AdministratorAccess"
}
