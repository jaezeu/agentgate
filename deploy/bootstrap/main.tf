provider "aws" {
  region = var.aws_region

  default_tags {
    tags = local.common_tags
  }
}

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
}

module "github_oidc" {
  source  = "terraform-module/github-oidc-provider/aws"
  version = "~> 2.2"

  create_oidc_provider = var.create_github_oidc_provider
  oidc_provider_arn    = var.create_github_oidc_provider ? null : var.existing_github_oidc_provider_arn

  # No trailing subject, so the module binds repo:<owner>/<repo>:* (any ref
  # or workflow in this repository), independent of GitHub environments.
  repositories = [var.github_repository]

  role_name            = "${var.name_prefix}-deployer"
  role_description     = "GitHub Actions deployment role for the disposable AgentGate sandbox account."
  max_session_duration = 3600

  # Any GitHub Actions run in this repository may assume the deployer role
  # (subject repo:<owner>/<repo>:*). Broad trust and broad policy are
  # acceptable only in this dedicated disposable account; production scopes
  # both behind a permission boundary (ADR-0001).
  oidc_role_attach_policies = [
    "arn:${data.aws_partition.current.partition}:iam::aws:policy/AdministratorAccess",
  ]

  tags = local.common_tags
}

# Registry for the application image the deploy workflow builds and pushes.
# Tags are immutable; layer 3 consumes the image by digest only.
resource "aws_ecr_repository" "application" {
  name                 = "${var.name_prefix}/agentgate"
  image_tag_mutability = "IMMUTABLE"
  force_delete         = true

  image_scanning_configuration {
    scan_on_push = true
  }

  encryption_configuration {
    encryption_type = "AES256"
  }

  tags = local.common_tags
}
