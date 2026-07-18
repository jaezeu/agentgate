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

  # Only these exact environment subjects may assume the deployer role.
  github_subjects = [
    "${var.github_repository}:environment:${var.github_plan_environment}",
    "${var.github_repository}:environment:${var.github_apply_environment}",
  ]
}

module "github_oidc" {
  source  = "terraform-module/github-oidc-provider/aws"
  version = "~> 2.2"

  create_oidc_provider = var.create_github_oidc_provider
  oidc_provider_arn    = var.create_github_oidc_provider ? null : var.existing_github_oidc_provider_arn

  repositories = local.github_subjects

  role_name            = "${var.name_prefix}-deployer"
  role_description     = "GitHub Actions deployment role for the disposable AgentGate sandbox account."
  max_session_duration = 3600

  # Broad policy is acceptable only in this dedicated disposable account;
  # production splits plan/apply roles behind a permission boundary (ADR-0001).
  oidc_role_attach_policies = [
    "arn:${data.aws_partition.current.partition}:iam::aws:policy/AdministratorAccess",
  ]

  tags = local.common_tags
}
