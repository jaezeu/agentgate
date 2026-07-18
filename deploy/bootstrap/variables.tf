variable "aws_region" {
  description = "AWS region for the sandbox and its pre-provisioned state bucket."
  type        = string
  default     = "ap-southeast-1"

  validation {
    condition     = can(regex("^[a-z]{2}(-gov)?-[a-z]+-[0-9]+$", var.aws_region))
    error_message = "aws_region must be a valid AWS region name."
  }
}

variable "name_prefix" {
  description = "Prefix used for all sandbox resources."
  type        = string
  default     = "agentgate-sandbox"

  validation {
    condition     = can(regex("^[a-z][a-z0-9-]{2,19}$", var.name_prefix))
    error_message = "name_prefix must be 3-20 lowercase alphanumeric or hyphen characters and start with a letter."
  }
}

variable "github_repository" {
  description = "GitHub repository (owner/name) whose Actions workflows may assume the deployer role."
  type        = string

  validation {
    condition     = can(regex("^[A-Za-z0-9][A-Za-z0-9._-]*/[A-Za-z0-9._-]+$", var.github_repository))
    error_message = "github_repository must be an owner/name GitHub repository slug."
  }
}

variable "github_plan_environment" {
  description = "GitHub Actions environment allowed to run read-only plans."
  type        = string
  default     = "sandbox-plan"

  validation {
    condition     = can(regex("^[A-Za-z0-9._-]+$", var.github_plan_environment))
    error_message = "github_plan_environment must be a valid GitHub environment name."
  }
}

variable "github_apply_environment" {
  description = "GitHub Actions environment allowed to run applies; protect it with required reviewers."
  type        = string
  default     = "sandbox"

  validation {
    condition     = can(regex("^[A-Za-z0-9._-]+$", var.github_apply_environment))
    error_message = "github_apply_environment must be a valid GitHub environment name."
  }
}

variable "create_github_oidc_provider" {
  description = "Create the token.actions.githubusercontent.com IAM OIDC provider. Set false when the account already has one and pass its ARN."
  type        = bool
  default     = true
}

variable "existing_github_oidc_provider_arn" {
  description = "Existing GitHub Actions IAM OIDC provider ARN, used only when create_github_oidc_provider is false."
  type        = string
  default     = ""

  validation {
    condition = (
      var.create_github_oidc_provider ||
      can(regex("^arn:[^:]+:iam::[0-9]{12}:oidc-provider/token\\.actions\\.githubusercontent\\.com$", var.existing_github_oidc_provider_arn))
    )
    error_message = "Provide the token.actions.githubusercontent.com provider ARN when create_github_oidc_provider is false."
  }
}

variable "additional_tags" {
  description = "Additional non-sensitive resource tags."
  type        = map(string)
  default     = {}
}
