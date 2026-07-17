variable "state_bucket" {
  description = "S3 bucket created by deploy/bootstrap that holds every root's Terraform state."
  type        = string

  validation {
    condition     = can(regex("^[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]$", var.state_bucket))
    error_message = "state_bucket must be a valid S3 bucket name."
  }
}

variable "state_bucket_region" {
  description = "AWS region of the Terraform state bucket."
  type        = string

  validation {
    condition     = can(regex("^[a-z]{2}(-gov)?-[a-z]+-[0-9]+$", var.state_bucket_region))
    error_message = "state_bucket_region must be a valid AWS region name."
  }
}

variable "cluster_domain" {
  description = "Kubernetes DNS cluster domain."
  type        = string
  default     = "cluster.local"

  validation {
    condition     = can(regex("^[a-z0-9.-]+$", var.cluster_domain))
    error_message = "cluster_domain must be a valid lowercase DNS suffix."
  }
}

variable "spire_trust_domain" {
  description = "SPIFFE trust domain for governed sandbox workloads."
  type        = string
  default     = "sandbox.agentgate.test"

  validation {
    condition     = can(regex("^[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?$", var.spire_trust_domain))
    error_message = "spire_trust_domain must be a valid lowercase trust domain."
  }
}

variable "platform_namespace" {
  description = "Namespace containing PostgreSQL and migration jobs."
  type        = string
  default     = "agentgate-platform"
}

variable "spire_namespace" {
  description = "Namespace containing the SPIRE stack."
  type        = string
  default     = "spire-system"
}

variable "vault_namespace" {
  description = "Namespace containing Vault."
  type        = string
  default     = "vault"
}

variable "agentgate_namespace" {
  description = "Namespace from which AgentGate may reach Vault and PostgreSQL."
  type        = string
  default     = "agentgate"
}

variable "runner_namespace" {
  description = "Namespace containing governed runner workloads."
  type        = string
  default     = "agentgate-sandbox"
}

variable "postgresql_credentials_secret_name" {
  description = "Existing runtime Secret containing password and postgres-password keys; values are bootstrapped outside Terraform state."
  type        = string
  default     = "agentgate-postgresql"
}

variable "vault_configuration_enabled" {
  description = "Enable Terraform-driven Vault resources only after Vault initialization/unseal and deployment-trust bootstrap (bootstrap-vault.sh)."
  type        = bool
  default     = false
}

variable "vault_address" {
  description = "In-cluster TLS Vault address recorded in outputs and descriptors."
  type        = string
  default     = "https://vault.vault.svc.cluster.local:8200"

  validation {
    condition     = startswith(var.vault_address, "https://")
    error_message = "vault_address must use HTTPS."
  }
}

variable "vault_auth_mount" {
  description = "Vault JWT auth mount trusted by SPIRE workloads."
  type        = string
  default     = "spire-jwt"

  validation {
    condition     = can(regex("^[a-z0-9][a-z0-9-]{1,30}$", var.vault_auth_mount))
    error_message = "vault_auth_mount must be a simple lowercase path segment."
  }
}

variable "vault_aws_mount" {
  description = "Vault AWS secrets engine mount."
  type        = string
  default     = "aws"

  validation {
    condition     = can(regex("^[a-z0-9][a-z0-9-]{1,30}$", var.vault_aws_mount))
    error_message = "vault_aws_mount must be a simple lowercase path segment."
  }
}

variable "vault_demo_role_name" {
  description = "Vault AWS role exposed to approved governed runners."
  type        = string
  default     = "terraform-sandbox"
}
