variable "hcp_terraform_organization" {
  description = "HCP Terraform organization containing the sandbox workspaces."
  type        = string

  validation {
    condition     = length(trimspace(var.hcp_terraform_organization)) >= 3
    error_message = "hcp_terraform_organization must not be empty."
  }
}

variable "infra_workspace_name" {
  description = "HCP Terraform workspace that owns deploy/infra."
  type        = string
  default     = "agentgate-infra"
}

variable "platform_workspace_name" {
  description = "HCP Terraform workspace that owns deploy/platform."
  type        = string
  default     = "agentgate-platform"
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

variable "agentgate_namespace" {
  description = "Namespace containing the credential-blind AgentGate control plane."
  type        = string
  default     = "agentgate"
}

variable "runner_namespace" {
  description = "Namespace containing the governed runner and PoC dispatcher."
  type        = string
  default     = "agentgate-sandbox"

  validation {
    condition     = var.runner_namespace == "agentgate-sandbox"
    error_message = "runner_namespace must match the workload path embedded in policies/authorization.rego."
  }
}

variable "agentgate_service_account_name" {
  description = "Exact Kubernetes service account attested as AgentGate."
  type        = string
  default     = "agentgate"
}

variable "runner_service_account_name" {
  description = "Exact Kubernetes service account attested as the governed runner."
  type        = string
  default     = "terraform-runner"

  validation {
    condition     = var.runner_service_account_name == "terraform-runner"
    error_message = "runner_service_account_name must match the workload path embedded in policies/authorization.rego."
  }
}

variable "dispatcher_service_account_name" {
  description = "Unprivileged service account used only by the PoC dispatcher Job."
  type        = string
  default     = "dispatcher-stub"
}

variable "agentgate_replicas" {
  description = "Number of stateless AgentGate control-plane replicas."
  type        = number
  default     = 2

  validation {
    condition     = var.agentgate_replicas >= 2 && var.agentgate_replicas <= 5
    error_message = "agentgate_replicas must be between 2 and 5."
  }
}

variable "application_image" {
  description = "Published AgentGate image built from deploy/images/Dockerfile and pinned by sha256 digest."
  type        = string

  # TODO(verify): publish the reviewed application image and record its immutable registry digest in the HCP workspace.
  validation {
    condition     = can(regex("^[^[:space:]@]+@sha256:[0-9a-f]{64}$", var.application_image))
    error_message = "application_image must be an immutable OCI reference ending in @sha256:<64 lowercase hex characters>."
  }
}

variable "postgresql_password_secret_name" {
  description = "Runtime Secret containing the PostgreSQL URL assembled by the bootstrap script."
  type        = string
  default     = "agentgate-postgresql"
}

variable "dispatcher_public_key_config_map_name" {
  description = "Runtime ConfigMap containing dispatcher-public.pem."
  type        = string
  default     = "agentgate-dispatcher-public-key"
}

variable "dispatcher_private_key_secret_name" {
  description = "Runtime Secret mounted only by the PoC dispatcher Job."
  type        = string
  default     = "agentgate-dispatcher-private-key"
}

variable "approver_token_secret_name" {
  description = "Runtime Secret containing the approval webhook URL and, in PoC mode, the separate human approver bearer token."
  type        = string
  default     = "agentgate-approver-token"
}

variable "demo_grant_secret_name" {
  description = "Short-lived runtime Secret containing one dispatcher-signed demo grant."
  type        = string
  default     = "agentgate-demo-grant"
}

variable "human_auth_mode" {
  description = "Human authentication rail. poc-static is sandbox-only; oidc uses the separately configured human issuer and audience."
  type        = string
  default     = "poc-static"

  validation {
    condition     = contains(["poc-static", "oidc"], var.human_auth_mode)
    error_message = "human_auth_mode must be poc-static or oidc."
  }
}

variable "human_oidc_issuer_url" {
  description = "OIDC issuer for human routes only; it is never accepted as workload identity."
  type        = string
  default     = ""

  validation {
    condition     = var.human_oidc_issuer_url == "" || startswith(var.human_oidc_issuer_url, "https://")
    error_message = "human_oidc_issuer_url must be empty or use HTTPS."
  }
}

variable "human_oidc_audience" {
  description = "Expected audience for human OIDC tokens; separate from the Vault workload audience."
  type        = string
  default     = ""
}

variable "demo_repository" {
  description = "Repository claim used by the suspended dispatcher demo Job."
  type        = string
  default     = "github.com/agentgate-sandbox/terraform-demo"

  validation {
    condition     = var.demo_repository == "github.com/agentgate-sandbox/terraform-demo"
    error_message = "demo_repository must match the repository embedded in policies/authorization.rego."
  }
}

variable "demo_commit_sha" {
  description = "Non-secret 40-character commit fixture used by the suspended dispatcher demo Job."
  type        = string
  default     = "0123456789abcdef0123456789abcdef01234567"

  validation {
    condition     = can(regex("^[0-9a-f]{40}$", var.demo_commit_sha))
    error_message = "demo_commit_sha must be exactly 40 lowercase hexadecimal characters."
  }
}

variable "demo_on_behalf_of" {
  description = "Sandbox human identity placed in the dispatcher-signed demo grant."
  type        = string
  default     = "sandbox-operator@example.test"

  validation {
    condition     = length(trimspace(var.demo_on_behalf_of)) >= 3
    error_message = "demo_on_behalf_of must not be empty."
  }
}

variable "demo_ticket_id" {
  description = "Sandbox ticket correlation placed in the dispatcher-signed demo grant."
  type        = string
  default     = "AGENTGATE-DEMO-1"

  validation {
    condition     = length(trimspace(var.demo_ticket_id)) >= 3
    error_message = "demo_ticket_id must not be empty."
  }
}
