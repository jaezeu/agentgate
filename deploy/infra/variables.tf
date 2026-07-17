variable "aws_region" {
  description = "AWS region for the isolated AgentGate sandbox."
  type        = string
  default     = "us-west-2"

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

variable "vpc_cidr" {
  description = "IPv4 CIDR for the sandbox VPC."
  type        = string
  default     = "10.42.0.0/16"

  validation {
    condition     = can(cidrnetmask(var.vpc_cidr))
    error_message = "vpc_cidr must be a valid IPv4 CIDR."
  }
}

variable "public_subnet_cidrs" {
  description = "Two public subnet CIDRs used for the internet gateway and the single sandbox NAT gateway."
  type        = list(string)
  default     = ["10.42.0.0/24", "10.42.1.0/24"]

  validation {
    condition     = length(var.public_subnet_cidrs) == 2 && alltrue([for cidr in var.public_subnet_cidrs : can(cidrnetmask(cidr))])
    error_message = "public_subnet_cidrs must contain exactly two valid IPv4 CIDRs."
  }
}

variable "private_subnet_cidrs" {
  description = "Two private subnet CIDRs used by the EKS managed node group."
  type        = list(string)
  default     = ["10.42.10.0/24", "10.42.11.0/24"]

  validation {
    condition     = length(var.private_subnet_cidrs) == 2 && alltrue([for cidr in var.private_subnet_cidrs : can(cidrnetmask(cidr))])
    error_message = "private_subnet_cidrs must contain exactly two valid IPv4 CIDRs."
  }
}

variable "kubernetes_version" {
  description = "Pinned EKS Kubernetes minor version."
  type        = string
  default     = "1.36"

  validation {
    condition     = var.kubernetes_version == "1.36"
    error_message = "This reviewed deployment pins EKS to Kubernetes 1.36."
  }
}

variable "cluster_endpoint_public_access_cidrs" {
  description = "Narrow IPv4 CIDRs allowed to reach the public EKS API endpoint, including the HCP agent egress CIDR."
  type        = list(string)

  validation {
    condition = (
      length(var.cluster_endpoint_public_access_cidrs) > 0 &&
      alltrue([
        for cidr in var.cluster_endpoint_public_access_cidrs :
        can(cidrnetmask(cidr)) && cidr != "0.0.0.0/0"
      ])
    )
    error_message = "Provide at least one valid, narrow IPv4 CIDR; 0.0.0.0/0 is prohibited."
  }
}

variable "node_instance_types" {
  description = "Managed node group instance types."
  type        = list(string)
  default     = ["t3.medium"]

  validation {
    condition     = length(var.node_instance_types) > 0 && alltrue([for instance_type in var.node_instance_types : instance_type == "t3.medium"])
    error_message = "The reviewed sandbox configuration permits only t3.medium nodes."
  }
}

variable "node_desired_size" {
  description = "Desired managed node count."
  type        = number
  default     = 2

  validation {
    condition     = var.node_desired_size == 2
    error_message = "The sandbox requires exactly two nodes by default and in this reviewed configuration."
  }
}

variable "node_disk_size_gib" {
  description = "Encrypted gp3 root volume size for each worker node."
  type        = number
  default     = 40

  validation {
    condition     = var.node_disk_size_gib >= 20 && var.node_disk_size_gib <= 100
    error_message = "node_disk_size_gib must be between 20 and 100 GiB."
  }
}

variable "hcp_terraform_organization" {
  description = "HCP Terraform organization used in workload identity subject restrictions."
  type        = string

  validation {
    condition     = can(regex("^[A-Za-z0-9][A-Za-z0-9_-]{2,39}$", var.hcp_terraform_organization))
    error_message = "hcp_terraform_organization must be 3-40 valid HCP Terraform organization characters."
  }
}

variable "hcp_terraform_project" {
  description = "HCP Terraform project used in workload identity subject restrictions."
  type        = string
  default     = "AgentGate Sandbox"

  validation {
    condition     = length(trimspace(var.hcp_terraform_project)) >= 3
    error_message = "hcp_terraform_project must not be empty."
  }
}

variable "hcp_terraform_platform_workspace" {
  description = "HCP Terraform workspace allowed to assume the platform run role."
  type        = string
  default     = "agentgate-platform"
}

variable "hcp_terraform_agentgate_workspace" {
  description = "HCP Terraform workspace allowed to assume the AgentGate run role."
  type        = string
  default     = "agentgate-agentgate"
}

variable "hcp_aws_oidc_provider_arn" {
  description = "Pre-provisioned AWS IAM OIDC provider ARN for app.terraform.io. This is trust metadata, not a credential."
  type        = string

  validation {
    condition     = can(regex("^arn:[^:]+:iam::[0-9]{12}:oidc-provider/app\\.terraform\\.io$", var.hcp_aws_oidc_provider_arn))
    error_message = "hcp_aws_oidc_provider_arn must identify the app.terraform.io IAM OIDC provider."
  }
}

variable "hcp_aws_workload_identity_audience" {
  description = "Audience configured for HCP Terraform AWS dynamic provider credentials."
  type        = string
  default     = "aws.workload.identity"

  validation {
    condition     = var.hcp_aws_workload_identity_audience == "aws.workload.identity"
    error_message = "The reviewed HCP Terraform AWS workload identity audience is aws.workload.identity."
  }
}

variable "operator_access_principal_arns" {
  description = "Human AWS SSO role ARNs granted EKS cluster-admin access for sandbox bootstrap and recovery."
  type        = set(string)
  default     = []

  validation {
    condition = alltrue([
      for arn in var.operator_access_principal_arns :
      can(regex("^arn:[^:]+:iam::[0-9]{12}:role/.+$", arn))
    ])
    error_message = "Each operator access principal must be an IAM role ARN."
  }
}

variable "additional_tags" {
  description = "Additional non-sensitive resource tags."
  type        = map(string)
  default     = {}
}
