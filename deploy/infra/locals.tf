locals {
  cluster_name = "${var.name_prefix}-eks"

  availability_zones = slice(data.aws_availability_zones.available.names, 0, 2)

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

  hcp_workspace_subjects = {
    platform  = "organization:${var.hcp_terraform_organization}:project:${var.hcp_terraform_project}:workspace:${var.hcp_terraform_platform_workspace}:run_phase:*"
    agentgate = "organization:${var.hcp_terraform_organization}:project:${var.hcp_terraform_project}:workspace:${var.hcp_terraform_agentgate_workspace}:run_phase:*"
  }

  demo_bucket_name = "${var.name_prefix}-${data.aws_caller_identity.current.account_id}-${var.aws_region}"
  demo_s3_prefix   = "governed-runner/"
}
