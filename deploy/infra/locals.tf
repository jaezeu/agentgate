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

  demo_bucket_name = "${var.name_prefix}-${data.aws_caller_identity.current.account_id}-${var.aws_region}"
  demo_s3_prefix   = "governed-runner/"
}
