output "aws_account_id" {
  description = "AWS account containing the sandbox."
  value       = data.aws_caller_identity.current.account_id
}

output "aws_region" {
  description = "AWS region containing the sandbox."
  value       = var.aws_region
}

output "vpc_id" {
  description = "Sandbox VPC ID."
  value       = aws_vpc.sandbox.id
}

output "vpc_cidr" {
  description = "Sandbox VPC CIDR used by in-cluster network policy."
  value       = aws_vpc.sandbox.cidr_block
}

output "cluster_service_ipv4_cidr" {
  description = "Kubernetes service CIDR used by in-cluster network policy."
  value       = aws_eks_cluster.sandbox.kubernetes_network_config[0].service_ipv4_cidr
}

output "public_subnet_ids" {
  description = "Public subnet IDs."
  value       = aws_subnet.public[*].id
}

output "private_subnet_ids" {
  description = "Private EKS node subnet IDs."
  value       = aws_subnet.private[*].id
}

output "cluster_name" {
  description = "EKS cluster name."
  value       = aws_eks_cluster.sandbox.name
}

output "cluster_endpoint" {
  description = "EKS API endpoint."
  value       = aws_eks_cluster.sandbox.endpoint
}

output "cluster_certificate_authority_data" {
  description = "Base64-encoded public EKS certificate authority data."
  value       = aws_eks_cluster.sandbox.certificate_authority[0].data
}

output "cluster_oidc_provider_arn" {
  description = "EKS IAM OIDC provider ARN used for IRSA."
  value       = aws_iam_openid_connect_provider.eks.arn
}

output "platform_run_role_arn" {
  description = "AWS role for HCP Terraform dynamic credentials in the platform workspace."
  value       = aws_iam_role.hcp_workspace["platform"].arn
}

output "agentgate_run_role_arn" {
  description = "AWS role for HCP Terraform dynamic credentials in the AgentGate workspace."
  value       = aws_iam_role.hcp_workspace["agentgate"].arn
}

output "vault_aws_broker_role_arn" {
  description = "IRSA role used by Vault's AWS secrets engine to assume only the demo target role."
  value       = aws_iam_role.vault_broker.arn
}

output "demo_target_role_arn" {
  description = "Narrow IAM role assumed by Vault for governed sandbox work."
  value       = aws_iam_role.demo_target.arn
}

output "demo_bucket_name" {
  description = "S3 bucket containing the governed demo prefix."
  value       = aws_s3_bucket.demo.id
}

output "demo_bucket_prefix" {
  description = "Only S3 object prefix writable by the demo target role."
  value       = local.demo_s3_prefix
}
