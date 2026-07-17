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
  value       = module.vpc.vpc_id
}

output "vpc_cidr" {
  description = "Sandbox VPC CIDR used by in-cluster network policy."
  value       = module.vpc.vpc_cidr_block
}

output "cluster_service_ipv4_cidr" {
  description = "Kubernetes service CIDR used by in-cluster network policy."
  value       = module.eks.cluster_service_cidr
}

output "public_subnet_ids" {
  description = "Public subnet IDs."
  value       = module.vpc.public_subnets
}

output "private_subnet_ids" {
  description = "Private EKS node subnet IDs."
  value       = module.vpc.private_subnets
}

output "cluster_name" {
  description = "EKS cluster name."
  value       = module.eks.cluster_name
}

output "cluster_endpoint" {
  description = "EKS API endpoint."
  value       = module.eks.cluster_endpoint
}

output "cluster_certificate_authority_data" {
  description = "Base64-encoded public EKS certificate authority data."
  value       = module.eks.cluster_certificate_authority_data
}

output "cluster_oidc_provider_arn" {
  description = "EKS IAM OIDC provider ARN used for IRSA."
  value       = module.eks.oidc_provider_arn
}

output "deployer_role_arn" {
  description = "Deployment role granted EKS cluster-admin access for the platform and agentgate roots."
  value       = var.deployer_role_arn
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
