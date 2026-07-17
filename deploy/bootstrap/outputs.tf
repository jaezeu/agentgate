output "state_bucket" {
  description = "S3 bucket holding Terraform state for the infra, platform, and agentgate roots."
  value       = module.state_bucket.s3_bucket_id
}

output "state_bucket_region" {
  description = "Region of the Terraform state bucket."
  value       = var.aws_region
}

output "state_kms_key_arn" {
  description = "KMS key encrypting Terraform state objects."
  value       = module.state_key.key_arn
}

output "deployer_role_arn" {
  description = "IAM role assumed by GitHub Actions deploy workflows through OIDC."
  value       = aws_iam_role.deployer.arn
}

output "github_oidc_provider_arn" {
  description = "GitHub Actions IAM OIDC provider trusted by the deployer role."
  value       = local.github_oidc_provider_arn
}

output "backend_config" {
  description = "Values passed to 'terraform init -backend-config' for every root."
  value = {
    bucket = module.state_bucket.s3_bucket_id
    region = var.aws_region
  }
}
