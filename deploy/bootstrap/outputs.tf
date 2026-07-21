output "deployer_role_arn" {
  description = "IAM role assumed by GitHub Actions deploy workflows through OIDC."
  value       = module.github_oidc.oidc_role
}

output "ecr_repository_url" {
  description = "Registry the deploy workflow pushes the application image to."
  value       = aws_ecr_repository.application.repository_url
}

output "github_oidc_provider_arn" {
  description = "GitHub Actions IAM OIDC provider trusted by the deployer role."
  value = (
    var.create_github_oidc_provider ?
    module.github_oidc.oidc_provider_arn :
    var.existing_github_oidc_provider_arn
  )
}
