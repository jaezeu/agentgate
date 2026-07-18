terraform {
  required_version = "~> 1.15.6"

  # Placeholder backend: bucket and region come from 'terraform init
  # -backend-config' (deploy/scripts/init-root.sh).
  backend "s3" {
    key          = "infra.tfstate"
    encrypt      = true
    use_lockfile = true
  }

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 6.55"
    }
  }
}
