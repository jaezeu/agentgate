terraform {
  required_version = "~> 1.15.6"

  # Partial backend configuration: bucket and region come from
  # 'terraform init -backend-config' (see deploy/scripts/init-root.sh).
  backend "s3" {
    key          = "agentgate.tfstate"
    encrypt      = true
    use_lockfile = true
  }

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 6.55"
    }
    kubernetes = {
      source  = "hashicorp/kubernetes"
      version = "~> 3.2"
    }
  }
}
