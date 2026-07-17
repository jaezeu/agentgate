terraform {
  required_version = "~> 1.15.6"

  # Partial backend configuration: bucket and region come from
  # 'terraform init -backend-config' (see deploy/scripts/init-root.sh), so a
  # fork can point at its own state bucket without editing source.
  backend "s3" {
    key          = "infra.tfstate"
    encrypt      = true
    use_lockfile = true
  }

  # Pessimistic constraints; the committed .terraform.lock.hcl pins the exact
  # provider versions actually used until 'terraform init -upgrade' is run
  # deliberately.
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 6.55"
    }
  }
}
