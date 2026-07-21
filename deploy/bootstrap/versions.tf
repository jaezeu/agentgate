terraform {
  required_version = "~> 1.15.6"

  # Same pre-created state bucket as the other roots so the deploy workflow
  # can re-run bootstrap idempotently; the bucket itself is ensured by
  # deploy/scripts/ci-ensure-state-bucket.sh before the first init.
  backend "s3" {
    key          = "bootstrap.tfstate"
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
