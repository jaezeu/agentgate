terraform {
  required_version = "~> 1.15.6"

  # This root deliberately uses local state. It creates the S3 state backend
  # and the GitHub OIDC deployment trust that every other root depends on, so
  # it cannot store its own state in that backend. Its state file contains
  # only public identifiers (bucket name, role ARN, provider ARN) and no
  # credential material. Keep the generated terraform.tfstate with the
  # operator bootstrap material outside the repository.

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 6.55"
    }
  }
}
