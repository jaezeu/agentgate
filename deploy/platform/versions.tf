terraform {
  required_version = "= 1.15.6"

  cloud {
    workspaces {
      name = "agentgate-platform"
    }
  }

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "= 6.55.0"
    }
    helm = {
      source  = "hashicorp/helm"
      version = "= 3.2.0"
    }
    kubernetes = {
      source  = "hashicorp/kubernetes"
      version = "= 3.2.1"
    }
    vault = {
      source  = "hashicorp/vault"
      version = "= 5.10.1"
    }
  }
}
