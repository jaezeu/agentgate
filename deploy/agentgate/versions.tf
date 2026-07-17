terraform {
  required_version = "= 1.15.6"

  cloud {
    workspaces {
      name = "agentgate-agentgate"
    }
  }

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "= 6.55.0"
    }
    kubernetes = {
      source  = "hashicorp/kubernetes"
      version = "= 3.2.1"
    }
  }
}
