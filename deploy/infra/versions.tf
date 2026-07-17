terraform {
  required_version = "= 1.15.6"

  cloud {
    workspaces {
      name = "agentgate-infra"
    }
  }

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "= 6.55.0"
    }
    tls = {
      source  = "hashicorp/tls"
      version = "= 4.3.0"
    }
  }
}
