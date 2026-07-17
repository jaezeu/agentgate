provider "aws" {
  region = local.aws_region
}

provider "kubernetes" {
  host                   = local.cluster_endpoint
  cluster_ca_certificate = base64decode(local.cluster_ca_data)

  exec {
    api_version = "client.authentication.k8s.io/v1"
    command     = "aws"
    args = [
      "eks",
      "get-token",
      "--cluster-name",
      local.cluster_name,
      "--region",
      local.aws_region,
    ]
  }
}

provider "helm" {
  kubernetes = {
    host                   = local.cluster_endpoint
    cluster_ca_certificate = base64decode(local.cluster_ca_data)
    exec = {
      api_version = "client.authentication.k8s.io/v1"
      command     = "aws"
      args = [
        "eks",
        "get-token",
        "--cluster-name",
        local.cluster_name,
        "--region",
        local.aws_region,
      ]
    }
  }
}

provider "vault" {}

data "aws_eks_cluster" "sandbox" {
  name = local.cluster_name
}

data "kubernetes_namespace_v1" "platform" {
  metadata {
    name = var.platform_namespace
  }
}

data "kubernetes_namespace_v1" "spire" {
  metadata {
    name = var.spire_namespace
  }
}

data "kubernetes_namespace_v1" "vault" {
  metadata {
    name = var.vault_namespace
  }
}
