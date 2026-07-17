data "terraform_remote_state" "infra" {
  backend = "remote"

  config = {
    hostname     = "app.terraform.io"
    organization = var.hcp_terraform_organization
    workspaces = {
      name = var.infra_workspace_name
    }
  }
}

locals {
  aws_region       = data.terraform_remote_state.infra.outputs.aws_region
  cluster_name     = data.terraform_remote_state.infra.outputs.cluster_name
  cluster_endpoint = data.terraform_remote_state.infra.outputs.cluster_endpoint
  cluster_ca_data  = data.terraform_remote_state.infra.outputs.cluster_certificate_authority_data
  vpc_cidr         = data.terraform_remote_state.infra.outputs.vpc_cidr
  service_cidr     = data.terraform_remote_state.infra.outputs.cluster_service_ipv4_cidr

  postgresql_service = "agentgate-postgresql.${var.platform_namespace}.svc.${var.cluster_domain}"
  spire_oidc_service = "spire-spiffe-oidc-discovery-provider.${var.spire_namespace}.svc.${var.cluster_domain}"
  spire_oidc_url     = "https://${local.spire_oidc_service}"

  vault_service_address  = "https://vault.${var.vault_namespace}.svc.${var.cluster_domain}:8200"
  vault_spiffe_id        = "spiffe://${var.spire_trust_domain}/ns/${var.vault_namespace}/sa/vault"
  agentgate_spiffe_id    = "spiffe://${var.spire_trust_domain}/ns/${var.agentgate_namespace}/sa/agentgate"
  spire_controller_class = "${var.spire_namespace}-spire"

  chart_versions = {
    postgresql = "18.8.0"
    spire      = "0.29.0"
    vault      = "0.34.0"
  }
}
