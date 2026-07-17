output "platform_namespace" {
  description = "Namespace containing PostgreSQL."
  value       = var.platform_namespace
}

output "spire_namespace" {
  description = "Namespace containing SPIRE."
  value       = var.spire_namespace
}

output "vault_namespace" {
  description = "Namespace containing Vault."
  value       = var.vault_namespace
}

output "runner_namespace" {
  description = "Namespace containing the governed runner."
  value       = var.runner_namespace
}

output "spire_trust_domain" {
  description = "SPIFFE trust domain."
  value       = var.spire_trust_domain
}

output "spire_controller_class" {
  description = "Class name required on AgentGate-owned ClusterSPIFFEID resources."
  value       = local.spire_controller_class
}

output "spire_oidc_discovery_url" {
  description = "In-cluster TLS SPIRE OIDC discovery URL trusted by Vault."
  value       = local.spire_oidc_url
}

output "spire_workload_api_csi_driver" {
  description = "CSI driver used to mount the SPIFFE Workload API socket."
  value       = "csi.spiffe.io"
}

output "vault_address" {
  description = "In-cluster TLS Vault address. This is an endpoint, not a credential."
  value       = local.vault_service_address
}

output "vault_auth_mount" {
  description = "Vault JWT auth mount for SPIRE JWT-SVIDs."
  value       = var.vault_auth_mount
}

output "vault_aws_mount" {
  description = "Vault AWS secrets engine mount."
  value       = var.vault_aws_mount
}

output "vault_demo_role_name" {
  description = "Vault AWS role backed by the narrow demo target IAM role."
  value       = var.vault_demo_role_name
}

output "postgresql_service" {
  description = "In-cluster PostgreSQL service DNS name."
  value       = local.postgresql_service
}

output "postgresql_database" {
  description = "AgentGate PostgreSQL database name."
  value       = "agentgate"
}

output "postgresql_username" {
  description = "AgentGate PostgreSQL username."
  value       = "agentgate"
}

output "postgresql_credentials_secret_name" {
  description = "Name of the runtime Kubernetes Secret; no secret value is output."
  value       = var.postgresql_credentials_secret_name
}
