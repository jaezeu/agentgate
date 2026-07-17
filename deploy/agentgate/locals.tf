locals {
  aws_region         = data.terraform_remote_state.infra.outputs.aws_region
  demo_bucket_name   = data.terraform_remote_state.infra.outputs.demo_bucket_name
  demo_bucket_prefix = data.terraform_remote_state.infra.outputs.demo_bucket_prefix
  cluster_name       = data.terraform_remote_state.infra.outputs.cluster_name
  cluster_endpoint   = data.terraform_remote_state.infra.outputs.cluster_endpoint
  cluster_ca_data    = data.terraform_remote_state.infra.outputs.cluster_certificate_authority_data

  spire_trust_domain        = data.terraform_remote_state.platform.outputs.spire_trust_domain
  spire_controller_class    = data.terraform_remote_state.platform.outputs.spire_controller_class
  spire_workload_api_driver = data.terraform_remote_state.platform.outputs.spire_workload_api_csi_driver
  spire_workload_api_socket = "unix:///run/spire/sockets/spire-agent.sock"
  vault_address             = data.terraform_remote_state.platform.outputs.vault_address
  vault_auth_mount          = data.terraform_remote_state.platform.outputs.vault_auth_mount
  vault_aws_mount           = data.terraform_remote_state.platform.outputs.vault_aws_mount
  vault_demo_role_name      = data.terraform_remote_state.platform.outputs.vault_demo_role_name
  vault_server_name         = "vault.${data.terraform_remote_state.platform.outputs.vault_namespace}.svc.${var.cluster_domain}"

  postgresql_service  = data.terraform_remote_state.platform.outputs.postgresql_service
  postgresql_database = data.terraform_remote_state.platform.outputs.postgresql_database
  postgresql_username = data.terraform_remote_state.platform.outputs.postgresql_username

  agentgate_spiffe_id = "spiffe://${local.spire_trust_domain}/ns/${var.agentgate_namespace}/sa/${var.agentgate_service_account_name}"
  runner_spiffe_id    = "spiffe://${local.spire_trust_domain}/ns/${var.runner_namespace}/sa/${var.runner_service_account_name}"
  agentgate_url       = "https://agentgate.${var.agentgate_namespace}.svc.${var.cluster_domain}:8443"
  spiffe_helper_image = "ghcr.io/spiffe/spiffe-helper@sha256:2759b3a699bb63b91cc5896f46cd6f70b9e3dfed9f7f4355a3a0a4e702984f9c"

  agentgate_labels = {
    "app.kubernetes.io/name"       = "agentgate"
    "app.kubernetes.io/instance"   = "agentgate"
    "app.kubernetes.io/component"  = "control-plane"
    "app.kubernetes.io/part-of"    = "agentgate"
    "app.kubernetes.io/managed-by" = "terraform"
  }

  runner_labels = {
    "app.kubernetes.io/name"       = "agent-sim"
    "app.kubernetes.io/instance"   = "agentgate-demo"
    "app.kubernetes.io/component"  = "governed-runner"
    "app.kubernetes.io/part-of"    = "agentgate"
    "app.kubernetes.io/managed-by" = "terraform"
  }

  dispatcher_labels = {
    "app.kubernetes.io/name"       = "orchestrator-stub"
    "app.kubernetes.io/instance"   = "agentgate-demo"
    "app.kubernetes.io/component"  = "dispatcher"
    "app.kubernetes.io/part-of"    = "agentgate"
    "app.kubernetes.io/managed-by" = "terraform"
  }

  agentgate_args = concat(
    [
      "serve",
      "--listen=:8443",
      "--tls-cert=/run/agentgate/tls/tls.crt",
      "--tls-key=/run/agentgate/tls/tls.key",
      "--svid-trust-bundle=/run/agentgate/tls/ca.pem",
      "--allowed-trust-domains=${local.spire_trust_domain}",
      "--dispatcher-public-key=/etc/agentgate/dispatcher/dispatcher-public.pem",
      "--database-url-env=AGENTGATE_DATABASE_URL",
      "--webhook-url-env=AGENTGATE_APPROVAL_WEBHOOK_URL",
      "--public-base-url=${local.agentgate_url}",
      "--vault-address=${local.vault_address}",
      "--vault-auth-mount=${local.vault_auth_mount}",
      "--vault-role-prefix=agentgate-role-",
      "--vault-policy-prefix=agentgate-policy-",
      "--vault-aws-mount=${local.vault_aws_mount}",
      "--vault-ca-cert=/run/agentgate/tls/ca.pem",
      "--vault-tls-server-name=${local.vault_server_name}",
      "--vault-management-auth-mount=${local.vault_auth_mount}",
      "--vault-management-role=agentgate-manager",
      "--vault-management-audience=vault",
      "--workload-api-addr=${local.spire_workload_api_socket}",
    ],
    var.human_auth_mode == "poc-static" ? [
      "--poc-static-human-auth",
      "--poc-human-token-env=AGENTGATE_POC_APPROVER_TOKEN",
      "--poc-human-subject=${var.demo_on_behalf_of}",
      ] : [
      "--human-oidc-issuer=${var.human_oidc_issuer_url}",
      "--human-oidc-audience=${var.human_oidc_audience}",
    ],
  )
}

check "embedded_policy_identity" {
  assert {
    condition = (
      local.spire_trust_domain == "sandbox.agentgate.test" &&
      local.runner_spiffe_id == "spiffe://sandbox.agentgate.test/ns/agentgate-sandbox/sa/terraform-runner"
    )
    error_message = "SPIRE identity inputs must match the exact workload configured in policies/authorization.rego."
  }
}

check "human_auth_configuration" {
  assert {
    condition = (
      (var.human_auth_mode == "poc-static" && var.human_oidc_issuer_url == "" && var.human_oidc_audience == "") ||
      (var.human_auth_mode == "oidc" && var.human_oidc_issuer_url != "" && var.human_oidc_audience != "")
    )
    error_message = "PoC static auth and human OIDC are separate modes; configure exactly one."
  }
}
