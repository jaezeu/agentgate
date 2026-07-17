resource "kubernetes_config_map_v1" "vault_spiffe_helper" {
  metadata {
    name      = "vault-spiffe-helper"
    namespace = data.kubernetes_namespace_v1.vault.metadata[0].name
    labels = {
      "app.kubernetes.io/name"       = "vault-spiffe-helper"
      "app.kubernetes.io/part-of"    = "agentgate"
      "app.kubernetes.io/managed-by" = "terraform"
    }
  }

  data = {
    "helper-init.conf" = <<-HCL
      agent_address = "/run/spire/agent-sockets/spire-agent.sock"
      cert_dir = "/vault/tls"
      svid_file_name = "tls.crt"
      svid_key_file_name = "tls.key"
      svid_bundle_file_name = "ca.pem"
      add_intermediates_to_bundle = true
      cert_file_mode = 0644
      key_file_mode = 0600
    HCL

    "helper.conf" = <<-HCL
      agent_address = "/run/spire/agent-sockets/spire-agent.sock"
      cert_dir = "/vault/tls"
      svid_file_name = "tls.crt"
      svid_key_file_name = "tls.key"
      svid_bundle_file_name = "ca.pem"
      add_intermediates_to_bundle = true
      cert_file_mode = 0644
      key_file_mode = 0600
      pid_file_name = "/vault/tls/vault.pid"
      renew_signal = "SIGHUP"
      health_checks {
        listener_enabled = true
        bind_port = 8081
        liveness_path = "/live"
        readiness_path = "/ready"
      }
    HCL
  }
}

resource "helm_release" "vault" {
  name       = "vault"
  namespace  = data.kubernetes_namespace_v1.vault.metadata[0].name
  repository = "https://helm.releases.hashicorp.com"
  chart      = "vault"
  version    = local.chart_versions.vault

  atomic          = false
  cleanup_on_fail = true
  timeout         = 600
  wait            = false

  values = [
    file("${path.module}/helm-values/vault.yaml"),
    yamlencode({
      server = {
        serviceAccount = {
          annotations = {
            "eks.amazonaws.com/role-arn" = data.terraform_remote_state.infra.outputs.vault_aws_broker_role_arn
          }
        }
        networkPolicy = {
          ingress = [
            {
              from = [
                {
                  namespaceSelector = {
                    matchLabels = {
                      "kubernetes.io/metadata.name" = var.vault_namespace
                    }
                  }
                },
                {
                  namespaceSelector = {
                    matchLabels = {
                      "kubernetes.io/metadata.name" = var.agentgate_namespace
                    }
                  }
                },
                {
                  namespaceSelector = {
                    matchLabels = {
                      "kubernetes.io/metadata.name" = var.runner_namespace
                    }
                  }
                },
              ]
              ports = [
                {
                  port     = 8200
                  protocol = "TCP"
                },
              ]
            },
            {
              from = [
                {
                  namespaceSelector = {
                    matchLabels = {
                      "kubernetes.io/metadata.name" = var.vault_namespace
                    }
                  }
                },
              ]
              ports = [
                {
                  port     = 8201
                  protocol = "TCP"
                },
              ]
            },
          ]
        }
      }
    }),
  ]

  depends_on = [
    helm_release.spire,
    kubernetes_config_map_v1.vault_spiffe_helper,
    kubernetes_network_policy_v1.vault_default_deny,
  ]
}

data "kubernetes_config_map_v1" "spire_bundle" {
  count = var.vault_configuration_enabled ? 1 : 0

  metadata {
    name      = "spire-bundle"
    namespace = var.spire_namespace
  }

  depends_on = [helm_release.spire]
}

resource "vault_audit" "file" {
  count = var.vault_configuration_enabled ? 1 : 0

  type = "file"
  path = "file"

  options = {
    file_path = "/vault/audit/audit.log"
    log_raw   = "false"
  }

  depends_on = [helm_release.vault]
}

resource "vault_jwt_auth_backend" "spire" {
  count = var.vault_configuration_enabled ? 1 : 0

  path                  = var.vault_auth_mount
  type                  = "jwt"
  description           = "SPIRE JWT-SVID authentication for exact AgentGate workload identities"
  oidc_discovery_url    = local.spire_oidc_url
  oidc_discovery_ca_pem = data.kubernetes_config_map_v1.spire_bundle[0].data["bundle.crt"]
  bound_issuer          = local.spire_oidc_url

  tune {
    default_lease_ttl = "15m"
    max_lease_ttl     = "15m"
    token_type        = "default-service"
  }

  depends_on = [vault_audit.file]
}

resource "vault_aws_secret_backend" "sandbox" {
  count = var.vault_configuration_enabled ? 1 : 0

  path                      = var.vault_aws_mount
  description               = "AgentGate sandbox AWS credentials issued directly to governed runners"
  region                    = local.aws_region
  default_lease_ttl_seconds = 900
  max_lease_ttl_seconds     = 900
  audit_non_hmac_request_keys = [
    "role_session_name",
  ]

  depends_on = [vault_audit.file]
}

resource "vault_aws_secret_backend_role" "sandbox" {
  count = var.vault_configuration_enabled ? 1 : 0

  backend         = vault_aws_secret_backend.sandbox[0].path
  name            = var.vault_demo_role_name
  credential_type = "assumed_role"
  role_arns       = [data.terraform_remote_state.infra.outputs.demo_target_role_arn]
  default_sts_ttl = 900
  max_sts_ttl     = 900
}

resource "vault_policy" "agentgate_management" {
  count = var.vault_configuration_enabled ? 1 : 0

  name   = "agentgate-management"
  policy = <<-HCL
    path "auth/${var.vault_auth_mount}/role/agentgate-role-*" {
      capabilities = ["create", "read", "update", "delete"]
    }

    path "sys/policies/acl/agentgate-policy-*" {
      capabilities = ["create", "read", "update", "delete"]
    }
  HCL
}

resource "vault_jwt_auth_backend_role" "agentgate_manager" {
  count = var.vault_configuration_enabled ? 1 : 0

  backend                 = vault_jwt_auth_backend.spire[0].path
  role_name               = "agentgate-manager"
  role_type               = "jwt"
  bound_audiences         = ["vault"]
  bound_subject           = local.agentgate_spiffe_id
  user_claim              = "sub"
  token_policies          = [vault_policy.agentgate_management[0].name]
  token_no_default_policy = true
  token_ttl               = 300
  token_max_ttl           = 900
  token_explicit_max_ttl  = 900
  verbose_oidc_logging    = false
}
