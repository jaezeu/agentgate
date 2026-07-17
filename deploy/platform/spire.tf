resource "helm_release" "spire" {
  name       = "spire"
  namespace  = data.kubernetes_namespace_v1.spire.metadata[0].name
  repository = "https://spiffe.github.io/helm-charts-hardened"
  chart      = "spire"
  version    = local.chart_versions.spire

  atomic          = true
  cleanup_on_fail = true
  timeout         = 900
  wait            = true
  wait_for_jobs   = true

  values = [
    file("${path.module}/helm-values/spire.yaml"),
    yamlencode({
      global = {
        spire = {
          clusterName = local.cluster_name
          trustDomain = var.spire_trust_domain
          jwtIssuer   = local.spire_oidc_url
          namespaces = {
            system = {
              name = var.spire_namespace
            }
            server = {
              name = var.spire_namespace
            }
          }
        }
      }
      spire-server = {
        dataStore = {
          sql = {
            host = local.postgresql_service
            externalSecret = {
              name = var.postgresql_credentials_secret_name
            }
          }
        }
        controllerManager = {
          identities = {
            clusterSPIFFEIDs = {
              vault = {
                spiffeIDTemplate = local.vault_spiffe_id
                namespaceSelector = {
                  matchLabels = {
                    "kubernetes.io/metadata.name" = var.vault_namespace
                  }
                }
                dnsNameTemplates = [
                  "vault",
                  "vault.${var.vault_namespace}",
                  "vault.${var.vault_namespace}.svc",
                  "vault.${var.vault_namespace}.svc.${var.cluster_domain}",
                ]
              }
            }
          }
        }
      }
    }),
  ]

  depends_on = [
    kubernetes_job_v1.agentgate_migrations,
    kubernetes_network_policy_v1.spire_default_deny,
    kubernetes_network_policy_v1.spire_internal,
    kubernetes_network_policy_v1.spire_oidc_vault,
  ]
}
