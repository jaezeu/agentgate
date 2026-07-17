resource "kubernetes_manifest" "agentgate_spiffe_id" {
  manifest = {
    apiVersion = "spire.spiffe.io/v1alpha1"
    kind       = "ClusterSPIFFEID"
    metadata = {
      name = "agentgate-control-plane"
    }
    spec = {
      className        = local.spire_controller_class
      hint             = "agentgate-control-plane"
      spiffeIDTemplate = local.agentgate_spiffe_id
      namespaceSelector = {
        matchLabels = {
          "kubernetes.io/metadata.name" = var.agentgate_namespace
        }
      }
      podSelector = {
        matchLabels = {
          "app.kubernetes.io/name"      = local.agentgate_labels["app.kubernetes.io/name"]
          "app.kubernetes.io/instance"  = local.agentgate_labels["app.kubernetes.io/instance"]
          "app.kubernetes.io/component" = local.agentgate_labels["app.kubernetes.io/component"]
        }
      }
      workloadSelectorTemplates = [
        "k8s:ns:${var.agentgate_namespace}",
        "k8s:sa:${var.agentgate_service_account_name}",
      ]
      dnsNameTemplates = [
        "agentgate",
        "agentgate.${var.agentgate_namespace}",
        "agentgate.${var.agentgate_namespace}.svc",
        "agentgate.${var.agentgate_namespace}.svc.${var.cluster_domain}",
      ]
      ttl    = "15m"
      jwtTtl = "5m"
    }
  }

  depends_on = [
    kubernetes_namespace_v1.agentgate,
    kubernetes_service_account_v1.agentgate,
  ]
}

resource "kubernetes_manifest" "runner_spiffe_id" {
  manifest = {
    apiVersion = "spire.spiffe.io/v1alpha1"
    kind       = "ClusterSPIFFEID"
    metadata = {
      name = "agentgate-terraform-runner"
    }
    spec = {
      className        = local.spire_controller_class
      hint             = "agentgate-terraform-runner"
      spiffeIDTemplate = local.runner_spiffe_id
      namespaceSelector = {
        matchLabels = {
          "kubernetes.io/metadata.name" = var.runner_namespace
        }
      }
      podSelector = {
        matchLabels = {
          "app.kubernetes.io/name"      = local.runner_labels["app.kubernetes.io/name"]
          "app.kubernetes.io/instance"  = local.runner_labels["app.kubernetes.io/instance"]
          "app.kubernetes.io/component" = local.runner_labels["app.kubernetes.io/component"]
        }
      }
      workloadSelectorTemplates = [
        "k8s:ns:${var.runner_namespace}",
        "k8s:sa:${var.runner_service_account_name}",
      ]
      ttl    = "15m"
      jwtTtl = "5m"
    }
  }

  depends_on = [
    kubernetes_namespace_v1.runner,
    kubernetes_service_account_v1.runner,
  ]
}
