resource "kubernetes_network_policy_v1" "platform_default_deny" {
  metadata {
    name      = "default-deny"
    namespace = data.kubernetes_namespace_v1.platform.metadata[0].name
  }

  spec {
    pod_selector {}
    policy_types = ["Ingress", "Egress"]
  }
}

resource "kubernetes_network_policy_v1" "migration" {
  metadata {
    name      = "agentgate-migrations"
    namespace = data.kubernetes_namespace_v1.platform.metadata[0].name
  }

  spec {
    pod_selector {
      match_labels = {
        "app.kubernetes.io/name" = "agentgate-migrations"
      }
    }

    policy_types = ["Egress"]

    egress {
      to {
        namespace_selector {
          match_labels = {
            "kubernetes.io/metadata.name" = "kube-system"
          }
        }
        pod_selector {
          match_labels = {
            "k8s-app" = "kube-dns"
          }
        }
      }

      ports {
        port     = "53"
        protocol = "UDP"
      }
      ports {
        port     = "53"
        protocol = "TCP"
      }
    }

    egress {
      to {
        pod_selector {
          match_labels = {
            "app.kubernetes.io/instance"  = "agentgate-postgresql"
            "app.kubernetes.io/name"      = "postgresql"
            "app.kubernetes.io/component" = "primary"
          }
        }
      }

      ports {
        port     = "5432"
        protocol = "TCP"
      }
    }
  }
}

resource "kubernetes_network_policy_v1" "spire_default_deny" {
  metadata {
    name      = "default-deny"
    namespace = data.kubernetes_namespace_v1.spire.metadata[0].name
  }

  spec {
    pod_selector {}
    policy_types = ["Ingress", "Egress"]
  }
}

resource "kubernetes_network_policy_v1" "spire_internal" {
  metadata {
    name      = "spire-internal"
    namespace = data.kubernetes_namespace_v1.spire.metadata[0].name
  }

  spec {
    pod_selector {}
    policy_types = ["Ingress", "Egress"]

    ingress {
      from {
        namespace_selector {
          match_labels = {
            "kubernetes.io/metadata.name" = var.spire_namespace
          }
        }
      }
    }

    ingress {
      from {
        ip_block {
          cidr = local.vpc_cidr
        }
      }

      ports {
        port     = "8008"
        protocol = "TCP"
      }
      ports {
        port     = "8080"
        protocol = "TCP"
      }
      ports {
        port     = "8081"
        protocol = "TCP"
      }
      ports {
        port     = "9443"
        protocol = "TCP"
      }
      ports {
        port     = "9809"
        protocol = "TCP"
      }
      ports {
        port     = "9982"
        protocol = "TCP"
      }
    }

    egress {
      to {
        namespace_selector {
          match_labels = {
            "kubernetes.io/metadata.name" = var.spire_namespace
          }
        }
      }
    }

    egress {
      to {
        namespace_selector {
          match_labels = {
            "kubernetes.io/metadata.name" = "kube-system"
          }
        }
        pod_selector {
          match_labels = {
            "k8s-app" = "kube-dns"
          }
        }
      }

      ports {
        port     = "53"
        protocol = "UDP"
      }
      ports {
        port     = "53"
        protocol = "TCP"
      }
    }

    egress {
      to {
        ip_block {
          cidr = local.service_cidr
        }
      }
      to {
        ip_block {
          cidr = local.vpc_cidr
        }
      }

      ports {
        port     = "443"
        protocol = "TCP"
      }
    }

    egress {
      to {
        namespace_selector {
          match_labels = {
            "kubernetes.io/metadata.name" = var.platform_namespace
          }
        }
        pod_selector {
          match_labels = {
            "app.kubernetes.io/instance"  = "agentgate-postgresql"
            "app.kubernetes.io/name"      = "postgresql"
            "app.kubernetes.io/component" = "primary"
          }
        }
      }

      ports {
        port     = "5432"
        protocol = "TCP"
      }
    }
  }
}

resource "kubernetes_network_policy_v1" "spire_oidc_vault" {
  metadata {
    name      = "spire-oidc-vault"
    namespace = data.kubernetes_namespace_v1.spire.metadata[0].name
  }

  spec {
    pod_selector {
      match_labels = {
        "component"         = "oidc-discovery-provider"
        "release"           = "spire"
        "release-namespace" = var.spire_namespace
      }
    }

    policy_types = ["Ingress"]

    ingress {
      from {
        namespace_selector {
          match_labels = {
            "kubernetes.io/metadata.name" = var.vault_namespace
          }
        }
        pod_selector {
          match_labels = {
            "app.kubernetes.io/name"     = "vault"
            "app.kubernetes.io/instance" = "vault"
            "component"                  = "server"
          }
        }
      }

      ports {
        port     = "8443"
        protocol = "TCP"
      }
    }
  }
}

resource "kubernetes_network_policy_v1" "vault_default_deny" {
  metadata {
    name      = "default-deny"
    namespace = data.kubernetes_namespace_v1.vault.metadata[0].name
  }

  spec {
    pod_selector {}
    policy_types = ["Ingress", "Egress"]
  }
}
