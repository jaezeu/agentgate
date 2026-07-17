resource "kubernetes_network_policy_v1" "agentgate_default_deny" {
  metadata {
    name      = "default-deny"
    namespace = kubernetes_namespace_v1.agentgate.metadata[0].name
  }

  spec {
    pod_selector {}
    policy_types = ["Ingress", "Egress"]
  }
}

resource "kubernetes_network_policy_v1" "runner_default_deny" {
  metadata {
    name      = "default-deny"
    namespace = kubernetes_namespace_v1.runner.metadata[0].name
  }

  spec {
    pod_selector {}
    policy_types = ["Ingress", "Egress"]
  }
}

resource "kubernetes_network_policy_v1" "agentgate" {
  metadata {
    name      = "agentgate"
    namespace = kubernetes_namespace_v1.agentgate.metadata[0].name
  }

  spec {
    pod_selector {
      match_labels = local.agentgate_labels
    }

    policy_types = ["Ingress", "Egress"]

    ingress {
      from {
        namespace_selector {
          match_labels = {
            "kubernetes.io/metadata.name" = var.runner_namespace
          }
        }
        pod_selector {
          match_labels = local.runner_labels
        }
      }

      ports {
        port     = "8443"
        protocol = "TCP"
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
        namespace_selector {
          match_labels = {
            "kubernetes.io/metadata.name" = data.terraform_remote_state.platform.outputs.platform_namespace
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

    egress {
      to {
        namespace_selector {
          match_labels = {
            "kubernetes.io/metadata.name" = data.terraform_remote_state.platform.outputs.vault_namespace
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
        port     = "8200"
        protocol = "TCP"
      }
    }

    egress {
      to {
        ip_block {
          cidr = "0.0.0.0/0"
          except = [
            "10.0.0.0/8",
            "100.64.0.0/10",
            "169.254.0.0/16",
            "172.16.0.0/12",
            "192.168.0.0/16",
          ]
        }
      }

      ports {
        port     = "443"
        protocol = "TCP"
      }
    }
  }
}

resource "kubernetes_network_policy_v1" "runner" {
  metadata {
    name      = "governed-runner"
    namespace = kubernetes_namespace_v1.runner.metadata[0].name
  }

  spec {
    pod_selector {
      match_labels = local.runner_labels
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
        namespace_selector {
          match_labels = {
            "kubernetes.io/metadata.name" = var.agentgate_namespace
          }
        }
        pod_selector {
          match_labels = local.agentgate_labels
        }
      }

      ports {
        port     = "8443"
        protocol = "TCP"
      }
    }

    egress {
      to {
        namespace_selector {
          match_labels = {
            "kubernetes.io/metadata.name" = data.terraform_remote_state.platform.outputs.vault_namespace
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
        port     = "8200"
        protocol = "TCP"
      }
    }

    egress {
      to {
        ip_block {
          cidr = "0.0.0.0/0"
          except = [
            "10.0.0.0/8",
            "100.64.0.0/10",
            "169.254.0.0/16",
            "172.16.0.0/12",
            "192.168.0.0/16",
          ]
        }
      }

      ports {
        port     = "443"
        protocol = "TCP"
      }
    }
  }
}
