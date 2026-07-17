resource "kubernetes_deployment_v1" "agentgate" {
  wait_for_rollout = false

  metadata {
    name      = "agentgate"
    namespace = kubernetes_namespace_v1.agentgate.metadata[0].name
    labels    = local.agentgate_labels
  }

  spec {
    replicas = var.agentgate_replicas

    selector {
      match_labels = local.agentgate_labels
    }

    strategy {
      type = "RollingUpdate"

      rolling_update {
        max_surge       = "1"
        max_unavailable = "0"
      }
    }

    template {
      metadata {
        labels = local.agentgate_labels
        annotations = {
          "checksum/spiffe-helper"        = sha256(kubernetes_config_map_v1.agentgate_spiffe_helper.data["helper.conf"])
          "agentgate.dev/embedded-policy" = filesha256("${path.module}/../../policies/authorization.rego")
        }
      }

      spec {
        service_account_name             = kubernetes_service_account_v1.agentgate.metadata[0].name
        automount_service_account_token  = false
        termination_grace_period_seconds = 30

        security_context {
          fs_group               = 65532
          fs_group_change_policy = "OnRootMismatch"
          run_as_group           = 65532
          run_as_non_root        = true
          run_as_user            = 65532

          seccomp_profile {
            type = "RuntimeDefault"
          }
        }

        topology_spread_constraint {
          max_skew           = 1
          topology_key       = "kubernetes.io/hostname"
          when_unsatisfiable = "DoNotSchedule"

          label_selector {
            match_labels = local.agentgate_labels
          }
        }

        init_container {
          name              = "spiffe-helper-init"
          image             = local.spiffe_helper_image
          image_pull_policy = "IfNotPresent"
          args = [
            "-config",
            "/etc/spiffe-helper/helper.conf",
            "-daemon-mode=false",
          ]

          resources {
            requests = {
              cpu    = "10m"
              memory = "16Mi"
            }
            limits = {
              cpu    = "100m"
              memory = "64Mi"
            }
          }

          security_context {
            allow_privilege_escalation = false
            privileged                 = false
            read_only_root_filesystem  = true
            run_as_group               = 65532
            run_as_non_root            = true
            run_as_user                = 65532

            capabilities {
              drop = ["ALL"]
            }
          }

          volume_mount {
            name       = "spiffe-helper-config"
            mount_path = "/etc/spiffe-helper"
            read_only  = true
          }

          volume_mount {
            name       = "spiffe-tls"
            mount_path = "/run/agentgate/tls"
          }

          volume_mount {
            name       = "spiffe-workload-api"
            mount_path = "/run/spire/sockets"
            read_only  = true
          }
        }

        container {
          name              = "agentgate"
          image             = var.application_image
          image_pull_policy = "IfNotPresent"
          command           = ["/usr/local/bin/agentgate"]
          args              = local.agentgate_args

          port {
            name           = "https"
            container_port = 8443
            protocol       = "TCP"
          }

          env {
            name  = "SPIFFE_ENDPOINT_SOCKET"
            value = local.spire_workload_api_socket
          }

          env {
            name = "AGENTGATE_DATABASE_URL"
            value_from {
              secret_key_ref {
                name = var.postgresql_password_secret_name
                key  = "database-url"
              }
            }
          }

          env {
            name = "AGENTGATE_APPROVAL_WEBHOOK_URL"
            value_from {
              secret_key_ref {
                name = var.approver_token_secret_name
                key  = "webhook-url"
              }
            }
          }

          dynamic "env" {
            for_each = var.human_auth_mode == "poc-static" ? [1] : []

            content {
              name = "AGENTGATE_POC_APPROVER_TOKEN"
              value_from {
                secret_key_ref {
                  name = var.approver_token_secret_name
                  key  = "token"
                }
              }
            }
          }

          resources {
            requests = {
              cpu    = "100m"
              memory = "128Mi"
            }
            limits = {
              cpu    = "500m"
              memory = "512Mi"
            }
          }

          security_context {
            allow_privilege_escalation = false
            privileged                 = false
            read_only_root_filesystem  = true
            run_as_group               = 65532
            run_as_non_root            = true
            run_as_user                = 65532

            capabilities {
              drop = ["ALL"]
            }
          }

          startup_probe {
            http_get {
              path   = "/livez"
              port   = "https"
              scheme = "HTTPS"
            }
            failure_threshold = 30
            period_seconds    = 2
            timeout_seconds   = 1
          }

          liveness_probe {
            http_get {
              path   = "/livez"
              port   = "https"
              scheme = "HTTPS"
            }
            failure_threshold     = 3
            period_seconds        = 10
            timeout_seconds       = 2
            initial_delay_seconds = 5
          }

          readiness_probe {
            http_get {
              path   = "/readyz"
              port   = "https"
              scheme = "HTTPS"
            }
            failure_threshold     = 3
            period_seconds        = 5
            timeout_seconds       = 2
            initial_delay_seconds = 2
          }

          volume_mount {
            name       = "dispatcher-public-key"
            mount_path = "/etc/agentgate/dispatcher"
            read_only  = true
          }

          volume_mount {
            name       = "spiffe-tls"
            mount_path = "/run/agentgate/tls"
            read_only  = true
          }

          volume_mount {
            name       = "spiffe-workload-api"
            mount_path = "/run/spire/sockets"
            read_only  = true
          }

          volume_mount {
            name       = "tmp"
            mount_path = "/tmp"
          }
        }

        container {
          name              = "spiffe-helper"
          image             = local.spiffe_helper_image
          image_pull_policy = "IfNotPresent"
          args = [
            "-config",
            "/etc/spiffe-helper/helper.conf",
          ]

          port {
            name           = "helper-health"
            container_port = 8081
            protocol       = "TCP"
          }

          resources {
            requests = {
              cpu    = "10m"
              memory = "16Mi"
            }
            limits = {
              cpu    = "100m"
              memory = "64Mi"
            }
          }

          security_context {
            allow_privilege_escalation = false
            privileged                 = false
            read_only_root_filesystem  = true
            run_as_group               = 65532
            run_as_non_root            = true
            run_as_user                = 65532

            capabilities {
              drop = ["ALL"]
            }
          }

          liveness_probe {
            http_get {
              path   = "/live"
              port   = "helper-health"
              scheme = "HTTP"
            }
            failure_threshold     = 3
            period_seconds        = 10
            timeout_seconds       = 2
            initial_delay_seconds = 5
          }

          readiness_probe {
            http_get {
              path   = "/ready"
              port   = "helper-health"
              scheme = "HTTP"
            }
            failure_threshold     = 3
            period_seconds        = 5
            timeout_seconds       = 2
            initial_delay_seconds = 2
          }

          volume_mount {
            name       = "spiffe-helper-config"
            mount_path = "/etc/spiffe-helper"
            read_only  = true
          }

          volume_mount {
            name       = "spiffe-tls"
            mount_path = "/run/agentgate/tls"
          }

          volume_mount {
            name       = "spiffe-workload-api"
            mount_path = "/run/spire/sockets"
            read_only  = true
          }
        }

        volume {
          name = "dispatcher-public-key"
          config_map {
            name         = var.dispatcher_public_key_config_map_name
            default_mode = "0444"
          }
        }

        volume {
          name = "spiffe-helper-config"
          config_map {
            name         = kubernetes_config_map_v1.agentgate_spiffe_helper.metadata[0].name
            default_mode = "0444"
          }
        }

        volume {
          name = "spiffe-tls"
          empty_dir {
            size_limit = "16Mi"
          }
        }

        volume {
          name = "spiffe-workload-api"
          csi {
            driver    = local.spire_workload_api_driver
            read_only = true
          }
        }

        volume {
          name = "tmp"
          empty_dir {
            size_limit = "64Mi"
          }
        }
      }
    }
  }

  depends_on = [kubernetes_manifest.agentgate_spiffe_id]
}

resource "kubernetes_service_v1" "agentgate" {
  metadata {
    name      = "agentgate"
    namespace = kubernetes_namespace_v1.agentgate.metadata[0].name
    labels    = local.agentgate_labels
  }

  spec {
    selector = local.agentgate_labels
    type     = "ClusterIP"

    port {
      name        = "workload-mtls"
      port        = 8443
      target_port = "https"
      protocol    = "TCP"
    }
  }
}

resource "kubernetes_pod_disruption_budget_v1" "agentgate" {
  metadata {
    name      = "agentgate"
    namespace = kubernetes_namespace_v1.agentgate.metadata[0].name
    labels    = local.agentgate_labels
  }

  spec {
    min_available = "1"

    selector {
      match_labels = local.agentgate_labels
    }
  }
}
