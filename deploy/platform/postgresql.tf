resource "kubernetes_config_map_v1" "postgresql_init" {
  metadata {
    name      = "agentgate-postgresql-init"
    namespace = data.kubernetes_namespace_v1.platform.metadata[0].name
    labels = {
      "app.kubernetes.io/name"       = "agentgate-postgresql-init"
      "app.kubernetes.io/part-of"    = "agentgate"
      "app.kubernetes.io/managed-by" = "terraform"
    }
  }

  data = {
    "00-create-spire.sql" = <<-SQL
      SELECT 'CREATE DATABASE spire OWNER agentgate'
      WHERE NOT EXISTS (SELECT FROM pg_database WHERE datname = 'spire')\gexec
    SQL
  }
}

resource "helm_release" "postgresql" {
  name       = "agentgate-postgresql"
  namespace  = data.kubernetes_namespace_v1.platform.metadata[0].name
  repository = "oci://registry-1.docker.io/bitnamicharts"
  chart      = "postgresql"
  version    = local.chart_versions.postgresql

  atomic          = true
  cleanup_on_fail = true
  timeout         = 600
  wait            = true
  wait_for_jobs   = true

  values = [
    file("${path.module}/helm-values/postgresql.yaml"),
    yamlencode({
      auth = {
        existingSecret = var.postgresql_credentials_secret_name
      }
      primary = {
        initdb = {
          scriptsConfigMap = kubernetes_config_map_v1.postgresql_init.metadata[0].name
        }
      }
    }),
  ]

  depends_on = [
    kubernetes_network_policy_v1.platform_default_deny,
    kubernetes_storage_class_v1.gp3,
  ]
}

resource "kubernetes_config_map_v1" "agentgate_migrations" {
  metadata {
    name      = "agentgate-migrations"
    namespace = data.kubernetes_namespace_v1.platform.metadata[0].name
    labels = {
      "app.kubernetes.io/name"       = "agentgate-migrations"
      "app.kubernetes.io/part-of"    = "agentgate"
      "app.kubernetes.io/managed-by" = "terraform"
    }
  }

  data = {
    "000001_foundation.up.sql"        = file("${path.module}/../../internal/audit/migrations/000001_foundation.up.sql")
    "000002_expiring_bindings.up.sql" = file("${path.module}/../../internal/audit/migrations/000002_expiring_bindings.up.sql")
  }
}

resource "kubernetes_job_v1" "agentgate_migrations" {
  metadata {
    name      = "agentgate-migrations-v2"
    namespace = data.kubernetes_namespace_v1.platform.metadata[0].name
    labels = {
      "app.kubernetes.io/name"       = "agentgate-migrations"
      "app.kubernetes.io/part-of"    = "agentgate"
      "app.kubernetes.io/managed-by" = "terraform"
    }
  }

  spec {
    backoff_limit = 3

    template {
      metadata {
        labels = {
          "app.kubernetes.io/name"    = "agentgate-migrations"
          "app.kubernetes.io/part-of" = "agentgate"
        }
      }

      spec {
        automount_service_account_token = false
        restart_policy                  = "OnFailure"

        security_context {
          fs_group               = 1001
          fs_group_change_policy = "OnRootMismatch"
          run_as_group           = 1001
          run_as_non_root        = true
          run_as_user            = 1001

          seccomp_profile {
            type = "RuntimeDefault"
          }
        }

        container {
          name  = "migrate"
          image = "registry-1.docker.io/bitnami/postgresql@sha256:db2312d9b243afa8c3b3f5496e478d17d0dff9791d06f3b93b9567abd86ae92f"

          command = ["/bin/bash", "-ec"]
          args = [<<-SHELL
            if [[ "$(psql -tAc "SELECT to_regclass('public.access_requests') IS NOT NULL")" != "t" ]]; then
              psql -v ON_ERROR_STOP=1 -f /migrations/000001_foundation.up.sql
            fi
            if [[ "$(psql -tAc "SELECT position('revoking' IN pg_get_constraintdef(oid)) > 0 FROM pg_constraint WHERE conname = 'access_requests_binding_state_check' AND conrelid = 'access_requests'::regclass")" != "t" ]]; then
              psql -v ON_ERROR_STOP=1 -f /migrations/000002_expiring_bindings.up.sql
            fi
          SHELL
          ]

          env {
            name  = "PGDATABASE"
            value = "agentgate"
          }
          env {
            name  = "PGHOST"
            value = local.postgresql_service
          }
          env {
            name  = "PGPORT"
            value = "5432"
          }
          env {
            name  = "PGUSER"
            value = "agentgate"
          }
          env {
            name = "PGPASSWORD"
            value_from {
              secret_key_ref {
                name = var.postgresql_credentials_secret_name
                key  = "password"
              }
            }
          }

          resources {
            limits = {
              cpu    = "250m"
              memory = "256Mi"
            }
            requests = {
              cpu    = "50m"
              memory = "64Mi"
            }
          }

          security_context {
            allow_privilege_escalation = false
            privileged                 = false
            read_only_root_filesystem  = true
            run_as_non_root            = true

            capabilities {
              drop = ["ALL"]
            }
          }

          volume_mount {
            name       = "migrations"
            mount_path = "/migrations"
            read_only  = true
          }

          volume_mount {
            name       = "tmp"
            mount_path = "/tmp"
          }
        }

        volume {
          name = "migrations"
          config_map {
            name = kubernetes_config_map_v1.agentgate_migrations.metadata[0].name
          }
        }

        volume {
          name = "tmp"
          empty_dir {}
        }
      }
    }
  }

  wait_for_completion = true

  timeouts {
    create = "10m"
    update = "10m"
  }

  depends_on = [helm_release.postgresql]
}
