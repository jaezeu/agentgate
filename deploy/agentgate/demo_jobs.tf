resource "kubernetes_manifest" "dispatcher_demo" {
  manifest = {
    apiVersion = "batch/v1"
    kind       = "Job"
    metadata = {
      name      = "agentgate-demo-dispatcher"
      namespace = kubernetes_namespace_v1.runner.metadata[0].name
      labels    = local.dispatcher_labels
    }
    spec = {
      suspend                 = true
      backoffLimit            = 0
      activeDeadlineSeconds   = 300
      ttlSecondsAfterFinished = 3600
      template = {
        metadata = {
          labels = local.dispatcher_labels
        }
        spec = {
          serviceAccountName           = kubernetes_service_account_v1.dispatcher.metadata[0].name
          automountServiceAccountToken = false
          restartPolicy                = "Never"
          securityContext = {
            fsGroup             = 65532
            fsGroupChangePolicy = "OnRootMismatch"
            runAsGroup          = 65532
            runAsNonRoot        = true
            runAsUser           = 65532
            seccompProfile = {
              type = "RuntimeDefault"
            }
          }
          containers = [
            {
              name            = "orchestrator-stub"
              image           = var.application_image
              imagePullPolicy = "IfNotPresent"
              command         = ["/usr/local/bin/orchestrator-stub"]
              args = [
                "--private-key=/var/run/agentgate/dispatcher/dispatcher-private.pem",
                "--repo=${var.demo_repository}",
                "--commit-sha=${var.demo_commit_sha}",
                "--operation=terraform-plan",
                "--environment=dev",
                "--vault-role=${local.vault_demo_role_name}",
                "--ttl=15m",
                "--on-behalf-of=${var.demo_on_behalf_of}",
                "--ticket-id=${var.demo_ticket_id}",
              ]
              resources = {
                requests = {
                  cpu    = "25m"
                  memory = "32Mi"
                }
                limits = {
                  cpu    = "100m"
                  memory = "64Mi"
                }
              }
              securityContext = {
                allowPrivilegeEscalation = false
                privileged               = false
                readOnlyRootFilesystem   = true
                runAsGroup               = 65532
                runAsNonRoot             = true
                runAsUser                = 65532
                capabilities = {
                  drop = ["ALL"]
                }
              }
              volumeMounts = [
                {
                  name      = "dispatcher-private-key"
                  mountPath = "/var/run/agentgate/dispatcher"
                  readOnly  = true
                },
                {
                  name      = "tmp"
                  mountPath = "/tmp"
                },
              ]
            },
          ]
          volumes = [
            {
              name = "dispatcher-private-key"
              secret = {
                secretName  = var.dispatcher_private_key_secret_name
                defaultMode = 256
              }
            },
            {
              name = "tmp"
              emptyDir = {
                sizeLimit = "16Mi"
              }
            },
          ]
        }
      }
    }
  }
}

resource "kubernetes_manifest" "agent_sim_demo" {
  manifest = {
    apiVersion = "batch/v1"
    kind       = "Job"
    metadata = {
      name      = "agentgate-demo-runner"
      namespace = kubernetes_namespace_v1.runner.metadata[0].name
      labels    = local.runner_labels
    }
    spec = {
      suspend                 = true
      backoffLimit            = 0
      activeDeadlineSeconds   = 900
      ttlSecondsAfterFinished = 3600
      template = {
        metadata = {
          labels = local.runner_labels
        }
        spec = {
          serviceAccountName           = kubernetes_service_account_v1.runner.metadata[0].name
          automountServiceAccountToken = false
          restartPolicy                = "Never"
          securityContext = {
            fsGroup             = 65532
            fsGroupChangePolicy = "OnRootMismatch"
            runAsGroup          = 65532
            runAsNonRoot        = true
            runAsUser           = 65532
            seccompProfile = {
              type = "RuntimeDefault"
            }
          }
          containers = [
            {
              name            = "agent-sim"
              image           = var.application_image
              imagePullPolicy = "IfNotPresent"
              command         = ["/usr/local/bin/agent-sim"]
              args = [
                "--agentgate-url=${local.agentgate_url}/v1/access-requests",
                "--agentgate-id=${local.agentgate_spiffe_id}",
                "--grant-file=/var/run/agentgate/grant/grant.json",
                "--vault-role=${local.vault_demo_role_name}",
                "--vault-tls-server-name=${local.vault_server_name}",
                "--terraform-bin=/usr/local/bin/terraform",
                "--terraform-work-root=/workspace",
                "--aws-region=${local.aws_region}",
                "--demo-bucket=${local.demo_bucket_name}",
                "--demo-prefix=${local.demo_bucket_prefix}",
                "--timeout=14m",
              ]
              env = [
                {
                  name  = "SPIFFE_ENDPOINT_SOCKET"
                  value = "unix:///run/spire/sockets/spire-agent.sock"
                },
              ]
              resources = {
                requests = {
                  cpu    = "100m"
                  memory = "128Mi"
                }
                limits = {
                  cpu    = "500m"
                  memory = "512Mi"
                }
              }
              securityContext = {
                allowPrivilegeEscalation = false
                privileged               = false
                readOnlyRootFilesystem   = true
                runAsGroup               = 65532
                runAsNonRoot             = true
                runAsUser                = 65532
                capabilities = {
                  drop = ["ALL"]
                }
              }
              volumeMounts = [
                {
                  name      = "task-grant"
                  mountPath = "/var/run/agentgate/grant"
                  readOnly  = true
                },
                {
                  name      = "spiffe-workload-api"
                  mountPath = "/run/spire/sockets"
                  readOnly  = true
                },
                {
                  name      = "tmp"
                  mountPath = "/tmp"
                },
                {
                  name      = "terraform-work"
                  mountPath = "/workspace"
                },
              ]
            },
          ]
          volumes = [
            {
              name = "task-grant"
              secret = {
                secretName  = var.demo_grant_secret_name
                defaultMode = 256
              }
            },
            {
              name = "spiffe-workload-api"
              csi = {
                driver   = local.spire_workload_api_driver
                readOnly = true
              }
            },
            {
              name = "tmp"
              emptyDir = {
                sizeLimit = "128Mi"
              }
            },
            {
              name = "terraform-work"
              emptyDir = {
                sizeLimit = "2Gi"
              }
            },
          ]
        }
      }
    }
  }

  depends_on = [kubernetes_manifest.runner_spiffe_id]
}
