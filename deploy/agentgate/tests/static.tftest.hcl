mock_provider "aws" {}
mock_provider "kubernetes" {}

run "static_plan" {
  command = plan

  variables {
    hcp_terraform_organization = "agentgate-static-validation"
    application_image          = "ghcr.io/example/agentgate:v0.0.0@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
  }

  override_data {
    target = data.terraform_remote_state.infra
    values = {
      outputs = {
        aws_region                         = "us-west-2"
        demo_bucket_name                   = "agentgate-demo-static"
        demo_bucket_prefix                 = "governed/"
        cluster_name                       = "agentgate-sandbox-eks"
        cluster_endpoint                   = "https://example.eks.amazonaws.com"
        cluster_certificate_authority_data = "dGVzdA=="
      }
    }
  }

  override_data {
    target = data.terraform_remote_state.platform
    values = {
      outputs = {
        spire_trust_domain            = "sandbox.agentgate.test"
        spire_controller_class        = "spire-system-spire"
        spire_workload_api_csi_driver = "csi.spiffe.io"
        vault_address                 = "https://vault.vault.svc.cluster.local:8200"
        vault_auth_mount              = "spire-jwt"
        vault_aws_mount               = "aws"
        vault_demo_role_name          = "terraform-sandbox"
        postgresql_service            = "agentgate-postgresql.agentgate-platform.svc.cluster.local"
        postgresql_database           = "agentgate"
        postgresql_username           = "agentgate"
        platform_namespace            = "agentgate-platform"
        vault_namespace               = "vault"
      }
    }
  }

  assert {
    condition     = kubernetes_deployment_v1.agentgate.spec[0].replicas == "2"
    error_message = "AgentGate must default to two replicas."
  }

  assert {
    condition = (
      kubernetes_deployment_v1.agentgate.spec[0].template[0].spec[0].automount_service_account_token == false &&
      kubernetes_deployment_v1.agentgate.spec[0].template[0].spec[0].container[0].security_context[0].read_only_root_filesystem &&
      kubernetes_deployment_v1.agentgate.spec[0].template[0].spec[0].container[0].security_context[0].run_as_non_root &&
      kubernetes_deployment_v1.agentgate.spec[0].template[0].spec[0].container[0].security_context[0].allow_privilege_escalation == false
    )
    error_message = "AgentGate pod and container hardening must remain enabled."
  }

  assert {
    condition = (
      length(kubernetes_deployment_v1.agentgate.spec[0].template[0].spec[0].container[0].liveness_probe) == 1 &&
      length(kubernetes_deployment_v1.agentgate.spec[0].template[0].spec[0].container[0].readiness_probe) == 1 &&
      kubernetes_deployment_v1.agentgate.spec[0].template[0].spec[0].container[0].liveness_probe[0].http_get[0].scheme == "HTTPS" &&
      kubernetes_deployment_v1.agentgate.spec[0].template[0].spec[0].container[0].resources[0].requests["cpu"] == "100m" &&
      kubernetes_deployment_v1.agentgate.spec[0].template[0].spec[0].container[0].resources[0].limits["memory"] == "512Mi"
    )
    error_message = "AgentGate probes and bounded resources must remain configured."
  }

  assert {
    condition = (
      length(kubernetes_deployment_v1.agentgate.spec[0].template[0].spec[0].init_container) == 1 &&
      length(kubernetes_deployment_v1.agentgate.spec[0].template[0].spec[0].container) == 2 &&
      kubernetes_deployment_v1.agentgate.spec[0].template[0].spec[0].init_container[0].image == "ghcr.io/spiffe/spiffe-helper@sha256:2759b3a699bb63b91cc5896f46cd6f70b9e3dfed9f7f4355a3a0a4e702984f9c" &&
      kubernetes_deployment_v1.agentgate.spec[0].template[0].spec[0].container[1].image == "ghcr.io/spiffe/spiffe-helper@sha256:2759b3a699bb63b91cc5896f46cd6f70b9e3dfed9f7f4355a3a0a4e702984f9c" &&
      length(kubernetes_deployment_v1.agentgate.spec[0].template[0].spec[0].container[1].liveness_probe) == 1 &&
      length(kubernetes_deployment_v1.agentgate.spec[0].template[0].spec[0].container[1].readiness_probe) == 1
    )
    error_message = "AgentGate must fetch and continuously rotate its server X509-SVID with the reviewed helper image."
  }

  assert {
    condition = (
      contains(kubernetes_deployment_v1.agentgate.spec[0].template[0].spec[0].container[0].args, "--listen=:8443") &&
      contains(kubernetes_deployment_v1.agentgate.spec[0].template[0].spec[0].container[0].args, "--tls-cert=/run/agentgate/tls/tls.crt") &&
      contains(kubernetes_deployment_v1.agentgate.spec[0].template[0].spec[0].container[0].args, "--vault-management-role=agentgate-manager") &&
      contains(kubernetes_deployment_v1.agentgate.spec[0].template[0].spec[0].container[0].args, "--poc-static-human-auth") &&
      contains(
        [for environment in kubernetes_deployment_v1.agentgate.spec[0].template[0].spec[0].container[0].env : environment.name],
        "AGENTGATE_DATABASE_URL",
      )
    )
    error_message = "AgentGate must consume the verified API, mTLS, database, human, and Vault configuration contracts."
  }

  assert {
    condition     = kubernetes_pod_disruption_budget_v1.agentgate.spec[0].min_available == "1"
    error_message = "AgentGate must retain one available replica during voluntary disruption."
  }

  assert {
    condition     = kubernetes_manifest.dispatcher_demo.manifest.spec.suspend
    error_message = "Dispatcher demo Job must remain suspended."
  }

  assert {
    condition     = kubernetes_manifest.agent_sim_demo.manifest.spec.suspend
    error_message = "Runner demo Job must remain suspended."
  }

  assert {
    condition = (
      contains(kubernetes_manifest.agent_sim_demo.manifest.spec.template.spec.containers[0].args, "--terraform-bin=/usr/local/bin/terraform") &&
      contains(kubernetes_manifest.agent_sim_demo.manifest.spec.template.spec.containers[0].args, "--terraform-work-root=/workspace") &&
      contains(kubernetes_manifest.agent_sim_demo.manifest.spec.template.spec.containers[0].args, "--aws-region=us-west-2") &&
      contains(kubernetes_manifest.agent_sim_demo.manifest.spec.template.spec.containers[0].args, "--demo-bucket=agentgate-demo-static") &&
      contains(kubernetes_manifest.agent_sim_demo.manifest.spec.template.spec.containers[0].args, "--demo-prefix=governed/") &&
      contains(kubernetes_manifest.agent_sim_demo.manifest.spec.template.spec.containers[0].args, "--vault-tls-server-name=vault.vault.svc.cluster.local") &&
      contains(
        [for mount in kubernetes_manifest.agent_sim_demo.manifest.spec.template.spec.containers[0].volumeMounts : mount.mountPath],
        "/workspace",
      )
    )
    error_message = "Runner demo Job must wire direct Vault TLS and the bounded Terraform target."
  }

  assert {
    condition     = output.runner_spiffe_id == "spiffe://sandbox.agentgate.test/ns/agentgate-sandbox/sa/terraform-runner"
    error_message = "Runner identity must match the embedded policy."
  }

  assert {
    condition = (
      kubernetes_manifest.runner_spiffe_id.manifest.spec.workloadSelectorTemplates == [
        "k8s:ns:agentgate-sandbox",
        "k8s:sa:terraform-runner",
      ] &&
      kubernetes_manifest.runner_spiffe_id.manifest.spec.jwtTtl == "5m"
    )
    error_message = "Runner registration must retain exact selectors and a five-minute JWT TTL."
  }
}
