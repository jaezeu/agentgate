resource "kubernetes_config_map_v1" "agentgate_spiffe_helper" {
  metadata {
    name      = "agentgate-spiffe-helper"
    namespace = kubernetes_namespace_v1.agentgate.metadata[0].name
    labels    = local.agentgate_labels
  }

  data = {
    "helper.conf" = <<-HCL
      agent_address = "/run/spire/sockets/spire-agent.sock"
      cert_dir = "/run/agentgate/tls"
      svid_file_name = "tls.crt"
      svid_key_file_name = "tls.key"
      svid_bundle_file_name = "ca.pem"
      add_intermediates_to_bundle = true
      cert_file_mode = 0444
      key_file_mode = 0400
      health_checks {
        listener_enabled = true
        bind_port = 8081
        liveness_path = "/live"
        readiness_path = "/ready"
      }
    HCL
  }
}
