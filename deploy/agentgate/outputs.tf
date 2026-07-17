output "agentgate_namespace" {
  description = "Namespace containing the AgentGate control plane."
  value       = kubernetes_namespace_v1.agentgate.metadata[0].name
}

output "runner_namespace" {
  description = "Namespace containing the governed runner."
  value       = kubernetes_namespace_v1.runner.metadata[0].name
}

output "agentgate_service" {
  description = "In-cluster AgentGate Service DNS name."
  value       = "agentgate.${var.agentgate_namespace}.svc.${var.cluster_domain}"
}

output "agentgate_spiffe_id" {
  description = "Exact SPIFFE ID assigned to the AgentGate control plane."
  value       = local.agentgate_spiffe_id
}

output "runner_spiffe_id" {
  description = "Exact SPIFFE ID assigned to the governed Terraform runner."
  value       = local.runner_spiffe_id
}

output "demo_jobs" {
  description = "Suspended PoC Jobs; operators unsuspend them only through the documented verification helper."
  value = {
    dispatcher = "agentgate-demo-dispatcher"
    runner     = "agentgate-demo-runner"
  }
}
