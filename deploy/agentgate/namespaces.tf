locals {
  namespace_labels = {
    "app.kubernetes.io/part-of"                  = "agentgate"
    "app.kubernetes.io/managed-by"               = "terraform"
    "pod-security.kubernetes.io/enforce"         = "restricted"
    "pod-security.kubernetes.io/enforce-version" = "v1.36"
    "pod-security.kubernetes.io/audit"           = "restricted"
    "pod-security.kubernetes.io/audit-version"   = "v1.36"
    "pod-security.kubernetes.io/warn"            = "restricted"
    "pod-security.kubernetes.io/warn-version"    = "v1.36"
  }
}

resource "kubernetes_namespace_v1" "agentgate" {
  metadata {
    name   = var.agentgate_namespace
    labels = local.namespace_labels
  }
}

resource "kubernetes_namespace_v1" "runner" {
  metadata {
    name   = var.runner_namespace
    labels = local.namespace_labels
  }
}

resource "kubernetes_service_account_v1" "agentgate" {
  metadata {
    name      = var.agentgate_service_account_name
    namespace = kubernetes_namespace_v1.agentgate.metadata[0].name
    labels    = local.agentgate_labels
  }

  automount_service_account_token = false
}

resource "kubernetes_service_account_v1" "runner" {
  metadata {
    name      = var.runner_service_account_name
    namespace = kubernetes_namespace_v1.runner.metadata[0].name
    labels    = local.runner_labels
  }

  automount_service_account_token = false
}

resource "kubernetes_service_account_v1" "dispatcher" {
  metadata {
    name      = var.dispatcher_service_account_name
    namespace = kubernetes_namespace_v1.runner.metadata[0].name
    labels    = local.dispatcher_labels
  }

  automount_service_account_token = false
}
