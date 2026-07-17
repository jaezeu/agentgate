#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck disable=SC1091
source "${SCRIPT_DIR}/lib/common.sh"

for command_name in jq kubectl; do
  require_command "${command_name}"
done
verify_aws_identity
verify_kubernetes_context

kubectl rollout status statefulset/agentgate-postgresql \
  --namespace agentgate-platform \
  --timeout=180s
kubectl rollout status statefulset/spire-server \
  --namespace spire-system \
  --timeout=180s
kubectl rollout status daemonset/spire-agent \
  --namespace spire-system \
  --timeout=180s
kubectl rollout status statefulset/vault \
  --namespace vault \
  --timeout=180s
kubectl rollout status deployment/agentgate \
  --namespace agentgate \
  --timeout=180s

agentgate_identity="$(kubectl get clusterspiffeid agentgate-control-plane -o json)"
runner_identity="$(kubectl get clusterspiffeid agentgate-terraform-runner -o json)"
agentgate_deployment="$(kubectl get deployment agentgate --namespace agentgate -o json)"
runner_job="$(kubectl get job agentgate-demo-runner --namespace agentgate-sandbox -o json)"

jq -e '
  .spec.spiffeIDTemplate == "spiffe://sandbox.agentgate.test/ns/agentgate/sa/agentgate" and
  .spec.workloadSelectorTemplates == ["k8s:ns:agentgate", "k8s:sa:agentgate"] and
  .spec.jwtTtl == "5m"
' <<<"${agentgate_identity}" >/dev/null ||
  die "AgentGate ClusterSPIFFEID does not have the reviewed exact selectors"

jq -e '
  .spec.spiffeIDTemplate == "spiffe://sandbox.agentgate.test/ns/agentgate-sandbox/sa/terraform-runner" and
  .spec.workloadSelectorTemplates == ["k8s:ns:agentgate-sandbox", "k8s:sa:terraform-runner"] and
  .spec.jwtTtl == "5m"
' <<<"${runner_identity}" >/dev/null ||
  die "runner ClusterSPIFFEID does not have the reviewed exact selectors"

jq -e '
  ([.spec.template.spec.initContainers[] | select(.name == "spiffe-helper-init")][0]) as $init |
  ([.spec.template.spec.containers[] | select(.name == "agentgate")][0]) as $app |
  ([.spec.template.spec.containers[] | select(.name == "spiffe-helper")][0]) as $helper |
  $init.image == "ghcr.io/spiffe/spiffe-helper@sha256:2759b3a699bb63b91cc5896f46cd6f70b9e3dfed9f7f4355a3a0a4e702984f9c" and
  $helper.image == $init.image and
  ($app.args | index("--listen=:8443") != null) and
  ($app.args | index("--vault-management-role=agentgate-manager") != null) and
  ($app.livenessProbe.httpGet.scheme == "HTTPS") and
  ($app.readinessProbe.httpGet.scheme == "HTTPS") and
  any(
    $app.env[];
    .name == "AGENTGATE_DATABASE_URL" and
    .valueFrom.secretKeyRef.name == "agentgate-postgresql" and
    .valueFrom.secretKeyRef.key == "database-url"
  )
' <<<"${agentgate_deployment}" >/dev/null ||
  die "AgentGate Deployment does not have the reviewed mTLS, SPIFFE rotation, and runtime references"

jq -e '
  ([.spec.template.spec.containers[] | select(.name == "agent-sim")][0]) as $runner |
  ($runner.args | index("--terraform-bin=/usr/local/bin/terraform") != null) and
  ($runner.args | index("--terraform-work-root=/workspace") != null) and
  any($runner.args[]; startswith("--aws-region=")) and
  any($runner.args[]; startswith("--demo-bucket=")) and
  any($runner.args[]; startswith("--demo-prefix=")) and
  any($runner.args[]; startswith("--vault-tls-server-name=")) and
  any($runner.volumeMounts[]; .name == "terraform-work" and .mountPath == "/workspace")
' <<<"${runner_job}" >/dev/null ||
  die "demo runner does not have the reviewed direct Vault and Terraform wiring"

for job_name in agentgate-demo-dispatcher agentgate-demo-runner; do
  [[ "$(kubectl get job "${job_name}" --namespace agentgate-sandbox -o jsonpath='{.spec.suspend}')" == "true" ]] ||
    die "demo Job is not suspended: ${job_name}"
done

if kubectl get pods --all-namespaces -o json |
  jq -e '
    any(
      .items[].spec.containers[]?.env[]?;
      .name == "AWS_ACCESS_KEY_ID" or
      .name == "AWS_SECRET_ACCESS_KEY" or
      .name == "AWS_SESSION_TOKEN"
    )
  ' >/dev/null; then
  die "a Kubernetes container declares an inherited AWS credential environment variable"
fi

note "Cluster workloads, exact SPIFFE registrations, suspended Jobs, and credential-env checks passed."
