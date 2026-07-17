#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck disable=SC1091
source "${SCRIPT_DIR}/lib/common.sh"

require_command kubectl
verify_aws_identity
verify_kubernetes_context
require_env HCP_TERRAFORM_AGENT_IMAGE
require_env HCP_TERRAFORM_AGENT_TOKEN_FILE
require_digest_reference "${HCP_TERRAFORM_AGENT_IMAGE}"
assert_file_mode_private "${HCP_TERRAFORM_AGENT_TOKEN_FILE}"

apply_namespace "hcp-terraform-agent" "restricted"

kubectl apply -f - >/dev/null <<'YAML'
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: default-deny
  namespace: hcp-terraform-agent
spec:
  podSelector: {}
  policyTypes:
    - Ingress
    - Egress
YAML

kubectl create secret generic hcp-terraform-agent-token \
  --namespace hcp-terraform-agent \
  --from-file="TFC_AGENT_TOKEN=${HCP_TERRAFORM_AGENT_TOKEN_FILE}" \
  --dry-run=client \
  -o yaml |
  kubectl apply -f - >/dev/null

manifest_file="$(mktemp)"
trap 'rm -f "${manifest_file}"' EXIT
chmod 0600 "${manifest_file}"

cat >"${manifest_file}" <<EOF
apiVersion: v1
kind: ServiceAccount
metadata:
  name: hcp-terraform-agent
  namespace: hcp-terraform-agent
automountServiceAccountToken: false
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: hcp-terraform-agent
  namespace: hcp-terraform-agent
  labels:
    app.kubernetes.io/name: hcp-terraform-agent
    app.kubernetes.io/part-of: agentgate
spec:
  replicas: 1
  selector:
    matchLabels:
      app.kubernetes.io/name: hcp-terraform-agent
  template:
    metadata:
      labels:
        app.kubernetes.io/name: hcp-terraform-agent
        app.kubernetes.io/part-of: agentgate
    spec:
      serviceAccountName: hcp-terraform-agent
      automountServiceAccountToken: false
      securityContext:
        runAsNonRoot: true
        runAsUser: 999
        runAsGroup: 999
        fsGroup: 999
        seccompProfile:
          type: RuntimeDefault
      containers:
        - name: agent
          image: ${HCP_TERRAFORM_AGENT_IMAGE}
          imagePullPolicy: IfNotPresent
          env:
            - name: TFC_AGENT_TOKEN
              valueFrom:
                secretKeyRef:
                  name: hcp-terraform-agent-token
                  key: TFC_AGENT_TOKEN
            - name: TFC_AGENT_NAME
              value: agentgate-sandbox
            - name: TFC_AGENT_LOG_JSON
              value: "true"
            - name: TFC_AGENT_LOG_LEVEL
              value: info
            - name: TFC_AGENT_AUTO_UPDATE
              value: disabled
          resources:
            requests:
              cpu: 100m
              memory: 256Mi
            limits:
              cpu: "1"
              memory: 1Gi
          securityContext:
            allowPrivilegeEscalation: false
            capabilities:
              drop:
                - ALL
            readOnlyRootFilesystem: true
            runAsNonRoot: true
            runAsUser: 999
            runAsGroup: 999
          volumeMounts:
            - name: data
              mountPath: /home/tfc-agent/.tfc-agent
            - name: tmp
              mountPath: /tmp
      volumes:
        - name: data
          emptyDir:
            sizeLimit: 4Gi
        - name: tmp
          emptyDir:
            sizeLimit: 1Gi
---
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: hcp-terraform-agent
  namespace: hcp-terraform-agent
spec:
  podSelector:
    matchLabels:
      app.kubernetes.io/name: hcp-terraform-agent
  policyTypes:
    - Ingress
    - Egress
  ingress: []
  egress:
    - to:
        - namespaceSelector:
            matchLabels:
              kubernetes.io/metadata.name: kube-system
          podSelector:
            matchLabels:
              k8s-app: kube-dns
      ports:
        - port: 53
          protocol: UDP
        - port: 53
          protocol: TCP
    - ports:
        - port: 443
          protocol: TCP
    - to:
        - namespaceSelector:
            matchLabels:
              kubernetes.io/metadata.name: vault
          podSelector:
            matchLabels:
              app.kubernetes.io/name: vault
              app.kubernetes.io/instance: vault
              component: server
      ports:
        - port: 8200
          protocol: TCP
EOF

kubectl apply -f "${manifest_file}" >/dev/null
kubectl rollout status deployment/hcp-terraform-agent \
  --namespace hcp-terraform-agent \
  --timeout=180s

note "HCP Terraform agent is running. Assign its pool to the platform and AgentGate workspaces."
