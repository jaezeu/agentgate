# AgentGate: 90-minute governed-agent lab

## Purpose

This lab uses the disposable AgentGate AWS/EKS sandbox to demonstrate two-proof
authorization, separate human and workload identity rails, direct
agent-to-Vault authentication, and end-to-end correlation without exposing
credential material.

The lab does **not** prove that an AI agent is safe or that an allowed Terraform
change has good intent. AgentGate limits access; IAM, review, TTL, monitoring,
and the sandbox boundary limit the resulting damage.

## Learning objectives

By the end, students should be able to explain and demonstrate:

1. the difference between AgentGate's control plane and the credential data
   plane;
2. human OIDC identity versus workload SPIFFE identity;
3. why access requires both an attested SVID and dispatcher-signed task context;
4. why the governed runner logs in directly to Vault and how Vault attributes
   that login;
5. how one `request_id` joins AgentGate, Vault, AWS STS, and CloudTrail;
6. why a 15-minute TTL is the primary control and why revocation and intent
   governance have limits.

## Safety, cost, and handling rules

- Use only the dedicated sandbox account. EKS, nodes, NAT, EBS, logs, and
  Terraform can incur charges. Destroy or explicitly hand off the sandbox.
- Never paste a JWT-SVID, Vault token, AWS access key, secret key, session token,
  unseal key, dispatcher private key, or approver token into a host shell,
  document, chat, or AgentGate request.
- Do not `cat` JWT, Vault response, SVID private-key, or protected bootstrap
  files. Commands below retain sensitive values in mode-`0600` pod-local files
  or protected operator files and print metadata only.
- Never run `vault read aws/creds/...` merely to inspect its JSON. That response
  contains AWS STS values.
- Revocation prevents new login where possible. It does not reliably invalidate
  AWS STS values that Vault has already issued.
- The dispatcher is trusted infrastructure. Students do not receive its private
  key; instructor-only commands reference its protected path.

## Prerequisites

The instructor must complete [DEPLOY.md](DEPLOY.md) through layer 3 before the
class and run:

```bash
deploy/scripts/verify-cluster.sh
```

Required student/operator tools:

- this repository at the reviewed revision;
- Docker, kubectl, jq, curl, OpenSSL, Go 1.24, and AWS CLI v2;
- access to the reviewed Kubernetes context;
- AWS SSO access for credential-free CloudTrail lookup;
- a protected `AGENTGATE_SECRET_DIR` outside the repository for the instructor;
- the disposable Vault root token retained only until the inspection exercise,
  then revoked as directed in `DEPLOY.md`.

The instructor prepares non-secret context:

```bash
export AG_NAMESPACE='agentgate'
export RUNNER_NAMESPACE='agentgate-sandbox'
export PLATFORM_NAMESPACE='agentgate-platform'
export VAULT_NAMESPACE='vault'
export AGENTGATE_TLS_NAME='agentgate.agentgate.svc.cluster.local'
export VAULT_ADDR='https://127.0.0.1:8200'
export VAULT_TLS_SERVER_NAME='vault.vault.svc.cluster.local'
export VAULT_CACERT="${AGENTGATE_SECRET_DIR}/spire-ca.pem"
```

Keep these two port-forwards in dedicated terminals:

```bash
kubectl port-forward --namespace agentgate service/agentgate 8443:8443
```

```bash
kubectl port-forward --namespace vault service/vault 8200:8200
```

For the PoC human rail only, the instructor creates a protected curl
configuration. `printf` is a shell builtin, so the token is not put in a process
argument:

```bash
export HUMAN_CURL_CONFIG="$(mktemp)"
chmod 0600 "${HUMAN_CURL_CONFIG}"
printf 'header = "Authorization: Bearer %s"\n' \
  "$(<"${AGENTGATE_SECRET_DIR}/approver-token")" \
  >"${HUMAN_CURL_CONFIG}"
```

With production OIDC, use the registered dashboard session instead. Do not
replace OIDC with this PoC setup outside the teaching sandbox.

## Timeline

| Time | Exercise | Minutes |
| --- | --- | ---: |
| 00:00 | 1. Architecture and trust boundaries | 8 |
| 00:08 | 2. Inspect secretless pod specifications | 7 |
| 00:15 | 3. Fetch and inspect the runner X509-SVID | 8 |
| 00:23 | 4. Obtain a JWT-SVID and prove direct Vault login | 12 |
| 00:35 | 5. Inspect the exact Vault role and one-path policy | 8 |
| 00:43 | 6. Inspect the signed-grant Terraform flow | 12 |
| 00:55 | 7. Trace one `request_id` across systems | 10 |
| 01:05 | 8. Run the required failure gauntlet | 15 |
| 01:20 | 9. Discuss limitations and answer questions | 5 |
| 01:25 | 10. Clean up or hand off | 5 |
|  | **Total** | **90** |

## 1. Architecture and trust boundaries (8 minutes)

Open [ARCHITECTURE.md](ARCHITECTURE.md) and identify these directions:

```text
runner --X509-SVID + signed task grant--> AgentGate
AgentGate --request role/policy configuration only--> Vault
runner --JWT-SVID--> Vault
Vault --Vault token and AWS STS values--> runner
runner --request_id role session--> AWS
human --OIDC or explicit PoC rail--> approval routes
```

Ask students to point out the deliberately absent arrows:

- no Vault workload token or AWS value goes to AgentGate;
- no human token authenticates the workload request;
- no workload SVID authenticates an approver;
- no policy result claims that the agent's intent is safe.

Expected conclusion: the request-specific Vault role is AgentGate's
credential-free control-plane artifact. The runner owns the credential data
plane.

## 2. Inspect secretless pod specifications (7 minutes)

Inspect only environment names, volume types, commands, and service accounts:

```bash
kubectl get deployment agentgate --namespace "${AG_NAMESPACE}" -o json |
  jq '{
    service_account: .spec.template.spec.serviceAccountName,
    automount: .spec.template.spec.automountServiceAccountToken,
    containers: [
      .spec.template.spec.containers[] |
      {
        name,
        env_names: [(.env // [])[].name],
        mounts: [(.volumeMounts // [])[] | {name,mountPath,readOnly}]
      }
    ]
  }'

kubectl get job agentgate-demo-runner --namespace "${RUNNER_NAMESPACE}" -o json |
  jq '{
    suspended: .spec.suspend,
    service_account: .spec.template.spec.serviceAccountName,
    automount: .spec.template.spec.automountServiceAccountToken,
    args: .spec.template.spec.containers[0].args,
    env_names: [(.spec.template.spec.containers[0].env // [])[].name],
    volumes: [.spec.template.spec.volumes[] | {name,secret:(.secret.secretName // null),csi:(.csi.driver // null)}]
  }'
```

Prove that no pod declares static AWS credential variables:

```bash
kubectl get pods --all-namespaces -o json |
  jq -e '
    [
      .items[].spec.containers[]?.env[]? |
      select(
        .name == "AWS_ACCESS_KEY_ID" or
        .name == "AWS_SECRET_ACCESS_KEY" or
        .name == "AWS_SESSION_TOKEN"
      )
    ] | length == 0
  '
```

Expected:

- both Kubernetes service-account token automounts are `false`;
- the runner mounts the SPIFFE CSI socket and a signed-grant Secret, not an AWS
  or Vault credential Secret;
- only `SPIFFE_ENDPOINT_SOCKET` is present in the runner environment before
  execution;
- the final jq command returns `true`.

The AgentGate pod references database and human-auth runtime Secrets. Those are
control-plane dependencies, not workload cloud credentials.

## 3. Fetch and inspect the runner X509-SVID (8 minutes)

Create a temporary diagnostics pod with the exact governed-runner labels and
service account. It uses the reviewed Vault image as a shell/tool container and
never mounts a Kubernetes service-account token:

```bash
kubectl apply -f - <<'YAML'
apiVersion: v1
kind: Pod
metadata:
  name: agentgate-manual-proof
  namespace: agentgate-sandbox
  labels:
    app.kubernetes.io/name: agent-sim
    app.kubernetes.io/instance: agentgate-demo
    app.kubernetes.io/component: governed-runner
    app.kubernetes.io/part-of: agentgate
    app.kubernetes.io/managed-by: terraform
spec:
  serviceAccountName: terraform-runner
  automountServiceAccountToken: false
  restartPolicy: Never
  securityContext:
    runAsNonRoot: true
    runAsUser: 100
    runAsGroup: 1000
    fsGroup: 1000
    seccompProfile:
      type: RuntimeDefault
  containers:
    - name: toolbox
      image: hashicorp/vault:2.0.3@sha256:a296a888b118615dc01d5f1a6846e6d4a7277946caaed5b447008fff5fe06b54
      command: [/bin/sh, -ec]
      args: ['sleep 900']
      resources:
        requests: {cpu: 10m, memory: 32Mi}
        limits: {cpu: 100m, memory: 128Mi}
      securityContext:
        allowPrivilegeEscalation: false
        readOnlyRootFilesystem: true
        capabilities: {drop: [ALL]}
      volumeMounts:
        - {name: workload-api, mountPath: /run/spire/sockets, readOnly: true}
        - {name: identity, mountPath: /identity}
        - {name: tools, mountPath: /tools}
        - {name: work, mountPath: /work}
  volumes:
    - name: workload-api
      csi: {driver: csi.spiffe.io, readOnly: true}
    - name: identity
      emptyDir: {sizeLimit: 1Mi}
    - name: tools
      emptyDir: {sizeLimit: 64Mi}
    - name: work
      emptyDir: {medium: Memory, sizeLimit: 4Mi}
YAML
kubectl wait pod/agentgate-manual-proof \
  --namespace "${RUNNER_NAMESPACE}" \
  --for=condition=Ready \
  --timeout=60s
```

Copy the public SPIRE CLI binary from the reviewed image into the pod. This does
not copy an identity or credential:

```bash
tool_dir="$(mktemp -d)"
spire_image='ghcr.io/spiffe/spire-agent:1.15.1'
spire_container="$(docker create --platform linux/amd64 "${spire_image}")"
docker cp \
  "${spire_container}:/opt/spire/bin/spire-agent" \
  "${tool_dir}/spire-agent"
docker rm "${spire_container}" >/dev/null
kubectl cp \
  "${tool_dir}/spire-agent" \
  "${RUNNER_NAMESPACE}/agentgate-manual-proof:/tools/spire-agent" \
  --container toolbox
rm -rf "${tool_dir}"
```

Fetch and inspect the X509-SVID:

```bash
kubectl exec --namespace "${RUNNER_NAMESPACE}" agentgate-manual-proof \
  --container toolbox -- \
  /tools/spire-agent api fetch x509 \
  -socketPath /run/spire/sockets/spire-agent.sock \
  -write /identity
```

Expected metadata includes:

```text
SPIFFE ID: spiffe://sandbox.agentgate.test/ns/agentgate-sandbox/sa/terraform-runner
```

The command writes `/identity/svid.0.key` only inside the pod so the next step
can use the public bundle. **Do not print or copy that key.**

## 4. Obtain a JWT-SVID and prove direct Vault login (12 minutes)

The request-scoped role must exist before a manual login. Start the normal demo
flow now; phase 6 will inspect its Terraform result:

```bash
deploy/scripts/prepare-demo-grant.sh
kubectl patch job agentgate-demo-runner \
  --namespace "${RUNNER_NAMESPACE}" \
  --type merge \
  --patch '{"spec":{"suspend":false}}' >/dev/null
kubectl wait job/agentgate-demo-runner \
  --namespace "${RUNNER_NAMESPACE}" \
  --for=condition=complete \
  --timeout=900s

export RUNNER_LOG="$(mktemp)"
chmod 0600 "${RUNNER_LOG}"
kubectl logs job/agentgate-demo-runner \
  --namespace "${RUNNER_NAMESPACE}" \
  --container agent-sim >"${RUNNER_LOG}"
export REQUEST_ID="$(tail -n 1 "${RUNNER_LOG}" | jq -er '.request_id')"
printf 'Teaching request_id: %s\n' "${REQUEST_ID}"
```

Run the JWT fetch and Vault login entirely inside the governed pod. The script
extracts the JWT to a memory-backed file, never prints it, records the Vault
token in another mode-`0600` file, prints only token metadata/capabilities, then
revokes that proof token:

```bash
kubectl exec --namespace "${RUNNER_NAMESPACE}" agentgate-manual-proof \
  --container toolbox -- /bin/sh -ec '
    set -eu
    umask 077
    cleanup() {
      rm -f /work/jwt-output /work/jwt /work/vault-token
    }
    trap cleanup EXIT

    /tools/spire-agent api fetch jwt \
      -socketPath /run/spire/sockets/spire-agent.sock \
      -audience vault > /work/jwt-output
    sed -n "s/^token(\(.*\)):$/JWT-SVID subject: \1/p" /work/jwt-output
    awk "
      /^token\\(/ {
        count++
        getline
        sub(/^[[:space:]]+/, \"\")
        print
      }
      END { if (count != 1) exit 1 }
    " /work/jwt-output > /work/jwt
    rm -f /work/jwt-output

    export VAULT_ADDR="https://vault.vault.svc.cluster.local:8200"
    export VAULT_CACERT="/identity/bundle.0.pem"
    export VAULT_TLS_SERVER_NAME="vault.vault.svc.cluster.local"
    vault write -field=token auth/spire-jwt/login \
      role="agentgate-role-$1" \
      jwt=@/work/jwt > /work/vault-token
    rm -f /work/jwt

    export VAULT_TOKEN="$(cat /work/vault-token)"
    printf "Vault display name: "
    vault token lookup -field=display_name
    printf "Vault token TTL seconds: "
    vault token lookup -field=ttl
    printf "Allowed path capabilities: "
    vault token capabilities aws/creds/terraform-sandbox
    printf "Sibling path capabilities: "
    vault token capabilities aws/creds/not-allowed
    vault token revoke -self >/dev/null
    unset VAULT_TOKEN
  ' proof "${REQUEST_ID}"
```

Expected shape:

```text
JWT-SVID subject: spiffe://sandbox.agentgate.test/ns/agentgate-sandbox/sa/terraform-runner
Vault display name: ...
Vault token TTL seconds: <no more than 900>
Allowed path capabilities: read
Sibling path capabilities: deny
```

This proves direct login without printing a JWT, Vault token, lease, or AWS
value. The JWT TTL is configured at five minutes; the Vault token cannot exceed
the remaining 15-minute AgentGate window.

## 5. Inspect the exact Vault role and one-path policy (8 minutes)

This is instructor-only and must occur before the request expires. Load the
disposable root token from its protected file; never paste or echo it:

```bash
export VAULT_TOKEN="$(<"${AGENTGATE_SECRET_DIR}/vault-root-token")"

vault read -format=json \
  "auth/spire-jwt/role/agentgate-role-${REQUEST_ID}" |
  jq '.data | {
    bound_audiences,
    bound_subject,
    token_policies,
    token_ttl,
    token_max_ttl,
    token_explicit_max_ttl,
    token_no_default_policy
  }'

vault policy read "agentgate-policy-${REQUEST_ID}"
unset VAULT_TOKEN
```

Expected:

- `bound_subject` is the exact governed-runner SPIFFE ID;
- the only audience is `vault`;
- default policy is disabled;
- TTL fields are no more than 15 minutes;
- the request policy contains one `read` capability on
  `aws/creds/terraform-sandbox` and no wildcard or sibling path.

AgentGate's management policy can write/read/delete only role and policy names
under its prefixes. It has no `read` capability on `aws/creds/*`.

## 6. Inspect the signed-grant Terraform flow (12 minutes)

The runner completed these steps:

1. fetched its rotating X509-SVID;
2. sent the signed grant to AgentGate over mTLS;
3. received a credential-free decision and descriptor;
4. fetched its own five-minute JWT-SVID;
5. logged in directly to Vault;
6. read exactly `aws/creds/terraform-sandbox`;
7. passed STS values only to the Terraform child environment;
8. planned one marker object under the governed S3 prefix;
9. cleared references and emitted credential-free JSON.

Inspect the scrubbed Terraform output and final result:

```bash
sed -n '/----- terraform init (scrubbed) -----/,$p' "${RUNNER_LOG}"
tail -n 1 "${RUNNER_LOG}" |
  jq '{
    request_id,
    spiffe_id,
    decision,
    approval_state,
    binding_state,
    vault_auth_role,
    aws_role_session_name,
    terraform
  }'
```

Expected final shape:

```json
{
  "request_id": "<same UUID>",
  "spiffe_id": "spiffe://sandbox.agentgate.test/ns/agentgate-sandbox/sa/terraform-runner",
  "decision": "allow",
  "approval_state": "not_required",
  "binding_state": "enabled",
  "vault_auth_role": "agentgate-role-<same UUID>",
  "aws_role_session_name": "<same UUID>",
  "terraform": {
    "initialized": true,
    "plan_completed": true,
    "changes_present": true
  }
}
```

The plan is never applied. It targets one marker key under the reviewed prefix.
Confirm the final JSON has no credential-bearing field:

```bash
tail -n 1 "${RUNNER_LOG}" |
  jq -e '
    [
      paths(scalars) as $p |
      ($p[-1] | tostring | ascii_downcase) |
      select(
        test("access.?key|secret.?key|session.?token|security.?token|vault.?token|lease.?id")
      )
    ] | length == 0
  '
```

Expected: `true`.

## 7. Trace one `request_id` across systems (10 minutes)

### AgentGate request and immutable events

```bash
curl --silent --show-error \
  --config "${HUMAN_CURL_CONFIG}" \
  --noproxy '*' \
  --cacert "${AGENTGATE_SECRET_DIR}/spire-ca.pem" \
  --resolve "${AGENTGATE_TLS_NAME}:8443:127.0.0.1" \
  "https://${AGENTGATE_TLS_NAME}:8443/v1/requests/${REQUEST_ID}" |
  jq '{
    request_id: .request.request_id,
    spiffe_id: .request.spiffe_id,
    on_behalf_of: .request.on_behalf_of,
    ticket_id: .request.ticket_id,
    policy_version: .request.decision.policy_version,
    binding_state: .request.binding_state,
    vault_auth_role: .request.vault_auth_role,
    aws_role_session_name: .request.aws_role_session_name,
    event_types: [.events[].event_type]
  }'
```

### Vault audit

The audit device HMACs sensitive values. `role_session_name` is deliberately
configured as a non-HMAC request field:

```bash
kubectl exec --namespace "${VAULT_NAMESPACE}" vault-0 -- \
  grep -F "${REQUEST_ID}" /vault/audit/audit.log |
  jq -c '{
    time,
    type,
    auth_display_name: .auth.display_name,
    request_path: .request.path,
    role_session_name: (.request.data.role_session_name // null)
  }'
```

Expected entries identify the agent login/credential path, not AgentGate, and
the AWS request contains the same `REQUEST_ID`.

### CloudTrail

Use the human's AWS SSO session, not the runner's STS values:

```bash
aws cloudtrail lookup-events \
  --region "${AGENTGATE_AWS_REGION}" \
  --max-results 50 \
  --query "Events[?contains(CloudTrailEvent, \`${REQUEST_ID}\`)].{Time:EventTime,Name:EventName,User:Username}" \
  --output table
```

Expected: the Vault `AssumeRole`/resulting session is discoverable with the same
request ID. Event History can lag; lack of an immediate row is a documented
manual verification gap, not permission to invent evidence.

## 8. Required failure gauntlet (15 minutes)

### One helper for disposable runner Jobs

Define a helper that copies only the reviewed runner pod template, strips
server-generated Job fields, selects a grant Secret, and optionally changes the
service account:

```bash
clone_runner_job() {
  local name="$1"
  local grant_secret="$2"
  local service_account="${3:-terraform-runner}"
  kubectl delete job "${name}" --namespace "${RUNNER_NAMESPACE}" \
    --ignore-not-found >/dev/null
  kubectl get job agentgate-demo-runner \
    --namespace "${RUNNER_NAMESPACE}" \
    -o json |
    jq \
      --arg name "${name}" \
      --arg secret "${grant_secret}" \
      --arg service_account "${service_account}" '
        del(
          .metadata.annotations,
          .metadata.creationTimestamp,
          .metadata.generation,
          .metadata.managedFields,
          .metadata.resourceVersion,
          .metadata.uid,
          .spec.selector,
          .status,
          .spec.template.metadata.creationTimestamp,
          .spec.template.metadata.labels["batch.kubernetes.io/controller-uid"],
          .spec.template.metadata.labels["batch.kubernetes.io/job-name"],
          .spec.template.metadata.labels["controller-uid"],
          .spec.template.metadata.labels["job-name"]
        ) |
        .metadata.name = $name |
        .spec.suspend = false |
        .spec.backoffLimit = 0 |
        .spec.template.spec.serviceAccountName = $service_account |
        .spec.template.spec.volumes |= map(
          if .name == "task-grant"
          then .secret.secretName = $secret
          else .
          end
        )
      ' |
    kubectl create -f - >/dev/null
}
```

Capture only non-secret grant fields from the existing demo Secret:

```bash
grant_template="$(mktemp)"
chmod 0600 "${grant_template}"
kubectl get secret agentgate-demo-grant \
  --namespace "${RUNNER_NAMESPACE}" \
  -o jsonpath='{.data.grant\.json}' |
  base64 --decode >"${grant_template}"
export DEMO_REPO="$(jq -er '.repo' "${grant_template}")"
export DEMO_COMMIT="$(jq -er '.commit_sha' "${grant_template}")"
export DEMO_ROLE="$(jq -er '.vault_role' "${grant_template}")"
export DEMO_HUMAN="$(jq -er '.on_behalf_of' "${grant_template}")"
export DEMO_TICKET="$(jq -er '.ticket_id' "${grant_template}")"
rm -f "${grant_template}"
```

### A. Tampered signed grant

The instructor references, but never reads aloud, the protected private key:

```bash
tampered_grant="$(mktemp)"
chmod 0600 "${tampered_grant}"
go run ./cmd/orchestrator-stub \
  --private-key="${AGENTGATE_SECRET_DIR}/dispatcher-private.pem" \
  --repo="${DEMO_REPO}" \
  --commit-sha="${DEMO_COMMIT}" \
  --operation=terraform-plan \
  --environment=dev \
  --vault-role="${DEMO_ROLE}" \
  --ttl=15m \
  --on-behalf-of="${DEMO_HUMAN}" \
  --ticket-id="${DEMO_TICKET}" \
  --tamper >"${tampered_grant}"
tampered_id="$(jq -er '.request_id' "${tampered_grant}")"
kubectl create secret generic agentgate-tampered-grant \
  --namespace "${RUNNER_NAMESPACE}" \
  --from-file="grant.json=${tampered_grant}" \
  --dry-run=client -o yaml |
  kubectl apply -f - >/dev/null
rm -f "${tampered_grant}"

clone_runner_job agentgate-tampered-runner agentgate-tampered-grant
kubectl wait job/agentgate-tampered-runner \
  --namespace "${RUNNER_NAMESPACE}" \
  --for=condition=failed \
  --timeout=90s
kubectl logs job/agentgate-tampered-runner \
  --namespace "${RUNNER_NAMESPACE}" |
  tail -n 3
```

Expected: signature verification fails before policy/Vault.

Prove no request or binding was written:

```bash
status="$(
  curl --silent --output /dev/null --write-out '%{http_code}' \
    --config "${HUMAN_CURL_CONFIG}" \
    --noproxy '*' \
    --cacert "${AGENTGATE_SECRET_DIR}/spire-ca.pem" \
    --resolve "${AGENTGATE_TLS_NAME}:8443:127.0.0.1" \
    "https://${AGENTGATE_TLS_NAME}:8443/v1/requests/${tampered_id}"
)"
test "${status}" = "404"
```

Expected: the test succeeds. Automated grant tests additionally prove the
invalid signature did not consume a valid nonce.

### B. Valid grant under the wrong service account

The pod can see the same valid signed grant, but SPIRE selectors do not issue the
governed identity:

```bash
kubectl create serviceaccount ungoverned-runner \
  --namespace "${RUNNER_NAMESPACE}" \
  --dry-run=client -o yaml |
  kubectl apply -f - >/dev/null
clone_runner_job \
  agentgate-wrong-identity \
  agentgate-demo-grant \
  ungoverned-runner
kubectl wait job/agentgate-wrong-identity \
  --namespace "${RUNNER_NAMESPACE}" \
  --for=condition=failed \
  --timeout=90s
kubectl logs job/agentgate-wrong-identity \
  --namespace "${RUNNER_NAMESPACE}" |
  tail -n 3
```

Expected: X509-SVID acquisition fails before AgentGate. If a differently
attested workload obtains its own JWT-SVID elsewhere, the request role's exact
`bound_subject` still rejects it. Seeing a valid grant is not enough.

### C. Production apply parks, then denial creates no binding

```bash
prod_grant="$(mktemp)"
chmod 0600 "${prod_grant}"
go run ./cmd/orchestrator-stub \
  --private-key="${AGENTGATE_SECRET_DIR}/dispatcher-private.pem" \
  --repo="${DEMO_REPO}" \
  --commit-sha="${DEMO_COMMIT}" \
  --operation=terraform-apply \
  --environment=prod \
  --vault-role="${DEMO_ROLE}" \
  --ttl=15m \
  --on-behalf-of="${DEMO_HUMAN}" \
  --ticket-id="${DEMO_TICKET}" >"${prod_grant}"
prod_id="$(jq -er '.request_id' "${prod_grant}")"
kubectl create secret generic agentgate-prod-grant \
  --namespace "${RUNNER_NAMESPACE}" \
  --from-file="grant.json=${prod_grant}" \
  --dry-run=client -o yaml |
  kubectl apply -f - >/dev/null
rm -f "${prod_grant}"
clone_runner_job agentgate-prod-runner agentgate-prod-grant
```

Poll the credential-free human detail route:

```bash
for _ in 1 2 3 4 5 6 7 8 9 10; do
  pending="$(
    curl --silent --show-error \
      --config "${HUMAN_CURL_CONFIG}" \
      --noproxy '*' \
      --cacert "${AGENTGATE_SECRET_DIR}/spire-ca.pem" \
      --resolve "${AGENTGATE_TLS_NAME}:8443:127.0.0.1" \
      "https://${AGENTGATE_TLS_NAME}:8443/v1/requests/${prod_id}"
  )" || true
  if jq -e '
    .request.decision.decision == "pending_approval" and
    .request.approval.state == "pending" and
    .request.binding_state == "pending" and
    (.request.descriptor == null)
  ' <<<"${pending}" >/dev/null 2>&1; then
    break
  fi
  sleep 1
done
jq '{
  decision: .request.decision.decision,
  approval: .request.approval.state,
  binding: .request.binding_state,
  descriptor_present: (.request.descriptor != null)
}' <<<"${pending}"
```

Expected:

```json
{"decision":"pending_approval","approval":"pending","binding":"pending","descriptor_present":false}
```

The separately authenticated human rail denies it:

```bash
curl --silent --show-error --fail-with-body \
  --config "${HUMAN_CURL_CONFIG}" \
  --noproxy '*' \
  --cacert "${AGENTGATE_SECRET_DIR}/spire-ca.pem" \
  --resolve "${AGENTGATE_TLS_NAME}:8443:127.0.0.1" \
  --header 'Content-Type: application/json' \
  --data '{"reason":"denied during the teaching failure gauntlet"}' \
  "https://${AGENTGATE_TLS_NAME}:8443/v1/requests/${prod_id}/deny" |
  jq '{approval:.request.approval.state,binding:.request.binding_state,descriptor_present:(.request.descriptor != null)}'
```

Expected: approval is `denied`, binding is `not_required`, and no descriptor or
Vault binding exists. The polling runner then exits denied; it never reaches
direct Vault redemption or Terraform.

## 9. Comprehension questions and instructor answers (5 minutes)

1. **Why does Vault's audit log show the agent, not AgentGate?**
   The runner fetches its own JWT-SVID and calls Vault's login and AWS secrets
   path directly. AgentGate only configures the request role and policy with its
   separate control-plane identity.

2. **Why can't an AWS STS credential generally be revoked early after Vault
   issued it?**
   Deleting the Vault role, policy, token, or lease can stop new issuance, but
   AWS validates the already issued STS session until its expiry. Short TTL and
   narrow IAM scope are therefore primary.

3. **Why can't this governed flow run on an employee laptop?**
   The Vault role binds one exact SPIFFE subject issued only to the selected
   Kubernetes namespace, pod labels, and service account. A laptop cannot obtain
   that attested identity, even if it sees a signed grant.

4. **Why are both an attested SVID and dispatcher-signed task grant required?**
   The SVID stops a grant from being used by the wrong workload. The signature
   stops an attested workload from inventing repository, operation, role, TTL,
   human attribution, or ticket context. Either proof alone leaves one attack.

5. **What damage can a prompt-injected agent still cause after a legitimate
   allow decision, and what limits it?**
   It can perform harmful actions that remain inside the allowed role and
   resource scope. IAM, one-path Vault policy, signed operation/environment,
   production approval, Terraform plan review, budgets, monitoring, and TTL
   limit but do not eliminate that risk.

6. **What does `request_id` prove?**
   It is a correlation key across independently recorded facts. It does not by
   itself prove that the action was desirable or that every subsystem was
   uncompromised.

## 10. Cleanup or explicit handoff (5 minutes)

Remove lab-only resources and protected temporary files:

```bash
kubectl delete pod agentgate-manual-proof \
  --namespace "${RUNNER_NAMESPACE}" \
  --ignore-not-found
kubectl delete job \
  agentgate-tampered-runner \
  agentgate-wrong-identity \
  agentgate-prod-runner \
  --namespace "${RUNNER_NAMESPACE}" \
  --ignore-not-found
kubectl delete secret \
  agentgate-tampered-grant \
  agentgate-prod-grant \
  --namespace "${RUNNER_NAMESPACE}" \
  --ignore-not-found
kubectl delete serviceaccount ungoverned-runner \
  --namespace "${RUNNER_NAMESPACE}" \
  --ignore-not-found
rm -f "${RUNNER_LOG}" "${HUMAN_CURL_CONFIG}"
unset RUNNER_LOG HUMAN_CURL_CONFIG REQUEST_ID
```

Request roles are automatically removed just before their 15-minute descriptor
expiry. An instructor may also invoke the human revoke route for hygiene, while
stating that already issued STS values can remain valid until expiry.

Choose exactly one end state:

1. **Destroy:** follow [Reverse destroy](DEPLOY.md#reverse-destroy) while the
   cluster, Vault material, and AWS SSO session are still available.
2. **Handoff:** record the named owner, AWS account, GitHub repository and
   environments, current cost window, Vault unseal-material custodian, and an
   explicit destruction deadline. The owner acknowledges that the sandbox is
   still billing.

Stop both port-forwards. If the disposable Vault root token was retained for the
lab, revoke it now using the protected-file procedure in `DEPLOY.md`.

## Troubleshooting

| Symptom | Check without exposing secrets |
| --- | --- |
| `rootless Docker not found` in local testcontainers | Export the active `DOCKER_HOST`; with Colima also set `TESTCONTAINERS_DOCKER_SOCKET_OVERRIDE=/var/run/docker.sock`. |
| Diagnostics pod has no SVID | Compare namespace, service account, and all five runner labels with `ClusterSPIFFEID/agentgate-terraform-runner`; inspect SPIRE agent logs. |
| Manual Vault login says role not found | The 15-minute window expired or expiry cleanup began. Prepare a fresh grant and runner Job; do not extend the old role. |
| Vault TLS verification fails | Check `bundle.0.pem`, `VAULT_TLS_SERVER_NAME`, Vault certificate rotation, and the SPIRE trust domain; never use `-tls-skip-verify`. |
| Runner remains pending | Inspect the human request route and webhook delivery. Webhook success does not approve; use the separately authenticated human rail. |
| Terraform plan fails | Read only the scrubbed runner output; verify target bucket/Region, Vault role configuration, and IAM scope. Do not enable Terraform debug logs because they can expose request data. |
| CloudTrail lookup is empty | Wait for delivery, verify Region/account and exact request ID, then record the check as unresolved rather than claiming correlation. |
| Demo Job already completed | Recreate it through the documented Terraform replacement or use the disposable clone helper; Kubernetes Jobs are not reset by resuspending them. |

The authoritative unresolved-risk register is
[KNOWN-GAPS.md](KNOWN-GAPS.md).
