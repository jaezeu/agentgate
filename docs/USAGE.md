# Usage and implementation guide

This guide is for the engineer who wants to run AgentGate, put a task
through it, and extend it. It documents the working software as it exists
today. [ARCHITECTURE.md](ARCHITECTURE.md) explains why the design looks this
way, [DEPLOY.md](DEPLOY.md) provisions the AWS sandbox that hosts it, and
[KNOWN-GAPS.md](KNOWN-GAPS.md) lists what is deliberately not finished.

Everything here can be exercised locally except the final credential
redemption, which needs the sandbox (SPIRE, Vault, and an AWS target).

## The pieces you interact with

| Piece | Role |
| --- | --- |
| `agentgate serve` | The broker: HTTPS API, policy evaluation, approval state, Vault role/policy management, audit |
| `agentgate grant-keygen` | Generates a disposable Ed25519 dispatcher key pair (PoC trust material) |
| `agentgate revoke` | Human-rail CLI wrapper for revoking an enabled request |
| `cmd/orchestrator-stub` | Reference dispatcher: signs a task grant with the dispatcher private key |
| `cmd/agent-sim` | Reference governed workload: requests access, polls approval, redeems from Vault, runs Terraform |
| `policies/authorization.rego` | Embedded default-deny policy; its SHA-256 is recorded on every decision |
| `dashboard/` | Optional React operations UI served from `--dashboard-dir` |

## Request lifecycle in one pass

1. A human asks the dispatcher for a task. The dispatcher signs a **task
   grant** naming exactly what was asked: operation, repo, commit, Vault
   role, TTL, requester (`on_behalf_of`), ticket, and a single-use nonce.
2. The workload (agent) presents that grant to
   `POST /v1/access-requests` over mTLS using its SPIRE-issued X509-SVID.
   Two proofs, one request: the SVID proves what is running, the signature
   proves what it was asked to do.
3. AgentGate verifies both proofs, evaluates the Rego policy, and either
   denies, parks the request as `pending_approval`, or writes a
   **one-request Vault role** bound to the workload's exact SPIFFE ID.
4. The workload receives a **redemption descriptor** (addresses and names,
   never a credential) and logs into Vault itself with a short-lived
   JWT-SVID. Vault issues the credential directly to the workload.
5. The expiry reconciler deletes the Vault role and policy when the window
   ends; a human can revoke earlier through the human rail.

AgentGate never sees, stores, or logs a credential at any step.

## Running the broker

`agentgate serve` fails closed: it validates every dependency at startup and
exits without printing secret values if any is missing.

Required flags:

| Flag | Meaning |
| --- | --- |
| `--tls-cert`, `--tls-key` | Server TLS certificate and key PEM |
| `--svid-trust-bundle` | SPIFFE X.509 trust bundle PEM used to verify workload client certificates |
| `--allowed-trust-domains` | Comma-separated SPIFFE trust domains accepted on the workload rail |
| `--dispatcher-public-key` | Ed25519 public key PEM that must have signed every grant |
| `--public-base-url` | Public AgentGate URL used in approval notifications |
| `--vault-address` | Vault API address |
| `--vault-management-role` | Vault JWT role for AgentGate's own SPIFFE identity |
| `--database-url-env` | Name of the environment variable holding the PostgreSQL URL (default `AGENTGATE_DATABASE_URL`) |
| `--webhook-url-env` | Name of the environment variable holding the approval webhook URL (default `AGENTGATE_APPROVAL_WEBHOOK_URL`) |

Secrets are passed by environment variable name, never by flag value, so a
process listing shows configuration but no secret material.

Frequently used optional flags:

| Flag | Default | Meaning |
| --- | --- | --- |
| `--listen` | `:8443` | HTTPS listener address |
| `--vault-auth-mount` | `jwt` | Auth mount agents log into |
| `--vault-aws-mount` | `aws` | Secrets mount serving `terraform-plan` and `terraform-apply` |
| `--vault-kubernetes-mount` | unset | Enables the `kubernetes-inspect` profile when set |
| `--vault-role-prefix` / `--vault-policy-prefix` | `agentgate-` | Per-request Vault role and policy name prefixes |
| `--vault-ca-cert`, `--vault-tls-server-name` | unset | Vault TLS trust when reaching Vault through a tunnel |
| `--workload-api-addr` | `SPIFFE_ENDPOINT_SOCKET` | SPIFFE Workload API socket |
| `--dashboard-dir` | unset | Serve a prebuilt dashboard SPA |

Human authentication is one of two mutually exclusive modes:

- **OIDC** (`--human-oidc-issuer` and `--human-oidc-audience`): approvers
  present bearer tokens from your IdP.
- **PoC static token** (`--poc-static-human-auth`): a single approver token
  read from `AGENTGATE_POC_APPROVER_TOKEN` (name overridable with
  `--poc-human-token-env`). Explicitly a proof-of-concept mode; the flag
  name says so on purpose.

Health endpoints are `GET /livez` and `GET /readyz`; readiness verifies
database connectivity and the migrated schema. Vault and Workload API
availability are validated at startup and surface as request-time errors
afterward.

## Dispatching a task

Generate a disposable dispatcher key pair and sign a grant:

```bash
go run ./cmd/agentgate grant-keygen

go run ./cmd/orchestrator-stub \
  --repo='github.com/example/governed-infra' \
  --commit-sha='0123456789abcdef0123456789abcdef01234567' \
  --vault-role='terraform-sandbox' \
  --on-behalf-of='engineer@example.test' \
  --ticket-id='OPS-1234'
```

The output is a signed, credential-free JSON grant:

| Field | Meaning |
| --- | --- |
| `request_id` | Correlation key for the entire lifecycle, through to CloudTrail |
| `repo`, `commit_sha` | The exact work the human authorized |
| `operation` | `terraform-plan`, `terraform-apply`, or `kubernetes-inspect` |
| `environment` | Target environment; `prod` applies require human approval |
| `vault_role` | Vault role the dispatcher asserts for this task |
| `ttl` | Requested access window in seconds; policy clamps it |
| `nonce` | Single use; replay of a verified grant is rejected |
| `issued_at` | Signature time; future-dated or stale grants are rejected |
| `on_behalf_of`, `ticket_id` | Human accountability, required |
| `signature` | Ed25519 over the canonical payload |

The stub's `--tamper` flag corrupts the signature so you can watch
verification fail. In a real integration your orchestrator holds the
private key and signs with `internal/grant`'s `Signer`; AgentGate only ever
needs the public key.

## The workload rail

The workload calls the API over mTLS with its X509-SVID as the client
certificate. Requests carrying an `Authorization` header on this route are
rejected: human and workload rails never mix.

```
POST /v1/access-requests
{
  "task_grant": { ...signed grant JSON... },
  "requested_vault_role": "terraform-sandbox"
}
```

The response reports the decision and, when access is enabled, the
redemption descriptor:

```
{
  "request_id": "...",
  "decision": { "decision": "allow", "granted_ttl": ..., "policy_version": "sha256..." },
  "approval_state": "approved",
  "binding_state": "enabled",
  "descriptor": {
    "request_id": "...",
    "vault_address": "https://vault.vault.svc.cluster.local:8200",
    "auth_mount": "jwt",
    "auth_role": "agentgate-<request_id>",
    "secrets_path": "aws/creds/agentgate-<request_id>",
    "audience": "vault",
    "expires_at": "..."
  }
}
```

The descriptor contains names and addresses only. The workload then:

1. fetches a JWT-SVID for audience `vault` from its own Workload API;
2. logs into Vault at `auth_mount` with `auth_role` (the role's
   `bound_subject` is the workload's exact SPIFFE ID, so no other workload
   can use it);
3. reads `secrets_path` exactly once, passing `role_session_name=request_id`
   for the AWS lane so CloudTrail carries the same correlation key;
4. uses the returned short-lived credential and lets it expire.

`cmd/agent-sim` implements this contract end to end, including
`pending_approval` polling and a governed Terraform child process, and is
the reference for writing your own runner.

A `pending_approval` response means the request parked for a human; the
workload polls `GET /v1/requests/{id}` (workload or human credentials both
work on that read route) until a human decides or the grant's own window
expires. A failed webhook delivery leaves the request pending and audited,
never silently approved.

## The human rail

All human routes require a bearer token (OIDC or the PoC approver token):

| Route | Action |
| --- | --- |
| `GET /v1/requests` | List requests; supports filtering |
| `GET /v1/requests/{id}` | Full request detail, including audit-relevant state |
| `POST /v1/requests/{id}/approve` | Approve a pending request; body `{"reason": "..."}` |
| `POST /v1/requests/{id}/deny` | Deny a pending request; body `{"reason": "..."}` |
| `POST /v1/requests/{id}/revoke` | Tear down an enabled binding early |

```bash
curl -sS --cacert agentgate-ca.pem \
  -H "Authorization: Bearer ${APPROVER_TOKEN}" \
  -X POST "https://agentgate.example/v1/requests/${REQUEST_ID}/approve" \
  -d '{"reason":"change reviewed in OPS-1234"}'
```

`agentgate revoke` wraps the revoke call for operators. Revocation deletes
the Vault role and policy so no new login or read can occur. An already
issued AWS STS credential normally remains valid until its own expiry;
that boundary is documented, not hidden (gap G-04).

Approval notifications go to the Slack-compatible webhook named by
`--webhook-url-env`. The payload carries grant context only, never a
descriptor or credential.

## Policy

The policy is embedded at build time from
[`policies/authorization.rego`](../policies/authorization.rego) and is
default-deny with one deterministic reason per denial. Deployment-specific
data lives in its `config` object: trust domains, allowed repositories,
environments, operations, and the workload allowlist mapping each SPIFFE
workload path to its permitted operations and Vault roles.

To change policy:

1. edit the `config` object (or the rules, if the contract itself changes);
2. run `make policy-check policy-test` (`opa test` must stay green; add
   cases for every new allow and deny path);
3. rebuild. The new bundle hash appears as `policy_version` on every
   decision and audit record, so a policy change is visible in the trail.

Production `terraform-apply` additionally requires human approval
regardless of policy allowlists.

## Adding an access profile (a new lane)

An access profile maps one operation to one Vault secrets mount; every lane
keeps the same contract of one role and one read-only
`<mount>/creds/<role>` path. `kubernetes-inspect` is the worked example of
these steps in the codebase.

1. **Vault**: enable and configure the secrets engine (in
   `deploy/platform` for the sandbox) so `<mount>/creds/<role>` issues the
   scoped credential you want.
2. **Operation**: add the constant in
   [`internal/grant/types.go`](../internal/grant/types.go) and accept it in
   `cmd/orchestrator-stub`.
3. **Profile**: wire the operation into the `SecretsMounts` map in
   `cmd/agentgate/serve.go`, gated by a flag like `--vault-kubernetes-mount`
   so the lane stays off until deliberately configured. An operation with
   no configured profile fails closed at binding time.
4. **Policy**: add the operation to `config.operations` and allowlist the
   workload path and Vault roles; add Rego tests for the allow and the
   cross-workload deny.
5. **Prove isolation**: extend the real-Vault integration test
   (`internal/vaultmgr/vaultapi/vault_integration_test.go`) so a token from
   the new lane cannot read any other lane's path, and revocation ends the
   lane's access.

## Verifying an integration

The merge bar is the contract:

```bash
AGENTGATE_REQUIRE_DOCKER=true make check
```

That runs formatting, build, vet, lint, the race-enabled test suite
(including a live Vault in Docker and, when Docker is required, a real
PostgreSQL container), and all OPA policy tests. The audit trail is
queryable through the human rail and the `audit_events` table; every event
is credential-free by construction and tested for it.

For the full sandbox walkthrough, including the suspended demo Jobs and the
CloudTrail correlation steps, continue with [DEPLOY.md](DEPLOY.md).
