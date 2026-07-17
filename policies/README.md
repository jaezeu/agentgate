# Policies

`authorization.rego` is AgentGate's embedded, default-deny authorization
bundle. Its configuration names only teaching-sandbox trust domains,
repositories, workload paths, operations, environments, and Vault roles. The
engine prepares this module once at startup and performs no network access
during evaluation.

## Input

The Go engine constructs input from trusted internal values:

```text
request_id                 AccessRequest correlation ID
spiffe_id                  authenticated X509-SVID identity
requested_vault_role       role independently requested by the workload
current_time               trusted RFC3339Nano decision time
task_grant.request_id      verified, dispatcher-signed task ID
task_grant.repo
task_grant.commit_sha
task_grant.operation
task_grant.environment
task_grant.vault_role
task_grant.ttl             seconds
task_grant.nonce
task_grant.issued_at       RFC3339Nano
task_grant.on_behalf_of    signed human attribution
task_grant.ticket_id
```

The top-level and signed `request_id` values must match. The dispatcher
signature is verified before policy evaluation and is not copied into policy
input. No Vault token, lease, cloud key, session token, or other credential is
accepted or produced.

## Decisions and reasons

Rego returns only `decision`, `reason`, and `granted_ttl_seconds`. Go rejects
missing fields, unknown fields, unknown decision kinds, and invalid decision/TTL
combinations.

Stable reason prefixes identify the rule family:

| Prefix | Meaning |
| --- | --- |
| `allow.scope_valid` | Both workload identity and signed task scope passed |
| `pending.prod_apply` | A fully valid production apply needs human approval |
| `deny.missing_*` | A required identity, task, or accountability value is absent |
| `deny.malformed_*`, `deny.invalid_*` | A value has the wrong shape |
| `deny.untrusted_*`, `deny.*_not_allowed*` | Identity or scope is outside configured allowlists |
| `deny.unsupported_*`, `deny.*_mismatch` | Signed and requested scope is inconsistent |
| `deny.non_positive_ttl`, `deny.ttl_exceeds_maximum` | TTL is outside hard bounds |
| `deny.grant_*` | Trusted time shows a future-issued or expired grant |
| `deny.default` | No authorization rule matched |
| `deny.policy_evaluation_error`, `deny.malformed_policy_output` | The Go engine failed closed |

Exact reason strings are asserted in the Rego and Go suites.

## TTL

| Signed request | Result |
| --- | --- |
| `1..900` seconds | Grant the requested duration |
| `901..3600` seconds | Clamp to 900 seconds |
| More than `3600` seconds | Deny |
| Zero, negative, or non-integral | Deny |

Production `terraform-apply` receives the same TTL calculation, but returns
`pending_approval` only after every other check succeeds.

## Policy version

`policy_version` is the lowercase hexadecimal SHA-256 of the exact
OPA-formatted bytes in `authorization.rego` that the Go engine evaluates.
Tests, this README, and Go wrappers are not part of the hash. Any policy or
configuration edit must be formatted before review, so changed evaluated bytes
produce a changed version on allow, deny, pending, and runtime fail-closed
decisions.

Run the teaching suite locally with:

```sh
make policy-test
opa check policies
opa fmt --diff policies
```