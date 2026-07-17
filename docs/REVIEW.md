# Independent adversarial review

Reviewer: Claude (Fable 5), acting as independent adversarial reviewer.
Review date: 2026-07-17. Builder: GPT 5.6 via Copilot.
Scope: full repository at commit `4306dca` (clean working tree).
Method: every merge-bar suite executed locally; every invariant traced to
code; every README test claim checked against the test body, not its name;
upstream version pins and API usage verified against reality.

**Bottom line:** no Critical findings. All ten invariants hold with code
evidence. The test suite genuinely tests what it claims, including the real
Vault audit-attribution assertion. One Major process finding: the documented
local merge bar silently skips the PostgreSQL integration tests. The rest are
Minor hardening items and documentation nits.

---

## 1. Step 0 — actual command results

Environment: macOS (darwin/arm64), colima Docker runtime, Go 1.26.5 toolchain
(module targets go 1.24.0), Terraform v1.15.6, golangci-lint 2.12.2, OPA
1.18.2, Helm v4.2.0, ShellCheck 0.11.0.

### `AGENTGATE_REQUIRE_DOCKER=true make check`

| Attempt | Result |
| --- | --- |
| First run, default shell env | **FAIL** — `TestVaultManagerWithRealVault` → `vault_integration_test.go:506: Docker is required for the Vault integration test: rootless Docker not found`; `make: *** [test] Error 1`. All other packages `ok`. |
| Second run, with the README's colima exports (`DOCKER_HOST=unix://$HOME/.colima/default/docker.sock`, `TESTCONTAINERS_DOCKET_SOCKET_OVERRIDE=/var/run/docker.sock`) | **PASS** — fmt-check, build, vet, `golangci-lint run` (0 issues), `go test -race ./...` all green; `TestVaultManagerWithRealVault` PASS (1.81s) against live `hashicorp/vault:2.0.3` by digest; `opa check` and all 52 `opa test` cases pass. |

The first failure is environmental and the README documents the colima
exports, so this is not a Critical "README claims green but isn't" case.
However, note the silent-skip finding **F-1** below: even the green run did
not execute the PostgreSQL integration tests.

### PostgreSQL integration tests (run separately)

`AGENTGATE_REQUIRE_DOCKER=true` does **not** run
`TestPostgresStoresLifecycleAndRace` or
`TestPostgresExpiredBindingClaimIsReplicaSafeAndRecoverable` — they SKIP
unless `AGENTGATE_TEST_DATABASE_URL` is set (CI sets it via a `postgres:17`
service; the README local quickstart never mentions it). Re-run against a
disposable `postgres:17` container with that variable set: **both PASS**,
along with the full `internal/api` workflow suite (17 tests) and
`internal/grant`, `internal/expiry`, `internal/approval` — all PASS.

### Dashboard suite

```
npm ci          → 0 vulnerabilities
npm run typecheck (tsc -b)  → PASS
npm run lint (oxlint)       → PASS
npm test (vitest)           → 7 files, 32 tests, all PASS
npm run build (tsc + vite)  → PASS (dist built, 417 kB JS)
```

### Deployment static checks

```
terraform fmt -check -recursive deploy          → clean
init -backend=false + validate (infra)          → Success! The configuration is valid.
init -backend=false + validate (platform)       → Success! The configuration is valid.
init -backend=false + validate (agentgate)      → Success! The configuration is valid.
terraform -chdir=deploy/agentgate test          → 1 passed, 0 failed
deploy/scripts/render-charts.sh                 → "Rendered chart manifests passed static assertions" (pulled real spire 0.29.0, vault 0.34.0, bitnami postgresql 18.8.0 charts with checksum/digest verification)
deploy/scripts/assert-agentgate-static.sh       → "AgentGate static security assertions passed."
shellcheck deploy/scripts/*.sh deploy/scripts/lib/*.sh → clean
```

### Version pins — verified against upstream reality

| Pin | Claimed in | Verdict |
| --- | --- | --- |
| Go 1.24 | `go.mod:3` (`go 1.24.0`), CI `go-version: 1.24.x` | **Real, consistent** |
| Terraform 1.15.6 | README, CI `ci.yml:197`, `deploy/images/Dockerfile:15` | **Real** — binary runs locally (upstream latest 1.15.8); both Dockerfile SHA256s match `releases.hashicorp.com/terraform/1.15.6/terraform_1.15.6_SHA256SUMS` exactly (amd64 `a7150d3b…`, arm64 `404c9cfa…`) |
| golangci-lint 2.12.2 | README, CI `ci.yml:94` | **Real** — ran locally, `0 issues` |
| Vault image 2.0.3 | `vault_integration_test.go:35` (digest-pinned), `helm-values/vault.yaml:12`, `assert-rendered-manifests.sh:37` | **Real** — image pulled by digest and ran in the integration test; all three references consistent |
| Vault chart 0.34.0, SPIRE chart 0.29.0, bitnami postgresql 18.8.0 | `render-charts.sh:26-42` | **Real** — pulled from upstream during this review with matching archive checksums |
| Helm v4.2.0, Node 24.x, postgres:17, CI actions by commit SHA | `ci.yml` | **Real** (Helm v4.2.0 ran locally) |

---

## 2. Invariant verdicts

| # | Invariant | Verdict | Key evidence |
| --- | --- | --- | --- |
| 1 | Credential blindness (incl. logs & webhooks) | **PASS** | Manager touches only `auth/<mount>/role/<name>` and `sys/policies/acl/<name>` ([manager.go:112-149,181-222](../internal/vaultmgr/vaultapi/manager.go)); `RedemptionDescriptor` has no credential field ([authz/types.go:39-47](../internal/authz/types.go)); `OperationError` strips Vault response bodies, keeps only status code ([errors.go:70-86](../internal/vaultmgr/vaultapi/errors.go)); audit `safeDetails` blocks token/credential key names and AKIA/ASIA values ([audit/postgres_store.go:417-462](../internal/audit/postgres_store.go)); webhook payload carries only grant context, no descriptor, no nonce ([webhook.go:239-322](../internal/approval/webhook.go)); log claim tested for real — `TestLogsAuditAndJSONDoNotCarryCredentialMaterial` asserts captured slog output + response + audit JSON contain no injected credential marker; integration test proves the management token **cannot** read the data-plane path ([vault_integration_test.go:143-147](../internal/vaultmgr/vaultapi/vault_integration_test.go)) and that no root/control/agent token or JWT appears in manager audit records (`assertManagerAuditRecords`, prohibited-values scan). |
| 2 | Attribution — agent redeems itself | **PASS** | Agent performs its own JWT login and creds read ([cmd/agent-sim/vault.go:157-252](../cmd/agent-sim/vault.go)); AgentGate's own Vault login uses AgentGate's JWT-SVID and management role, never the agent's ([cmd/agentgate/vault_provider.go:28-56](../cmd/agentgate/vault_provider.go)); no code path forwards a Vault token to or from an agent; the integration test parses Vault's actual audit device and asserts the **agent** SPIFFE subject on both the login and the secrets read ([vault_integration_test.go:598-652](../internal/vaultmgr/vaultapi/vault_integration_test.go)). |
| 3 | Two proofs enforced before policy | **PASS** | SVID validated by middleware from `request.TLS.PeerCertificates` ([router.go:203-216](../internal/api/router.go)); grant verified before policy ([handlers.go:164](../internal/api/handlers.go)); OPA input built exclusively from the verified grant + authenticated `spiffe_id` + server clock ([authz/opa.go:153-173](../internal/authz/opa.go)); request body has no identity field and `requested_vault_role` must equal the signed `vault_role` ([handlers.go:999](../internal/api/handlers.go)); `TestAccessRequestBodiesAreBoundedAndCannotSupplyIdentity` and `TestInvalidGrantStopsBeforePolicyAndVault` cover both failure directions. |
| 4 | Grant verification | **PASS** | Signer and verifier share one `canonicalPayload` (same struct, same field order, RFC3339Nano UTC — [ed25519.go:108-136](../internal/grant/ed25519.go)); `cmd/orchestrator-stub` signs via `grant.Signer` ([main.go:68](../cmd/orchestrator-stub/main.go)), so byte-identical by construction; signature checked **before** time bounds and nonce ([ed25519.go:68-105](../internal/grant/ed25519.go)) — invalid signatures cannot burn a nonce (`TestInvalidSignatureDoesNotConsumeValidNonce`); nonce consumption is a single atomic `INSERT … ON CONFLICT … WHERE expired … RETURNING` ([postgres_nonce_store.go:34-42](../internal/grant/postgres_nonce_store.go)) — no check-then-act TOCTOU; `on_behalf_of` required at sign and verify time ([ed25519.go:138-141](../internal/grant/ed25519.go)); future-issue bound (30s skew) and expiry enforced. |
| 5 | SVID validation | **PASS** | Full chain verification against configured roots with ClientAuth EKU, leaf profile checks (no CA / cert-sign / CRL-sign), exactly one URI SAN and zero DNS/email/IP SANs, trust-domain allowlist, identity derived from the certificate ([svid/x509.go:37-73](../internal/svid/x509.go)); serve wires the same roots into TLS 1.3-min config ([serve.go:457-462](../internal/../cmd/agentgate/serve.go)); no header or body identity is ever consulted. |
| 6 | Vault binding correctness + injection | **PASS** | `bound_subject` = the exact canonical SPIFFE ID, wildcards rejected, round-trip canonicality enforced ([binding.go:80-87](../internal/vaultmgr/vaultapi/binding.go)); `bound_audiences=["vault"]`; `token_ttl = token_max_ttl = token_explicit_max_ttl = granted seconds`, `token_no_default_policy=true` ([binding.go:61-72](../internal/vaultmgr/vaultapi/binding.go)); policy grants `read` on exactly one `%q`-quoted `aws/creds/<role>` path. Injection trace: every grant-derived value reaching a Vault path (`RequestID`, `VaultRole`, mounts, prefixes) must match `^[A-Za-z0-9][A-Za-z0-9_-]*$` ([config.go:20](../internal/vaultmgr/vaultapi/config.go)); `RequestID` is additionally UUID-validated at the API ([handlers.go:986](../internal/api/handlers.go)). No slash, glob, `..`, or HCL metacharacter can reach a path, role name, or policy body. Reconcile compares existing role/policy and fails closed on any conflicting security field, then read-back-verifies its own writes. |
| 7 | Approval gates provisioning | **PASS** | `Decide` takes `SELECT … FOR UPDATE OF ap, ar`, re-checks state inside the transaction, and updates state+version — a genuinely serializable winner, not check-then-act ([postgres_store.go:294-374](../internal/approval/postgres_store.go)); proven with real concurrent goroutines asserting exactly one winner ([postgres_integration_test.go:165-208](../internal/approval/postgres_integration_test.go)). `EnableAccess` is unreachable until `Decide` commits `approved` + `binding_state='enabling'`, or a later `ClaimBinding` CAS (also `FOR UPDATE`) claims a failed/stale binding. Rail separation: `requireWorkload` rejects any request carrying an `Authorization` header ([router.go:193](../internal/api/router.go)); human routes require a verified bearer token; a workload SVID cannot satisfy approve/deny/list/revoke and a human token cannot satisfy the workload route (`TestFullPendingApprovalFlowAndSeparateReadRails`, `TestWebhookFailureLeavesPendingAndHumanRailRejectsWorkload`). |
| 8 | `request_id` propagation | **PASS** | Decision row: `access_requests.request_id` PK with `policy_version CHAR(64)` recorded at `Create` — before any Vault call ([handlers.go:240](../internal/api/handlers.go), [migrations/000001](../internal/audit/migrations/000001_foundation.up.sql)); `policy_version` = SHA-256 of the exact embedded bundle ([opa.go:62,182-185](../internal/authz/opa.go)), shape-validated before persist; Vault role/policy names = `prefix + request_id` ([binding.go:36-37](../internal/vaultmgr/vaultapi/binding.go)); STS session: agent sends `role_session_name = descriptor.RequestID` on the creds read ([cmd/agent-sim/vault.go:203-209](../cmd/agent-sim/vault.go)); deploy side uses `credential_type = "assumed_role"` so the caller-supplied session name flows to `AssumeRole`/CloudTrail, and `audit_non_hmac_request_keys = ["role_session_name"]` keeps it legible in Vault audit ([deploy/platform/vault.tf:180-204](../deploy/platform/vault.tf)). |
| 9 | Fail closed | **PASS** | OPA evaluation error, malformed output, missing `bundle_ready`, or out-of-range TTL → deny + 500, never allow ([opa.go:94-115,241-271](../internal/authz/opa.go)); startup validates every dependency including the migration-2 constraint and refuses to boot ([serve.go:242-268,571-603](../cmd/agentgate/serve.go)); Postgres failure → 500 on every store call and readiness failure; Vault failure → `binding_failed` + 502 with no descriptor; audit append failure → 500 **before** the descriptor is returned ([handlers.go:212-215,268-278](../internal/api/handlers.go)); malformed grant → rejected before policy. `TestReadinessFailsGenericallyWhenDependencyIsUnavailable`, `TestEnableAccessFailsClosedOnConflictAndAuditsFailure` cover error paths. |
| 10 | Expiry reconciler | **PASS** (with two Minor notes) | Claim is one atomic `UPDATE … FROM (SELECT … FOR UPDATE SKIP LOCKED LIMIT 1)` ([postgres_store.go:514-564](../internal/approval/postgres_store.go)) — multi-replica safe, proven with concurrent claim test; failed revocations release the claim back to `enabled` for retry; stale `revoking` claims are reclaimed after 30s (replica-crash recovery, tested). Descriptor-vs-reap race: cleanup deliberately starts 30s **before** `redemption_expires_at` (`bindingCleanupLead`, [postgres_store.go:31](../internal/approval/postgres_store.go)), so a binding can only be deleted pre-login when the remaining window is under ~30s (finding F-4); clock skew between replicas can also only reap **early** — the failure direction is denial of access, never extension. Late reap (worker/Vault down) leaves the role configured; that is exactly gap G-04 and honestly documented. |

---

## 3. Findings by severity

### Critical

None. No invariant is violated; no credential-bearing field, log line,
webhook payload, DB column, or dashboard response was found; no test
misrepresents what it verifies.

### Major

**F-1 — The documented local merge bar silently skips the PostgreSQL
integration tests.**
`AGENTGATE_REQUIRE_DOCKER=true make check` reports `ok` for
`internal/approval` while `TestPostgresStoresLifecycleAndRace` and
`TestPostgresExpiredBindingClaimIsReplicaSafeAndRecoverable` SKIP — they gate
on `AGENTGATE_TEST_DATABASE_URL` ([postgres_integration_test.go](../internal/approval/postgres_integration_test.go)), which appears
nowhere in the README's local quickstart or merge-bar section. CI sets it via
a service container, so CI is covered, but a contributor who runs the
documented commands and sees green has not executed the approval-race,
binding-claim, or stale-recovery proofs — the very tests backing invariants
7 and 10. `AGENTGATE_REQUIRE_DOCKER=true` (the documented "make required
tests mandatory" switch) does not apply to them, which is the same silent-skip
failure mode the Vault test explicitly engineered against.
*Fix:* make the Postgres tests fail (not skip) when
`AGENTGATE_REQUIRE_DOCKER=true` and no database URL is set — or auto-start a
testcontainers Postgres in that mode — and document
`AGENTGATE_TEST_DATABASE_URL` in the README local quickstart.

### Minor

**F-2 — The task grant carries no intended-workload claim.**
`TaskGrant` ([grant/types.go:17-30](../internal/grant/types.go)) has no
`spiffe_id`/workload-path field, so grant→workload binding rests entirely on
the policy's per-workload `vault_roles`/`operations` allowlists
([policies/authorization.rego:13-22](../policies/authorization.rego)). In the
shipped config each role maps to exactly one workload path, so the property
holds — but it holds by configuration, not by construction. If a future
policy edit gives two workload paths the same `vault_role`, a grant issued to
one runner class becomes redeemable by the other, silently. The dispatcher
launches the runner and already knows its identity.
*Fix:* add an optional signed `bound_workload_path` (or full SPIFFE ID) claim
and, when present, require it to match the authenticated identity in
`policyInput`/Rego; alternatively add a Rego test asserting no `vault_role`
is shared across workload entries.

**F-3 — Vault token lifetime is anchored at login, not at grant time.**
`token_ttl`/`token_explicit_max_ttl` equal the remaining window at binding
enablement ([binding.go:66-70](../internal/vaultmgr/vaultapi/binding.go)),
but Vault counts them from login. An agent that logs in at T+(window−ε) holds
a token valid ~a full window past the granted expiry. In practice the cutoff
is enforced because the expiry worker deletes the role (blocks new logins)
**and** the policy (a token whose policies were deleted retains no
capabilities), and the reference agent clamps the creds `ttl` param itself —
but the absolute cutoff depends on cleanup liveness, which is exactly G-04.
The KNOWN-GAPS entry is honest about this ("no native absolute expiration
field"); recording it here because it is the one place where "effective
access window ≤ granted TTL" is a liveness property, not a safety property.
*Fix:* none available inside open-source Vault JWT roles (as G-04 states);
consider tightening `token_ttl` to a small constant (e.g. 60s, renewable up
to the window) so a late login cannot mint a long-lived token.

**F-4 — Bindings with under ~30 seconds of remaining life can be revoked
before the agent redeems.** `bindingCleanupLead = 30s`
([postgres_store.go:31](../internal/approval/postgres_store.go)) means
`ClaimExpiredBinding` targets rows expiring within 30s, including a binding
enabled moments ago with a short granted window. Fail-safe direction (agent
gets a login failure, never extra access), and the descriptor consumer
rejects expired windows anyway — but a legitimate sub-30s grant is
effectively unusable and the failure is surfaced as a Vault login error, not
a policy message.
*Fix:* skip claims where `binding_updated_at` is within a grace period of
enablement, or floor the effective TTL at enablement to `lead + margin`.

**F-5 — A valid grant's nonce is burned even when the request fails
downstream.** `Verify` consumes the nonce ([ed25519.go:98-104](../internal/grant/ed25519.go))
before the audit append, policy evaluation, and store write; any later 500
(audit store down, Postgres blip) leaves the grant permanently unusable —
resubmission returns `replayed_task_grant`. Fail-closed and arguably correct
("first accepted use" semantics), but the dispatcher must reissue on any
transient server error, and the agent's recovery path (GET
`/v1/requests/{id}`) only works if the record was created.
*Fix:* accept as designed but document it in the API contract; or move nonce
consumption after the `Create` conflict check inside the same request (the
atomic store already tolerates either order across replicas).

**F-6 — Workload read endpoint is an existence oracle.** On
`GET /v1/requests/{id}`, a workload with a valid SVID gets 404 for a
nonexistent request but 403 for another workload's request
([handlers.go:360-387](../internal/api/handlers.go)), letting any attested
workload probe which request UUIDs exist. UUIDs are unguessable, so impact is
negligible.
*Fix:* return 404 for both cases on the workload rail.

**F-7 — LICENSE copyright placeholder is unfilled.** [LICENSE:190](../LICENSE)
still reads `Copyright [yyyy] [name of copyright owner]` — the Apache-2.0
appendix template was never instantiated. Harmless legally (the license is
valid without it) but sloppy for a repo this polished.
*Fix:* fill in year and owner or delete the appendix block.

**F-8 — Deployment nits (sandbox-acceptable, all already implied by G-07):**
`helm-values/postgresql.yaml:6` uses `tag: latest` (mitigated by digest pin
on the next line, and the migrations Job pins the same digest);
`tls.enabled: false` for in-cluster Postgres and SPIRE datastore
`sslmode: disable` — plaintext DB traffic inside the cluster, consistent
with G-07's disclosure. `cmd/agent-sim/agentgate.go:45` sets client TLS
MinVersion 1.2 while the server requires 1.3 (negotiation lands on 1.3;
cosmetic inconsistency).

**F-9 — Docs wording: the demo S3 access is read-write within the prefix.**
[deploy/infra/demo_target.tf:158-168](../deploy/infra/demo_target.tf) grants
`s3:PutObject`/`s3:DeleteObject` under `governed-runner/*` (needed for the
plan-marker object). ARCHITECTURE.md's phrasing ("one S3 prefix plus
read-only EC2 describe") is technically accurate — "read-only" modifies EC2 —
but readers routinely misparse it as read-only S3, and the "tagged sandbox
resource set" phrasing describes resource tags, not an IAM tag condition.
*Fix:* one clarifying sentence in ARCHITECTURE.md §Deployment.

---

## 4. Tests vs claims

| README/doc claim | Verdict | Evidence |
| --- | --- | --- |
| Vault integration test "proves agent audit attribution" | **TRUE, genuinely** | `assertVaultAuditAttribution` copies the audit file out of the container, JSON-decodes every entry, and requires the **agent's SPIFFE subject** in `auth.display_name` for both the `auth/<mount>/login` response and the secrets-path read ([vault_integration_test.go:598-652](../internal/vaultmgr/vaultapi/vault_integration_test.go)). Not a mere login-success check. |
| "Exact one-path access" | **TRUE, with negative tests** | The agent token must read the allowed path, then **fail** to read `aws/creds/terraform-sibling` and **fail** `sys` policy listing ([vault_integration_test.go:160-172](../internal/vaultmgr/vaultapi/vault_integration_test.go)); the stored policy is asserted to contain exactly one `path` stanza with `capabilities = ["read"]` (lines 126-134). |
| "Post-revoke login failure" | **TRUE** | After the expiry worker's revocation, a fresh login with the previously working JWT must fail against live Vault (lines 221-229); role and policy absence is read back with the root client. |
| "Expiry cleanup" | **TRUE** | Cleanup is driven by the real `expiry.Worker` running against live Vault, not by calling `Revoke` directly (`expireBindingWithWorker`, lines 250-306). |
| Multi-replica transition tests "actually run concurrent transitions" | **TRUE** | Concurrent goroutine `Decide` calls with exactly-one-winner assertion ([postgres_integration_test.go:174-208](../internal/approval/postgres_integration_test.go)); concurrent `ClaimExpiredBinding` across separate store instances exercising `FOR UPDATE SKIP LOCKED` (lines 307-347); stale-claim recovery via a "restarted" store. |
| Rego: default deny; distinct reason per deny path; clamp boundaries | **TRUE** | `default decision := deny` ([authorization.rego:25-29](../policies/authorization.rego)); 33 distinct `deny.*` reasons, each appearing exactly once in the policy and **all 33** referenced in tests; boundary tests at exactly 900/901 (`test_ttl_of_exactly_fifteen_minutes…`, `test_ttl_above_fifteen_minutes_is_clamped…`) and 3600/3601 (`…sixty_minutes…allowed_but_clamped`, `test_ttl_above_sixty_minutes_is_denied`). 52 tests total, all passing. |
| "Invalid signatures do not burn a valid nonce" | **TRUE** | Ordering in [ed25519.go:68-105](../internal/grant/ed25519.go) plus `TestInvalidSignatureDoesNotConsumeValidNonce`, which tampers a signed grant, submits it, then proves the original still verifies. |
| Logs/webhooks credential-free | **TRUE (tested, not asserted)** | `TestLogsAuditAndJSONDoNotCarryCredentialMaterial` injects an AWS-key-shaped marker into a Vault error and asserts it appears in neither the captured slog buffer, the HTTP response, nor any audit record; webhook payload test (`TestHTTPNotifierRetriesCredentialFreeSlackPayload`) checks the delivered body. |
| Migrations up/down + append-only audit trigger | **TRUE** | CI applies both migrations, proves `UPDATE audit_events` raises `audit_events is append-only`, then rolls both back ([ci.yml:140-183](../.github/workflows/ci.yml)). |

**Caveat the README already owns:** the "aws" mount in the integration test
is a KV-v1 stand-in with deterministic data, not the real AWS secrets engine
(no STS, no CloudTrail). The README and G-05 state this explicitly
("deterministic Vault logical mount instead of AWS"), so it is disclosed, not
misrepresented — but readers should not take "exact one-path access" as
evidence about real AWS lease behavior.

**Mock-away check:** no test was found that mocks the property it claims to
verify. The unit suites use fakes for *collaborators* (audit store, Vault
client) while the claimed property (path validation, conflict handling,
serialization) runs real code; every live-Vault claim runs against live
Vault, and every concurrency claim spawns real goroutines against real
Postgres.

---

## 5. Hallucination sweep

Everything checked resolves to real upstream APIs and versions.

- **hashicorp/vault/api v1.23.0** — `Logical().ReadWithContext/WriteWithContext/DeleteWithContext/ReadWithDataWithContext`, `Sys().PutPolicyWithContext/GetPolicyWithContext/DeletePolicyWithContext/EnableAuditWithOptionsWithContext/EnableAuthWithOptionsWithContext/MountWithContext`, `Client.Clone/SetNamespace/SetToken/ClearToken/Address/Namespace`, `ResponseError.StatusCode`, `Config.DisableRedirects`, `ConfigureTLS` — all real. JWT-auth role fields written (`role_type`, `user_claim`, `bound_subject`, `bound_audiences`, `token_policies`, `token_no_default_policy`, `token_ttl`, `token_max_ttl`, `token_explicit_max_ttl`, `verbose_oidc_logging`) are all genuine Vault JWT-auth role parameters; the `role_session_name` and `ttl` query parameters on `aws/creds/:name` reads are genuine AWS-secrets-engine features for `credential_type = "assumed_role"`. Empirically confirmed by the passing live-Vault test.
- **go-spiffe v2.8.1** — `workloadapi.NewJWTSource/NewX509Source`, `jwtsvid.Params{Audience}`, `tlsconfig.MTLSClientConfig` + `AuthorizeID`, `x509bundle.Source`, `spiffeid.FromURI/FromString/TrustDomainFromString` — all real API.
- **OPA** — go.mod pins `github.com/open-policy-agent/opa v1.7.1` and imports `…/opa/v1/rego`; the unversioned module path with a `/v1` package directory is exactly OPA ≥1.0's layout. `rego.Query/Module/PrepareForEval/EvalInput` real. `import rego.v1` in the policy is current idiom.
- **testcontainers-go v0.40.0** — `GenericContainer`, `HostAccessPorts` + `testcontainers.HostInternal` (host-port exposure for the JWKS server), `CopyFileFromContainer`, `CleanupContainer`, `wait.ForHTTP` — all real and empirically exercised.
- **Terraform providers** (subagent-verified, then validated with `terraform init/validate`): `vault_jwt_auth_backend` with `oidc_discovery_url`/`bound_issuer`/`oidc_discovery_ca_pem`; `vault_aws_secret_backend` with `audit_non_hmac_request_keys` (specifically checked — real common-mount argument, not invented); `vault_aws_secret_backend_role` with `credential_type = "assumed_role"`, `role_arns`, `default_sts_ttl`/`max_sts_ttl` — all real.
- **SPIRE↔Vault OIDC wiring** ([deploy/platform/vault.tf:161-178](../deploy/platform/vault.tf), [helm-values/spire.yaml:7,224](../deploy/platform/helm-values/spire.yaml)) — `spiffe-oidc-discovery-provider` is enabled in the chart, `jwtIssuer` and `oidc_discovery_url`/`bound_issuer` all equal `https://spire-spiffe-oidc-discovery-provider.spire-system.svc.cluster.local`, discovery CA taken from the `spire-bundle` ConfigMap. Consistent end to end; the chart keys used (`spiffe-oidc-discovery-provider`, `controllerManager.identities.clusterSPIFFEIDs`, `server.ha.raft`, `server.extraContainers`) are real keys of the pinned charts (charts pulled and rendered during this review).
- **AgentGate management policy in deploy** ([deploy/platform/vault.tf:206-219](../deploy/platform/vault.tf)) — exactly two path stanzas, `auth/spire-jwt/role/agentgate-role-*` and `sys/policies/acl/agentgate-policy-*`, CRUD only, **no** read on any secrets engine; prefixes match the runtime flags in `deploy/agentgate/locals.tf:66-67`; `bootstrap-vault.sh:115-117` independently fails if `aws/creds/` ever appears in the policy. Matches the architecture's credential-blindness contract.
- **Dockerfiles** — `golang:1.24.13-alpine3.23` and `distroless/static-debian13:nonroot` digest-pinned; Terraform 1.15.6 checksum-verified against upstream during this review (exact match both arches). `tfc-agent:1.29.0`, aws-cli 2.36.1, kubectl v1.36.1 digest-pinned (not pulled during review; digests fail loudly if wrong).
- **KNOWN-GAPS re-ranking** — the register is accurate and, unusually, *underclaims*: everything it lists as proven was found proven, and the two `TODO(verify)` items (EBS CSI add-on pin `v1.62.0-eksbuild.1` for K8s 1.36 in `deploy/infra/addons.tf`; fresh-account deploy G-01) remain genuinely unverified — they require an AWS account and are correctly quarantined as manual steps. No gap entry was found to be understated; G-04's framing matches finding F-3 precisely.
- **Credential scan** — CI's static-credential grep re-run locally over `deploy/`: no matches; no hardcoded passwords or tokens anywhere in deploy (Postgres password via `existingSecret` + out-of-band 64-hex generation; approver token via `openssl rand`; the only literal AWS account ID is the documented `111122223333` placeholder in a render-time `--set`).

---

## 6. What the builder got right

This is an unusually disciplined codebase, and the review should say so
plainly:

1. **The credential-blindness invariant is enforced in depth, not asserted.**
   Type-level (no credential fields exist to leak), error-level (Vault
   response bodies stripped at construction), audit-level (key-name and
   value-pattern rejection), transport-level (webhook/dashboard field
   allowlists), and test-level (marker-injection tests against real captured
   logs; prohibited-value scans over audit JSON against a live Vault).
2. **The atomicity claims are real SQL, not wishful locking.** Nonce burn is
   one upsert; approval winner is `FOR UPDATE` + in-transaction re-check;
   expiry claim is `FOR UPDATE SKIP LOCKED` with stale-claim recovery — and
   each has a genuine concurrency test.
3. **The integration test actually proves the architecture's central story**
   — agent-attributed Vault audit — by parsing the audit device, with
   negative tests for sibling path, wrong subject, wrong audience, and
   post-revoke login. This is the test most projects fake; here it is real.
4. **Fail-closed is systematic.** Every error path examined (OPA, Postgres,
   Vault, audit, config, malformed policy output, drifted Vault state)
   denies; startup refuses to boot on any missing dependency; the policy
   engine even self-tests "empty input must be denied" at construction.
5. **Injection surface is closed by construction** — one conservative
   name-part regex gates every externally influenced value before it can
   touch a Vault path or policy body, and the API layer independently
   requires UUIDs.
6. **Honest limitations.** The KNOWN-GAPS register and README under-promise
   relative to what the code does; STS non-revocability is force-stamped into
   every revocation report (`NormalizeRevocationReport` makes
   `sts_credentials_may_remain=true` non-optional).
7. **Version pins are real and verified**, down to matching upstream SHA256s
   in the Dockerfile and digest-pinned test images — the exact place
   hallucinations usually hide, and none were found.
8. **Deployment hygiene**: suspended-by-default demo Jobs, digest-only image
   variable validation, checksum-gated chart rendering, a bootstrap script
   that refuses a management policy mentioning `aws/creds/`, and no static
   credentials anywhere.

## 7. Prioritized fix list

1. **F-1 (Major):** Make `AGENTGATE_REQUIRE_DOCKER=true` (or a sibling
   `AGENTGATE_REQUIRE_POSTGRES`) force the Postgres integration tests to run
   or fail loudly; document `AGENTGATE_TEST_DATABASE_URL` in the README local
   quickstart. Until then, local green ≠ CI green.
2. **F-2:** Add an intended-workload claim to the task grant (or a Rego test
   forbidding shared `vault_roles` across workload entries) so grant→workload
   binding is structural, not configurational.
3. **F-3:** Consider a small constant `token_ttl` with renewal up to the
   window, so a last-second login cannot outlive the granted window even if
   cleanup stalls (complements G-04).
4. **F-4:** Add an enablement grace period to `ClaimExpiredBinding` (or floor
   granted TTLs) so sub-30-second windows are either usable or rejected with
   a clear reason.
5. **F-5:** Document nonce-burn-on-server-error semantics in the API
   contract, or reorder nonce consumption after record creation.
6. **F-7:** Fill in the LICENSE appendix placeholder ([LICENSE:190](../LICENSE)).
7. **F-6, F-8, F-9:** 404-for-both on the workload read rail; pin the
   Postgres chart `tag` to match its digest; one clarifying sentence on S3
   read-write-within-prefix in ARCHITECTURE.md.

## Source modifications made during this review

None. No source, test, policy, or deployment file was changed; this document
(`docs/REVIEW.md`) is the only addition. Zero one-line fixes were applied —
every finding is listed above instead.
