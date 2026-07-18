# Known gaps

This register is ordered by demo-breaking likelihood and then impact. It records
what has not been proved; it is not a waiver for AgentGate's architectural
invariants. A credential crossing AgentGate, loss of either required proof, or
mixing human and workload identity rails is a release blocker, not an acceptable
gap.

Evidence was last reconciled on 2026-07-17. Automated checks use real PostgreSQL
and Vault, but normal CI intentionally does not require AWS, EKS, or
CloudTrail.

## Demo blocker / high likelihood

### G-01: A fresh AWS sandbox deployment has not been observed

- **Owner:** First sandbox operator and issue #6 integration owner.
- **Affected component:** All four Terraform roots, the GitHub OIDC deploy
  workflow, EKS, SPIRE, Vault, PostgreSQL, AgentGate, and the governed
  runner Job.
- **Evidence/source checked:** Terraform formatting, initialization, validation,
  static tests, chart rendering, ShellCheck, local image builds, real PostgreSQL,
  and real Vault testcontainers pass. No AWS account or GitHub environment
  was changed during this integration pass.
- **Exact manual verification:** Follow [DEPLOY.md](DEPLOY.md) from preflight
  through all three applies; run `deploy/scripts/verify-cluster.sh`; execute the
  signed-grant runner; verify the Terraform plan, Vault audit attribution,
  `request_id` role session, CloudTrail lookup, and reverse destroy.
- **Failure symptom:** A provider, chart, admission, network, storage, IAM, or
  service-version mismatch stops the demo despite a green static suite.
- **Workaround:** Use the real-Vault integration suite for teaching the trust
  boundary and describe AWS/EKS outcomes as unverified. Do not claim an
  end-to-end cloud demonstration.
- **Closure criterion:** One clean-account deployment and reverse destroy are
  recorded with credential-free evidence for every checkpoint in `DEPLOY.md`.

### G-02: No reviewed application image has been published by immutable digest

- **Owner:** Release operator.
- **Affected component:** `deploy/images/Dockerfile`,
  `deploy/agentgate/variables.tf`, AgentGate Deployment, and both demo Jobs.
- **Evidence/source checked:** The multi-binary image builds locally, contains
  Terraform 1.15.6, and passes static manifest assertions. The repository cannot
  know the operator's registry digest in advance.
- **Exact manual verification:** Build for the EKS node architecture, scan the
  image, push it, pull it by digest, run `agentgate version`, `agent-sim -h`, and
  `terraform version`, then set the digest-only image variable as shown in
  `DEPLOY.md`.
- **Failure symptom:** Layer 3 rejects a tag-only value, cannot pull the image,
  or runs bytes other than the reviewed build.
- **Workaround:** None for the cloud demo. Keep the Jobs suspended until a digest
  is reviewed.
- **Closure criterion:** The release record contains the registry digest, scan
  result, source revision, and successful EKS pull for the reviewed image.

### G-03: The pinned EBS CSI add-on may not exist in the chosen Region

- **Owner:** First sandbox operator.
- **Affected component:** `deploy/infra/addons.tf`, Vault and PostgreSQL PVCs.
- **Evidence/source checked:** AWS EKS documentation and the add-on API contract
  were reviewed; availability is Region-specific and is marked `TODO(verify)` in
  source.
- **Exact manual verification:** Run the `aws eks describe-addon-versions`
  command in `DEPLOY.md` for Kubernetes 1.36 and confirm
  `v1.62.0-eksbuild.1` before planning.
- **Failure symptom:** Infra apply rejects the add-on version or platform PVCs
  remain Pending.
- **Workaround:** Select a currently offered, reviewed 1.36-compatible pin and
  rerun all Terraform and chart checks; never accept an implicit latest version.
- **Closure criterion:** The selected Region returns the exact pin and a fresh
  cluster provisions and deletes an encrypted gp3 test PVC.

## High impact but less likely

### G-04: Binding expiry cleanup depends on AgentGate and Vault availability

- **Owner:** AgentGate runtime owner and Vault operator.
- **Affected component:** `internal/expiry`, `internal/approval`, request-scoped
  Vault JWT roles and policies.
- **Evidence/source checked:** The worker claims expiring bindings with
  PostgreSQL `FOR UPDATE SKIP LOCKED`, starts cleanup 30 seconds before expiry,
  retries failures, and recovers stale claims after a replica restart. Unit,
  race, PostgreSQL, and real-Vault tests prove the normal and recovery paths.
  Open-source Vault JWT roles do not have a native absolute expiration field.
- **Exact manual verification:** During a sandbox request, stop one AgentGate
  replica before expiry and verify the other removes the role. Then make Vault
  temporarily unavailable, restore it, and verify the stale claim is reconciled
  and a new JWT login fails.
- **Failure symptom:** During a prolonged AgentGate/Vault outage, an expired
  request role remains configured. The reference agent still rejects the expired
  descriptor, but a compromised workload could attempt Vault directly.
- **Workaround:** Restore the control plane, delete the exact request role and
  policy, and rely on the already bounded Vault/AWS TTL. Alert on `revoking` or
  expired `enabled` rows.
- **Closure criterion:** Production has monitored reconciliation SLOs and an
  independently enforced absolute login cutoff, or a Vault capability that gives
  request auth configuration a native absolute expiry.

### G-05: AWS target scope and full CloudTrail correlation remain manual

- **Owner:** Sandbox cloud operator.
- **Affected component:** Demo S3 bucket/prefix, Vault AWS role, STS session, and
  CloudTrail.
- **Evidence/source checked:** Terraform policies are statically constrained;
  the agent sends the exact `request_id` as `role_session_name`; API and Vault
  integration tests preserve the same identifier. CI uses a deterministic Vault
  logical mount instead of AWS.
- **Exact manual verification:** Run the demo plan, inspect the bucket's
  `Application=AgentGate` tag and prefix, verify out-of-prefix access is denied,
  and run the CloudTrail lookup in `DEPLOY.md`.
- **Failure symptom:** The plan receives AccessDenied on the intended target,
  can access an unintended target, or CloudTrail cannot be joined to the
  AgentGate request.
- **Workaround:** Stop the demo, revoke new access, wait for STS expiry, and use
  AgentGate/PostgreSQL plus Vault audit as the available partial correlation.
- **Closure criterion:** Credential-free evidence shows the intended plan,
  denied out-of-scope action, Vault agent subject, exact STS session name, and
  matching CloudTrail event.

### G-06: Production human OIDC has not been exercised in the sandbox

- **Owner:** Identity-platform integrator.
- **Affected component:** Human API middleware, dashboard, OIDC client
  registration, and `human_auth_mode=oidc`.
- **Evidence/source checked:** OIDC issuer/audience validation, route separation,
  and dashboard OIDC behavior have automated tests. The deployment defaults to
  the explicitly labeled PoC static-token mode.
- **Exact manual verification:** Register a public SPA client, deploy with OIDC
  mode, sign in through the dashboard, approve and deny requests, then prove the
  human token fails on `/v1/access-requests` and an X509-SVID cannot call human
  routes.
- **Failure symptom:** Login redirect loops, issuer/audience rejection, or a
  route accepts the wrong identity rail.
- **Workaround:** Use the PoC token only in an isolated teaching sandbox and
  access human APIs with a protected curl configuration; never call it
  production SSO.
- **Closure criterion:** The target IdP passes login, logout, expiry, audience,
  subject, and both rail-separation tests.

## Production hardening delta

### G-07: Stateful platform services are sandbox-shaped

- **Owner:** Platform/SRE team.
- **Affected component:** Single-replica Vault, PostgreSQL, SPIRE server storage,
  backups, TLS, unseal, and disaster recovery.
- **Evidence/source checked:** Chart values and security contexts are statically
  tested. The sandbox uses KMS auto-unseal but a single Vault replica and a
  disposable storage policy; PostgreSQL traffic is cluster-internal without
  database TLS.
- **Exact manual verification:** Exercise Raft and database backup/restore,
  node loss, trust-bundle rotation, certificate rotation, and recovery while
  preserving audit data.
- **Failure symptom:** A node or volume failure makes authorization unavailable
  or loses decisions/audit records.
- **Workaround:** None appropriate for production. Recreate the disposable
  sandbox from protected bootstrap material.
- **Closure criterion:** Managed or HA services have encryption, tested
  backup/restore, retention, monitoring, and documented RTO/RPO. Auto-unseal
  is in place; the remaining work is replication and recovery.

### G-08: Dispatcher trust uses one PoC Ed25519 key

- **Owner:** Dispatcher/platform security team.
- **Affected component:** Task-grant issuance, human attribution, key rotation,
  and compromise response.
- **Evidence/source checked:** Canonical signing, signature validation, expiry,
  required claims, and shared nonce replay protection are tested. There is no
  key ID, overlap window, or organizational issuer integration.
- **Exact manual verification:** Protect and rotate the sandbox key, confirm an
  old key is rejected after the planned overlap, and audit who can issue each
  claim.
- **Failure symptom:** A key loss stops all requests; a key compromise permits
  forged task context within policy limits.
- **Workaround:** Replace the key pair and redeploy the public key, accepting
  that in-flight grants fail.
- **Closure criterion:** Production verifies an organizational dispatcher
  identity with key IDs, rotation, revocation, issuance audit, and authenticated
  SSO-derived `on_behalf_of`.

### G-16: The kubernetes-inspect profile has no sandbox wiring or runner

- **Owner:** Platform integrator adding the Kubernetes lane.
- **Affected component:** `deploy/platform` (no Vault Kubernetes secrets
  engine), `deploy/agentgate` (no `--vault-kubernetes-mount` argument or
  inspector workload registration), `cmd/agent-sim` (Terraform-only runner).
- **Evidence/source checked:** Policy, transport validation, per-request
  binding, cross-profile isolation, and revocation for `kubernetes-inspect`
  are tested against real Vault using a deterministic logical mount. No
  Kubernetes secrets engine, RBAC, or governed inspector workload exists in
  the deployment.
- **Exact manual verification:** Configure Vault's Kubernetes secrets engine
  with a token-request-scoped ServiceAccount, register an inspector workload,
  start AgentGate with `--vault-kubernetes-mount`, and redeem a
  `kubernetes-inspect` grant end to end.
- **Failure symptom:** A `kubernetes-inspect` grant passes policy but binding
  enablement fails closed because no mount profile is configured.
- **Workaround:** None needed; the sandbox default leaves the profile
  disabled, and enablement failure is deny-by-default.
- **Closure criterion:** A sandbox run shows a short-lived, namespace-scoped
  ServiceAccount token issued directly to an attested inspector workload with
  the same audit chain as the Terraform lane.

### G-09: Release provenance is not production grade

- **Owner:** Release engineering.
- **Affected component:** Application, Terraform-provider, and teaching-tool
  supply chain.
- **Evidence/source checked:** Base images and Terraform downloads are pinned,
  checksummed, and built with `-trimpath`; CI actions are commit-pinned. No SBOM,
  signature, provenance attestation, or admission verification is emitted.
- **Exact manual verification:** Generate an SBOM, scan dependencies and image
  layers, sign the image, and verify signature/provenance at admission.
- **Failure symptom:** Operators cannot prove that deployed bytes correspond to
  the reviewed source and dependency set.
- **Workaround:** Record the source revision and immutable digest and restrict
  the registry while the sandbox is active.
- **Closure criterion:** Reproducible release automation emits and verifies an
  SBOM, vulnerability policy, signature, and SLSA-style provenance.

## Accepted PoC limitation

### G-10: Issued AWS STS credentials generally cannot be revoked early

- **Owner:** Architecture owner; risk accepted by the sandbox operator.
- **Affected component:** Vault AWS lease, AWS STS, revoke UI/API, incident
  response.
- **Evidence/source checked:** AWS/Vault semantics and manager tests. Every
  revocation report forces `sts_credentials_may_remain=true` and an explicit
  warning.
- **Exact manual verification:** Revoke a request after issuance, prove new
  Vault login fails, and confirm the existing STS session remains usable only
  until its bounded expiry.
- **Failure symptom:** An operator expects immediate invalidation but sees
  activity from the already issued session.
- **Workaround:** Keep TTL and IAM scope small, disable or constrain the target
  AWS role during an incident, and investigate with CloudTrail.
- **Closure criterion:** This limitation cannot be closed by AgentGate alone; a
  target credential mechanism with reliable early invalidation would be needed.

### G-11: AgentGate governs access, not agent intent

- **Owner:** Application owner and human approver.
- **Affected component:** All authorized Terraform and AWS actions.
- **Evidence/source checked:** The policy evaluates identity and signed scope,
  not prompts or semantic correctness.
- **Exact manual verification:** Review the generated Terraform plan and test
  that IAM, prefix, operation, environment, and TTL controls bound a deliberately
  undesirable but in-scope action.
- **Failure symptom:** A prompt-injected or faulty agent causes damage that is
  still inside legitimately granted permissions.
- **Workaround:** Human approval for production apply, narrow IAM, plan review,
  budgets, monitoring, and short TTL.
- **Closure criterion:** Not solvable as an authorization claim. Risk remains
  explicitly bounded and reviewed.

### G-12: Reliable task-completion detection is unsolved

- **Owner:** Architecture and workload-runtime owners.
- **Affected component:** Early cleanup and autonomous subprocess lifecycle.
- **Evidence/source checked:** A workload callback is forgeable and cannot prove
  that subprocesses or copied credentials are gone. The implementation does not
  depend on such a callback.
- **Exact manual verification:** Terminate an agent during a child process and
  observe that TTL and expiry reconciliation, not a completion signal, end new
  access.
- **Failure symptom:** Operators expect immediate cleanup when a task reports
  success.
- **Workaround:** Treat TTL as primary and use completion only as optional
  hygiene if introduced later.
- **Closure criterion:** A trustworthy runtime primitive can attest that the
  workload and descendants are gone; application self-report alone is
  insufficient.

### G-13: The dispatcher remains trusted infrastructure

- **Owner:** Dispatcher security owner.
- **Affected component:** Task scope, human attribution, and grant issuance.
- **Evidence/source checked:** AgentGate independently limits signed claims with
  policy, but it cannot reconstruct truthful assignment context if the signer is
  malicious.
- **Exact manual verification:** Audit dispatcher access and issue deliberately
  overbroad valid grants; AgentGate must still deny claims outside policy.
- **Failure symptom:** A compromised dispatcher issues believable in-policy
  grants with false business intent or attribution.
- **Workaround:** Protect signer identity, constrain claim construction, audit
  issuance, and keep AgentGate policy independently narrow.
- **Closure criterion:** Trust cannot be eliminated; production must make it
  explicit, monitored, least-privileged, and recoverable.

### G-14: In-process credential erasure is best effort

- **Owner:** Governed-runner maintainer.
- **Affected component:** `cmd/agent-sim` process memory and Terraform child
  environment.
- **Evidence/source checked:** Credentials are private fields, passed only in the
  child environment, removed from references, scrubbed from bounded output, and
  never written to AgentGate or files. Go strings and operating-system process
  memory cannot be guaranteed to be zeroized.
- **Exact manual verification:** Inspect the pod spec, filesystem, logs, crash
  output, and process environment after the child exits; no credential-shaped
  value may persist or be emitted.
- **Failure symptom:** A memory or core dump could retain a prior value even
  after application references are cleared.
- **Workaround:** Disable core dumps, isolate nodes, keep the process and TTL
  short, and terminate the Job after the plan.
- **Closure criterion:** Use a runtime and operating model with reviewed secure
  memory handling if strict zeroization is a requirement.

## Documentation / manual verification only

### G-15: Diagrams, external links, and upstream pins can drift

- **Owner:** Documentation and dependency owners.
- **Affected component:** Mermaid diagrams, deployment commands, provider/chart
  references, and reviewed version claims.
- **Evidence/source checked:** Repository-relative links and command/file names
  are checked during this integration pass; Mermaid and external upstream pages
  are not rendered or fetched by normal CI.
- **Exact manual verification:** Render every Mermaid block, run the documented
  commands in a disposable environment, check external links, and revalidate
  provider/chart/image pins before each teaching event.
- **Failure symptom:** A diagram fails to render, an anchor is stale, or an
  upstream version no longer exists or behaves as documented.
- **Workaround:** Use `docs/ARCHITECTURE.md` and source contracts as authoritative
  while correcting the documentation.
- **Closure criterion:** Add repeatable link, Mermaid, and command-snippet checks
  that do not contact credentialed systems.
