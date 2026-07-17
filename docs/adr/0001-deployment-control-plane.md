# ADR-0001: GitHub Actions OIDC and S3 state replace HCP Terraform

- **Status:** Accepted (2026-07-18)
- **Deciders:** Repository owner; independent architecture review
- **Supersedes:** The HCP Terraform workspace/agent deployment design shipped
  with the initial integration

## Context

The original deployment used three CLI-driven HCP Terraform workspaces with
dynamic provider credentials, a custom in-cluster `tfc-agent` image so runs
could reach in-cluster Vault, a 285-line workspace-reconciliation API script,
and two OIDC federations (`app.terraform.io` trusted by AWS IAM and by
Vault). The repository's stated priorities are **simplicity** and
**reproducibility**: a stranger with a clean AWS account and this repository
should reach a working sandbox with minimal ceremony, and the entire merge
bar must be statically verifiable without cloud access.

Before touching AWS, the HCP flow required: an HCP organization, a user
token, a project, three workspaces, an agent pool, an agent token, and a
locally built, digest-pinned agent image. The legacy HCP Terraform free plan
also reached end-of-life on 2026-03-31, so routine create/destroy cycles of
this sandbox would be metered on an external SaaS.

## Decision

1. **State lives in S3.** A new `deploy/bootstrap` root (local state,
   contains only public identifiers) creates one versioned, KMS-encrypted,
   public-access-blocked, TLS-only state bucket. Every root uses a partial
   `backend "s3"` block with `use_lockfile = true` (native S3 locking; no
   DynamoDB table). Cross-root wiring uses `terraform_remote_state` over S3.
2. **CI deploys through GitHub Actions OIDC.** The bootstrap root creates
   the `token.actions.githubusercontent.com` IAM OIDC provider and one
   deployer role trusted only for this repository's `sandbox-plan` and
   `sandbox` environments. `deploy.yml` runs plan/apply per root plus
   scheduled drift detection. Applies are gated by the protected `sandbox`
   environment. Local applies remain first-class through AWS SSO with the
   same S3 backend.
3. **Vault trusts GitHub OIDC instead of HCP.** `bootstrap-vault.sh` writes
   the same narrowly scoped `terraform-platform` policy as before, but the
   optional CI trust is a `jwt-deployer` auth mount bound to the exact
   repository environments. The deploy workflow port-forwards Vault over
   TLS and exchanges its job identity token for a 15-minute Vault token; no
   Vault credential is ever stored.
4. **Helm stays inside Terraform.** Three pinned charts share one dependency
   graph with the IAM, storage, and NetworkPolicy resources they need, and
   the layered roots already avoid configuring a Kubernetes provider against
   a cluster created in the same apply.
5. **Diagrams are Mermaid, in-repo.** GitHub renders them natively, they
   diff in review, and they cannot drift into stale binary assets.

## Alternatives considered

| Alternative | Why not |
| --- | --- |
| **Keep HCP Terraform workspaces** | Seven SaaS artifacts and a custom agent image before first apply; two OIDC federations; metered post-free-tier; remote-run debugging. Its strongest feature (in-cluster agent reaching Vault) is replaced by the same TLS port-forward the Vault bootstrap already used. |
| **HCP Terraform Stacks** | Conceptually the best fit for the three ordered layers (components, deferred changes), and Stacks now supports agent pools. Rejected because it re-buys the HCP control plane plus a new HCL dialect, has no `terraform test`/static-validation story (this repo's merge bar is its credibility), deepens lock-in (not even Terraform Enterprise supports Stacks), and its fan-out strengths only pay off with many deployments of the same components. Revisit if AgentGate ever needs N identical sandboxes. |
| **GitOps (Argo CD/Flux) for charts** | The enterprise pattern at fleet scale, but adds a controller, bootstrap ordering, and repository plumbing to a single-cluster sandbox. Documented as the migration path once more than one cluster exists. |
| **Helmfile for charts** | Adds a tool without removing Terraform; the charts still need Terraform-managed IAM/storage inputs. |
| **DynamoDB state locking** | Deprecated pattern; S3 native lockfile (Terraform >= 1.10) removes a table and its IAM surface. |

## Enterprise posture

Enterprises split into a governance-procurement camp (TFE/HCP, Spacelift)
and an engineering-led camp (CI + OIDC + object-store state). This design
implements the control properties both camps share: zero static credentials,
encrypted/versioned/locked state, reviewed applies, drift detection,
attributable deploys, and pinned toolchains. Known deltas from a large-org
setup, deliberate for a sandbox: single account (no landing zone), one
deployer role instead of split plan/apply roles, AdministratorAccess with a
dedicated account instead of least-privilege policies plus permission
boundary, and Terraform-managed charts instead of GitOps.

## Amendment (2026-07-18): community modules and pessimistic constraints

The hand-rolled VPC, EKS (cluster, node group, IAM, KMS, log group, OIDC
provider, add-ons, access entries), state bucket, and state KMS resources are
replaced by `terraform-aws-modules` community modules (`vpc ~> 6.6`,
`eks ~> 21.24`, `s3-bucket ~> 5.14`, `kms ~> 4.2`), cutting the infra root by
roughly two thirds. Provider and module constraints are pessimistic (`~>`);
reproducibility comes from the committed dual-platform
`.terraform.lock.hcl` files, which pin exact provider versions until
`terraform init -upgrade` is run deliberately. Two deliberate exceptions stay
as raw resources: the GitHub OIDC provider and deployer role trust policy
(the security boundary of the deployment model — every claim condition
should be reviewable in place), and the demo-target/Vault-broker/add-on IRSA
IAM (bespoke narrow policies where a module would obscure the scope).

## Consequences

- `deploy/bootstrap` is a new root with local state; destroying it removes
  deployment trust and the state bucket and is documented as the final
  teardown step.
- The EKS public endpoint allowlist gains an explicit
  `allow_public_cluster_endpoint` acknowledgment: GitHub-hosted runners have
  broad egress, so CI applies of cluster-touching roots need either
  `0.0.0.0/0` (IAM-authenticated), a self-hosted runner, or operator-run
  applies for those roots.
- `deploy/scripts/setup-workspaces.sh`, `bootstrap-hcp-agent.sh`, and
  `deploy/images/tfc-agent.Dockerfile` are deleted; `init-root.sh` and
  `ci-vault-env.sh` are added.
- Static validation now covers four roots and two `terraform test` suites.
