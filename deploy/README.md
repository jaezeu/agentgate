# Sandbox deployment

The deployment has four Terraform roots applied in this order:

1. `deploy/bootstrap` (state bucket trust, GitHub OIDC deployer role, ECR)
2. `deploy/infra`
3. `deploy/platform`
4. `deploy/agentgate`

The `Deploy` GitHub Actions workflow runs all of them end to end in one run,
including unattended Vault initialization and the digest-pinned image build;
if a stage fails, "Re-run failed jobs" resumes from there. All roots,
bootstrap included, store state in one S3 bucket (created by the workflow if
missing) with native lock files. Operators can equally apply any root
locally from an AWS SSO session against the same backend. Destroy in the
reverse order.

Read [`docs/DEPLOY.md`](../docs/DEPLOY.md) before planning or applying
anything, and
[`docs/adr/0001-deployment-control-plane.md`](../docs/adr/0001-deployment-control-plane.md)
for why this replaced HCP Terraform. The guide distinguishes completed static
checks from first-operator checks and documents the current application
runtime gates.
