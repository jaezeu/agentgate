# Sandbox deployment

The deployment has four independently applied Terraform roots in this order:

1. `deploy/bootstrap` (GitHub OIDC deployment trust; local state, applied
   once per account)
2. `deploy/infra`
3. `deploy/platform`
4. `deploy/agentgate`

The sandbox roots store state in a pre-existing S3 bucket with native lock
files and can be applied from an operator AWS SSO session or through the
`Deploy` GitHub Actions workflow (OIDC, protected `sandbox` environment,
scheduled drift detection). Destroy in the reverse order. Read
[`docs/DEPLOY.md`](../docs/DEPLOY.md) before planning or applying anything,
and [`docs/adr/0001-deployment-control-plane.md`](../docs/adr/0001-deployment-control-plane.md)
for why this replaced HCP Terraform. The guide distinguishes completed static
checks from first-operator checks and documents the current application
runtime gates.
