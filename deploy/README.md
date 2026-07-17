# Sandbox deployment

The deployment has three independently applied HCP Terraform roots in this
order:

1. `deploy/infra`
2. `deploy/platform`
3. `deploy/agentgate`

Destroy them in the reverse order. Read
[`docs/DEPLOY.md`](../docs/DEPLOY.md) before planning or applying anything.
The guide distinguishes completed static checks from first-operator checks and
documents the current application runtime gates.