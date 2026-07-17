# Database migrations

Migrations are plain PostgreSQL SQL and run in lexical order. Apply them with a
migration runner in deployed environments. For a local disposable database:

```sh
psql "$DATABASE_URL" -v ON_ERROR_STOP=1 \
  -f internal/audit/migrations/000001_foundation.up.sql \
  -f internal/audit/migrations/000002_expiring_bindings.up.sql
```

Roll back the foundation schema only when all AgentGate data may be discarded:

```sh
psql "$DATABASE_URL" -v ON_ERROR_STOP=1 \
  -f internal/audit/migrations/000002_expiring_bindings.down.sql \
  -f internal/audit/migrations/000001_foundation.down.sql
```

The schema stores credential-free request snapshots, policy decisions,
optimistically versioned approvals, binding state, revocation reports,
single-use nonces, and immutable audit events. `consumed_grant_nonces` is
independent of `access_requests` because the existing grant verifier atomically
consumes a nonce before policy evaluation and request persistence.

Migration `000002` adds the transient `revoking` state and an expiry-sweep index.
This lets one AgentGate replica claim an expired request binding while other
replicas skip it, with stale claims recoverable after a process restart.

It must never store signed grant signatures, Vault tokens, Vault leases, AWS
access keys, secret keys, session tokens, or other credential material.