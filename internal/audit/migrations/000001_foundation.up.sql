BEGIN;

CREATE TABLE access_requests (
    request_id UUID PRIMARY KEY,
    spiffe_id TEXT NOT NULL CHECK (spiffe_id LIKE 'spiffe://%'),
    on_behalf_of TEXT NOT NULL CHECK (length(btrim(on_behalf_of)) > 0),
    ticket_id TEXT NOT NULL,
    repo TEXT NOT NULL,
    commit_sha CHAR(40) NOT NULL CHECK (commit_sha ~ '^[0-9a-f]{40}$'),
    operation TEXT NOT NULL CHECK (operation IN ('terraform-plan', 'terraform-apply')),
    environment TEXT NOT NULL,
    vault_role TEXT NOT NULL,
    requested_ttl_seconds INTEGER NOT NULL CHECK (requested_ttl_seconds > 0),
    granted_ttl_seconds INTEGER CHECK (granted_ttl_seconds > 0),
    decision TEXT NOT NULL CHECK (decision IN ('allow', 'deny', 'pending_approval')),
    decision_reason TEXT NOT NULL,
    policy_version CHAR(64) NOT NULL CHECK (policy_version ~ '^[0-9a-f]{64}$'),
    grant_hash CHAR(64) NOT NULL CHECK (grant_hash ~ '^[0-9a-f]{64}$'),
    grant_nonce TEXT NOT NULL UNIQUE,
    grant_issued_at TIMESTAMPTZ NOT NULL,
    requested_at TIMESTAMPTZ NOT NULL,
    decided_at TIMESTAMPTZ NOT NULL,
    binding_state TEXT NOT NULL CHECK (binding_state IN (
        'not_required',
        'pending',
        'enabling',
        'enabled',
        'failed',
        'revoked'
    )),
    binding_error TEXT NOT NULL DEFAULT '',
    binding_updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    vault_address TEXT,
    vault_auth_mount TEXT,
    vault_auth_role TEXT,
    vault_secrets_path TEXT,
    vault_audience TEXT,
    redemption_expires_at TIMESTAMPTZ,
    revocation_role_removed BOOLEAN,
    revocation_policy_removed BOOLEAN,
    revocation_leases_revoked BOOLEAN,
    revocation_sts_may_remain BOOLEAN,
    revocation_warnings JSONB CHECK (
        revocation_warnings IS NULL OR jsonb_typeof(revocation_warnings) = 'array'
    ),
    revoked_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    CHECK (
        binding_state <> 'enabled'
        OR (
            vault_address IS NOT NULL
            AND vault_auth_mount IS NOT NULL
            AND vault_auth_role IS NOT NULL
            AND vault_secrets_path IS NOT NULL
            AND vault_audience IS NOT NULL
            AND redemption_expires_at IS NOT NULL
        )
    )
);

CREATE INDEX access_requests_created_at_idx ON access_requests (created_at DESC);
CREATE INDEX access_requests_decision_idx ON access_requests (decision, created_at DESC);
CREATE INDEX access_requests_on_behalf_of_idx ON access_requests (on_behalf_of, created_at DESC);

CREATE TABLE consumed_grant_nonces (
    nonce TEXT PRIMARY KEY,
    expires_at TIMESTAMPTZ NOT NULL,
    consumed_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX consumed_grant_nonces_expires_at_idx ON consumed_grant_nonces (expires_at);

CREATE TABLE approvals (
    request_id UUID PRIMARY KEY REFERENCES access_requests (request_id) ON DELETE RESTRICT,
    state TEXT NOT NULL CHECK (state IN ('pending', 'approved', 'denied', 'expired')),
    requested_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    decided_at TIMESTAMPTZ,
    decided_by TEXT,
    reason TEXT NOT NULL DEFAULT '',
    version BIGINT NOT NULL DEFAULT 1 CHECK (version > 0),
    CHECK (
        (state = 'pending' AND decided_at IS NULL AND decided_by IS NULL)
        OR
        (state <> 'pending' AND decided_at IS NOT NULL AND length(btrim(decided_by)) > 0)
    )
);

CREATE INDEX approvals_state_idx ON approvals (state, requested_at);

CREATE TABLE audit_events (
    id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    event_id UUID NOT NULL UNIQUE,
    request_id UUID NOT NULL,
    event_type TEXT NOT NULL CHECK (event_type IN (
        'grant_verified',
        'decision_recorded',
        'approval_requested',
        'approval_decided',
        'binding_enabled',
        'binding_failed',
        'revocation'
    )),
    occurred_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    spiffe_id TEXT NOT NULL CHECK (spiffe_id LIKE 'spiffe://%'),
    on_behalf_of TEXT NOT NULL CHECK (length(btrim(on_behalf_of)) > 0),
    ticket_id TEXT NOT NULL,
    decision TEXT CHECK (decision IN ('allow', 'deny', 'pending_approval')),
    decision_reason TEXT,
    policy_version CHAR(64) CHECK (policy_version ~ '^[0-9a-f]{64}$'),
    decision_snapshot JSONB CHECK (
        decision_snapshot IS NULL OR jsonb_typeof(decision_snapshot) = 'object'
    ),
    approval_state TEXT CHECK (approval_state IN ('pending', 'approved', 'denied', 'expired')),
    vault_auth_role TEXT,
    aws_role_session_name TEXT,
    task_grant JSONB NOT NULL DEFAULT '{}'::jsonb CHECK (jsonb_typeof(task_grant) = 'object'),
    details JSONB NOT NULL DEFAULT '{}'::jsonb CHECK (jsonb_typeof(details) = 'object')
);

CREATE INDEX audit_events_request_id_idx ON audit_events (request_id, occurred_at, id);
CREATE INDEX audit_events_occurred_at_idx ON audit_events (occurred_at DESC);

CREATE FUNCTION reject_audit_event_mutation()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    RAISE EXCEPTION 'audit_events is append-only';
END;
$$;

CREATE TRIGGER audit_events_no_update
BEFORE UPDATE ON audit_events
FOR EACH ROW EXECUTE FUNCTION reject_audit_event_mutation();

CREATE TRIGGER audit_events_no_delete
BEFORE DELETE ON audit_events
FOR EACH ROW EXECUTE FUNCTION reject_audit_event_mutation();

COMMENT ON TABLE audit_events IS
'Credential-free correlation events. Never store Vault tokens, leases, AWS access keys, secret keys, or session tokens.';

COMMIT;