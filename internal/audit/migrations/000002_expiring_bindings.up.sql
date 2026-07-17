BEGIN;

ALTER TABLE access_requests
    DROP CONSTRAINT access_requests_binding_state_check;

ALTER TABLE access_requests
    ADD CONSTRAINT access_requests_binding_state_check CHECK (binding_state IN (
        'not_required',
        'pending',
        'enabling',
        'enabled',
        'failed',
        'revoking',
        'revoked'
    ));

CREATE INDEX access_requests_expired_bindings_idx
    ON access_requests (redemption_expires_at, binding_updated_at)
    WHERE revoked_at IS NULL AND binding_state IN ('enabled', 'revoking');

COMMIT;
