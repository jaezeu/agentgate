BEGIN;

UPDATE access_requests
SET binding_state = 'enabled',
    binding_updated_at = now(),
    updated_at = now()
WHERE binding_state = 'revoking';

DROP INDEX access_requests_expired_bindings_idx;

ALTER TABLE access_requests
    DROP CONSTRAINT access_requests_binding_state_check;

ALTER TABLE access_requests
    ADD CONSTRAINT access_requests_binding_state_check CHECK (binding_state IN (
        'not_required',
        'pending',
        'enabling',
        'enabled',
        'failed',
        'revoked'
    ));

COMMIT;
