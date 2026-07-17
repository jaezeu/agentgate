BEGIN;

DROP TRIGGER IF EXISTS audit_events_no_delete ON audit_events;
DROP TRIGGER IF EXISTS audit_events_no_update ON audit_events;
DROP FUNCTION IF EXISTS reject_audit_event_mutation();
DROP TABLE IF EXISTS audit_events;
DROP TABLE IF EXISTS approvals;
DROP TABLE IF EXISTS consumed_grant_nonces;
DROP TABLE IF EXISTS access_requests;

COMMIT;