import type {
  AuditEvent,
  RequestRecord,
  RevocationReport,
  WireListRequestsResponse,
  WireRequest,
  WireRequestDetailResponse,
} from '../api/schema'

export const serverNow = '2026-07-17T10:00:00Z'
export const policyVersion =
  '0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef'

export const activeRequest: RequestRecord = {
  request_id: '11111111-1111-4111-8111-111111111111',
  spiffe_id: 'spiffe://agentgate.test/ns/agents/sa/runner',
  on_behalf_of: 'requester@example.test',
  ticket_id: 'OPS-421',
  repo: 'github.com/jaezeu/agentgate',
  commit_sha: '0123456789abcdef0123456789abcdef01234567',
  operation: 'terraform-plan',
  environment: 'staging',
  requested_vault_role: 'terraform-sandbox',
  requested_ttl_seconds: 1_200,
  effective_ttl_seconds: 900,
  decision: 'allow',
  decision_reason: 'Scoped staging plan is allowed',
  policy_version: policyVersion,
  decision_decided_at: '2026-07-17T10:00:01Z',
  approval_state: 'not_required',
  approval_requested_at: '2026-07-17T10:00:00Z',
  approval_decided_at: null,
  approval_version: 1,
  binding_state: 'enabled',
  grant_issued_at: '2026-07-17T09:59:55Z',
  created_at: '2026-07-17T10:00:00Z',
  binding_created_at: '2026-07-17T10:00:02Z',
  expires_at: '2026-07-17T10:15:00Z',
  revoked_at: null,
  revocation: null,
  correlation: {
    vault_auth_role: 'agentgate-11111111',
    aws_role_session_name: '11111111-1111-4111-8111-111111111111',
  },
}

export const pendingRequest: RequestRecord = {
  ...activeRequest,
  request_id: '22222222-2222-4222-8222-222222222222',
  operation: 'terraform-apply',
  environment: 'production',
  requested_ttl_seconds: 1_800,
  effective_ttl_seconds: 900,
  decision: 'pending_approval',
  decision_reason: 'Production apply requires human approval',
  approval_state: 'pending',
  approval_requested_at: '2026-07-17T09:58:00Z',
  binding_state: 'pending',
  grant_issued_at: '2026-07-17T09:58:00Z',
  created_at: '2026-07-17T09:58:00Z',
  binding_created_at: null,
  expires_at: '2026-07-17T10:13:00Z',
  correlation: {},
}

export function wireRequest(request: RequestRecord): WireRequest {
  return {
    request_id: request.request_id,
    spiffe_id: request.spiffe_id,
    on_behalf_of: request.on_behalf_of,
    ticket_id: request.ticket_id,
    repo: request.repo,
    commit_sha: request.commit_sha,
    operation: request.operation,
    environment: request.environment,
    requested_vault_role: request.requested_vault_role,
    requested_ttl_seconds: request.requested_ttl_seconds,
    requested_at: request.created_at,
    grant_issued_at: request.grant_issued_at,
    expires_at: request.expires_at,
    decision: {
      decision: request.decision,
      reason: request.decision_reason,
      granted_ttl:
        (request.effective_ttl_seconds ?? 0) * 1_000_000_000,
      policy_version: request.policy_version,
      decided_at: request.decision_decided_at,
    },
    approval: {
      request_id: request.request_id,
      state: request.approval_state,
      requested_at: request.approval_requested_at ?? request.created_at,
      ...(request.approval_decided_at
        ? { decided_at: request.approval_decided_at }
        : {}),
      ...(request.approval_decided_by
        ? { decided_by: request.approval_decided_by }
        : {}),
      ...(request.approval_reason
        ? { reason: request.approval_reason }
        : {}),
      version: request.approval_version,
    },
    binding_state: request.binding_state,
    ...(request.binding_error
      ? { binding_error: request.binding_error }
      : {}),
    ...(request.binding_created_at
      ? { binding_created_at: request.binding_created_at }
      : {}),
    ...(request.correlation.vault_auth_role
      ? { vault_auth_role: request.correlation.vault_auth_role }
      : {}),
    ...(request.correlation.aws_role_session_name
      ? {
          aws_role_session_name:
            request.correlation.aws_role_session_name,
        }
      : {}),
    ...(request.revocation ? { revocation: request.revocation } : {}),
    ...(request.revoked_at ? { revoked_at: request.revoked_at } : {}),
  }
}

export const expiredPendingRequest: RequestRecord = {
  ...pendingRequest,
  request_id: '33333333-3333-4333-8333-333333333333',
  ticket_id: 'OPS-422',
  grant_issued_at: '2026-07-17T09:40:00Z',
  created_at: '2026-07-17T09:40:00Z',
  expires_at: '2026-07-17T09:55:00Z',
}

export const revocationReport: RevocationReport = {
  request_id: activeRequest.request_id,
  role_removed: true,
  policy_removed: false,
  leases_revoked: true,
  sts_credentials_may_remain: true,
  warnings: ['One Vault lease cleanup attempt requires operator review.'],
}

export const timelineEvents: AuditEvent[] = [
  {
    event_id: 'event-1',
    request_id: activeRequest.request_id,
    event_type: 'grant_verified',
    occurred_at: '2026-07-17T10:00:00Z',
    spiffe_id: activeRequest.spiffe_id,
    on_behalf_of: activeRequest.on_behalf_of,
    ticket_id: activeRequest.ticket_id,
  },
  {
    event_id: 'event-2',
    request_id: activeRequest.request_id,
    event_type: 'decision_recorded',
    occurred_at: '2026-07-17T10:00:01Z',
    spiffe_id: activeRequest.spiffe_id,
    on_behalf_of: activeRequest.on_behalf_of,
    ticket_id: activeRequest.ticket_id,
    decision: 'allow',
    decision_reason: activeRequest.decision_reason,
    policy_version: policyVersion,
  },
  {
    event_id: 'event-3',
    request_id: activeRequest.request_id,
    event_type: 'approval_requested',
    occurred_at: '2026-07-17T10:00:02Z',
    spiffe_id: activeRequest.spiffe_id,
    on_behalf_of: activeRequest.on_behalf_of,
    ticket_id: activeRequest.ticket_id,
    approval_state: 'pending',
  },
  {
    event_id: 'event-4',
    request_id: activeRequest.request_id,
    event_type: 'approval_decided',
    occurred_at: '2026-07-17T10:00:03Z',
    spiffe_id: activeRequest.spiffe_id,
    on_behalf_of: activeRequest.on_behalf_of,
    ticket_id: activeRequest.ticket_id,
    approval_state: 'approved',
    actor: 'approver@example.test',
    reason: 'Exact production scope reviewed',
  },
  {
    event_id: 'event-5',
    request_id: activeRequest.request_id,
    event_type: 'binding_enabled',
    occurred_at: '2026-07-17T10:00:04Z',
    spiffe_id: activeRequest.spiffe_id,
    on_behalf_of: activeRequest.on_behalf_of,
    ticket_id: activeRequest.ticket_id,
    vault_auth_role: activeRequest.correlation.vault_auth_role,
    aws_role_session_name:
      activeRequest.correlation.aws_role_session_name,
  },
  {
    event_id: 'event-6',
    request_id: activeRequest.request_id,
    event_type: 'revocation',
    occurred_at: '2026-07-17T10:05:00Z',
    spiffe_id: activeRequest.spiffe_id,
    on_behalf_of: activeRequest.on_behalf_of,
    ticket_id: activeRequest.ticket_id,
    actor: 'operator@example.test',
    revocation: {
      request_id: activeRequest.request_id,
      role_removed: true,
      policy_removed: true,
      leases_revoked: false,
      sts_credentials_may_remain: true,
      warnings: ['Lease cleanup was not confirmed.'],
    },
  },
]

export function listResponse(
  requests: RequestRecord[],
  options: {
    offset?: number
    limit?: number
    hasMore?: boolean
    warnings?: string[]
  } = {},
): WireListRequestsResponse {
  return {
    requests: requests.map(wireRequest),
    limit: options.limit ?? 25,
    offset: options.offset ?? 0,
    has_more: options.hasMore ?? false,
    server_time: serverNow,
    warnings: options.warnings ?? [],
  }
}

export function detailResponse(
  request = activeRequest,
  events = timelineEvents,
): WireRequestDetailResponse {
  return {
    request: wireRequest(request),
    events,
    server_time: serverNow,
    warnings: [],
  }
}
