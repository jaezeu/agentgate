import { z } from 'zod'

const dateTime = z.iso.datetime({ offset: true })
const optionalDateTime = dateTime.nullable()

export const decisionValues = [
  'allow',
  'deny',
  'pending_approval',
] as const
export const approvalValues = [
  'not_required',
  'pending',
  'approved',
  'denied',
  'expired',
] as const
export const bindingValues = [
  'not_required',
  'pending',
  'enabling',
  'enabled',
  'failed',
  'revoking',
  'revoked',
] as const
export const operationValues = [
  'terraform-plan',
  'terraform-apply',
] as const
export const eventTypeValues = [
  'grant_verified',
  'decision_recorded',
  'approval_requested',
  'approval_decided',
  'binding_enabled',
  'binding_failed',
  'revocation',
] as const

export const DecisionSchema = z.enum(decisionValues)
export const ApprovalStateSchema = z.enum(approvalValues)
export const BindingStateSchema = z.enum(bindingValues)
export const OperationSchema = z.enum(operationValues)
export const EventTypeSchema = z.enum(eventTypeValues)

export const RevocationReportSchema = z.object({
  request_id: z.string().min(1),
  role_removed: z.boolean(),
  policy_removed: z.boolean(),
  leases_revoked: z.boolean(),
  sts_credentials_may_remain: z.boolean(),
  warnings: z.array(z.string().max(1_024)).max(20).default([]),
})

const WireDecisionSchema = z.object({
  decision: DecisionSchema,
  reason: z.string().min(1),
  granted_ttl: z.number().int().nonnegative(),
  policy_version: z.string().regex(/^[0-9a-f]{64}$/),
  decided_at: dateTime,
})

const WireApprovalSchema = z.object({
  request_id: z.string().min(1),
  state: ApprovalStateSchema,
  requested_at: dateTime,
  decided_at: dateTime.optional(),
  decided_by: z.string().optional(),
  reason: z.string().optional(),
  version: z.number().int().positive(),
})

export const WireRequestSchema = z.object({
  request_id: z.string().min(1),
  spiffe_id: z.string().startsWith('spiffe://'),
  on_behalf_of: z.string().min(1),
  ticket_id: z.string(),
  repo: z.string().min(1),
  commit_sha: z.string().regex(/^[0-9a-f]{40}$/),
  operation: OperationSchema,
  environment: z.string().min(1),
  requested_vault_role: z.string().min(1),
  requested_ttl_seconds: z.number().int().positive(),
  requested_at: dateTime,
  grant_issued_at: dateTime.optional(),
  expires_at: dateTime,
  decision: WireDecisionSchema,
  approval: WireApprovalSchema,
  binding_state: BindingStateSchema,
  binding_error: z.string().optional(),
  binding_created_at: dateTime.optional(),
  vault_auth_role: z.string().optional(),
  aws_role_session_name: z.string().optional(),
  revocation: RevocationReportSchema.optional(),
  revoked_at: dateTime.optional(),
})

export const RequestSchema = z.object({
  request_id: z.string().min(1),
  spiffe_id: z.string().startsWith('spiffe://'),
  on_behalf_of: z.string().min(1),
  ticket_id: z.string(),
  repo: z.string().min(1),
  commit_sha: z.string().regex(/^[0-9a-f]{40}$/),
  operation: OperationSchema,
  environment: z.string().min(1),
  requested_vault_role: z.string().min(1),
  requested_ttl_seconds: z.number().int().positive(),
  effective_ttl_seconds: z.number().int().positive().nullable(),
  decision: DecisionSchema,
  decision_reason: z.string().min(1),
  policy_version: z.string().regex(/^[0-9a-f]{64}$/),
  decision_decided_at: dateTime,
  approval_state: ApprovalStateSchema,
  approval_requested_at: optionalDateTime,
  approval_decided_at: optionalDateTime,
  approval_decided_by: z.string().optional(),
  approval_reason: z.string().optional(),
  approval_version: z.number().int().positive(),
  binding_state: BindingStateSchema,
  binding_error: z.string().optional(),
  grant_issued_at: dateTime,
  created_at: dateTime,
  binding_created_at: optionalDateTime,
  expires_at: dateTime,
  revoked_at: optionalDateTime,
  revocation: RevocationReportSchema.nullable(),
  correlation: z.object({
    vault_auth_role: z.string().optional(),
    aws_role_session_name: z.string().optional(),
  }),
})

export const AuditEventSchema = z.object({
  event_id: z.string().min(1),
  request_id: z.string().min(1),
  event_type: EventTypeSchema,
  occurred_at: dateTime,
  spiffe_id: z.string().startsWith('spiffe://'),
  on_behalf_of: z.string().min(1),
  ticket_id: z.string(),
  decision: DecisionSchema.optional(),
  decision_reason: z.string().optional(),
  policy_version: z
    .string()
    .regex(/^[0-9a-f]{64}$/)
    .optional(),
  approval_state: ApprovalStateSchema.optional(),
  actor: z.string().optional(),
  reason: z.string().optional(),
  vault_auth_role: z.string().optional(),
  aws_role_session_name: z.string().optional(),
  revocation: RevocationReportSchema.optional(),
})

export const WireListRequestsResponseSchema = z.object({
  requests: z.array(WireRequestSchema).max(100),
  limit: z.number().int().positive().max(100),
  offset: z.number().int().nonnegative().max(10_000),
  has_more: z.boolean().default(false),
  warnings: z.array(z.string().max(1_000)).max(20).default([]),
  server_time: dateTime.optional(),
})

export const WireRequestDetailResponseSchema = z.object({
  request: WireRequestSchema,
  events: z.array(AuditEventSchema).max(1_000).default([]),
  warnings: z.array(z.string().max(1_000)).max(20).default([]),
  server_time: dateTime.optional(),
})

export const WireRevocationResponseSchema = z.object({
  request_id: z.string().min(1),
  revocation: RevocationReportSchema,
  server_time: dateTime.optional(),
})

export type Decision = z.infer<typeof DecisionSchema>
export type ApprovalState = z.infer<typeof ApprovalStateSchema>
export type BindingState = z.infer<typeof BindingStateSchema>
export type Operation = z.infer<typeof OperationSchema>
export type EventType = z.infer<typeof EventTypeSchema>
export type RevocationReport = z.infer<typeof RevocationReportSchema>
export type WireRequest = z.infer<typeof WireRequestSchema>
export type WireListRequestsResponse = z.infer<
  typeof WireListRequestsResponseSchema
>
export type WireRequestDetailResponse = z.infer<
  typeof WireRequestDetailResponseSchema
>
export type RequestRecord = z.infer<typeof RequestSchema>
export type AuditEvent = z.infer<typeof AuditEventSchema>

export interface Pagination {
  limit: number
  offset: number
  has_more: boolean
}

export interface ListRequestsResponse {
  requests: RequestRecord[]
  pagination: Pagination
  warnings: string[]
}

export interface RequestDetailResponse {
  request: RequestRecord
  events: AuditEvent[]
  warnings: string[]
}

export interface DecisionResponse {
  request: RequestRecord
}

export function normalizeRequest(wire: WireRequest): RequestRecord {
  const grantedNanoseconds = wire.decision.granted_ttl
  const grantedSeconds =
    grantedNanoseconds > 0 ? grantedNanoseconds / 1_000_000_000 : null
  if (grantedSeconds !== null && !Number.isSafeInteger(grantedSeconds)) {
    throw new CompatibilityError(
      'AgentGate API returned an invalid granted TTL',
    )
  }

  return {
    request_id: wire.request_id,
    spiffe_id: wire.spiffe_id,
    on_behalf_of: wire.on_behalf_of,
    ticket_id: wire.ticket_id,
    repo: wire.repo,
    commit_sha: wire.commit_sha,
    operation: wire.operation,
    environment: wire.environment,
    requested_vault_role: wire.requested_vault_role,
    requested_ttl_seconds: wire.requested_ttl_seconds,
    effective_ttl_seconds: grantedSeconds,
    decision: wire.decision.decision,
    decision_reason: wire.decision.reason,
    policy_version: wire.decision.policy_version,
    decision_decided_at: wire.decision.decided_at,
    approval_state: wire.approval.state,
    approval_requested_at: wire.approval.requested_at,
    approval_decided_at: wire.approval.decided_at ?? null,
    approval_decided_by: wire.approval.decided_by,
    approval_reason: wire.approval.reason,
    approval_version: wire.approval.version,
    binding_state: wire.binding_state,
    binding_error: wire.binding_error,
    grant_issued_at: wire.grant_issued_at ?? wire.requested_at,
    created_at: wire.requested_at,
    binding_created_at: wire.binding_created_at ?? null,
    expires_at: wire.expires_at,
    revoked_at: wire.revoked_at ?? null,
    revocation: wire.revocation ?? null,
    correlation: {
      vault_auth_role: wire.vault_auth_role,
      aws_role_session_name: wire.aws_role_session_name,
    },
  }
}

const forbiddenResponseFields = new Set([
  'access_key',
  'access_key_id',
  'access_token',
  'authorization',
  'aws_access_key',
  'aws_access_key_id',
  'aws_secret_access_key',
  'aws_session_token',
  'client_secret',
  'credential',
  'credentials',
  'descriptor',
  'grant_nonce',
  'id_token',
  'lease',
  'lease_id',
  'lease_secret',
  'nonce',
  'private_key',
  'redemption_descriptor',
  'refresh_token',
  'secret',
  'secret_access_key',
  'session_token',
  'signature',
  'token',
  'vault_lease',
  'vault_token',
])

export class CompatibilityError extends Error {
  constructor(message = 'AgentGate API compatibility error') {
    super(message)
    this.name = 'CompatibilityError'
  }
}

export function assertCredentialFreeResponse(
  value: unknown,
  seen = new WeakSet<object>(),
): void {
  if (typeof value === 'string') {
    const upper = value.toUpperCase()
    if (
      /(?:AKIA|ASIA)[A-Z0-9]{16}/u.test(upper) ||
      upper.startsWith('BEARER ') ||
      upper.includes('-----BEGIN PRIVATE KEY-----') ||
      upper.includes('-----BEGIN RSA PRIVATE KEY-----')
    ) {
      throw new CompatibilityError(
        'AgentGate human API returned credential-shaped content',
      )
    }
    return
  }
  if (value === null || typeof value !== 'object') return
  if (seen.has(value)) return
  seen.add(value)

  if (Array.isArray(value)) {
    value.forEach((entry) => assertCredentialFreeResponse(entry, seen))
    return
  }

  for (const [key, entry] of Object.entries(value)) {
    if (forbiddenResponseFields.has(key.toLowerCase())) {
      throw new CompatibilityError(
        `AgentGate human API returned prohibited field: ${key}`,
      )
    }
    assertCredentialFreeResponse(entry, seen)
  }
}

export function parseCredentialFree<T>(
  schema: z.ZodType<T>,
  value: unknown,
): T {
  assertCredentialFreeResponse(value)
  const parsed = schema.safeParse(value)
  if (!parsed.success) {
    const paths = [
      ...new Set(
        parsed.error.issues.map((issue) => issue.path.join('.') || 'response'),
      ),
    ]
    throw new CompatibilityError(
      `AgentGate API response is incompatible at: ${paths.join(', ')}`,
    )
  }
  return parsed.data
}
