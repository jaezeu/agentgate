import type { z } from 'zod'
import {
  CompatibilityError,
  WireListRequestsResponseSchema,
  WireRequestDetailResponseSchema,
  WireRevocationResponseSchema,
  normalizeRequest,
  parseCredentialFree,
  type ApprovalState,
  type BindingState,
  type Decision,
  type DecisionResponse,
  type ListRequestsResponse,
  type Operation,
  type RequestDetailResponse,
  type RevocationReport,
} from './schema'

export interface RequestFilters {
  decision?: Decision
  approval?: ApprovalState
  active?: boolean
  binding?: BindingState
  spiffeId?: string
  onBehalfOf?: string
  createdAfter?: string
  createdBefore?: string
  environment?: string
  operation?: Operation
  repo?: string
  limit: number
  offset: number
}

export interface TimedResponse<T> {
  value: T
  serverOffsetMs: number
  clockWarning?: string
}

export class ApiError extends Error {
  readonly status: number

  constructor(status: number) {
    super(`AgentGate API request failed with status ${status}`)
    this.name = 'ApiError'
    this.status = status
  }
}

type BearerTokenProvider = () => Promise<string | undefined>
type Fetch = typeof fetch
const MAX_RESPONSE_BYTES = 2 * 1024 * 1024

async function readBoundedJson(response: Response): Promise<unknown> {
  const contentLength = Number(response.headers.get('Content-Length'))
  if (
    Number.isFinite(contentLength) &&
    contentLength > MAX_RESPONSE_BYTES
  ) {
    throw new CompatibilityError('AgentGate API response exceeds size limit')
  }
  if (!response.body) {
    throw new CompatibilityError('AgentGate API returned an empty response')
  }

  const reader = response.body.getReader()
  const decoder = new TextDecoder()
  let received = 0
  let text = ''

  while (true) {
    const chunk = await reader.read()
    if (chunk.done) break
    received += chunk.value.byteLength
    if (received > MAX_RESPONSE_BYTES) {
      await reader.cancel()
      throw new CompatibilityError(
        'AgentGate API response exceeds size limit',
      )
    }
    text += decoder.decode(chunk.value, { stream: true })
  }
  text += decoder.decode()

  try {
    return JSON.parse(text) as unknown
  } catch {
    throw new CompatibilityError('AgentGate API returned invalid JSON')
  }
}

export class AgentGateClient {
  readonly baseUrl: URL
  private readonly bearerToken: BearerTokenProvider
  private readonly fetchImplementation: Fetch
  private unauthorizedHandler: () => void = () => undefined

  constructor(
    baseUrl: string,
    bearerToken: BearerTokenProvider = async () => undefined,
    fetchImplementation: Fetch = fetch,
  ) {
    this.baseUrl = new URL(baseUrl)
    this.bearerToken = bearerToken
    this.fetchImplementation = fetchImplementation
  }

  setUnauthorizedHandler(handler: () => void): () => void {
    this.unauthorizedHandler = handler
    return () => {
      if (this.unauthorizedHandler === handler) {
        this.unauthorizedHandler = () => undefined
      }
    }
  }

  async listRequests(
    filters: RequestFilters,
    signal?: AbortSignal,
  ): Promise<TimedResponse<ListRequestsResponse>> {
    const query = new URLSearchParams()
    if (filters.decision) query.set('decision', filters.decision)
    if (filters.approval) query.set('approval', filters.approval)
    if (filters.active !== undefined) {
      query.set('active', String(filters.active))
    }
    if (filters.binding) query.set('binding', filters.binding)
    if (filters.spiffeId) query.set('spiffe_id', filters.spiffeId)
    if (filters.onBehalfOf) query.set('on_behalf_of', filters.onBehalfOf)
    if (filters.createdAfter) query.set('created_after', filters.createdAfter)
    if (filters.createdBefore) {
      query.set('created_before', filters.createdBefore)
    }
    if (filters.environment) query.set('environment', filters.environment)
    if (filters.operation) query.set('operation', filters.operation)
    if (filters.repo) query.set('repo', filters.repo)
    query.set('limit', String(filters.limit))
    query.set('offset', String(filters.offset))

    const response = await this.get(
      `/v1/requests?${query.toString()}`,
      WireListRequestsResponseSchema,
      signal,
    )
    if (
      response.value.limit !== filters.limit ||
      response.value.offset !== filters.offset
    ) {
      throw new CompatibilityError(
        'AgentGate API returned mismatched pagination metadata',
      )
    }
    return {
      ...response,
      value: {
        requests: response.value.requests
          .slice(0, filters.limit)
          .map(normalizeRequest),
        pagination: {
          limit: filters.limit,
          offset: response.value.offset,
          has_more: response.value.has_more,
        },
        warnings: response.value.warnings,
      },
    }
  }

  async getRequest(
    requestId: string,
    signal?: AbortSignal,
  ): Promise<TimedResponse<RequestDetailResponse>> {
    const response = await this.get(
      `/v1/requests/${encodeURIComponent(requestId)}`,
      WireRequestDetailResponseSchema,
      signal,
    )
    if (response.value.request.request_id !== requestId) {
      throw new CompatibilityError(
        'AgentGate API returned mismatched request correlation',
      )
    }
    return {
      ...response,
      value: {
        request: normalizeRequest(response.value.request),
        events: response.value.events,
        warnings: response.value.warnings,
      },
    }
  }

  async decide(
    requestId: string,
    action: 'approve' | 'deny',
    reason: string,
  ): Promise<TimedResponse<DecisionResponse>> {
    const response = await this.request(
      `/v1/requests/${encodeURIComponent(requestId)}/${action}`,
      WireRequestDetailResponseSchema,
      {
        method: 'POST',
        body: JSON.stringify({ reason }),
      },
    )
    if (response.value.request.request_id !== requestId) {
      throw new CompatibilityError(
        'AgentGate API returned mismatched request correlation',
      )
    }
    return {
      ...response,
      value: { request: normalizeRequest(response.value.request) },
    }
  }

  async revoke(
    requestId: string,
  ): Promise<TimedResponse<RevocationReport>> {
    const response = await this.request(
      `/v1/requests/${encodeURIComponent(requestId)}/revoke`,
      WireRevocationResponseSchema,
      { method: 'POST', body: '{}' },
    )
    if (response.value.request_id !== requestId) {
      throw new CompatibilityError(
        'AgentGate API returned mismatched request correlation',
      )
    }
    if (response.value.revocation.request_id !== requestId) {
      throw new CompatibilityError(
        'AgentGate API returned mismatched revocation correlation',
      )
    }
    return { ...response, value: response.value.revocation }
  }

  private get<T>(
    path: string,
    schema: z.ZodType<T>,
    signal?: AbortSignal,
  ): Promise<TimedResponse<T>> {
    return this.request(path, schema, { method: 'GET', signal })
  }

  private async request<T>(
    path: string,
    schema: z.ZodType<T>,
    init: RequestInit,
  ): Promise<TimedResponse<T>> {
    const token = await this.bearerToken()
    const headers = new Headers({
      Accept: 'application/json',
    })
    if (init.body !== undefined) {
      headers.set('Content-Type', 'application/json')
    }
    if (token) {
      headers.set('Authorization', `Bearer ${token}`)
    }

    const response = await this.fetchImplementation(
      new URL(path.replace(/^\//, ''), this.baseUrl),
      {
        ...init,
        cache: 'no-store',
        credentials: 'include',
        headers,
      },
    )

    if (!response.ok) {
      if (response.status === 401) {
        this.unauthorizedHandler()
      }
      throw new ApiError(response.status)
    }

    const payload = await readBoundedJson(response)
    const value = parseCredentialFree(schema, payload)
    return this.withServerClock(value, response)
  }

  private withServerClock<T>(
    value: T,
    response: Response,
  ): TimedResponse<T> {
    const receivedAt = Date.now()
    const embeddedServerTime =
      typeof value === 'object' &&
      value !== null &&
      'server_time' in value &&
      typeof value.server_time === 'string'
        ? value.server_time
        : undefined
    const serverTime = embeddedServerTime ?? response.headers.get('Date')
    const parsedTime = serverTime ? Date.parse(serverTime) : Number.NaN

    if (!Number.isFinite(parsedTime)) {
      return {
        value,
        serverOffsetMs: 0,
        clockWarning:
          'Server time was unavailable; countdowns may reflect browser clock skew.',
      }
    }
    return {
      value,
      serverOffsetMs: parsedTime - receivedAt,
    }
  }
}
