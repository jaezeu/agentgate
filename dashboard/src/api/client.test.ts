import { describe, expect, it } from 'vitest'
import type { RequestRecord } from './schema'
import { AgentGateClient } from './client'
import {
  activeRequest,
  revocationReport,
  wireRequest,
} from '../test/fixtures'

describe('AgentGateClient write boundary', () => {
  it('limits write methods to approve, deny, and revoke request routes', async () => {
    const calls: Array<{ method: string; path: string; body: string | null }> =
      []
    const approved: RequestRecord = {
      ...activeRequest,
      approval_state: 'approved',
    }
    const fetchImplementation: typeof fetch = async (input, init) => {
      const request = new Request(input, init)
      calls.push({
        method: request.method,
        path: new URL(request.url).pathname,
        body: request.body ? await request.text() : null,
      })
      const payload = request.url.endsWith('/revoke')
        ? {
            request_id: activeRequest.request_id,
            revocation: revocationReport,
          }
        : { request: wireRequest(approved) }
      return Response.json(payload)
    }
    const client = new AgentGateClient(
      'https://agentgate.example.test/',
      async () => undefined,
      fetchImplementation,
    )

    await client.decide(activeRequest.request_id, 'approve', 'approved')
    await client.decide(activeRequest.request_id, 'deny', 'denied')
    await client.revoke(activeRequest.request_id)

    expect(calls).toEqual([
      {
        method: 'POST',
        path: `/v1/requests/${activeRequest.request_id}/approve`,
        body: '{"reason":"approved"}',
      },
      {
        method: 'POST',
        path: `/v1/requests/${activeRequest.request_id}/deny`,
        body: '{"reason":"denied"}',
      },
      {
        method: 'POST',
        path: `/v1/requests/${activeRequest.request_id}/revoke`,
        body: '{}',
      },
    ])
  })
})
