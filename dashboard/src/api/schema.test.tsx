import { http, HttpResponse } from 'msw'
import { screen } from '@testing-library/react'
import { describe, expect, it } from 'vitest'
import {
  CompatibilityError,
  WireListRequestsResponseSchema,
  assertCredentialFreeResponse,
  parseCredentialFree,
} from './schema'
import {
  activeRequest,
  detailResponse,
  listResponse,
  pendingRequest,
  timelineEvents,
  wireRequest,
} from '../test/fixtures'
import { renderView } from '../test/render'
import { server } from '../test/server'
import { ActiveGrantsView } from '../views/ActiveGrantsView'

describe('human API response safety', () => {
  it('treats an unknown enum value as a visible compatibility error', async () => {
    server.use(
      http.get('http://localhost/v1/requests', () =>
        HttpResponse.json({
          ...listResponse([activeRequest]),
          requests: [
            {
              ...wireRequest(activeRequest),
              decision: {
                ...wireRequest(activeRequest).decision,
                decision: 'future_allow',
              },
            },
          ],
        }),
      ),
    )
    renderView(<ActiveGrantsView />)

    expect(
      await screen.findByRole('heading', {
        name: 'API compatibility error',
      }),
    ).toBeInTheDocument()
  })

  it('rejects credential-shaped fields without rendering their values', async () => {
    const prohibitedValue = 'must-never-reach-the-dom'
    server.use(
      http.get('http://localhost/v1/requests', () =>
        HttpResponse.json({
          ...listResponse([activeRequest]),
          aws_secret_access_key: prohibitedValue,
        }),
      ),
    )
    renderView(<ActiveGrantsView />)

    expect(
      await screen.findByRole('heading', {
        name: 'API compatibility error',
      }),
    ).toBeInTheDocument()
    expect(screen.queryByText(prohibitedValue)).not.toBeInTheDocument()
  })

  it('rejects nested prohibited fields before schema decoding', () => {
    expect(() =>
      assertCredentialFreeResponse({
        request: {
          nested: {
            vault_token: 'not-rendered',
          },
        },
      }),
    ).toThrow(CompatibilityError)
    expect(() =>
      assertCredentialFreeResponse({
        warnings: ['AKIAIOSFODNN7EXAMPLE'],
      }),
    ).toThrow(CompatibilityError)
  })

  it('keeps all request and event fixtures credential-free', () => {
    const fixtures = [
      activeRequest,
      pendingRequest,
      listResponse([activeRequest, pendingRequest]),
      detailResponse(),
      timelineEvents,
    ]
    for (const fixture of fixtures) {
      expect(() => assertCredentialFreeResponse(fixture)).not.toThrow()
    }
    expect(() =>
      parseCredentialFree(
        WireListRequestsResponseSchema,
        listResponse([activeRequest]),
      ),
    ).not.toThrow()
  })
})
