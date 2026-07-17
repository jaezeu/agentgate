import axe from 'axe-core'
import { http, HttpResponse, delay } from 'msw'
import { screen, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { describe, expect, it } from 'vitest'
import type { RequestRecord } from '../api/schema'
import {
  detailResponse,
  expiredPendingRequest,
  listResponse,
  pendingRequest,
  wireRequest,
} from '../test/fixtures'
import { renderView } from '../test/render'
import { server } from '../test/server'
import { setViewport } from '../test/setup'
import { PendingApprovalsView } from './PendingApprovalsView'

function handlePendingList(requests = [pendingRequest]) {
  server.use(
    http.get('http://localhost/v1/requests', ({ request }) => {
      expect(new URL(request.url).searchParams.get('approval')).toBe(
        'pending',
      )
      return HttpResponse.json(listResponse(requests))
    }),
  )
}

function decidedRequest(
  state: 'approved' | 'denied',
): RequestRecord {
  return {
    ...pendingRequest,
    approval_state: state,
    approval_decided_at: '2026-07-17T10:01:00Z',
    approval_decided_by: 'approver@example.test',
    binding_state: state === 'approved' ? 'enabling' : 'not_required',
  }
}

describe('PendingApprovalsView', () => {
  it('renders full review scope and makes an expired request non-actionable', async () => {
    handlePendingList([pendingRequest, expiredPendingRequest])
    renderView(<PendingApprovalsView />)

    expect(
      await screen.findByText(pendingRequest.request_id),
    ).toBeInTheDocument()
    expect(screen.getAllByText(pendingRequest.spiffe_id)).not.toHaveLength(0)
    expect(
      screen.getAllByText(pendingRequest.on_behalf_of),
    ).not.toHaveLength(0)
    expect(screen.getAllByText(/OPS-421/)).not.toHaveLength(0)
    expect(screen.getAllByText(/terraform-apply/)).not.toHaveLength(0)
    expect(screen.getAllByText(/production/)).not.toHaveLength(0)
    expect(
      screen.getAllByText(pendingRequest.decision_reason),
    ).not.toHaveLength(0)
    expect(
      screen.getAllByText(pendingRequest.policy_version),
    ).not.toHaveLength(0)
    expect(screen.getAllByText(/Requested 30m/)[0]).toHaveTextContent(
      'Effective 15m',
    )

    const expiredRow = screen
      .getByText(expiredPendingRequest.request_id)
      .closest('tr')
    expect(expiredRow).not.toBeNull()
    expect(
      within(expiredRow as HTMLElement).getByRole('button', {
        name: 'Approve',
      }),
    ).toBeDisabled()
    expect(
      within(expiredRow as HTMLElement).getByRole('button', {
        name: 'Deny',
      }),
    ).toBeDisabled()
    expect(within(expiredRow as HTMLElement).getByText('Expired')).toBeVisible()
  })

  it.each([
    ['approve', 'approved', 'Approve', 'Approved'] as const,
    ['deny', 'denied', 'Deny', 'Denied'] as const,
  ])(
    'sends exactly one %s request with only the operator reason',
    async (action, storedState, buttonLabel, storedLabel) => {
      handlePendingList()
      let calls = 0
      let requestBody: unknown
      server.use(
        http.post(
          `http://localhost/v1/requests/${pendingRequest.request_id}/${action}`,
          async ({ request }) => {
            calls += 1
            requestBody = await request.json()
            await delay(50)
            return HttpResponse.json({
              request: wireRequest(decidedRequest(storedState)),
            })
          },
        ),
      )
      const user = userEvent.setup()
      renderView(<PendingApprovalsView />)

      await user.click(
        await screen.findByRole('button', { name: buttonLabel }),
      )
      const dialog = screen.getByRole('dialog', {
        name: `${buttonLabel} pending request`,
      })
      expect(dialog).toHaveTextContent(
        /dashboard does not issue or receive credentials/,
      )
      await user.type(
        within(dialog).getByLabelText('Operator reason (optional)'),
        'Reviewed exact scope',
      )
      await user.click(
        within(dialog).getByRole('checkbox', {
          name: /I confirm the exact repository/,
        }),
      )
      const submit = within(dialog).getByRole('button', {
        name: `${buttonLabel} request`,
      })
      await user.click(submit)
      await user.click(submit)

      expect(
        await within(dialog).findByText(
          new RegExp(`Server state: ${storedLabel}`),
        ),
      ).toBeInTheDocument()
      expect(calls).toBe(1)
      expect(requestBody).toEqual({ reason: 'Reviewed exact scope' })
    },
  )

  it('refreshes the winning stored state after a 409 decision race', async () => {
    handlePendingList()
    let decisionCalls = 0
    server.use(
      http.post(
        `http://localhost/v1/requests/${pendingRequest.request_id}/approve`,
        () => {
          decisionCalls += 1
          return new HttpResponse(null, { status: 409 })
        },
      ),
      http.get(
        `http://localhost/v1/requests/${pendingRequest.request_id}`,
        () =>
          HttpResponse.json(
            detailResponse(decidedRequest('approved'), []),
          ),
      ),
    )
    const user = userEvent.setup()
    renderView(<PendingApprovalsView />)

    await user.click(
      await screen.findByRole('button', { name: 'Approve' }),
    )
    const dialog = screen.getByRole('dialog')
    await user.click(
      within(dialog).getByRole('checkbox', {
        name: /I confirm the exact repository/,
      }),
    )
    await user.click(
      within(dialog).getByRole('button', { name: 'Approve request' }),
    )

    expect(
      await within(dialog).findByText(
        /Another operator won this decision race/,
      ),
    ).toHaveTextContent('Stored server state: Approved')
    expect(decisionCalls).toBe(1)
  })

  it('supports keyboard dialog operation and core accessibility', async () => {
    handlePendingList()
    const user = userEvent.setup()
    const { container } = renderView(<PendingApprovalsView />)

    const approve = await screen.findByRole('button', { name: 'Approve' })
    approve.focus()
    await user.keyboard('{Enter}')
    expect(screen.getByRole('dialog')).toBeInTheDocument()
    await user.keyboard('{Escape}')
    expect(screen.queryByRole('dialog')).not.toBeInTheDocument()

    const results = await axe.run(container, {
      rules: { 'color-contrast': { enabled: false } },
    })
    expect(results.violations).toEqual([])
  })

  it('uses bounded mobile cards without overlapping decision controls', async () => {
    handlePendingList()
    setViewport(390)
    const { container } = renderView(<PendingApprovalsView />)

    expect(
      await screen.findAllByText(pendingRequest.request_id),
    ).not.toHaveLength(0)
    expect(screen.queryByRole('table')).not.toBeInTheDocument()
    const card = container.querySelector('.request-card')
    expect(card).not.toBeNull()
    expect(getComputedStyle(card as Element).minWidth).toBe('0px')
    expect(
      within(card as HTMLElement).getByRole('button', { name: 'Approve' }),
    ).toBeVisible()
    expect(
      within(card as HTMLElement).getByRole('button', { name: 'Deny' }),
    ).toBeVisible()
  })
})
