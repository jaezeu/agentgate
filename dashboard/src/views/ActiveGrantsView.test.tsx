import axe from 'axe-core'
import { delay, http, HttpResponse } from 'msw'
import {
  screen,
  within,
} from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { describe, expect, it } from 'vitest'
import { server } from '../test/server'
import {
  activeRequest,
  listResponse,
  revocationReport,
} from '../test/fixtures'
import { renderView } from '../test/render'
import { setViewport } from '../test/setup'
import { ActiveGrantsView } from './ActiveGrantsView'

function handleActiveList() {
  server.use(
    http.get('http://localhost/v1/requests', ({ request }) => {
      const url = new URL(request.url)
      expect(url.searchParams.get('active')).toBe('true')
      expect(url.searchParams.get('binding')).toBe('enabled')
      expect(url.searchParams.get('limit')).toBe('25')
      return HttpResponse.json(listResponse([activeRequest]))
    }),
  )
}

describe('ActiveGrantsView', () => {
  it('renders complete scope, absolute expiry, and a server-adjusted countdown', async () => {
    handleActiveList()
    const renderTime = Date.now()
    const view = renderView(<ActiveGrantsView />, {
      clockNow: renderTime,
    })

    expect(
      await screen.findByText(activeRequest.request_id),
    ).toBeInTheDocument()
    view.setClock(Date.now())

    expect(screen.getByText(activeRequest.spiffe_id)).toBeInTheDocument()
    expect(screen.getByText(activeRequest.on_behalf_of)).toBeInTheDocument()
    expect(screen.getByText(activeRequest.policy_version)).toBeInTheDocument()
    expect(
      screen.getByText(/17 Jul 2026, 10:15:00 UTC/),
    ).toBeInTheDocument()
    expect(
      screen.getByLabelText('Time to expiry: 00:15:00'),
    ).toBeInTheDocument()
  })

  it('reaches zero without rewriting the server decision or binding state', async () => {
    handleActiveList()
    const view = renderView(<ActiveGrantsView />, {
      clockNow: Date.now(),
    })

    expect(
      await screen.findAllByText(activeRequest.request_id),
    ).not.toHaveLength(0)
    const currentClientTime = Date.now()
    view.setClock(currentClientTime)
    expect(screen.getByText('Enabled')).toBeInTheDocument()
    expect(screen.getByText('Allow')).toBeInTheDocument()

    view.setClock(currentClientTime + 15 * 60 * 1_000 + 1_000)

    expect(screen.getByLabelText('Time to expiry: Expired')).toBeInTheDocument()
    expect(screen.getByText('Enabled')).toBeInTheDocument()
    expect(screen.getByText('Allow')).toBeInTheDocument()
    expect(screen.getByRole('button', { name: 'Revoke' })).toBeDisabled()
  })

  it('confirms the STS limitation and renders every revoke report field', async () => {
    handleActiveList()
    let revokeCalls = 0
    server.use(
      http.post(
        `http://localhost/v1/requests/${activeRequest.request_id}/revoke`,
        () => {
          revokeCalls += 1
          return HttpResponse.json({
            request_id: activeRequest.request_id,
            revocation: revocationReport,
          })
        },
      ),
    )
    const user = userEvent.setup()
    renderView(<ActiveGrantsView />)

    await user.click(
      await screen.findByRole('button', { name: 'Revoke' }),
    )
    const dialog = screen.getByRole('dialog', {
      name: 'Revoke AgentGate access',
    })
    expect(dialog).toHaveTextContent(
      /AWS STS credentials already issued may remain usable until their TTL expires/,
    )
    const submit = within(dialog).getByRole('button', {
      name: 'Revoke access',
    })
    expect(submit).toBeDisabled()

    await user.click(
      within(dialog).getByRole('checkbox', {
        name: /I confirm this exact request/,
      }),
    )
    await user.click(submit)

    const report = await within(dialog).findByRole('heading', {
      name: 'Latest revocation report',
    })
    const panel = report.closest('section')
    expect(panel).not.toBeNull()
    const reportPanel = within(panel as HTMLElement)
    expect(
      reportPanel.getByText('Role removed').parentElement,
    ).toHaveTextContent('Yes')
    expect(
      reportPanel.getByText('Policy removed').parentElement,
    ).toHaveTextContent('No')
    expect(
      reportPanel.getByText('Vault leases revoked').parentElement,
    ).toHaveTextContent('Yes')
    expect(
      reportPanel.getByText('Issued AWS STS credentials may remain')
        .parentElement,
    ).toHaveTextContent('Yes')
    expect(
      reportPanel.getByText(revocationReport.warnings[0]),
    ).toBeInTheDocument()
    expect(revokeCalls).toBe(1)
  })

  it('is accessible and switches to a non-overflowing mobile list', async () => {
    handleActiveList()
    setViewport(390)
    const { container } = renderView(<ActiveGrantsView />)

    expect(
      await screen.findAllByText(activeRequest.request_id),
    ).not.toHaveLength(0)
    expect(screen.queryByRole('table')).not.toBeInTheDocument()
    expect(
      screen.getByRole('list', {
        name: 'Active AgentGate access bindings',
      }),
    ).toBeInTheDocument()
    const card = container.querySelector('.request-card')
    expect(card).not.toBeNull()
    expect(getComputedStyle(card as Element).minWidth).toBe('0px')

    const results = await axe.run(container, {
      rules: { 'color-contrast': { enabled: false } },
    })
    expect(results.violations).toEqual([])
  })

  it('shows empty, partial-data, and in-place refresh states', async () => {
    let calls = 0
    server.use(
      http.get('http://localhost/v1/requests', async () => {
        calls += 1
        if (calls > 1) await delay(80)
        return HttpResponse.json(
          listResponse(calls === 1 ? [activeRequest] : [], {
            warnings: ['one replica omitted a non-critical audit hint'],
          }),
        )
      }),
    )
    const user = userEvent.setup()
    renderView(<ActiveGrantsView />)

    expect(screen.getByText('Loading active grants...')).toBeInTheDocument()
    await screen.findByText(activeRequest.request_id)
    expect(screen.getByText(/Partial data:/)).toHaveTextContent(
      /one replica omitted/,
    )

    await user.click(screen.getByRole('button', { name: 'Refresh' }))
    expect(screen.getByText(activeRequest.request_id)).toBeInTheDocument()
    expect(screen.getByText('Refreshing server data...')).toBeInTheDocument()
    expect(
      await screen.findByRole('heading', { name: 'No active grants' }),
    ).toBeInTheDocument()
  })

  it('retries a server failure once and then exposes a retry action', async () => {
    let calls = 0
    server.use(
      http.get('http://localhost/v1/requests', () => {
        calls += 1
        return new HttpResponse(null, { status: 503 })
      }),
    )
    renderView(<ActiveGrantsView />)

    expect(
      await screen.findByRole('heading', {
        name: 'AgentGate could not load this view',
      }),
    ).toBeInTheDocument()
    expect(screen.getByRole('button', { name: 'Retry' })).toBeInTheDocument()
    expect(calls).toBe(2)
  })
})
