import axe from 'axe-core'
import { http, HttpResponse } from 'msw'
import { fireEvent, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { describe, expect, it } from 'vitest'
import {
  activeRequest,
  detailResponse,
  listResponse,
  timelineEvents,
} from '../test/fixtures'
import { renderView } from '../test/render'
import { server } from '../test/server'
import { setViewport } from '../test/setup'
import { DecisionHistoryView } from './DecisionHistoryView'

function handleHistoryList(urls: URL[], hasMore = true) {
  server.use(
    http.get('http://localhost/v1/requests', ({ request }) => {
      const url = new URL(request.url)
      urls.push(url)
      return HttpResponse.json(
        listResponse([activeRequest], {
          offset: Number(url.searchParams.get('offset') ?? 0),
          hasMore,
        }),
      )
    }),
  )
}

describe('DecisionHistoryView', () => {
  it('applies every server filter and paginates with stable offsets', async () => {
    const urls: URL[] = []
    handleHistoryList(urls)
    const user = userEvent.setup()
    renderView(<DecisionHistoryView />)

    expect(
      await screen.findAllByText(activeRequest.request_id),
    ).not.toHaveLength(0)
    fireEvent.change(screen.getByLabelText('From (local time)'), {
      target: { value: '2026-07-17T08:30' },
    })
    fireEvent.change(screen.getByLabelText('To (local time)'), {
      target: { value: '2026-07-17T11:30' },
    })
    await user.selectOptions(screen.getByLabelText('Decision'), 'deny')
    await user.selectOptions(
      screen.getByLabelText('Approval state'),
      'approved',
    )
    await user.selectOptions(screen.getByLabelText('Access status'), 'true')
    await user.selectOptions(
      screen.getByLabelText('Operation'),
      'terraform-apply',
    )
    await user.type(
      screen.getByLabelText('Workload SPIFFE ID'),
      activeRequest.spiffe_id,
    )
    await user.type(
      screen.getByLabelText('On behalf of'),
      'requester@example.test',
    )
    await user.type(screen.getByLabelText('Environment'), 'production')
    await user.type(
      screen.getByLabelText('Repository'),
      'github.com/jaezeu/agentgate',
    )
    await user.click(screen.getByRole('button', { name: 'Apply filters' }))

    await waitFor(() => expect(urls.length).toBeGreaterThanOrEqual(2))
    const filtered = urls.at(-1)
    expect(filtered?.searchParams.get('created_after')).toBe(
      new Date('2026-07-17T08:30').toISOString(),
    )
    expect(filtered?.searchParams.get('created_before')).toBe(
      new Date('2026-07-17T11:30').toISOString(),
    )
    expect(filtered?.searchParams.get('decision')).toBe('deny')
    expect(filtered?.searchParams.get('approval')).toBe('approved')
    expect(filtered?.searchParams.get('active')).toBe('true')
    expect(filtered?.searchParams.get('operation')).toBe('terraform-apply')
    expect(filtered?.searchParams.get('spiffe_id')).toBe(
      activeRequest.spiffe_id,
    )
    expect(filtered?.searchParams.get('on_behalf_of')).toBe(
      'requester@example.test',
    )
    expect(filtered?.searchParams.get('environment')).toBe('production')
    expect(filtered?.searchParams.get('repo')).toBe(
      'github.com/jaezeu/agentgate',
    )
    expect(filtered?.searchParams.get('offset')).toBe('0')
    expect(filtered?.searchParams.get('limit')).toBe('25')

    await user.click(screen.getByRole('button', { name: 'Next' }))
    await waitFor(() =>
      expect(urls.at(-1)?.searchParams.get('offset')).toBe('25'),
    )
  })

  it('expands the full correlation timeline and exact audit hints', async () => {
    handleHistoryList([], false)
    server.use(
      http.get(
        `http://localhost/v1/requests/${activeRequest.request_id}`,
        () => HttpResponse.json(detailResponse()),
      ),
    )
    const user = userEvent.setup()
    renderView(<DecisionHistoryView />)

    await user.click(
      await screen.findByRole('button', { name: 'View timeline' }),
    )
    expect(
      await screen.findByRole('heading', { name: 'Full correlation chain' }),
    ).toBeInTheDocument()
    for (const event of timelineEvents) {
      expect(screen.getByText(`Event ${event.event_id}`)).toBeInTheDocument()
    }
    expect(screen.getByText('Grant verified')).toBeInTheDocument()
    expect(screen.getByText('Decision recorded')).toBeInTheDocument()
    expect(screen.getByText('Approval requested')).toBeInTheDocument()
    expect(screen.getByText('Approval decided')).toBeInTheDocument()
    expect(screen.getByText('Binding enabled')).toBeInTheDocument()
    expect(screen.getByText('Revocation requested')).toBeInTheDocument()
    expect(
      screen.getByText('Issued AWS STS credentials may remain').parentElement,
    ).toHaveTextContent('Yes')
    expect(
      screen.getAllByText(activeRequest.policy_version).length,
    ).toBeGreaterThan(0)
    expect(
      screen.getByRole('heading', { name: 'CloudTrail correlation' }),
    ).toBeInTheDocument()
    expect(screen.getByText(/AWS STS role session name/)).toHaveTextContent(
      /request_id/,
    )
    expect(
      screen.getByRole('heading', { name: 'Vault audit correlation' }),
    ).toBeInTheDocument()
    expect(screen.getByText(/Vault identifies the agent/)).toHaveTextContent(
      /workload logs in directly/,
    )
  })

  it('passes accessibility checks and uses mobile cards without table overflow', async () => {
    handleHistoryList([], false)
    setViewport(390)
    const { container } = renderView(<DecisionHistoryView />)

    expect(
      await screen.findAllByText(activeRequest.request_id),
    ).not.toHaveLength(0)
    expect(screen.queryByRole('table')).not.toBeInTheDocument()
    expect(
      screen.getByRole('list', {
        name: 'Immutable AgentGate decision history',
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
})
