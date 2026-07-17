import { http, HttpResponse } from 'msw'
import {
  act,
  render,
  screen,
} from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { describe, expect, it, vi } from 'vitest'
import { AgentGateClient } from './api/client'
import type { AuthAdapter, AuthSession } from './auth/types'
import { App } from './App'
import { activeRequest, listResponse } from './test/fixtures'
import { server } from './test/server'
import { setOnline } from './test/setup'

const operator: AuthSession = {
  subject: 'operator-subject',
  displayName: 'operator@example.test',
}

function fakeAuth({
  initial = operator,
  callbackError = false,
}: {
  initial?: AuthSession | null
  callbackError?: boolean
} = {}) {
  let expired: (() => void) | undefined
  const adapter: AuthAdapter = {
    getSession: vi.fn(async () => initial),
    completeSignIn: vi.fn(async () => {
      if (callbackError) throw new Error('provider callback details')
      return operator
    }),
    login: vi.fn(async () => operator),
    logout: vi.fn(async () => undefined),
    clearSession: vi.fn(async () => undefined),
    getBearerToken: vi.fn(async () => undefined),
    onSessionExpired: vi.fn((callback) => {
      expired = callback
      return () => {
        expired = undefined
      }
    }),
  }
  return {
    adapter,
    expire() {
      expired?.()
    },
  }
}

function handleEmptyList(status = 200) {
  server.use(
    http.get('http://localhost/v1/requests', () =>
      status === 200
        ? HttpResponse.json(listResponse([]))
        : new HttpResponse(null, { status }),
    ),
  )
}

describe('dashboard authentication states', () => {
  it('requires human OIDC sign-in and never offers a SPIFFE login path', async () => {
    handleEmptyList()
    const auth = fakeAuth({ initial: null })
    const user = userEvent.setup()
    render(
      <App
        auth={auth.adapter}
        api={new AgentGateClient('http://localhost/')}
      />,
    )

    expect(
      await screen.findByRole('heading', { name: 'Human sign-in required' }),
    ).toBeInTheDocument()
    expect(screen.getByText(/Workload SPIFFE identities/)).toBeInTheDocument()
    expect(
      screen.queryByRole('button', { name: /SPIFFE/ }),
    ).not.toBeInTheDocument()

    await user.click(
      screen.getByRole('button', { name: 'Sign in with OIDC' }),
    )
    expect(
      await screen.findByRole('heading', { name: 'Active grants' }),
    ).toBeInTheDocument()
    expect(auth.adapter.login).toHaveBeenCalledTimes(1)
  })

  it('surfaces callback failure without exposing provider details', async () => {
    window.history.replaceState(
      null,
      '',
      '/auth/callback?error=access_denied&error_description=sensitive-detail',
    )
    const auth = fakeAuth({ callbackError: true })
    render(
      <App
        auth={auth.adapter}
        api={new AgentGateClient('http://localhost/')}
      />,
    )

    expect(
      await screen.findByRole('heading', {
        name: 'Sign-in could not be completed',
      }),
    ).toBeInTheDocument()
    expect(screen.queryByText(/sensitive-detail/)).not.toBeInTheDocument()
  })

  it('handles an expired in-memory session and allows reauthentication', async () => {
    handleEmptyList()
    const auth = fakeAuth()
    render(
      <App
        auth={auth.adapter}
        api={new AgentGateClient('http://localhost/')}
      />,
    )

    await screen.findByRole('heading', { name: 'Active grants' })
    act(() => auth.expire())

    expect(
      await screen.findByRole('heading', { name: 'Your session expired' }),
    ).toBeInTheDocument()
    expect(auth.adapter.clearSession).toHaveBeenCalledTimes(1)
  })

  it('turns an API 401 into an expired-session state', async () => {
    handleEmptyList(401)
    const auth = fakeAuth()
    render(
      <App
        auth={auth.adapter}
        api={new AgentGateClient('http://localhost/')}
      />,
    )

    expect(
      await screen.findByRole('heading', { name: 'Your session expired' }),
    ).toBeInTheDocument()
  })

  it('renders forbidden server authorization without hiding the failure', async () => {
    handleEmptyList(403)
    const auth = fakeAuth()
    render(
      <App
        auth={auth.adapter}
        api={new AgentGateClient('http://localhost/')}
      />,
    )

    expect(
      await screen.findByRole('heading', { name: 'Forbidden' }),
    ).toBeInTheDocument()
    expect(screen.getByText(/Server authorization/)).toBeInTheDocument()
  })

  it('announces offline mode while preserving credential-free stale reads', async () => {
    handleEmptyList()
    setOnline(false)
    const auth = fakeAuth()
    render(
      <App
        auth={auth.adapter}
        api={new AgentGateClient('http://localhost/')}
      />,
    )

    expect(
      await screen.findByText(/Offline\. Displayed data may be stale/),
    ).toBeInTheDocument()
  })

  it('logs out through the configured human provider', async () => {
    handleEmptyList()
    const auth = fakeAuth()
    const user = userEvent.setup()
    render(
      <App
        auth={auth.adapter}
        api={new AgentGateClient('http://localhost/')}
      />,
    )

    await user.click(await screen.findByRole('button', { name: 'Sign out' }))
    expect(auth.adapter.logout).toHaveBeenCalledTimes(1)
    expect(
      await screen.findByRole('heading', { name: 'Human sign-in required' }),
    ).toBeInTheDocument()
  })

  it('clears operator data before a different human session starts', async () => {
    let requestCount = 0
    let releaseSecondRequest: (() => void) | undefined
    const secondRequest = new Promise<void>((resolve) => {
      releaseSecondRequest = resolve
    })
    server.use(
      http.get('http://localhost/v1/requests', async () => {
        requestCount += 1
        if (requestCount === 1) {
          return HttpResponse.json(listResponse([activeRequest]))
        }
        await secondRequest
        return HttpResponse.json(listResponse([]))
      }),
    )
    const auth = fakeAuth()
    const user = userEvent.setup()
    render(
      <App
        auth={auth.adapter}
        api={new AgentGateClient('http://localhost/')}
      />,
    )

    expect(
      await screen.findByText(activeRequest.request_id),
    ).toBeInTheDocument()
    await user.click(screen.getByRole('button', { name: 'Sign out' }))
    await user.click(
      await screen.findByRole('button', { name: 'Sign in with OIDC' }),
    )
    expect(
      await screen.findByRole('heading', { name: 'Active grants' }),
    ).toBeInTheDocument()
    expect(
      screen.queryByText(activeRequest.request_id),
    ).not.toBeInTheDocument()

    releaseSecondRequest?.()
    expect(
      await screen.findByRole('heading', { name: 'No active grants' }),
    ).toBeInTheDocument()
  })

  it('labels explicitly gated development mock sessions', async () => {
    handleEmptyList()
    const auth = fakeAuth()
    render(
      <App
        auth={auth.adapter}
        api={new AgentGateClient('http://localhost/')}
        mockAuth
      />,
    )

    expect(
      await screen.findByText(
        'Development mock human authentication is enabled.',
      ),
    ).toBeInTheDocument()
  })
})
