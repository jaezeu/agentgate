import {
  useCallback,
  useEffect,
  useMemo,
  useState,
  type MouseEvent,
} from 'react'
import {
  QueryClient,
  QueryClientProvider,
  useQueryClient,
} from '@tanstack/react-query'
import type { AgentGateClient } from './api/client'
import { ApiProvider } from './api/context'
import { AuthBoundary } from './auth/AuthBoundary'
import { AuthProvider, useAuth } from './auth/context'
import type { AuthAdapter } from './auth/types'
import { ClockProvider } from './hooks/clock'
import { useOnline } from './hooks/useOnline'
import { ActiveGrantsView } from './views/ActiveGrantsView'
import { DecisionHistoryView } from './views/DecisionHistoryView'
import { PendingApprovalsView } from './views/PendingApprovalsView'

type Route = 'active' | 'approvals' | 'history'

function routeFromPath(pathname: string): Route {
  if (pathname.startsWith('/approvals')) return 'approvals'
  if (pathname.startsWith('/history')) return 'history'
  return 'active'
}

function useRoute(): [Route, (route: Route) => void] {
  const [route, setRoute] = useState(() =>
    routeFromPath(window.location.pathname),
  )

  useEffect(() => {
    function onPopState() {
      setRoute(routeFromPath(window.location.pathname))
    }
    window.addEventListener('popstate', onPopState)
    return () => window.removeEventListener('popstate', onPopState)
  }, [])

  function navigate(next: Route) {
    window.history.pushState(null, '', `/${next}`)
    setRoute(next)
    document.querySelector<HTMLElement>('#main-content')?.focus()
  }

  return [route, navigate]
}

function NavLink({
  route,
  current,
  navigate,
  children,
}: {
  route: Route
  current: Route
  navigate(route: Route): void
  children: string
}) {
  function onClick(event: MouseEvent<HTMLAnchorElement>) {
    if (
      event.button !== 0 ||
      event.metaKey ||
      event.ctrlKey ||
      event.shiftKey ||
      event.altKey
    ) {
      return
    }
    event.preventDefault()
    navigate(route)
  }

  return (
    <a
      href={`/${route}`}
      aria-current={current === route ? 'page' : undefined}
      onClick={onClick}
    >
      {children}
    </a>
  )
}

function SessionBridge({ client }: { client: AgentGateClient }) {
  const { expire } = useAuth()
  const queryClient = useQueryClient()
  const clearAndExpire = useCallback(() => {
    queryClient.clear()
    expire()
  }, [expire, queryClient])

  useEffect(
    () => client.setUnauthorizedHandler(clearAndExpire),
    [clearAndExpire, client],
  )
  return null
}

function DashboardShell({ mockAuth }: { mockAuth: boolean }) {
  const [route, navigate] = useRoute()
  const { state, logout } = useAuth()
  const queryClient = useQueryClient()
  const online = useOnline()
  const session = state.status === 'authenticated' ? state.session : null
  const signOut = useCallback(() => {
    queryClient.clear()
    void logout()
  }, [logout, queryClient])

  return (
    <div className="app-shell">
      <a className="skip-link" href="#main-content">
        Skip to content
      </a>
      {!online && (
        <div className="offline-banner" role="status">
          Offline. Displayed data may be stale; write actions will fail until
          connectivity returns.
        </div>
      )}
      {mockAuth && (
        <div className="mock-banner" role="status">
          Development mock human authentication is enabled.
        </div>
      )}
      <header className="topbar">
        <div className="brand">
          <span className="brand-mark" aria-hidden="true">
            AG
          </span>
          <span>
            <strong>AgentGate</strong>
            <small>Operations</small>
          </span>
        </div>
        <nav className="primary-nav" aria-label="Operations views">
          <NavLink route="active" current={route} navigate={navigate}>
            Active grants
          </NavLink>
          <NavLink route="approvals" current={route} navigate={navigate}>
            Pending approvals
          </NavLink>
          <NavLink route="history" current={route} navigate={navigate}>
            Decision history
          </NavLink>
        </nav>
        <div className="operator">
          <span>
            <small>Signed in as</small>
            <strong>{session?.displayName}</strong>
          </span>
          <button className="button button-small" type="button" onClick={signOut}>
            Sign out
          </button>
        </div>
      </header>
      <main id="main-content" className="main-content" tabIndex={-1}>
        {route === 'active' && <ActiveGrantsView />}
        {route === 'approvals' && <PendingApprovalsView />}
        {route === 'history' && <DecisionHistoryView />}
      </main>
    </div>
  )
}

export function App({
  auth,
  api,
  mockAuth = false,
}: {
  auth: AuthAdapter
  api: AgentGateClient
  mockAuth?: boolean
}) {
  const queryClient = useMemo(
    () =>
      new QueryClient({
        defaultOptions: {
          mutations: { retry: false },
        },
      }),
    [],
  )

  return (
    <AuthProvider adapter={auth}>
      <AuthBoundary>
        <QueryClientProvider client={queryClient}>
          <ApiProvider client={api}>
            <ClockProvider>
              <SessionBridge client={api} />
              <DashboardShell mockAuth={mockAuth} />
            </ClockProvider>
          </ApiProvider>
        </QueryClientProvider>
      </AuthBoundary>
    </AuthProvider>
  )
}
