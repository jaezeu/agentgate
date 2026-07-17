/* oxlint-disable react/only-export-components */
import {
  createContext,
  useCallback,
  useContext,
  useEffect,
  useMemo,
  useState,
  type ReactNode,
} from 'react'
import type { AuthAdapter, AuthSession } from './types'

type AuthState =
  | { status: 'loading' }
  | { status: 'unauthenticated' }
  | { status: 'callback_error' }
  | { status: 'session_expired' }
  | { status: 'authenticated'; session: AuthSession }

interface AuthContextValue {
  state: AuthState
  login(): Promise<void>
  logout(): Promise<void>
  expire(): void
}

const AuthContext = createContext<AuthContextValue | null>(null)

function isOidcCallback(): boolean {
  return window.location.pathname === '/auth/callback'
}

export function AuthProvider({
  adapter,
  children,
}: {
  adapter: AuthAdapter
  children: ReactNode
}) {
  const [state, setState] = useState<AuthState>({ status: 'loading' })

  const expire = useCallback(() => {
    setState({ status: 'session_expired' })
    void adapter.clearSession().catch(() => {
      setState({ status: 'callback_error' })
    })
  }, [adapter])

  useEffect(() => adapter.onSessionExpired(expire), [adapter, expire])

  useEffect(() => {
    let active = true

    async function initialize() {
      try {
        const session = isOidcCallback()
          ? await adapter.completeSignIn(window.location.href)
          : await adapter.getSession()
        if (!active) return
        if (session) {
          if (isOidcCallback()) {
            window.history.replaceState(null, '', '/active')
          }
          setState({ status: 'authenticated', session })
        } else {
          setState({ status: 'unauthenticated' })
        }
      } catch {
        if (active) setState({ status: 'callback_error' })
      }
    }

    void initialize()
    return () => {
      active = false
    }
  }, [adapter])

  const login = useCallback(async () => {
    setState({ status: 'loading' })
    try {
      const session = await adapter.login()
      if (session) setState({ status: 'authenticated', session })
    } catch {
      setState({ status: 'callback_error' })
    }
  }, [adapter])

  const logout = useCallback(async () => {
    setState({ status: 'loading' })
    try {
      await adapter.logout()
      setState({ status: 'unauthenticated' })
    } catch {
      setState({ status: 'callback_error' })
    }
  }, [adapter])

  const value = useMemo(
    () => ({ state, login, logout, expire }),
    [expire, login, logout, state],
  )

  return <AuthContext value={value}>{children}</AuthContext>
}

export function useAuth(): AuthContextValue {
  const value = useContext(AuthContext)
  if (!value) throw new Error('useAuth must be used within AuthProvider')
  return value
}
