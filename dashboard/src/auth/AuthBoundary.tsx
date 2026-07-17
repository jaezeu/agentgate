import type { ReactNode } from 'react'
import { useAuth } from './context'

export function AuthBoundary({ children }: { children: ReactNode }) {
  const { state, login } = useAuth()

  if (state.status === 'authenticated') return children

  if (state.status === 'loading') {
    return (
      <main className="auth-page" aria-busy="true">
        <section className="auth-card" aria-live="polite">
          <p className="eyebrow">AgentGate operations</p>
          <h1>Checking human session</h1>
          <p>Contacting the configured human identity provider.</p>
        </section>
      </main>
    )
  }

  const expired = state.status === 'session_expired'
  const callbackError = state.status === 'callback_error'

  return (
    <main className="auth-page">
      <section className="auth-card" aria-labelledby="auth-title">
        <p className="eyebrow">AgentGate operations</p>
        <h1 id="auth-title">
          {expired
            ? 'Your session expired'
            : callbackError
              ? 'Sign-in could not be completed'
              : 'Human sign-in required'}
        </h1>
        <p>
          {expired
            ? 'Sign in again to continue. No pending action was submitted.'
            : callbackError
              ? 'Retry through the configured OIDC provider. Authentication details were not retained.'
              : 'Use the human OIDC identity rail. Workload SPIFFE identities and task grants cannot sign in here.'}
        </p>
        <button className="button button-primary" type="button" onClick={login}>
          {expired || callbackError ? 'Sign in again' : 'Sign in with OIDC'}
        </button>
      </section>
    </main>
  )
}
