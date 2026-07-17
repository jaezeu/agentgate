import { StrictMode } from 'react'
import { createRoot } from 'react-dom/client'
import { AgentGateClient } from './api/client'
import { createMockAuthAdapter, createOidcAuthAdapter } from './auth/oidc'
import type { AuthAdapter } from './auth/types'
import { loadConfig } from './config'
import { App } from './App'
import './index.css'

const rootElement = document.getElementById('root')
if (!rootElement) {
  throw new Error('Dashboard root element is missing')
}
const root = createRoot(rootElement)

try {
  const config = loadConfig()
  let auth: AuthAdapter
  if (config.authMode === 'mock') {
    auth = createMockAuthAdapter(
      config.mockSubject ?? 'operator@example.test',
    )
  } else if (config.oidc) {
    auth = createOidcAuthAdapter(config.oidc)
  } else {
    throw new Error('OIDC configuration is missing')
  }

  const api = new AgentGateClient(config.apiBaseUrl, () =>
    auth.getBearerToken(),
  )

  root.render(
    <StrictMode>
      <App auth={auth} api={api} mockAuth={config.authMode === 'mock'} />
    </StrictMode>,
  )
} catch {
  root.render(
    <StrictMode>
      <main className="auth-page">
        <section className="auth-card" role="alert">
          <p className="eyebrow">AgentGate operations</p>
          <h1>Dashboard configuration error</h1>
          <p>
            Required non-secret deployment settings are missing or invalid.
            Review the dashboard deployment documentation.
          </p>
        </section>
      </main>
    </StrictMode>,
  )
}
