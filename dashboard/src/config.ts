export type AuthMode = 'oidc' | 'mock'

export interface OidcConfig {
  authority: string
  clientId: string
  redirectUri: string
  postLogoutRedirectUri: string
  scope: string
}

export interface AppConfig {
  apiBaseUrl: string
  authMode: AuthMode
  oidc?: OidcConfig
  mockSubject?: string
}

type Environment = Record<string, string | boolean | undefined>

function required(environment: Environment, name: string): string {
  const value = environment[name]
  if (typeof value !== 'string' || value.trim() === '') {
    throw new Error(`Missing required dashboard configuration: ${name}`)
  }
  return value.trim()
}

function absoluteUrl(value: string, origin: string, name: string): string {
  try {
    return new URL(value, origin).toString()
  } catch {
    throw new Error(`Invalid URL in dashboard configuration: ${name}`)
  }
}

export function loadConfig(
  environment: Environment = import.meta.env,
  origin = window.location.origin,
): AppConfig {
  const apiBaseUrl = absoluteUrl(
    typeof environment.VITE_AGENTGATE_API_BASE_URL === 'string'
      ? environment.VITE_AGENTGATE_API_BASE_URL
      : '/',
    origin,
    'VITE_AGENTGATE_API_BASE_URL',
  )
  const authMode = environment.VITE_AUTH_MODE ?? 'oidc'

  if (authMode === 'mock') {
    if (
      environment.DEV !== true ||
      environment.VITE_ENABLE_MOCK_AUTH !== 'true'
    ) {
      throw new Error(
        'Mock authentication requires DEV and VITE_ENABLE_MOCK_AUTH=true',
      )
    }
    return {
      apiBaseUrl,
      authMode,
      mockSubject:
        typeof environment.VITE_MOCK_SUBJECT === 'string'
          ? environment.VITE_MOCK_SUBJECT
          : 'operator@example.test',
    }
  }

  if (authMode !== 'oidc') {
    throw new Error('VITE_AUTH_MODE must be "oidc" or "mock"')
  }

  return {
    apiBaseUrl,
    authMode,
    oidc: {
      authority: absoluteUrl(
        required(environment, 'VITE_OIDC_AUTHORITY'),
        origin,
        'VITE_OIDC_AUTHORITY',
      ),
      clientId: required(environment, 'VITE_OIDC_CLIENT_ID'),
      redirectUri: absoluteUrl(
        typeof environment.VITE_OIDC_REDIRECT_URI === 'string'
          ? environment.VITE_OIDC_REDIRECT_URI
          : '/auth/callback',
        origin,
        'VITE_OIDC_REDIRECT_URI',
      ),
      postLogoutRedirectUri: absoluteUrl(
        typeof environment.VITE_OIDC_POST_LOGOUT_REDIRECT_URI === 'string'
          ? environment.VITE_OIDC_POST_LOGOUT_REDIRECT_URI
          : '/',
        origin,
        'VITE_OIDC_POST_LOGOUT_REDIRECT_URI',
      ),
      scope:
        typeof environment.VITE_OIDC_SCOPE === 'string'
          ? environment.VITE_OIDC_SCOPE
          : 'openid profile email',
    },
  }
}
