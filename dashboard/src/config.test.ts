import { describe, expect, it } from 'vitest'
import { loadConfig } from './config'

describe('loadConfig', () => {
  it('rejects mock authentication outside an explicit development build', () => {
    expect(() =>
      loadConfig(
        {
          DEV: false,
          VITE_AUTH_MODE: 'mock',
          VITE_ENABLE_MOCK_AUTH: 'true',
        },
        'https://dashboard.example.test',
      ),
    ).toThrow(/Mock authentication requires DEV/)
  })

  it('requires an explicit mock gate even in development', () => {
    expect(() =>
      loadConfig(
        {
          DEV: true,
          VITE_AUTH_MODE: 'mock',
          VITE_ENABLE_MOCK_AUTH: 'false',
        },
        'http://localhost:5173',
      ),
    ).toThrow(/VITE_ENABLE_MOCK_AUTH/)
  })

  it('loads only non-secret OIDC PKCE configuration', () => {
    const config = loadConfig(
      {
        DEV: false,
        VITE_AGENTGATE_API_BASE_URL: 'https://api.example.test',
        VITE_AUTH_MODE: 'oidc',
        VITE_OIDC_AUTHORITY: 'https://id.example.test',
        VITE_OIDC_CLIENT_ID: 'agentgate-dashboard',
      },
      'https://dashboard.example.test',
    )

    expect(config.authMode).toBe('oidc')
    expect(config.oidc).toEqual({
      authority: 'https://id.example.test/',
      clientId: 'agentgate-dashboard',
      redirectUri: 'https://dashboard.example.test/auth/callback',
      postLogoutRedirectUri: 'https://dashboard.example.test/',
      scope: 'openid profile email',
    })
    expect(config).not.toHaveProperty('clientSecret')
  })
})
