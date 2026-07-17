import {
  InMemoryWebStorage,
  UserManager,
  WebStorageStateStore,
  type User,
} from 'oidc-client-ts'
import type { OidcConfig } from '../config'
import type { AuthAdapter, AuthSession } from './types'

function sessionFromUser(user: User): AuthSession {
  return {
    subject: user.profile.sub,
    displayName:
      user.profile.name ??
      user.profile.preferred_username ??
      user.profile.email ??
      user.profile.sub,
  }
}

export function createOidcAuthAdapter(config: OidcConfig): AuthAdapter {
  const manager = new UserManager({
    authority: config.authority,
    client_id: config.clientId,
    redirect_uri: config.redirectUri,
    post_logout_redirect_uri: config.postLogoutRedirectUri,
    response_type: 'code',
    scope: config.scope,
    automaticSilentRenew: false,
    loadUserInfo: false,
    monitorSession: false,
    revokeTokensOnSignout: true,
    stateStore: new WebStorageStateStore({
      prefix: 'agentgate.oidc.state.',
      store: window.sessionStorage,
    }),
    userStore: new WebStorageStateStore({
      prefix: 'agentgate.oidc.user.',
      store: new InMemoryWebStorage(),
    }),
  })

  return {
    async getSession() {
      const user = await manager.getUser()
      if (!user || user.expired) {
        if (user) await manager.removeUser()
        return null
      }
      return sessionFromUser(user)
    },
    async completeSignIn(url) {
      const user = await manager.signinRedirectCallback(url)
      if (user.expired) {
        await manager.removeUser()
        throw new Error('OIDC session expired during callback')
      }
      return sessionFromUser(user)
    },
    async login() {
      await manager.signinRedirect()
    },
    async logout() {
      await manager.signoutRedirect()
    },
    async clearSession() {
      await manager.removeUser()
    },
    async getBearerToken() {
      const user = await manager.getUser()
      return user && !user.expired ? user.id_token : undefined
    },
    onSessionExpired(callback) {
      const removeExpired = manager.events.addAccessTokenExpired(callback)
      const removeSignedOut = manager.events.addUserSignedOut(callback)
      return () => {
        removeExpired()
        removeSignedOut()
      }
    },
  }
}

export function createMockAuthAdapter(subject: string): AuthAdapter {
  let session: AuthSession | null = null
  const expiredListeners = new Set<() => void>()

  return {
    async getSession() {
      return session
    },
    async completeSignIn() {
      throw new Error('Mock authentication has no OIDC callback')
    },
    async login() {
      session = { subject, displayName: `${subject} (development mock)` }
      return session
    },
    async logout() {
      session = null
    },
    async clearSession() {
      session = null
    },
    async getBearerToken() {
      return undefined
    },
    onSessionExpired(callback) {
      expiredListeners.add(callback)
      return () => expiredListeners.delete(callback)
    },
  }
}
