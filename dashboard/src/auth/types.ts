export interface AuthSession {
  subject: string
  displayName: string
}

export interface AuthAdapter {
  getSession(): Promise<AuthSession | null>
  completeSignIn(url: string): Promise<AuthSession>
  login(): Promise<AuthSession | void>
  logout(): Promise<void>
  clearSession(): Promise<void>
  getBearerToken(): Promise<string | undefined>
  onSessionExpired(callback: () => void): () => void
}
