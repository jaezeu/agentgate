import type { ReactNode } from 'react'
import { ApiError } from '../api/client'
import { CompatibilityError } from '../api/schema'
import { useOnline } from '../hooks/useOnline'

export function LoadingState({ label }: { label: string }) {
  return (
    <div className="state-panel" aria-busy="true" aria-live="polite">
      <span className="spinner" aria-hidden="true" />
      <p>{label}</p>
    </div>
  )
}

export function EmptyState({
  title,
  detail,
}: {
  title: string
  detail: string
}) {
  return (
    <div className="state-panel">
      <h2>{title}</h2>
      <p>{detail}</p>
    </div>
  )
}

export function ErrorState({
  error,
  retry,
}: {
  error: unknown
  retry(): void
}) {
  const online = useOnline()
  let title = online ? 'AgentGate could not load this view' : 'You are offline'
  let detail = online
    ? 'The server did not complete the request.'
    : 'Reconnect, then retry. Existing data may be stale.'

  if (error instanceof CompatibilityError) {
    title = 'API compatibility error'
    detail =
      'The response contains an unknown state or unsupported shape. Update the dashboard or AgentGate API before acting.'
  } else if (error instanceof ApiError && error.status === 403) {
    title = 'Forbidden'
    detail =
      'Your authenticated human identity is not authorized for this operation. Server authorization remains authoritative.'
  } else if (error instanceof ApiError && error.status === 401) {
    title = 'Session expired'
    detail = 'Sign in again before continuing.'
  }

  return (
    <div className="state-panel state-error" role="alert">
      <h2>{title}</h2>
      <p>{detail}</p>
      <button className="button" type="button" onClick={retry}>
        Retry
      </button>
    </div>
  )
}

export function DataNotices({
  fetching,
  stale,
  warnings,
  clockWarning,
}: {
  fetching: boolean
  stale: boolean
  warnings: string[]
  clockWarning?: string
}) {
  if (!fetching && !stale && warnings.length === 0 && !clockWarning) {
    return null
  }

  return (
    <div className="notices" aria-live="polite">
      {fetching && <p className="notice">Refreshing server data...</p>}
      {stale && !fetching && (
        <p className="notice notice-warning">
          Displayed data is stale. Refresh before making an operational
          decision.
        </p>
      )}
      {clockWarning && <p className="notice notice-warning">{clockWarning}</p>}
      {warnings.map((warning) => (
        <p className="notice notice-warning" key={warning}>
          Partial data: {warning}
        </p>
      ))}
    </div>
  )
}

export function ViewHeader({
  eyebrow,
  title,
  detail,
  actions,
}: {
  eyebrow: string
  title: string
  detail: string
  actions?: ReactNode
}) {
  return (
    <header className="view-header">
      <div>
        <p className="eyebrow">{eyebrow}</p>
        <h1>{title}</h1>
        <p>{detail}</p>
      </div>
      {actions && <div className="view-actions">{actions}</div>}
    </header>
  )
}
