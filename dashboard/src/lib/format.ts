import type {
  ApprovalState,
  BindingState,
  Decision,
  EventType,
} from '../api/schema'

const absoluteDateFormatter = new Intl.DateTimeFormat('en-GB', {
  dateStyle: 'medium',
  timeStyle: 'medium',
  timeZone: 'UTC',
})

export function formatAbsoluteTime(value: string): string {
  return `${absoluteDateFormatter.format(new Date(value))} UTC`
}

export function formatCountdown(expiresAt: string, nowMs: number): string {
  const remainingMs = Date.parse(expiresAt) - nowMs
  if (remainingMs <= 0) return 'Expired'

  const totalSeconds = Math.ceil(remainingMs / 1_000)
  const days = Math.floor(totalSeconds / 86_400)
  const hours = Math.floor((totalSeconds % 86_400) / 3_600)
  const minutes = Math.floor((totalSeconds % 3_600) / 60)
  const seconds = totalSeconds % 60
  const clock = [hours, minutes, seconds]
    .map((part) => String(part).padStart(2, '0'))
    .join(':')
  return days > 0 ? `${days}d ${clock}` : clock
}

export function formatAge(createdAt: string, nowMs: number): string {
  const elapsedSeconds = Math.max(
    0,
    Math.floor((nowMs - Date.parse(createdAt)) / 1_000),
  )
  if (elapsedSeconds < 60) return `${elapsedSeconds}s`
  const minutes = Math.floor(elapsedSeconds / 60)
  if (minutes < 60) return `${minutes}m`
  const hours = Math.floor(minutes / 60)
  if (hours < 24) return `${hours}h ${minutes % 60}m`
  return `${Math.floor(hours / 24)}d ${hours % 24}h`
}

export function formatTtl(seconds: number | null): string {
  if (seconds === null) return 'Not granted'
  const hours = Math.floor(seconds / 3_600)
  const minutes = Math.floor((seconds % 3_600) / 60)
  const remaining = seconds % 60
  return [
    hours > 0 ? `${hours}h` : '',
    minutes > 0 ? `${minutes}m` : '',
    remaining > 0 || (hours === 0 && minutes === 0) ? `${remaining}s` : '',
  ]
    .filter(Boolean)
    .join(' ')
}

export function titleCase(value: string): string {
  return value
    .split('_')
    .map((part) => part.charAt(0).toUpperCase() + part.slice(1))
    .join(' ')
}

export function decisionLabel(value: Decision): string {
  switch (value) {
    case 'allow':
      return 'Allow'
    case 'deny':
      return 'Deny'
    case 'pending_approval':
      return 'Pending approval'
  }
}

export function approvalLabel(value: ApprovalState): string {
  switch (value) {
    case 'not_required':
      return 'Not required'
    case 'pending':
      return 'Pending'
    case 'approved':
      return 'Approved'
    case 'denied':
      return 'Denied'
    case 'expired':
      return 'Expired'
  }
}

export function bindingLabel(value: BindingState): string {
  switch (value) {
    case 'not_required':
      return 'Not required'
    case 'pending':
      return 'Pending'
    case 'enabling':
      return 'Enabling'
    case 'enabled':
      return 'Enabled'
    case 'failed':
      return 'Failed'
    case 'revoking':
      return 'Revoking'
    case 'revoked':
      return 'Revoked'
  }
}

export function eventLabel(value: EventType): string {
  switch (value) {
    case 'grant_verified':
      return 'Grant verified'
    case 'decision_recorded':
      return 'Decision recorded'
    case 'approval_requested':
      return 'Approval requested'
    case 'approval_decided':
      return 'Approval decided'
    case 'binding_enabled':
      return 'Binding enabled'
    case 'binding_failed':
      return 'Binding failed'
    case 'revocation':
      return 'Revocation requested'
  }
}

export function shortCommit(value: string): string {
  return value.slice(0, 8)
}
