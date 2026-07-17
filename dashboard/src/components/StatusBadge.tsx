import type {
  ApprovalState,
  BindingState,
  Decision,
} from '../api/schema'
import {
  approvalLabel,
  bindingLabel,
  decisionLabel,
} from '../lib/format'

type StatusValue = Decision | ApprovalState | BindingState | 'expired'

function tone(value: StatusValue): string {
  switch (value) {
    case 'allow':
    case 'approved':
    case 'enabled':
      return 'positive'
    case 'deny':
    case 'denied':
    case 'failed':
      return 'negative'
    case 'pending':
    case 'pending_approval':
    case 'enabling':
    case 'revoking':
      return 'attention'
    case 'expired':
    case 'revoked':
      return 'neutral'
    case 'not_required':
      return 'muted'
  }
}

function label(value: StatusValue): string {
  if (value === 'expired') return 'Expired'
  if (
    value === 'allow' ||
    value === 'deny' ||
    value === 'pending_approval'
  ) {
    return decisionLabel(value)
  }
  if (
    value === 'pending' ||
    value === 'approved' ||
    value === 'denied'
  ) {
    return approvalLabel(value)
  }
  return bindingLabel(value)
}

export function StatusBadge({ value }: { value: StatusValue }) {
  return (
    <span className={`status status-${tone(value)}`}>
      <span className="status-marker" aria-hidden="true" />
      {label(value)}
    </span>
  )
}
