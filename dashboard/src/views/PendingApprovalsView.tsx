import {
  useMemo,
  useRef,
  useState,
} from 'react'
import { useMutation, useQueryClient } from '@tanstack/react-query'
import { ApiError } from '../api/client'
import { useApi } from '../api/context'
import type {
  ApprovalState,
  RequestRecord,
} from '../api/schema'
import { CopyButton } from '../components/CopyButton'
import { Dialog } from '../components/Dialog'
import {
  DataNotices,
  EmptyState,
  ErrorState,
  LoadingState,
  ViewHeader,
} from '../components/Feedback'
import { Pagination } from '../components/Pagination'
import { ScopeSummary } from '../components/ScopeSummary'
import { StatusBadge } from '../components/StatusBadge'
import { useServerNow } from '../hooks/clock'
import { useMediaQuery } from '../hooks/useMediaQuery'
import { useRequestList } from '../hooks/queries'
import {
  approvalLabel,
  formatAbsoluteTime,
  formatAge,
  formatTtl,
  shortCommit,
} from '../lib/format'

const PAGE_SIZE = 25
type DecisionAction = 'approve' | 'deny'

type DecisionOutcome =
  | { kind: 'stored'; state: ApprovalState }
  | { kind: 'race'; state: ApprovalState }

function PendingRequestId({ requestId }: { requestId: string }) {
  return (
    <span className="request-id">
      <span className="mono wrap-anywhere">{requestId}</span>
      <CopyButton value={requestId} />
    </span>
  )
}

function DecisionDialog({
  request,
  action,
  onClose,
}: {
  request: RequestRecord
  action: DecisionAction
  onClose(): void
}) {
  const api = useApi()
  const queryClient = useQueryClient()
  const [confirmed, setConfirmed] = useState(false)
  const [reason, setReason] = useState('')
  const submitting = useRef(false)
  const mutation = useMutation({
    mutationFn: async (): Promise<DecisionOutcome> => {
      try {
        const response = await api.decide(request.request_id, action, reason)
        return {
          kind: 'stored',
          state: response.value.request.approval_state,
        }
      } catch (error) {
        if (error instanceof ApiError && error.status === 409) {
          const stored = await api.getRequest(request.request_id)
          return {
            kind: 'race',
            state: stored.value.request.approval_state,
          }
        }
        throw error
      }
    },
    onSuccess: () => {
      void queryClient.invalidateQueries({ queryKey: ['requests'] })
      void queryClient.invalidateQueries({
        queryKey: ['request', request.request_id],
      })
    },
    onSettled: () => {
      submitting.current = false
    },
  })

  function submit() {
    if (!confirmed || submitting.current) return
    submitting.current = true
    mutation.mutate()
  }

  const completed = mutation.data !== undefined
  const actionLabel = action === 'approve' ? 'Approve' : 'Deny'

  return (
    <Dialog
      title={`${actionLabel} pending request`}
      description="Review and confirm the exact signed and authenticated scope."
      onClose={onClose}
      footer={
        <>
          <button className="button" type="button" onClick={onClose}>
            {completed ? 'Close' : 'Cancel'}
          </button>
          {!completed && (
            <button
              className={
                action === 'approve'
                  ? 'button button-primary'
                  : 'button button-danger'
              }
              type="button"
              disabled={!confirmed || mutation.isPending}
              onClick={submit}
            >
              {mutation.isPending
                ? `Submitting ${action}...`
                : `${actionLabel} request`}
            </button>
          )}
        </>
      }
    >
      <ScopeSummary request={request} />
      <div className="callout">
        Approval authorizes AgentGate to create a scoped Vault binding. The
        dashboard does not issue or receive credentials, and it does not receive
        the originating workload&apos;s redemption descriptor.
      </div>
      {!completed && (
        <>
          <label className="field">
            <span>Operator reason (optional)</span>
            <textarea
              value={reason}
              maxLength={500}
              onChange={(event) => setReason(event.target.value)}
            />
          </label>
          <label className="confirmation">
            <input
              type="checkbox"
              checked={confirmed}
              onChange={(event) => setConfirmed(event.target.checked)}
            />
            I confirm the exact repository, commit, operation, environment,
            role, identity, and TTL shown above.
          </label>
        </>
      )}
      {mutation.error && (
        <p className="inline-error" role="alert">
          {mutation.error instanceof ApiError &&
          mutation.error.status === 403
            ? 'The server denied this decision.'
            : 'The decision did not complete. Refresh the stored state before retrying.'}
        </p>
      )}
      {mutation.data?.kind === 'stored' && (
        <p className="callout callout-success" role="status">
          Server state: {approvalLabel(mutation.data.state)}. The dashboard
          issued no credentials.
        </p>
      )}
      {mutation.data?.kind === 'race' && (
        <p className="callout callout-warning" role="status">
          Another operator won this decision race. Stored server state:{' '}
          {approvalLabel(mutation.data.state)}.
        </p>
      )}
    </Dialog>
  )
}

function PendingActions({
  request,
  expired,
  onSelect,
}: {
  request: RequestRecord
  expired: boolean
  onSelect(request: RequestRecord, action: DecisionAction): void
}) {
  const disabled = expired || request.approval_state !== 'pending'
  return (
    <div className="button-group">
      <button
        className="button button-primary button-small"
        type="button"
        disabled={disabled}
        onClick={() => onSelect(request, 'approve')}
      >
        Approve
      </button>
      <button
        className="button button-danger button-small"
        type="button"
        disabled={disabled}
        onClick={() => onSelect(request, 'deny')}
      >
        Deny
      </button>
    </div>
  )
}

function DesktopPending({
  requests,
  now,
  onSelect,
}: {
  requests: RequestRecord[]
  now: number
  onSelect(request: RequestRecord, action: DecisionAction): void
}) {
  return (
    <div className="table-frame">
      <table>
        <caption className="sr-only">
          AgentGate requests pending human approval
        </caption>
        <thead>
          <tr>
            <th scope="col">Request and scope</th>
            <th scope="col">Identity</th>
            <th scope="col">Policy and TTL</th>
            <th scope="col">Age and expiry</th>
            <th scope="col">
              <span className="sr-only">Decision actions</span>
            </th>
          </tr>
        </thead>
        <tbody>
          {requests.map((request) => {
            const expired = now >= Date.parse(request.expires_at)
            return (
              <tr key={request.request_id}>
                <td>
                  <PendingRequestId requestId={request.request_id} />
                  <strong className="cell-title wrap-anywhere">
                    {request.repo}
                  </strong>
                  <span className="meta">
                    <span className="mono">
                      {shortCommit(request.commit_sha)}
                    </span>{' '}
                    · {request.operation} · {request.environment}
                  </span>
                  <span className="meta mono wrap-anywhere">
                    Role: {request.requested_vault_role}
                  </span>
                </td>
                <td>
                  <span className="cell-title">
                    {request.on_behalf_of}
                  </span>
                  <span className="meta">
                    Ticket: {request.ticket_id || 'None'}
                  </span>
                  <span className="meta mono wrap-anywhere">
                    {request.spiffe_id}
                  </span>
                </td>
                <td>
                  <span className="cell-title">{request.decision_reason}</span>
                  <span className="meta">
                    Requested {formatTtl(request.requested_ttl_seconds)} ·
                    Effective {formatTtl(request.effective_ttl_seconds)}
                  </span>
                  <span className="meta mono hash wrap-anywhere">
                    {request.policy_version}
                  </span>
                </td>
                <td>
                  <StatusBadge value={request.approval_state} />
                  {expired && <StatusBadge value="expired" />}
                  <span className="cell-title">
                    Waiting {formatAge(request.created_at, now)}
                  </span>
                  <span className="meta">
                    Expires {formatAbsoluteTime(request.expires_at)}
                  </span>
                </td>
                <td className="action-cell">
                  <PendingActions
                    request={request}
                    expired={expired}
                    onSelect={onSelect}
                  />
                </td>
              </tr>
            )
          })}
        </tbody>
      </table>
    </div>
  )
}

function MobilePending({
  requests,
  now,
  onSelect,
}: {
  requests: RequestRecord[]
  now: number
  onSelect(request: RequestRecord, action: DecisionAction): void
}) {
  return (
    <ul
      className="card-list"
      aria-label="AgentGate requests pending human approval"
    >
      {requests.map((request) => {
        const expired = now >= Date.parse(request.expires_at)
        return (
          <li className="request-card" key={request.request_id}>
            <div className="card-header">
              <div className="status-stack">
                <StatusBadge value={request.approval_state} />
                {expired && <StatusBadge value="expired" />}
              </div>
              <span className="meta">
                Waiting {formatAge(request.created_at, now)}
              </span>
            </div>
            <PendingRequestId requestId={request.request_id} />
            <ScopeSummary request={request} />
            <dl className="compact-details">
              <div>
                <dt>Policy reason</dt>
                <dd>{request.decision_reason}</dd>
              </div>
              <div>
                <dt>Policy version</dt>
                <dd className="mono wrap-anywhere">
                  {request.policy_version}
                </dd>
              </div>
              <div>
                <dt>Expires</dt>
                <dd>{formatAbsoluteTime(request.expires_at)}</dd>
              </div>
            </dl>
            <PendingActions
              request={request}
              expired={expired}
              onSelect={onSelect}
            />
          </li>
        )
      })}
    </ul>
  )
}

export function PendingApprovalsView() {
  const [offset, setOffset] = useState(0)
  const [selection, setSelection] = useState<{
    request: RequestRecord
    action: DecisionAction
  } | null>(null)
  const filters = useMemo(
    () => ({ approval: 'pending' as const, limit: PAGE_SIZE, offset }),
    [offset],
  )
  const query = useRequestList(filters)
  const mobile = useMediaQuery('(max-width: 760px)')
  const now = useServerNow(query.data?.serverOffsetMs ?? 0)

  function select(request: RequestRecord, action: DecisionAction) {
    setSelection({ request, action })
  }

  return (
    <section>
      <ViewHeader
        eyebrow="Human decision queue"
        title="Pending approvals"
        detail="Review the exact authenticated workload and signed task scope. AgentGate remains the authorization authority."
        actions={
          <button
            className="button"
            type="button"
            disabled={query.isFetching}
            onClick={() => void query.refetch()}
          >
            Refresh
          </button>
        }
      />
      {query.isPending && (
        <LoadingState label="Loading pending approvals..." />
      )}
      {query.isError && (
        <ErrorState error={query.error} retry={() => void query.refetch()} />
      )}
      {query.data && (
        <>
          <DataNotices
            fetching={query.isFetching}
            stale={query.isStale}
            warnings={query.data.value.warnings}
            clockWarning={query.data.clockWarning}
          />
          {query.data.value.requests.length === 0 ? (
            <EmptyState
              title="No requests are waiting"
              detail="AgentGate reports no pending approvals for this page."
            />
          ) : mobile ? (
            <MobilePending
              requests={query.data.value.requests}
              now={now}
              onSelect={select}
            />
          ) : (
            <DesktopPending
              requests={query.data.value.requests}
              now={now}
              onSelect={select}
            />
          )}
          <Pagination
            offset={query.data.value.pagination.offset}
            limit={query.data.value.pagination.limit}
            hasMore={query.data.value.pagination.has_more}
            onPage={setOffset}
          />
        </>
      )}
      {selection && (
        <DecisionDialog
          request={selection.request}
          action={selection.action}
          onClose={() => setSelection(null)}
        />
      )}
    </section>
  )
}
