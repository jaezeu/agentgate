import {
  useMemo,
  useRef,
  useState,
} from 'react'
import { useMutation, useQueryClient } from '@tanstack/react-query'
import { ApiError } from '../api/client'
import { useApi } from '../api/context'
import type { RequestRecord, RevocationReport } from '../api/schema'
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
import { RevocationReportPanel } from '../components/RevocationReportPanel'
import { ScopeSummary } from '../components/ScopeSummary'
import { StatusBadge } from '../components/StatusBadge'
import { useServerNow } from '../hooks/clock'
import { useMediaQuery } from '../hooks/useMediaQuery'
import { useRequestList } from '../hooks/queries'
import {
  formatAbsoluteTime,
  formatCountdown,
  shortCommit,
} from '../lib/format'

const PAGE_SIZE = 25

function RequestId({ requestId }: { requestId: string }) {
  return (
    <span className="request-id">
      <span className="mono wrap-anywhere">{requestId}</span>
      <CopyButton value={requestId} />
    </span>
  )
}

function GrantStatus({
  request,
  now,
}: {
  request: RequestRecord
  now: number
}) {
  const expired = now >= Date.parse(request.expires_at)
  return (
    <div className="status-stack">
      <StatusBadge value={request.binding_state} />
      {expired && <StatusBadge value="expired" />}
      <StatusBadge value={request.decision} />
      {request.revoked_at && <span className="meta">Revocation recorded</span>}
    </div>
  )
}

function Countdown({
  expiresAt,
  now,
}: {
  expiresAt: string
  now: number
}) {
  const value = formatCountdown(expiresAt, now)
  return (
    <span
      className={`countdown${value === 'Expired' ? ' countdown-expired' : ''}`}
      aria-label={`Time to expiry: ${value}`}
    >
      {value}
    </span>
  )
}

function RevokeDialog({
  request,
  onClose,
}: {
  request: RequestRecord
  onClose(): void
}) {
  const api = useApi()
  const queryClient = useQueryClient()
  const [confirmed, setConfirmed] = useState(false)
  const [report, setReport] = useState<RevocationReport | null>(null)
  const submitting = useRef(false)
  const mutation = useMutation({
    mutationFn: () => api.revoke(request.request_id),
    onSuccess: ({ value }) => {
      setReport(value)
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

  return (
    <Dialog
      title="Revoke AgentGate access"
      description="Confirm the exact binding and understand the remaining AWS STS window."
      onClose={onClose}
      footer={
        <>
          <button className="button" type="button" onClick={onClose}>
            {report ? 'Close' : 'Cancel'}
          </button>
          {!report && (
            <button
              className="button button-danger"
              type="button"
              disabled={!confirmed || mutation.isPending}
              onClick={submit}
            >
              {mutation.isPending ? 'Requesting revoke...' : 'Revoke access'}
            </button>
          )}
        </>
      }
    >
      <ScopeSummary request={request} />
      <div className="callout callout-warning">
        <strong>Revocation is best-effort hygiene.</strong> AgentGate will
        prevent new access and attempt Vault lease cleanup. AWS STS credentials
        already issued may remain usable until their TTL expires. Short TTL is
        the primary control.
      </div>
      {!report && (
        <label className="confirmation">
          <input
            type="checkbox"
            checked={confirmed}
            onChange={(event) => setConfirmed(event.target.checked)}
          />
          I confirm this exact request and understand that issued AWS STS
          credentials may remain valid until expiry.
        </label>
      )}
      {mutation.error && (
        <p className="inline-error" role="alert">
          {mutation.error instanceof ApiError &&
          mutation.error.status === 403
            ? 'The server denied this revoke action.'
            : 'The revoke request did not complete. Refresh before retrying.'}
        </p>
      )}
      {report && <RevocationReportPanel report={report} />}
    </Dialog>
  )
}

function DesktopGrants({
  requests,
  now,
  onRevoke,
}: {
  requests: RequestRecord[]
  now: number
  onRevoke(request: RequestRecord): void
}) {
  return (
    <div className="table-frame">
      <table>
        <caption className="sr-only">
          Active AgentGate access bindings
        </caption>
        <thead>
          <tr>
            <th scope="col">State</th>
            <th scope="col">Request and scope</th>
            <th scope="col">Identity</th>
            <th scope="col">Policy</th>
            <th scope="col">Access window</th>
            <th scope="col">
              <span className="sr-only">Actions</span>
            </th>
          </tr>
        </thead>
        <tbody>
          {requests.map((request) => {
            const expired = now >= Date.parse(request.expires_at)
            const canRevoke =
              !expired &&
              !request.revoked_at &&
              request.binding_state === 'enabled'
            return (
              <tr key={request.request_id}>
                <td>
                  <GrantStatus request={request} now={now} />
                </td>
                <td>
                  <RequestId requestId={request.request_id} />
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
                  <span className="meta mono hash wrap-anywhere">
                    {request.policy_version}
                  </span>
                </td>
                <td>
                  <Countdown expiresAt={request.expires_at} now={now} />
                  <span className="meta">
                    Grant issued {formatAbsoluteTime(request.grant_issued_at)}
                  </span>
                  <span className="meta">
                    Binding recorded{' '}
                    {formatAbsoluteTime(
                      request.binding_created_at ?? request.created_at,
                    )}
                  </span>
                  <span className="meta">
                    Expires {formatAbsoluteTime(request.expires_at)}
                  </span>
                  {request.revocation && (
                    <span className="meta">
                      Revoke report: role{' '}
                      {request.revocation.role_removed
                        ? 'removed'
                        : 'not removed'}
                    </span>
                  )}
                </td>
                <td className="action-cell">
                  <button
                    className="button button-danger button-small"
                    type="button"
                    disabled={!canRevoke}
                    onClick={() => onRevoke(request)}
                  >
                    Revoke
                  </button>
                </td>
              </tr>
            )
          })}
        </tbody>
      </table>
    </div>
  )
}

function MobileGrants({
  requests,
  now,
  onRevoke,
}: {
  requests: RequestRecord[]
  now: number
  onRevoke(request: RequestRecord): void
}) {
  return (
    <ul className="card-list" aria-label="Active AgentGate access bindings">
      {requests.map((request) => {
        const expired = now >= Date.parse(request.expires_at)
        const canRevoke =
          !expired &&
          !request.revoked_at &&
          request.binding_state === 'enabled'
        return (
          <li className="request-card" key={request.request_id}>
            <div className="card-header">
              <GrantStatus request={request} now={now} />
              <Countdown expiresAt={request.expires_at} now={now} />
            </div>
            <RequestId requestId={request.request_id} />
            <ScopeSummary request={request} />
            <dl className="compact-details">
              <div>
                <dt>Decision reason</dt>
                <dd>{request.decision_reason}</dd>
              </div>
              <div>
                <dt>Policy version</dt>
                <dd className="mono wrap-anywhere">
                  {request.policy_version}
                </dd>
              </div>
              <div>
                <dt>Grant issued</dt>
                <dd>{formatAbsoluteTime(request.grant_issued_at)}</dd>
              </div>
              <div>
                <dt>Binding recorded</dt>
                <dd>
                  {formatAbsoluteTime(
                    request.binding_created_at ?? request.created_at,
                  )}
                </dd>
              </div>
              <div>
                <dt>Expires</dt>
                <dd>{formatAbsoluteTime(request.expires_at)}</dd>
              </div>
            </dl>
            <button
              className="button button-danger"
              type="button"
              disabled={!canRevoke}
              onClick={() => onRevoke(request)}
            >
              Revoke
            </button>
          </li>
        )
      })}
    </ul>
  )
}

export function ActiveGrantsView() {
  const [offset, setOffset] = useState(0)
  const [selected, setSelected] = useState<RequestRecord | null>(null)
  const filters = useMemo(
    () => ({
      active: true,
      binding: 'enabled' as const,
      limit: PAGE_SIZE,
      offset,
    }),
    [offset],
  )
  const query = useRequestList(filters)
  const mobile = useMediaQuery('(max-width: 760px)')
  const now = useServerNow(query.data?.serverOffsetMs ?? 0)

  return (
    <section>
      <ViewHeader
        eyebrow="Current control-plane bindings"
        title="Active grants"
        detail="Allowed or approved access that AgentGate reports as unexpired. Countdown values are display-only; server authorization is authoritative."
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

      {query.isPending && <LoadingState label="Loading active grants..." />}
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
              title="No active grants"
              detail="AgentGate reports no currently active access bindings for this page."
            />
          ) : mobile ? (
            <MobileGrants
              requests={query.data.value.requests}
              now={now}
              onRevoke={setSelected}
            />
          ) : (
            <DesktopGrants
              requests={query.data.value.requests}
              now={now}
              onRevoke={setSelected}
            />
          )}
          <Pagination
            offset={query.data.value.pagination.offset}
            limit={query.data.value.pagination.limit}
            count={query.data.value.requests.length}
            hasMore={query.data.value.pagination.has_more}
            onPage={setOffset}
          />
        </>
      )}
      {selected && (
        <RevokeDialog request={selected} onClose={() => setSelected(null)} />
      )}
    </section>
  )
}
