import {
  Fragment,
  useId,
  useMemo,
  useState,
  type FormEvent,
} from 'react'
import type {
  ApprovalState,
  Decision,
  Operation,
  RequestRecord,
} from '../api/schema'
import { CopyButton } from '../components/CopyButton'
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
import { useRequestDetail, useRequestList } from '../hooks/queries'
import {
  eventLabel,
  formatAbsoluteTime,
  shortCommit,
} from '../lib/format'

const PAGE_SIZE = 25

interface HistoryFilters {
  createdAfter: string
  createdBefore: string
  decision: '' | Decision
  approval: '' | ApprovalState
  active: '' | 'true' | 'false'
  spiffeId: string
  onBehalfOf: string
  environment: string
  operation: '' | Operation
  repo: string
}

const emptyFilters: HistoryFilters = {
  createdAfter: '',
  createdBefore: '',
  decision: '',
  approval: '',
  active: '',
  spiffeId: '',
  onBehalfOf: '',
  environment: '',
  operation: '',
  repo: '',
}

function toIso(value: string): string | undefined {
  if (!value) return undefined
  return new Date(value).toISOString()
}

function HistoryFiltersForm({
  filters,
  onApply,
}: {
  filters: HistoryFilters
  onApply(filters: HistoryFilters): void
}) {
  const [draft, setDraft] = useState(filters)

  function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault()
    onApply(draft)
  }

  function reset() {
    setDraft(emptyFilters)
    onApply(emptyFilters)
  }

  return (
    <form className="filters" onSubmit={submit} aria-label="History filters">
      <div className="filter-grid">
        <label className="field">
          <span>From (local time)</span>
          <input
            type="datetime-local"
            value={draft.createdAfter}
            onChange={(event) =>
              setDraft({ ...draft, createdAfter: event.target.value })
            }
          />
        </label>
        <label className="field">
          <span>To (local time)</span>
          <input
            type="datetime-local"
            value={draft.createdBefore}
            onChange={(event) =>
              setDraft({ ...draft, createdBefore: event.target.value })
            }
          />
        </label>
        <label className="field">
          <span>Decision</span>
          <select
            value={draft.decision}
            onChange={(event) =>
              setDraft({
                ...draft,
                decision: event.target.value as HistoryFilters['decision'],
              })
            }
          >
            <option value="">All decisions</option>
            <option value="allow">Allow</option>
            <option value="deny">Deny</option>
            <option value="pending_approval">Pending approval</option>
          </select>
        </label>
        <label className="field">
          <span>Approval state</span>
          <select
            value={draft.approval}
            onChange={(event) =>
              setDraft({
                ...draft,
                approval: event.target.value as HistoryFilters['approval'],
              })
            }
          >
            <option value="">All approval states</option>
            <option value="not_required">Not required</option>
            <option value="pending">Pending</option>
            <option value="approved">Approved</option>
            <option value="denied">Denied</option>
            <option value="expired">Expired</option>
          </select>
        </label>
        <label className="field">
          <span>Access status</span>
          <select
            value={draft.active}
            onChange={(event) =>
              setDraft({
                ...draft,
                active: event.target.value as HistoryFilters['active'],
              })
            }
          >
            <option value="">Active and expired</option>
            <option value="true">Active</option>
            <option value="false">Expired or inactive</option>
          </select>
        </label>
        <label className="field">
          <span>Operation</span>
          <select
            value={draft.operation}
            onChange={(event) =>
              setDraft({
                ...draft,
                operation: event.target.value as HistoryFilters['operation'],
              })
            }
          >
            <option value="">All operations</option>
            <option value="terraform-plan">Terraform plan</option>
            <option value="terraform-apply">Terraform apply</option>
          </select>
        </label>
        <label className="field">
          <span>Workload SPIFFE ID</span>
          <input
            value={draft.spiffeId}
            placeholder="spiffe://..."
            onChange={(event) =>
              setDraft({ ...draft, spiffeId: event.target.value })
            }
          />
        </label>
        <label className="field">
          <span>On behalf of</span>
          <input
            value={draft.onBehalfOf}
            onChange={(event) =>
              setDraft({ ...draft, onBehalfOf: event.target.value })
            }
          />
        </label>
        <label className="field">
          <span>Environment</span>
          <input
            value={draft.environment}
            onChange={(event) =>
              setDraft({ ...draft, environment: event.target.value })
            }
          />
        </label>
        <label className="field">
          <span>Repository</span>
          <input
            value={draft.repo}
            onChange={(event) =>
              setDraft({ ...draft, repo: event.target.value })
            }
          />
        </label>
      </div>
      <div className="filter-actions">
        <span className="meta">Stable order: newest first</span>
        <button className="button" type="button" onClick={reset}>
          Clear
        </button>
        <button className="button button-primary" type="submit">
          Apply filters
        </button>
      </div>
    </form>
  )
}

function CorrelationHints({ request }: { request: RequestRecord }) {
  const sessionName =
    request.correlation.aws_role_session_name ?? request.request_id
  return (
    <div className="correlation-grid">
      <section className="correlation-hint">
        <h4>CloudTrail correlation</h4>
        <p>
          Search the AWS STS role session name for{' '}
          <code className="wrap-anywhere">{sessionName}</code>. AgentGate
          embeds <code>request_id</code> in that role session name.
        </p>
      </section>
      <section className="correlation-hint">
        <h4>Vault audit correlation</h4>
        <p>
          Search for request <code>{request.request_id}</code> and subject{' '}
          <code className="wrap-anywhere">{request.spiffe_id}</code>. Vault
          identifies the agent because the workload logs in directly.
        </p>
      </section>
    </div>
  )
}

function Timeline({ requestId }: { requestId: string }) {
  const query = useRequestDetail(requestId)

  if (query.isPending) {
    return <LoadingState label="Loading full request timeline..." />
  }
  if (query.isError) {
    return (
      <ErrorState error={query.error} retry={() => void query.refetch()} />
    )
  }

  const detail = query.data.value
  return (
    <section className="timeline-panel" aria-label="Full request timeline">
      <DataNotices
        fetching={query.isFetching}
        stale={query.isStale}
        warnings={detail.warnings}
        clockWarning={query.data.clockWarning}
      />
      <div className="timeline-summary">
        <div>
          <h3>Full correlation chain</h3>
          <p>
            Exact policy version:{' '}
            <code className="wrap-anywhere">
              {detail.request.policy_version}
            </code>
          </p>
          <p>Decision reason: {detail.request.decision_reason}</p>
        </div>
        <CopyButton
          value={detail.request.request_id}
          label="Copy timeline request ID"
        />
      </div>
      {detail.events.length === 0 ? (
        <p>No immutable events were returned for this request.</p>
      ) : (
        <ol className="timeline">
          {detail.events.map((event) => (
            <li key={event.event_id}>
              <span className="timeline-marker" aria-hidden="true" />
              <div className="timeline-event">
                <div className="timeline-event-header">
                  <span>
                    <strong>{eventLabel(event.event_type)}</strong>
                    <span className="meta mono">
                      Event {event.event_id}
                    </span>
                  </span>
                  <time dateTime={event.occurred_at}>
                    {formatAbsoluteTime(event.occurred_at)}
                  </time>
                </div>
                <dl className="event-details">
                  {event.decision && (
                    <div>
                      <dt>Decision</dt>
                      <dd>{event.decision}</dd>
                    </div>
                  )}
                  {event.decision_reason && (
                    <div>
                      <dt>Reason</dt>
                      <dd>{event.decision_reason}</dd>
                    </div>
                  )}
                  {event.approval_state && (
                    <div>
                      <dt>Approval</dt>
                      <dd>{event.approval_state}</dd>
                    </div>
                  )}
                  {event.actor && (
                    <div>
                      <dt>Operator</dt>
                      <dd>{event.actor}</dd>
                    </div>
                  )}
                  {event.reason && (
                    <div>
                      <dt>Operator reason</dt>
                      <dd>{event.reason}</dd>
                    </div>
                  )}
                  {event.policy_version && (
                    <div>
                      <dt>Policy version</dt>
                      <dd className="mono wrap-anywhere">
                        {event.policy_version}
                      </dd>
                    </div>
                  )}
                  {event.vault_auth_role && (
                    <div>
                      <dt>Vault auth role</dt>
                      <dd className="mono wrap-anywhere">
                        {event.vault_auth_role}
                      </dd>
                    </div>
                  )}
                  {event.aws_role_session_name && (
                    <div>
                      <dt>AWS role session</dt>
                      <dd className="mono wrap-anywhere">
                        {event.aws_role_session_name}
                      </dd>
                    </div>
                  )}
                  {event.revocation && (
                    <>
                      <div>
                        <dt>Role removed</dt>
                        <dd>{event.revocation.role_removed ? 'Yes' : 'No'}</dd>
                      </div>
                      <div>
                        <dt>Policy removed</dt>
                        <dd>
                          {event.revocation.policy_removed ? 'Yes' : 'No'}
                        </dd>
                      </div>
                      <div>
                        <dt>Vault leases revoked</dt>
                        <dd>
                          {event.revocation.leases_revoked ? 'Yes' : 'No'}
                        </dd>
                      </div>
                      <div>
                        <dt>Issued AWS STS credentials may remain</dt>
                        <dd>
                          {event.revocation.sts_credentials_may_remain
                            ? 'Yes'
                            : 'No'}
                        </dd>
                      </div>
                    </>
                  )}
                </dl>
                {event.revocation &&
                  event.revocation.warnings.length > 0 && (
                    <ul className="event-warnings">
                      {event.revocation.warnings.map((warning) => (
                        <li key={warning}>{warning}</li>
                      ))}
                    </ul>
                  )}
              </div>
            </li>
          ))}
        </ol>
      )}
      <CorrelationHints request={detail.request} />
    </section>
  )
}

function HistoryRequestId({ requestId }: { requestId: string }) {
  return (
    <span className="request-id">
      <span className="mono wrap-anywhere">{requestId}</span>
      <CopyButton value={requestId} />
    </span>
  )
}

function DesktopHistoryRow({
  request,
  now,
}: {
  request: RequestRecord
  now: number
}) {
  const [expanded, setExpanded] = useState(false)
  const regionId = useId()
  const active =
    !request.revoked_at &&
    request.binding_state === 'enabled' &&
    now < Date.parse(request.expires_at)

  return (
    <Fragment>
      <tr>
        <td>
          <HistoryRequestId requestId={request.request_id} />
          <span className="cell-title wrap-anywhere">{request.repo}</span>
          <span className="meta">
            <span className="mono">{shortCommit(request.commit_sha)}</span> ·{' '}
            {request.operation} · {request.environment}
          </span>
        </td>
        <td>
          <div className="status-stack">
            <StatusBadge value={request.decision} />
            <StatusBadge value={request.approval_state} />
            <span
              className={`status ${active ? 'status-positive' : 'status-muted'}`}
            >
              <span className="status-marker" aria-hidden="true" />
              {active ? 'Active' : 'Inactive / expired'}
            </span>
          </div>
        </td>
        <td>
          <span className="cell-title">{request.on_behalf_of}</span>
          <span className="meta">Ticket: {request.ticket_id || 'None'}</span>
          <span className="meta mono wrap-anywhere">
            {request.spiffe_id}
          </span>
          <span className="meta mono wrap-anywhere">
            Role: {request.requested_vault_role}
          </span>
        </td>
        <td>
          <span className="cell-title">{request.decision_reason}</span>
          <span className="meta mono hash wrap-anywhere">
            {request.policy_version}
          </span>
        </td>
        <td>
          <time dateTime={request.decision_decided_at}>
            {formatAbsoluteTime(request.decision_decided_at)}
          </time>
          <span className="meta">
            Requested {formatAbsoluteTime(request.created_at)}
          </span>
          <span className="meta">
            Expires {formatAbsoluteTime(request.expires_at)}
          </span>
        </td>
        <td className="action-cell">
          <button
            className="button button-small"
            type="button"
            aria-expanded={expanded}
            aria-controls={regionId}
            onClick={() => setExpanded((value) => !value)}
          >
            {expanded ? 'Hide timeline' : 'View timeline'}
          </button>
        </td>
      </tr>
      {expanded && (
        <tr className="expanded-row">
          <td colSpan={6}>
            <div id={regionId}>
              <Timeline requestId={request.request_id} />
            </div>
          </td>
        </tr>
      )}
    </Fragment>
  )
}

function DesktopHistory({
  requests,
  now,
}: {
  requests: RequestRecord[]
  now: number
}) {
  return (
    <div className="table-frame">
      <table>
        <caption className="sr-only">
          Immutable AgentGate decision history
        </caption>
        <thead>
          <tr>
            <th scope="col">Request and scope</th>
            <th scope="col">Lifecycle</th>
            <th scope="col">Identity</th>
            <th scope="col">Policy result</th>
            <th scope="col">Time</th>
            <th scope="col">
              <span className="sr-only">Timeline</span>
            </th>
          </tr>
        </thead>
        <tbody>
          {requests.map((request) => (
            <DesktopHistoryRow
              request={request}
              now={now}
              key={request.request_id}
            />
          ))}
        </tbody>
      </table>
    </div>
  )
}

function MobileHistoryEntry({
  request,
}: {
  request: RequestRecord
}) {
  const [expanded, setExpanded] = useState(false)
  const regionId = useId()

  return (
    <li className="request-card">
      <div className="card-header">
        <div className="status-stack">
          <StatusBadge value={request.decision} />
          <StatusBadge value={request.approval_state} />
        </div>
        <time dateTime={request.created_at}>
          {formatAbsoluteTime(request.created_at)}
        </time>
      </div>
      <HistoryRequestId requestId={request.request_id} />
      <ScopeSummary request={request} />
      <dl className="compact-details">
        <div>
          <dt>Decision reason</dt>
          <dd>{request.decision_reason}</dd>
        </div>
        <div>
          <dt>Policy version</dt>
          <dd className="mono wrap-anywhere">{request.policy_version}</dd>
        </div>
        <div>
          <dt>Expires</dt>
          <dd>{formatAbsoluteTime(request.expires_at)}</dd>
        </div>
      </dl>
      <button
        className="button"
        type="button"
        aria-expanded={expanded}
        aria-controls={regionId}
        onClick={() => setExpanded((value) => !value)}
      >
        {expanded ? 'Hide timeline' : 'View timeline'}
      </button>
      {expanded && (
        <div id={regionId}>
          <Timeline requestId={request.request_id} />
        </div>
      )}
    </li>
  )
}

function MobileHistory({ requests }: { requests: RequestRecord[] }) {
  return (
    <ul className="card-list" aria-label="Immutable AgentGate decision history">
      {requests.map((request) => (
        <MobileHistoryEntry request={request} key={request.request_id} />
      ))}
    </ul>
  )
}

export function DecisionHistoryView() {
  const [offset, setOffset] = useState(0)
  const [filters, setFilters] = useState<HistoryFilters>(emptyFilters)
  const requestFilters = useMemo(
    () => ({
      decision: filters.decision || undefined,
      approval: filters.approval || undefined,
      active:
        filters.active === '' ? undefined : filters.active === 'true',
      spiffeId: filters.spiffeId.trim() || undefined,
      onBehalfOf: filters.onBehalfOf.trim() || undefined,
      createdAfter: toIso(filters.createdAfter),
      createdBefore: toIso(filters.createdBefore),
      environment: filters.environment.trim() || undefined,
      operation: filters.operation || undefined,
      repo: filters.repo.trim() || undefined,
      limit: PAGE_SIZE,
      offset,
    }),
    [filters, offset],
  )
  const query = useRequestList(requestFilters)
  const mobile = useMediaQuery('(max-width: 760px)')
  const now = useServerNow(query.data?.serverOffsetMs ?? 0)

  function applyFilters(next: HistoryFilters) {
    setFilters(next)
    setOffset(0)
  }

  return (
    <section>
      <ViewHeader
        eyebrow="Immutable correlation records"
        title="Decision history"
        detail="Inspect policy outcomes, approval and binding events, and the identifiers needed to correlate existing Vault audit and CloudTrail records."
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
      <HistoryFiltersForm filters={filters} onApply={applyFilters} />
      {query.isPending && <LoadingState label="Loading decision history..." />}
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
              title="No matching decisions"
              detail="No request records match the applied server-side filters."
            />
          ) : mobile ? (
            <MobileHistory requests={query.data.value.requests} />
          ) : (
            <DesktopHistory
              requests={query.data.value.requests}
              now={now}
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
    </section>
  )
}
