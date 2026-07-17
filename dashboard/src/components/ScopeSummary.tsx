import type { RequestRecord } from '../api/schema'
import { formatTtl, shortCommit } from '../lib/format'

export function ScopeSummary({ request }: { request: RequestRecord }) {
  return (
    <dl className="scope-summary">
      <div>
        <dt>Request</dt>
        <dd className="mono wrap-anywhere">{request.request_id}</dd>
      </div>
      <div>
        <dt>Repository / commit</dt>
        <dd>
          <span className="wrap-anywhere">{request.repo}</span>{' '}
          <span className="mono">{shortCommit(request.commit_sha)}</span>
        </dd>
      </div>
      <div>
        <dt>Operation / environment</dt>
        <dd>
          {request.operation} / {request.environment}
        </dd>
      </div>
      <div>
        <dt>Vault role</dt>
        <dd className="mono wrap-anywhere">
          {request.requested_vault_role}
        </dd>
      </div>
      <div>
        <dt>Workload</dt>
        <dd className="mono wrap-anywhere">{request.spiffe_id}</dd>
      </div>
      <div>
        <dt>Human / ticket</dt>
        <dd>
          {request.on_behalf_of} / {request.ticket_id || 'No ticket'}
        </dd>
      </div>
      <div>
        <dt>Requested / effective TTL</dt>
        <dd>
          {formatTtl(request.requested_ttl_seconds)} /{' '}
          {formatTtl(request.effective_ttl_seconds)}
        </dd>
      </div>
    </dl>
  )
}
