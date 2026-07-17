import type { RevocationReport } from '../api/schema'

function reportValue(value: boolean): string {
  return value ? 'Yes' : 'No'
}

export function RevocationReportPanel({
  report,
}: {
  report: RevocationReport
}) {
  return (
    <section className="report-panel" aria-labelledby="revoke-report-title">
      <h3 id="revoke-report-title">Latest revocation report</h3>
      <dl>
        <div>
          <dt>Role removed</dt>
          <dd>{reportValue(report.role_removed)}</dd>
        </div>
        <div>
          <dt>Policy removed</dt>
          <dd>{reportValue(report.policy_removed)}</dd>
        </div>
        <div>
          <dt>Vault leases revoked</dt>
          <dd>{reportValue(report.leases_revoked)}</dd>
        </div>
        <div>
          <dt>Issued AWS STS credentials may remain</dt>
          <dd>{reportValue(report.sts_credentials_may_remain)}</dd>
        </div>
      </dl>
      {report.sts_credentials_may_remain && (
        <p className="callout callout-warning">
          Already issued AWS STS credentials may remain usable until their TTL
          expires.
        </p>
      )}
      {report.warnings.length > 0 && (
        <div>
          <h4>Warnings</h4>
          <ul>
            {report.warnings.map((warning) => (
              <li key={warning}>{warning}</li>
            ))}
          </ul>
        </div>
      )}
    </section>
  )
}
