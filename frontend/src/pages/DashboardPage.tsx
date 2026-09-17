import type { SystemStatus } from '../api/types.ts';
import { useApprovals, useAuditEvents } from '../api/client.ts';

interface Props {
  status: SystemStatus | undefined;
}

export function DashboardPage({ status }: Props) {
  const { data: pendingApprovals } = useApprovals('pending');
  const { data: totalEvents } = useAuditEvents({ limit: 5 });
  const { data: blockedEvents } = useAuditEvents({ action: 'BLOCK', limit: 1 });
  const { data: redactedEvents } = useAuditEvents({ action: 'REDACT', limit: 1 });
  const { data: approvedEvents } = useAuditEvents({ action: 'REQUIRE_APPROVAL', limit: 1 });

  const pendingCount = Array.isArray(pendingApprovals) ? pendingApprovals.length : 0;
  const totalCount = totalEvents?.total ?? 0;
  const blockedCount = blockedEvents?.total ?? 0;
  const redactedCount = redactedEvents?.total ?? 0;
  const reqApprovalCount = approvedEvents?.total ?? 0;

  return (
    <div
      className="page-content"
      id="tabpanel-dashboard"
      role="tabpanel"
      aria-labelledby="tab-dashboard"
    >
      <div className="page-header">
        <h2>Security Dashboard</h2>
        <p className="page-subtitle">
          Real-time proxy enforcement telemetry, policy decisions, and approval metrics.
        </p>
      </div>

      <div className="dashboard-grid">
        <div className="card metric-card">
          <span className="card-label">Active Security Profile</span>
          <span className="metric-value capitalize">{status?.profile || 'Balanced'}</span>
          <span className="card-hint">Precedence: BLOCK &gt; APPROVAL &gt; REDACT</span>
        </div>

        <div className="card metric-card">
          <span className="card-label">Pending Approvals</span>
          <span className={`metric-value ${pendingCount > 0 ? 'color-yellow' : ''}`}>
            {pendingCount}
          </span>
          <span className="card-hint">In-flight holds awaiting operator decision</span>
        </div>

        <div className="card metric-card">
          <span className="card-label">Total Mediated Requests</span>
          <span className="metric-value">{totalCount}</span>
          <span className="card-hint">Audit events recorded locally in SQLite</span>
        </div>

        <div className="card metric-card">
          <span className="card-label">Blocked / Intercepted</span>
          <span className="metric-value color-red">{blockedCount}</span>
          <span className="card-hint">Hard stops (secrets or policy denies)</span>
        </div>
      </div>

      <div className="dashboard-grid">
        <div className="card metric-card">
          <span className="card-label">Redacted Inbound/Outbound</span>
          <span className="metric-value color-primary">{redactedCount}</span>
          <span className="card-hint">PII or terms replaced with pseudonyms</span>
        </div>

        <div className="card metric-card">
          <span className="card-label">Approval Holds Triggered</span>
          <span className="metric-value color-yellow">{reqApprovalCount}</span>
          <span className="card-hint">Sensitive payloads paused before egress</span>
        </div>

        <div className="card metric-card">
          <span className="card-label">Loopback Binding</span>
          <span className="metric-value">
            {status ? `${status.host}:${status.port}` : '127.0.0.1:8765'}
          </span>
          <span className="card-hint">Local interface with Origin checking</span>
        </div>

        <div className="card metric-card">
          <span className="card-label">Cloud Egress Protection</span>
          <span className="metric-value color-green">Enforced</span>
          <span className="card-hint">No external telemetry; local-only</span>
        </div>
      </div>

      <div className="card info-section">
        <h3>Recent Traffic Stream</h3>
        {Array.isArray(totalEvents?.items) && totalEvents.items.length > 0 ? (
          <div className="recent-events-table">
            <div className="event-row event-header-row">
              <span>Time</span>
              <span>Provider</span>
              <span>Endpoint</span>
              <span>Action</span>
              <span>Findings</span>
            </div>
            {totalEvents.items.slice(0, 5).map((evt) => (
              <div key={evt.id} className="event-row">
                <span className="text-muted">
                  {new Date(evt.timestamp).toLocaleTimeString()}
                </span>
                <span className="badge-provider">{evt.provider.toUpperCase()}</span>
                <span className="text-endpoint">{evt.endpoint}</span>
                <span className={`action-pill action-${evt.action.toLowerCase()}`}>
                  {evt.action}
                </span>
                <span className="text-secondary">
                  {Object.values(evt.finding_counts).reduce((a, b) => a + b, 0)} findings
                </span>
              </div>
            ))}
          </div>
        ) : (
          <div className="empty-state">
            <p>No proxy traffic recorded yet. Route coding-agent requests through 127.0.0.1:8765.</p>
          </div>
        )}
      </div>
    </div>
  );
}
