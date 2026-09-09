import type { SystemStatus } from '../api/types.ts';

interface Props {
  status: SystemStatus | undefined;
}

export function DashboardPage({ status }: Props) {
  return (
    <div className="page-content" id="tabpanel-dashboard" role="tabpanel" aria-labelledby="tab-dashboard">
      <div className="page-header">
        <h2>Security Dashboard</h2>
        <p className="page-subtitle">
          Overview of local proxy enforcement, policy status, and traffic metrics.
        </p>
      </div>

      <div className="dashboard-grid">
        <div className="card metric-card">
          <span className="card-label">Active Profile</span>
          <span className="metric-value capitalize">{status?.profile || 'Balanced'}</span>
          <span className="card-hint">Blocking secrets &amp; redacting PII</span>
        </div>

        <div className="card metric-card">
          <span className="card-label">Loopback Binding</span>
          <span className="metric-value">
            {status ? `${status.host}:${status.port}` : '127.0.0.1:8765'}
          </span>
          <span className="card-hint">Host &amp; Origin validation active</span>
        </div>

        <div className="card metric-card">
          <span className="card-label">Persistence Engine</span>
          <span className="metric-value">SQLite WAL</span>
          <span className="card-hint">
            Migration: {status?.database.migration_version || '0001_baseline_schema'}
          </span>
        </div>

        <div className="card metric-card">
          <span className="card-label">Cloud Egress Protection</span>
          <span className="metric-value color-green">Enforced</span>
          <span className="card-hint">Zero third-party telemetry or cloud sync</span>
        </div>
      </div>

      <div className="card info-section">
        <h3>Milestone 1 Foundation Status</h3>
        <ul className="checklist">
          <li>✓ Strict loopback binding on 127.0.0.1 with Host/Origin validation</li>
          <li>✓ Restricted-permission credential and database storage (0600)</li>
          <li>✓ SQLite WAL persistence with baseline Alembic migrations</li>
          <li>✓ Management API health &amp; diagnostic status endpoints</li>
          <li>✓ React 19 SPA served directly from local FastAPI backend</li>
        </ul>
      </div>
    </div>
  );
}
