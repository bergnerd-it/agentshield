import type { SystemStatus } from '../api/types.ts';

interface Props {
  status: SystemStatus | undefined;
}

export function SettingsPage({ status }: Props) {
  return (
    <div className="page-content" id="tabpanel-settings" role="tabpanel" aria-labelledby="tab-settings">
      <div className="page-header">
        <h2>System Settings &amp; Limits</h2>
        <p className="page-subtitle">
          Configuration parameters, loopback network bindings, and protection limits.
        </p>
      </div>

      <div className="card settings-card">
        <h3>Local Runtime Configuration</h3>
        <div className="settings-row">
          <span className="setting-name">Bound Host</span>
          <span className="setting-val">{status?.host || '127.0.0.1'} (Loopback only)</span>
        </div>
        <div className="settings-row">
          <span className="setting-name">Port</span>
          <span className="setting-val">{status?.port || 8765}</span>
        </div>
        <div className="settings-row">
          <span className="setting-name">Operating Platform</span>
          <span className="setting-val">{status?.platform || 'darwin'}</span>
        </div>
        <div className="settings-row">
          <span className="setting-name">Database Engine</span>
          <span className="setting-val">
            SQLite (WAL Mode) - Migration {status?.database.migration_version || '0001_baseline_schema'}
          </span>
        </div>
        <div className="settings-row">
          <span className="setting-name">Frontend Assets</span>
          <span className="setting-val">
            {status?.frontend_available ? 'Compiled & Active' : 'Development Server'}
          </span>
        </div>
      </div>
    </div>
  );
}
