import { useState, useEffect } from 'react';
import type { SystemStatus } from '../api/types.ts';
import { useSettings, useUpdateSettingsMutation } from '../api/client.ts';

interface Props {
  status: SystemStatus | undefined;
}

export function SettingsPage({ status }: Props) {
  const { data: settings, isLoading, isError } = useSettings();
  const updateMutation = useUpdateSettingsMutation();

  const [profile, setProfile] = useState<string>('balanced');
  const [approvalTimeout, setApprovalTimeout] = useState<number>(60);
  const [pseudonymTtl, setPseudonymTtl] = useState<number>(3600);
  const [successMsg, setSuccessMsg] = useState<string | null>(null);

  useEffect(() => {
    if (settings) {
      setProfile(settings.profile);
      setApprovalTimeout(settings.approval_timeout_seconds);
      setPseudonymTtl(settings.pseudonym_ttl_seconds);
    }
  }, [settings]);

  const handleSave = (e: React.FormEvent) => {
    e.preventDefault();
    setSuccessMsg(null);
    updateMutation.mutate(
      {
        profile,
        approval_timeout_seconds: Number(approvalTimeout),
        pseudonym_ttl_seconds: Number(pseudonymTtl),
      },
      {
        onSuccess: () => {
          setSuccessMsg('Settings updated successfully.');
          setTimeout(() => setSuccessMsg(null), 4000);
        },
      }
    );
  };

  return (
    <div
      className="page-content"
      id="tabpanel-settings"
      role="tabpanel"
      aria-labelledby="tab-settings"
    >
      <div className="page-header">
        <h2>System Settings &amp; Limits</h2>
        <p className="page-subtitle">
          Configuration parameters, loopback network bindings, and explicit protection limits.
        </p>
      </div>

      {/* Upstream Provider Presence */}
      <div className="card settings-card">
        <h3>Upstream Provider Key Presence</h3>
        <p className="page-subtitle">
          Zero raw secret storage: AgentShield checks for presence in native secure storage or memory without displaying keys.
        </p>

        <div className="providers-grid">
          <div className="provider-status-card">
            <div className="provider-status-header">
              <span className="provider-name">OpenAI</span>
              <span
                className={`status-pill ${
                  settings?.openai_configured ? 'dot-green-pill' : 'dot-yellow-pill'
                }`}
              >
                {settings?.openai_configured ? 'KEY CONFIGURED' : 'NOT CONFIGURED'}
              </span>
            </div>
            <span className="card-hint">
              Target: <code>https://api.openai.com/v1</code>
            </span>
          </div>

          <div className="provider-status-card">
            <div className="provider-status-header">
              <span className="provider-name">Anthropic</span>
              <span
                className={`status-pill ${
                  settings?.anthropic_configured ? 'dot-green-pill' : 'dot-yellow-pill'
                }`}
              >
                {settings?.anthropic_configured ? 'KEY CONFIGURED' : 'NOT CONFIGURED'}
              </span>
            </div>
            <span className="card-hint">
              Target: <code>https://api.anthropic.com/v1</code>
            </span>
          </div>
        </div>
      </div>

      {/* Runtime Configuration Overrides */}
      <div className="card settings-card">
        <h3>Runtime Policy &amp; Hold Settings</h3>
        <form onSubmit={handleSave} className="settings-form">
          <div className="form-group">
            <label htmlFor="setting-profile" className="form-label">
              Active Security Profile
            </label>
            <select
              id="setting-profile"
              className="input-field"
              value={profile}
              onChange={(e) => setProfile(e.target.value)}
            >
              <option value="audit">Audit (Warn only, passes traffic)</option>
              <option value="balanced">Balanced (Blocks secrets, redacts PII)</option>
              <option value="strict">Strict (Blocks all non-conforming content)</option>
            </select>
            <span className="form-hint">
              Controls default actions when no overriding rules match.
            </span>
          </div>

          <div className="form-group">
            <label htmlFor="setting-approval-timeout" className="form-label">
              Manual Approval Hold Timeout (Seconds)
            </label>
            <input
              id="setting-approval-timeout"
              type="number"
              className="input-field"
              min={5}
              max={3600}
              value={approvalTimeout}
              onChange={(e) => setApprovalTimeout(Number(e.target.value))}
            />
            <span className="form-hint">
              Requests held for operator approval will expire and fail-closed after this duration.
            </span>
          </div>

          <div className="form-group">
            <label htmlFor="setting-pseudonym-ttl" className="form-label">
              Pseudonym Vault TTL (Seconds)
            </label>
            <input
              id="setting-pseudonym-ttl"
              type="number"
              className="input-field"
              min={60}
              max={86400}
              value={pseudonymTtl}
              onChange={(e) => setPseudonymTtl(Number(e.target.value))}
            />
            <span className="form-hint">
              Duration that reversible pseudonym mappings are kept in memory for rehydration.
            </span>
          </div>

          {successMsg && <div className="form-success">{successMsg}</div>}
          {updateMutation.isError && (
            <div className="form-error">
              Failed to update settings: {updateMutation.error.message}
            </div>
          )}

          <div className="form-actions">
            <button
              type="submit"
              className="button-primary"
              disabled={updateMutation.isPending || isLoading || isError}
            >
              {updateMutation.isPending ? 'Saving Overrides…' : 'Save Runtime Settings'}
            </button>
          </div>
        </form>
      </div>

      {/* Local Runtime Configuration */}
      <div className="card settings-card">
        <h3>Local Network &amp; Storage Boundaries</h3>
        <div className="settings-row">
          <span className="setting-name">Bound Interface</span>
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
          <span className="setting-name">Max Request Body</span>
          <span className="setting-val">
            {settings ? `${(settings.proxy_max_body_bytes / (1024 * 1024)).toFixed(0)} MB` : '10 MB'}
          </span>
        </div>
      </div>

      {/* Explicit Protection Limits */}
      <div className="card settings-card protection-limits-card">
        <h3>Explicit Protection Boundaries</h3>
        <p className="page-subtitle">
          AgentShield V1 enforces local security boundaries without making claims it cannot enforce:
        </p>

        <ul className="limits-list">
          {settings?.protection_limits ? (
            settings.protection_limits.map((limit, idx) => (
              <li key={idx} className="limit-item">
                <span className="limit-icon">🛡️</span>
                <span>{limit}</span>
              </li>
            ))
          ) : (
            <li className="limit-item">
              <span className="limit-icon">🛡️</span>
              <span>AgentShield Version 1 mediates only traffic explicitly routed through its proxy port.</span>
            </li>
          )}
        </ul>
      </div>
    </div>
  );
}
