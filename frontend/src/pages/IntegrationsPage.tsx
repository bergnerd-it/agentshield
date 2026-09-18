import { useState } from 'react';
import {
  previewIntegration,
  testIntegration,
  useConfigureIntegrationMutation,
  useIntegrations,
  useRollbackIntegrationMutation,
} from '../api/client.ts';
import type { ConfigDiff, IntegrationStatus } from '../api/types.ts';
import { DiffViewer } from '../components/DiffViewer.tsx';

export function IntegrationsPage() {
  const { data: integrations, isLoading, isError, refetch } = useIntegrations();
  const configureMutation = useConfigureIntegrationMutation();
  const rollbackMutation = useRollbackIntegrationMutation();

  const [activePreview, setActivePreview] = useState<ConfigDiff | null>(null);
  const [previewLoading, setPreviewLoading] = useState<boolean>(false);
  const [testResults, setTestResults] = useState<
    Record<string, { status: string; latency_ms?: number; error?: string }>
  >({});
  const [testingAgent, setTestingAgent] = useState<string | null>(null);
  const [actionMessage, setActionMessage] = useState<{
    type: 'success' | 'error';
    text: string;
  } | null>(null);

  const handlePreview = async (agent: string) => {
    setPreviewLoading(true);
    setActionMessage(null);
    try {
      const diff = await previewIntegration(agent);
      setActivePreview(diff);
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : 'Failed to fetch diff preview';
      setActionMessage({ type: 'error', text: msg });
    } finally {
      setPreviewLoading(false);
    }
  };

  const handleConfigure = async (agent: string) => {
    setActionMessage(null);
    try {
      await configureMutation.mutateAsync(agent);
      setActivePreview(null);
      setActionMessage({
        type: 'success',
        text: `Successfully configured ${agent} integration and backed up prior config.`,
      });
      void refetch();
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : 'Configuration failed';
      setActionMessage({ type: 'error', text: msg });
    }
  };

  const handleRollback = async (agent: string) => {
    setActionMessage(null);
    try {
      await rollbackMutation.mutateAsync(agent);
      setActionMessage({
        type: 'success',
        text: `Successfully restored ${agent} configuration from the latest backup.`,
      });
      void refetch();
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : 'Rollback failed';
      setActionMessage({ type: 'error', text: msg });
    }
  };

  const handleTest = async (agent: string) => {
    setTestingAgent(agent);
    try {
      const res = await testIntegration(agent);
      setTestResults((prev) => ({ ...prev, [agent]: res }));
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : 'Test failed';
      setTestResults((prev) => ({
        ...prev,
        [agent]: { status: 'error', error: msg },
      }));
    } finally {
      setTestingAgent(null);
    }
  };

  return (
    <div
      className="page-content"
      id="tabpanel-integrations"
      role="tabpanel"
      aria-labelledby="tab-integrations"
    >
      {/* Cooperative Reverse Proxy Security Notice */}
      <div
        className="card"
        style={{
          borderLeft: '4px solid var(--color-yellow)',
          background: 'rgba(245, 158, 11, 0.08)',
          marginBottom: '1.5rem',
          padding: '1rem 1.25rem',
        }}
        role="region"
        aria-label="Cooperative Proxy Security Boundary Notice"
      >
        <div style={{ display: 'flex', gap: '0.75rem', alignItems: 'flex-start' }}>
          <span style={{ fontSize: '1.5rem', lineHeight: 1 }}>⚠️</span>
          <div>
            <strong style={{ color: 'var(--color-yellow)', fontSize: '0.95rem' }}>
              Cooperative Reverse Proxy Security Notice
            </strong>
            <p style={{ fontSize: '0.85rem', color: 'var(--text-primary)', marginTop: '0.25rem' }}>
              AgentShield Version 1 is a <strong>cooperative reverse proxy</strong>. It inspects only traffic explicitly routed through its loopback endpoints (e.g. <code>127.0.0.1:8765/proxy/...</code>). Direct network requests made outside the configured proxy endpoints are not intercepted or blocked.
            </p>
          </div>
        </div>
      </div>

      <div className="page-header-row">
        <div className="page-header">
          <h2>Coding Agent Integrations</h2>
          <p className="page-subtitle">
            Configure local CLI coding agents to route traffic through AgentShield with unified diff preview, atomic backups, and 1-click rollback.
          </p>
        </div>

        <button
          type="button"
          className="status-retry-button"
          onClick={() => void refetch()}
          aria-label="Refresh integration statuses"
        >
          ↻ Refresh
        </button>
      </div>

      {actionMessage && (
        <div
          className="card"
          style={{
            borderColor:
              actionMessage.type === 'success' ? 'var(--color-green)' : 'var(--color-red)',
            marginBottom: '1rem',
          }}
          role="alert"
        >
          <p
            style={{
              color:
                actionMessage.type === 'success' ? 'var(--color-green)' : 'var(--color-red)',
            }}
          >
            {actionMessage.type === 'success' ? '✓ ' : '✗ '}
            {actionMessage.text}
          </p>
        </div>
      )}

      {isLoading && (
        <div className="card empty-state">
          <p>Detecting coding agent configurations…</p>
        </div>
      )}

      {isError && (
        <div className="card empty-state" style={{ borderColor: 'var(--color-red)' }}>
          <p style={{ color: 'var(--color-red)' }}>
            Failed to query integrations. Ensure backend is running.
          </p>
        </div>
      )}

      {!isLoading && !isError && integrations && (
        <div
          style={{
            display: 'grid',
            gridTemplateColumns: 'repeat(auto-fit, minmax(360px, 1fr))',
            gap: '1.25rem',
          }}
        >
          {integrations.map((item: IntegrationStatus) => {
            const isConfigured = item.configured;
            const testResult = testResults[item.agent_type];

            return (
              <div
                key={item.agent_type}
                className="card"
                style={{
                  display: 'flex',
                  flexDirection: 'column',
                  justifyContent: 'space-between',
                }}
              >
                <div>
                  <div
                    style={{
                      display: 'flex',
                      justifyContent: 'space-between',
                      alignItems: 'center',
                      marginBottom: '1rem',
                    }}
                  >
                    <div>
                      <h3 style={{ fontSize: '1.15rem', color: 'var(--text-primary)' }}>
                        {item.agent_type === 'codex' ? 'OpenAI Codex CLI' : 'Anthropic Claude Code'}
                      </h3>
                      <span className="code-tag" style={{ fontSize: '0.75rem' }}>
                        {item.agent_type}
                      </span>
                    </div>

                    <span
                      className={`badge ${
                        isConfigured ? 'badge-allow' : 'badge-warn'
                      }`}
                    >
                      {isConfigured ? 'Routed to Proxy' : 'Not Configured'}
                    </span>
                  </div>

                  <div
                    style={{
                      display: 'flex',
                      flexDirection: 'column',
                      gap: '0.6rem',
                      fontSize: '0.85rem',
                      marginBottom: '1rem',
                    }}
                  >
                    <div>
                      <span style={{ color: 'var(--text-muted)' }}>Config Path:</span>{' '}
                      <code style={{ fontSize: '0.8rem' }}>{item.config_path}</code>
                    </div>
                    <div>
                      <span style={{ color: 'var(--text-muted)' }}>Proxy URL:</span>{' '}
                      <code style={{ fontSize: '0.8rem' }}>{item.proxy_url}</code>
                    </div>
                    <div>
                      <span style={{ color: 'var(--text-muted)' }}>Dedicated Token:</span>{' '}
                      <span style={{ color: item.has_token ? 'var(--color-green)' : 'var(--text-muted)' }}>
                        {item.has_token ? 'Configured (attributed)' : 'Not set'}
                      </span>
                    </div>
                    {item.last_backup_path && (
                      <div>
                        <span style={{ color: 'var(--text-muted)' }}>Latest Backup:</span>{' '}
                        <code style={{ fontSize: '0.75rem' }}>{item.last_backup_path}</code>
                      </div>
                    )}
                  </div>

                  {/* Test Connectivity Result */}
                  {testResult && (
                    <div
                      style={{
                        padding: '0.5rem 0.75rem',
                        borderRadius: '4px',
                        background:
                          testResult.status === 'ok'
                            ? 'rgba(16, 185, 129, 0.1)'
                            : 'rgba(239, 68, 68, 0.1)',
                        border: `1px solid ${
                          testResult.status === 'ok' ? 'var(--color-green)' : 'var(--color-red)'
                        }`,
                        fontSize: '0.8rem',
                        marginBottom: '1rem',
                      }}
                    >
                      {testResult.status === 'ok' ? (
                        <span style={{ color: 'var(--color-green)' }}>
                          ✓ Local proxy reachability OK ({testResult.latency_ms} ms)
                        </span>
                      ) : (
                        <span style={{ color: 'var(--color-red)' }}>
                          ✗ Connectivity test failed: {testResult.error ?? 'Unknown error'}
                        </span>
                      )}
                    </div>
                  )}
                </div>

                {/* Action Buttons */}
                <div
                  style={{
                    display: 'flex',
                    flexWrap: 'wrap',
                    gap: '0.5rem',
                    paddingTop: '0.75rem',
                    borderTop: '1px solid var(--border-color)',
                  }}
                >
                  <button
                    type="button"
                    className="status-retry-button"
                    disabled={previewLoading}
                    onClick={() => void handlePreview(item.agent_type)}
                    aria-label={`Preview changes for ${item.agent_type}`}
                  >
                    🔍 Preview Diff
                  </button>
                  <button
                    type="button"
                    className="status-retry-button"
                    disabled={configureMutation.isPending}
                    onClick={() => void handleConfigure(item.agent_type)}
                    aria-label={`Apply configuration for ${item.agent_type}`}
                  >
                    {configureMutation.isPending ? 'Applying…' : '⚡ Apply Config'}
                  </button>
                  <button
                    type="button"
                    className="status-retry-button"
                    disabled={testingAgent === item.agent_type}
                    onClick={() => void handleTest(item.agent_type)}
                    aria-label={`Test connection for ${item.agent_type}`}
                  >
                    {testingAgent === item.agent_type ? 'Testing…' : '📡 Test Connection'}
                  </button>
                  <button
                    type="button"
                    className="status-retry-button"
                    disabled={!item.last_backup_path || rollbackMutation.isPending}
                    onClick={() => void handleRollback(item.agent_type)}
                    aria-label={`Rollback configuration for ${item.agent_type}`}
                    title={!item.last_backup_path ? 'No backup file available' : 'Restore last backup'}
                  >
                    ↩ Rollback
                  </button>
                </div>
              </div>
            );
          })}
        </div>
      )}

      {/* Unified Diff Preview Modal */}
      {activePreview && (
        <div
          className="modal-backdrop"
          onClick={() => setActivePreview(null)}
          role="dialog"
          aria-modal="true"
          aria-labelledby="diff-preview-title"
        >
          <div
            className="modal-container"
            onClick={(e) => e.stopPropagation()}
            style={{ maxWidth: '800px' }}
          >
            <div className="modal-header">
              <div>
                <h3 id="diff-preview-title">Configuration Diff Preview</h3>
                <span className="modal-id">
                  {activePreview.agent_type} • {activePreview.config_path}
                </span>
              </div>
              <button
                type="button"
                className="modal-close-button"
                onClick={() => setActivePreview(null)}
                aria-label="Close diff preview"
              >
                ✕
              </button>
            </div>

            <div className="modal-body">
              {!activePreview.has_changes ? (
                <div className="card empty-state">
                  <p>Configuration is already up to date with AgentShield settings. No changes required.</p>
                </div>
              ) : (
                <DiffViewer
                  originalText={activePreview.original_content}
                  modifiedText={activePreview.modified_content}
                  title={`Proposed Changes for ${activePreview.agent_type}`}
                  originalLabel="Current Configuration"
                  redactedLabel="AgentShield Routed Configuration"
                />
              )}
            </div>

            <div
              className="modal-decision-footer"
              style={{ display: 'flex', justifyContent: 'flex-end', gap: '0.75rem' }}
            >
              <button
                type="button"
                className="status-retry-button"
                onClick={() => setActivePreview(null)}
              >
                Cancel
              </button>
              {activePreview.has_changes && (
                <button
                  type="button"
                  className="status-retry-button"
                  style={{
                    backgroundColor: 'var(--color-primary)',
                    color: '#000',
                    fontWeight: 600,
                  }}
                  onClick={() => void handleConfigure(activePreview.agent_type)}
                >
                  Confirm and Apply Changes
                </button>
              )}
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
