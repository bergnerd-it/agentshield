import { useEffect, useRef, useState } from 'react';
import { exportAudit, useAuditEvent, useAuditEvents } from '../api/client.ts';
import type { AuditExportRequest } from '../api/types.ts';

const PAGE_SIZE = 15;

export function AuditPage() {
  const [actionFilter, setActionFilter] = useState<string>('');
  const [providerFilter, setProviderFilter] = useState<string>('');
  const [agentFilter, setAgentFilter] = useState<string>('');
  const [projectFilter, setProjectFilter] = useState<string>('');
  const [startTime, setStartTime] = useState<string>('');
  const [endTime, setEndTime] = useState<string>('');
  const [offset, setOffset] = useState<number>(0);
  const [selectedEventId, setSelectedEventId] = useState<string | null>(null);
  const [isExporting, setIsExporting] = useState<boolean>(false);
  const [exportError, setExportError] = useState<string | null>(null);
  const modalRef = useRef<HTMLDivElement | null>(null);

  // Escape key handler & focus trap for accessibility (WCAG 2.1 SC 2.1.2)
  useEffect(() => {
    if (!selectedEventId) return;

    const handleKeyDown = (e: KeyboardEvent) => {
      if (e.key === 'Escape') {
        setSelectedEventId(null);
        return;
      }

      if (e.key === 'Tab' && modalRef.current) {
        const focusableElements = modalRef.current.querySelectorAll<HTMLElement>(
          'button, [href], input, select, textarea, [tabindex]:not([tabindex="-1"])'
        );
        if (focusableElements.length === 0) return;

        const firstElement = focusableElements[0];
        const lastElement = focusableElements[focusableElements.length - 1];

        if (e.shiftKey) {
          if (document.activeElement === firstElement) {
            lastElement.focus();
            e.preventDefault();
          }
        } else {
          if (document.activeElement === lastElement) {
            firstElement.focus();
            e.preventDefault();
          }
        }
      }
    };

    window.addEventListener('keydown', handleKeyDown);
    return () => window.removeEventListener('keydown', handleKeyDown);
  }, [selectedEventId]);

  const { data: eventList, isLoading, isError, refetch } = useAuditEvents({
    limit: PAGE_SIZE,
    offset,
    action: actionFilter || undefined,
    provider: providerFilter || undefined,
    agent: agentFilter || undefined,
    project: projectFilter || undefined,
    start_time: startTime ? new Date(startTime).toISOString() : undefined,
    end_time: endTime ? new Date(endTime).toISOString() : undefined,
  });

  const { data: selectedEvent } = useAuditEvent(selectedEventId);

  const total = eventList?.total ?? 0;
  const totalPages = Math.ceil(total / PAGE_SIZE);
  const currentPage = Math.floor(offset / PAGE_SIZE) + 1;

  const handleNextPage = () => {
    if (offset + PAGE_SIZE < total) {
      setOffset(offset + PAGE_SIZE);
    }
  };

  const handlePrevPage = () => {
    if (offset - PAGE_SIZE >= 0) {
      setOffset(offset - PAGE_SIZE);
    }
  };

  const handleExport = async (format: 'json' | 'html') => {
    setIsExporting(true);
    setExportError(null);
    try {
      const payload: AuditExportRequest = {
        format,
        action: actionFilter || null,
        provider: providerFilter || null,
        agent: agentFilter || null,
        project: projectFilter || null,
        start_time: startTime ? new Date(startTime).toISOString() : null,
        end_time: endTime ? new Date(endTime).toISOString() : null,
        limit: 1000,
      };

      const blob = await exportAudit(payload);
      const url = window.URL.createObjectURL(blob);
      const link = document.createElement('a');
      link.href = url;
      const timestamp = new Date().toISOString().replace(/[:.]/g, '-');
      link.download = `agentshield_audit_export_${timestamp}.${format}`;
      document.body.appendChild(link);
      link.click();
      document.body.removeChild(link);
      window.URL.revokeObjectURL(url);
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : 'Export failed';
      setExportError(msg);
    } finally {
      setIsExporting(false);
    }
  };

  return (
    <div
      className="page-content"
      id="tabpanel-audit"
      role="tabpanel"
      aria-labelledby="tab-audit"
    >
      <div className="page-header-row">
        <div className="page-header">
          <h2>Privacy-Preserving Audit Log</h2>
          <p className="page-subtitle">
            Historical audit records, policy evaluations, and sanitized compliance export.
          </p>
        </div>

        <div className="traffic-filters" style={{ display: 'flex', gap: '0.5rem', flexWrap: 'wrap' }}>
          <button
            type="button"
            className="status-retry-button"
            disabled={isExporting}
            onClick={() => void handleExport('json')}
            aria-label="Export audit records as JSON"
          >
            {isExporting ? 'Exporting…' : '📥 Export JSON'}
          </button>
          <button
            type="button"
            className="status-retry-button"
            disabled={isExporting}
            onClick={() => void handleExport('html')}
            aria-label="Export audit records as standalone HTML"
          >
            {isExporting ? 'Exporting…' : '📄 Export HTML'}
          </button>
          <button
            type="button"
            className="status-retry-button"
            onClick={() => void refetch()}
            aria-label="Refresh audit events"
          >
            ↻ Refresh
          </button>
        </div>
      </div>

      {exportError && (
        <div className="card" style={{ borderColor: 'var(--color-red)', marginBottom: '1rem' }} role="alert">
          <p style={{ color: 'var(--color-red)' }}>Export error: {exportError}</p>
        </div>
      )}

      {/* Filter Toolbar */}
      <div
        className="card"
        style={{
          display: 'grid',
          gridTemplateColumns: 'repeat(auto-fit, minmax(180px, 1fr))',
          gap: '0.75rem',
          marginBottom: '1rem',
          padding: '0.75rem 1rem',
        }}
      >
        <div>
          <label htmlFor="audit-action-filter" style={{ display: 'block', fontSize: '0.75rem', color: 'var(--text-muted)', marginBottom: '0.25rem' }}>
            Policy Action
          </label>
          <select
            id="audit-action-filter"
            className="filter-select"
            style={{ width: '100%' }}
            value={actionFilter}
            onChange={(e) => {
              setActionFilter(e.target.value);
              setOffset(0);
            }}
            aria-label="Filter by Policy Action"
          >
            <option value="">All Actions</option>
            <option value="ALLOW">ALLOW</option>
            <option value="WARN">WARN</option>
            <option value="REDACT">REDACT</option>
            <option value="REQUIRE_APPROVAL">REQUIRE_APPROVAL</option>
            <option value="BLOCK">BLOCK</option>
          </select>
        </div>

        <div>
          <label htmlFor="audit-provider-filter" style={{ display: 'block', fontSize: '0.75rem', color: 'var(--text-muted)', marginBottom: '0.25rem' }}>
            Provider
          </label>
          <select
            id="audit-provider-filter"
            className="filter-select"
            style={{ width: '100%' }}
            value={providerFilter}
            onChange={(e) => {
              setProviderFilter(e.target.value);
              setOffset(0);
            }}
            aria-label="Filter by Provider"
          >
            <option value="">All Providers</option>
            <option value="openai">OpenAI</option>
            <option value="anthropic">Anthropic</option>
          </select>
        </div>

        <div>
          <label htmlFor="audit-agent-filter" style={{ display: 'block', fontSize: '0.75rem', color: 'var(--text-muted)', marginBottom: '0.25rem' }}>
            Agent Attribution
          </label>
          <select
            id="audit-agent-filter"
            className="filter-select"
            style={{ width: '100%' }}
            value={agentFilter}
            onChange={(e) => {
              setAgentFilter(e.target.value);
              setOffset(0);
            }}
            aria-label="Filter by Agent"
          >
            <option value="">All Agents</option>
            <option value="codex">Codex</option>
            <option value="claude-code">Claude Code</option>
          </select>
        </div>

        <div>
          <label htmlFor="audit-project-filter" style={{ display: 'block', fontSize: '0.75rem', color: 'var(--text-muted)', marginBottom: '0.25rem' }}>
            Project
          </label>
          <input
            id="audit-project-filter"
            type="text"
            className="filter-select"
            style={{ width: '100%' }}
            placeholder="Filter by project..."
            value={projectFilter}
            onChange={(e) => {
              setProjectFilter(e.target.value);
              setOffset(0);
            }}
            aria-label="Filter by Project"
          />
        </div>

        <div>
          <label htmlFor="audit-start-date" style={{ display: 'block', fontSize: '0.75rem', color: 'var(--text-muted)', marginBottom: '0.25rem' }}>
            From Date (local time)
          </label>
          <input
            id="audit-start-date"
            type="datetime-local"
            className="filter-select"
            style={{ width: '100%' }}
            value={startTime}
            onChange={(e) => {
              setStartTime(e.target.value);
              setOffset(0);
            }}
            aria-label="Filter by Start Date"
          />
        </div>

        <div>
          <label htmlFor="audit-end-date" style={{ display: 'block', fontSize: '0.75rem', color: 'var(--text-muted)', marginBottom: '0.25rem' }}>
            To Date (local time)
          </label>
          <input
            id="audit-end-date"
            type="datetime-local"
            className="filter-select"
            style={{ width: '100%' }}
            value={endTime}
            onChange={(e) => {
              setEndTime(e.target.value);
              setOffset(0);
            }}
            aria-label="Filter by End Date"
          />
        </div>
      </div>

      {isLoading && (
        <div className="card empty-state">
          <p>Loading audit records…</p>
        </div>
      )}

      {isError && (
        <div className="card empty-state" style={{ borderColor: 'var(--color-red)' }}>
          <p style={{ color: 'var(--color-red)' }}>
            Failed to load audit records. Ensure backend is reachable.
          </p>
        </div>
      )}

      {!isLoading && !isError && eventList && (
        <div className="card">
          <div className="table-responsive">
            <table className="traffic-table" aria-label="Audit Events">
              <thead>
                <tr>
                  <th scope="col">Timestamp</th>
                  <th scope="col">Action</th>
                  <th scope="col">Provider</th>
                  <th scope="col">Agent</th>
                  <th scope="col">Project</th>
                  <th scope="col">Findings</th>
                  <th scope="col">Details</th>
                </tr>
              </thead>
              <tbody>
                {eventList.items.length === 0 ? (
                  <tr>
                    <td colSpan={7} className="empty-cell">
                      No audit events match the specified filters.
                    </td>
                  </tr>
                ) : (
                  eventList.items.map((evt) => {
                    const actionClass =
                      evt.action === 'ALLOW'
                        ? 'badge-allow'
                        : evt.action === 'WARN'
                        ? 'badge-warn'
                        : evt.action === 'REDACT'
                        ? 'badge-redact'
                        : evt.action === 'REQUIRE_APPROVAL'
                        ? 'badge-approval'
                        : 'badge-block';

                    const findingsCount = Object.values(evt.finding_counts ?? {}).reduce(
                      (acc, v) => acc + v,
                      0
                    );

                    return (
                      <tr
                        key={evt.id}
                        onClick={() => setSelectedEventId(evt.id)}
                        onKeyDown={(e) => {
                          if (e.key === 'Enter' || e.key === ' ') {
                            e.preventDefault();
                            setSelectedEventId(evt.id);
                          }
                        }}
                        tabIndex={0}
                        role="button"
                        style={{ cursor: 'pointer' }}
                        aria-label={`Inspect audit record at ${new Date(evt.timestamp).toLocaleString()}`}
                      >
                        <td>{new Date(evt.timestamp).toLocaleString()}</td>
                        <td>
                          <span className={`badge ${actionClass}`}>{evt.action}</span>
                        </td>
                        <td>
                          <span className="code-tag">{evt.provider}</span>
                        </td>
                        <td>
                          <span className="code-tag">{evt.agent ?? 'default'}</span>
                        </td>
                        <td>
                          <span className="code-tag">{evt.project ?? 'default'}</span>
                        </td>
                        <td>
                          {findingsCount > 0 ? (
                            <span style={{ color: 'var(--color-yellow)', fontWeight: 600 }}>
                              {`${findingsCount} finding${findingsCount > 1 ? 's' : ''}`}
                            </span>
                          ) : (
                            <span style={{ color: 'var(--text-muted)' }}>0 findings</span>
                          )}
                        </td>
                        <td>
                          <button
                            type="button"
                            className="status-retry-button"
                            style={{ padding: '0.2rem 0.6rem', fontSize: '0.75rem' }}
                            onClick={(e) => {
                              e.stopPropagation();
                              setSelectedEventId(evt.id);
                            }}
                            aria-label={`Inspect event from ${new Date(evt.timestamp).toLocaleTimeString()}`}
                          >
                            Inspect
                          </button>
                        </td>
                      </tr>
                    );
                  })
                )}
              </tbody>
            </table>
          </div>

          {/* Pagination Controls */}
          {total > PAGE_SIZE && (
            <div className="pagination" style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginTop: '1rem' }}>
              <span className="page-subtitle" style={{ margin: 0 }}>
                Showing {offset + 1}–{Math.min(offset + PAGE_SIZE, total)} of {total} records
              </span>
              <div style={{ display: 'flex', gap: '0.5rem' }}>
                <button
                  type="button"
                  className="status-retry-button"
                  disabled={offset === 0}
                  onClick={handlePrevPage}
                  aria-label="Previous page"
                >
                  ← Previous
                </button>
                <span className="status-pill profile-pill" style={{ alignSelf: 'center' }}>
                  {currentPage} / {totalPages}
                </span>
                <button
                  type="button"
                  className="status-retry-button"
                  disabled={offset + PAGE_SIZE >= total}
                  onClick={handleNextPage}
                  aria-label="Next page"
                >
                  Next →
                </button>
              </div>
            </div>
          )}
        </div>
      )}

      {/* Privacy-Preserving Event Inspection Drawer / Modal */}
      {selectedEventId && (
        <div
          className="modal-backdrop"
          onClick={() => setSelectedEventId(null)}
          role="dialog"
          aria-modal="true"
          aria-labelledby="audit-detail-title"
        >
          <div
            ref={modalRef}
            className="modal-container"
            onClick={(e) => e.stopPropagation()}
            style={{ maxWidth: '680px' }}
          >
            <div className="modal-header">
              <div>
                <h3 id="audit-detail-title">Audit Record Inspector</h3>
                <span className="modal-id">{selectedEventId}</span>
              </div>
              <button
                type="button"
                className="modal-close-button"
                onClick={() => setSelectedEventId(null)}
                aria-label="Close modal"
              >
                ✕
              </button>
            </div>

            <div className="modal-body">
              {selectedEvent ? (
                <>
                  <div
                    style={{
                      background: 'rgba(56, 189, 248, 0.08)',
                      border: '1px solid var(--border-color)',
                      borderRadius: '6px',
                      padding: '0.75rem',
                      marginBottom: '1rem',
                      fontSize: '0.8rem',
                      color: 'var(--text-secondary)',
                    }}
                  >
                    🔒 <strong>Privacy Guarantee (ADR 0004):</strong> Raw prompt text, LLM completions, and detected secret contents are permanently purged from persistent storage and sanitized across this audit inspector.
                  </div>

                  {(() => {
                    const meta = (selectedEvent.metadata ?? {}) as Record<string, unknown>;
                    const sha256 = typeof meta.sha256_fingerprint === 'string' ? meta.sha256_fingerprint : 'N/A';
                    const overheadMs = typeof meta.proxy_overhead_ms === 'number' ? meta.proxy_overhead_ms : 0;
                    const reqBytes = typeof meta.request_size === 'number' ? meta.request_size : 0;
                    const respBytes = typeof meta.response_size === 'number' ? meta.response_size : 0;
                    const policyVer = typeof meta.policy_version === 'string' ? meta.policy_version : '1.0';
                    const findingEntries = Object.entries(selectedEvent.finding_counts ?? {});

                    return (
                      <>
                        <div className="details-grid" style={{ display: 'grid', gridTemplateColumns: 'repeat(2, 1fr)', gap: '0.75rem', marginBottom: '1rem' }}>
                          <div className="detail-item">
                            <span className="detail-label">Timestamp</span>
                            <span className="detail-value">{new Date(selectedEvent.timestamp).toLocaleString()}</span>
                          </div>
                          <div className="detail-item">
                            <span className="detail-label">Policy Action</span>
                            <span className="detail-value">
                              <span className={`badge badge-${selectedEvent.action.toLowerCase()}`}>{selectedEvent.action}</span>
                            </span>
                          </div>
                          <div className="detail-item">
                            <span className="detail-label">Upstream Provider</span>
                            <span className="detail-value">{selectedEvent.provider}</span>
                          </div>
                          <div className="detail-item">
                            <span className="detail-label">Client / Agent</span>
                            <span className="detail-value">{selectedEvent.agent ?? 'default'}</span>
                          </div>
                          <div className="detail-item">
                            <span className="detail-label">Project</span>
                            <span className="detail-value">{selectedEvent.project ?? 'default'}</span>
                          </div>
                          <div className="detail-item">
                            <span className="detail-label">Policy Version</span>
                            <span className="detail-value">{policyVer}</span>
                          </div>
                        </div>

                        {/* Fingerprint & Timing Metrics */}
                        <div className="card" style={{ background: 'var(--bg-secondary)', padding: '0.75rem', marginBottom: '1rem' }}>
                          <h4 style={{ fontSize: '0.875rem', marginBottom: '0.5rem', color: 'var(--color-primary)' }}>
                            Request Fingerprint & Safe Telemetry
                          </h4>
                          <div style={{ fontSize: '0.8rem', display: 'flex', flexDirection: 'column', gap: '0.25rem' }}>
                            <div>
                              <strong>SHA-256 Fingerprint:</strong>{' '}
                              <code style={{ fontSize: '0.75rem', wordBreak: 'break-all' }}>
                                {sha256}
                              </code>
                            </div>
                            <div style={{ display: 'flex', gap: '1rem', marginTop: '0.25rem' }}>
                              <span>
                                <strong>Proxy Overhead:</strong> {overheadMs} ms
                              </span>
                              <span>
                                <strong>Request Bytes:</strong> {reqBytes} B
                              </span>
                              <span>
                                <strong>Response Bytes:</strong> {respBytes} B
                              </span>
                            </div>
                          </div>
                        </div>

                        {/* Findings */}
                        <div>
                          <h4 style={{ fontSize: '0.875rem', marginBottom: '0.5rem' }}>
                            Security & Privacy Findings ({findingEntries.reduce((a, [, c]) => a + c, 0)})
                          </h4>
                          {findingEntries.length > 0 ? (
                            <div style={{ display: 'flex', flexDirection: 'column', gap: '0.5rem' }}>
                              {findingEntries.map(([category, count]) => (
                                <div
                                  key={category}
                                  style={{
                                    background: 'var(--bg-secondary)',
                                    padding: '0.5rem 0.75rem',
                                    borderRadius: '4px',
                                    borderLeft: '3px solid var(--color-yellow)',
                                    fontSize: '0.8rem',
                                  }}
                                >
                                  <div style={{ display: 'flex', justifyContent: 'space-between' }}>
                                    <strong>{category}</strong>
                                    <span style={{ color: 'var(--color-yellow)', fontWeight: 600 }}>
                                      {count} finding{count > 1 ? 's' : ''}
                                    </span>
                                  </div>
                                </div>
                              ))}
                            </div>
                          ) : (
                            <p style={{ color: 'var(--text-muted)', fontSize: '0.85rem' }}>
                              No sensitive terms or policy findings were triggered on this request.
                            </p>
                          )}
                        </div>
                      </>
                    );
                  })()}
                </>
              ) : (
                <p>Loading event details…</p>
              )}
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
