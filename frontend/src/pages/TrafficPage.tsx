import { useState } from 'react';
import { useAuditEvent, useAuditEvents } from '../api/client.ts';

const PAGE_SIZE = 15;

export function TrafficPage() {
  const [actionFilter, setActionFilter] = useState<string>('');
  const [providerFilter, setProviderFilter] = useState<string>('');
  const [offset, setOffset] = useState<number>(0);
  const [selectedEventId, setSelectedEventId] = useState<string | null>(null);

  const { data: eventList, isLoading, isError, refetch } = useAuditEvents({
    limit: PAGE_SIZE,
    offset,
    action: actionFilter || undefined,
    provider: providerFilter || undefined,
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

  return (
    <div
      className="page-content"
      id="tabpanel-traffic"
      role="tabpanel"
      aria-labelledby="tab-traffic"
    >
      <div className="page-header-row">
        <div className="page-header">
          <h2>Live Traffic Inspector</h2>
          <p className="page-subtitle">
            Audit log of all inspected LLM requests, redaction actions, and security decisions.
          </p>
        </div>

        <div className="traffic-filters">
          <select
            className="filter-select"
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

          <select
            className="filter-select"
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

          <button
            type="button"
            className="status-retry-button"
            onClick={() => void refetch()}
            aria-label="Refresh traffic events"
          >
            ↻ Refresh
          </button>
        </div>
      </div>

      {isLoading && (
        <div className="card empty-state">
          <p>Loading traffic log…</p>
        </div>
      )}

      {isError && (
        <div className="card empty-state color-red">
          <p>Failed to load traffic events from backend.</p>
        </div>
      )}

      {!isLoading && !isError && (!eventList || eventList.items.length === 0) && (
        <div className="card empty-state">
          <p>No matching traffic events found.</p>
          <span className="card-hint">
            Traffic traversing OpenAI (/proxy/openai/...) or Anthropic (/proxy/anthropic/...) appears here.
          </span>
        </div>
      )}

      {!isLoading && eventList && eventList.items.length > 0 && (
        <div className="card traffic-card">
          <div className="table-responsive">
            <table className="traffic-table" role="table" aria-label="Proxy traffic events">
              <thead>
                <tr>
                  <th>Timestamp</th>
                  <th>Direction</th>
                  <th>Provider</th>
                  <th>Endpoint</th>
                  <th>Action</th>
                  <th>Findings</th>
                  <th>Latency</th>
                  <th>Details</th>
                </tr>
              </thead>
              <tbody>
                {eventList.items.map((evt) => {
                  const findingTotal = Object.values(evt.finding_counts).reduce(
                    (a, b) => a + b,
                    0
                  );
                  const latencyMs = evt.metadata['latency_ms'] as number | undefined;

                  return (
                    <tr key={evt.id}>
                      <td className="text-muted">
                        {new Date(evt.timestamp).toLocaleTimeString()}
                      </td>
                      <td>
                        <span className="direction-badge">{evt.direction}</span>
                      </td>
                      <td>
                        <span className="badge-provider">{evt.provider.toUpperCase()}</span>
                      </td>
                      <td className="text-endpoint">{evt.endpoint}</td>
                      <td>
                        <span className={`action-pill action-${evt.action.toLowerCase()}`}>
                          {evt.action}
                        </span>
                      </td>
                      <td>
                        {findingTotal > 0 ? (
                          <span className="finding-count-badge">{findingTotal}</span>
                        ) : (
                          <span className="text-muted">0</span>
                        )}
                      </td>
                      <td>{latencyMs !== undefined ? `${latencyMs.toFixed(0)} ms` : '-'}</td>
                      <td>
                        <button
                          type="button"
                          className="button-secondary btn-sm"
                          onClick={() => setSelectedEventId(evt.id)}
                        >
                          Inspect
                        </button>
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>

          <div className="pagination-bar">
            <span className="pagination-info">
              Showing {offset + 1} - {Math.min(offset + PAGE_SIZE, total)} of {total} events
              {totalPages > 1 && ` (Page ${currentPage} of ${totalPages})`}
            </span>
            <div className="pagination-buttons">
              <button
                type="button"
                className="button-secondary btn-sm"
                onClick={handlePrevPage}
                disabled={offset === 0}
              >
                Previous
              </button>
              <button
                type="button"
                className="button-secondary btn-sm"
                onClick={handleNextPage}
                disabled={offset + PAGE_SIZE >= total}
              >
                Next
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Event Details Inspection Modal */}
      {selectedEventId && (
        <div className="modal-backdrop" role="dialog" aria-modal="true" aria-labelledby="event-modal-title">
          <div className="modal-container">
            <div className="modal-header">
              <div className="modal-header-left">
                <h3 id="event-modal-title">Audit Record Inspection</h3>
                <span className="modal-id">Event ID: {selectedEventId}</span>
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
                  <div className="detail-meta-grid">
                    <div className="detail-meta-item">
                      <span className="card-label">Action Outcome</span>
                      <span className={`action-pill action-${selectedEvent.action.toLowerCase()}`}>
                        {selectedEvent.action}
                      </span>
                    </div>
                    <div className="detail-meta-item">
                      <span className="card-label">Provider</span>
                      <span className="metric-value-sm">{selectedEvent.provider.toUpperCase()}</span>
                    </div>
                    <div className="detail-meta-item">
                      <span className="card-label">Direction</span>
                      <span className="direction-badge">{selectedEvent.direction}</span>
                    </div>
                    <div className="detail-meta-item">
                      <span className="card-label">Timestamp</span>
                      <span className="setting-val">
                        {new Date(selectedEvent.timestamp).toLocaleString()}
                      </span>
                    </div>
                  </div>

                  <div className="detail-meta-grid">
                    <div className="detail-meta-item">
                      <span className="card-label">Endpoint</span>
                      <span className="setting-val">{selectedEvent.endpoint}</span>
                    </div>
                    <div className="detail-meta-item">
                      <span className="card-label">Model</span>
                      <span className="setting-val">{selectedEvent.model ?? '-'}</span>
                    </div>
                    <div className="detail-meta-item">
                      <span className="card-label">Agent ID</span>
                      <span className="setting-val">{selectedEvent.agent ?? '-'}</span>
                    </div>
                    <div className="detail-meta-item">
                      <span className="card-label">Project</span>
                      <span className="setting-val">{selectedEvent.project ?? '-'}</span>
                    </div>
                  </div>

                  <div className="findings-section">
                    <h4>Finding Category Summary</h4>
                    {Object.keys(selectedEvent.finding_counts).length > 0 ? (
                      <div className="finding-chips">
                        {Object.entries(selectedEvent.finding_counts).map(([cat, count]) => (
                          <span key={cat} className="finding-chip">
                            🛡️ {cat}: <strong>{count}</strong>
                          </span>
                        ))}
                      </div>
                    ) : (
                      <p className="text-secondary">Zero protected content findings detected.</p>
                    )}
                  </div>

                  <div className="metadata-section">
                    <h4>Safe Audit Metadata</h4>
                    <pre className="metadata-json">
                      <code>{JSON.stringify(selectedEvent.metadata, null, 2)}</code>
                    </pre>
                  </div>
                </>
              ) : (
                <p>Loading audit record details…</p>
              )}
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
