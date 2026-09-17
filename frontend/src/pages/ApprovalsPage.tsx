import { useState } from 'react';
import {
  useApprovalDetail,
  useApprovals,
  useApproveMutation,
  useDenyMutation,
} from '../api/client.ts';
import { ApprovalCard } from '../components/ApprovalCard.tsx';
import { DiffViewer } from '../components/DiffViewer.tsx';

type FilterStatus = 'pending' | 'all' | 'approved' | 'denied' | 'expired';

export function ApprovalsPage() {
  const [filter, setFilter] = useState<FilterStatus>('pending');
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [modalReason, setModalReason] = useState('');

  const statusParam = filter === 'all' ? undefined : filter;
  const { data: approvals, isLoading, isError, refetch } = useApprovals(statusParam);
  const { data: selectedDetail, isLoading: isDetailLoading } = useApprovalDetail(selectedId);

  const approveMutation = useApproveMutation();
  const denyMutation = useDenyMutation();

  const handleApprove = (id: string, reason?: string) => {
    approveMutation.mutate({ id, reason });
  };

  const handleDeny = (id: string, reason?: string) => {
    denyMutation.mutate({ id, reason });
  };

  const handleModalApprove = () => {
    if (!selectedId) return;
    approveMutation.mutate(
      { id: selectedId, reason: modalReason.trim() || undefined },
      {
        onSuccess: () => {
          setSelectedId(null);
          setModalReason('');
        },
      }
    );
  };

  const handleModalDeny = () => {
    if (!selectedId) return;
    denyMutation.mutate(
      { id: selectedId, reason: modalReason.trim() || undefined },
      {
        onSuccess: () => {
          setSelectedId(null);
          setModalReason('');
        },
      }
    );
  };

  return (
    <div
      className="page-content"
      id="tabpanel-approvals"
      role="tabpanel"
      aria-labelledby="tab-approvals"
    >
      <div className="page-header-row">
        <div className="page-header">
          <h2>Manual Approvals Queue</h2>
          <p className="page-subtitle">
            Interactive authorization for requests triggering REQUIRE_APPROVAL policy actions.
          </p>
        </div>

        <div className="status-filter-tabs">
          {(['pending', 'all', 'approved', 'denied', 'expired'] as FilterStatus[]).map((st) => (
            <button
              key={st}
              type="button"
              className={`filter-chip ${filter === st ? 'filter-chip-active' : ''}`}
              onClick={() => setFilter(st)}
              aria-pressed={filter === st}
            >
              {st.toUpperCase()}
            </button>
          ))}
          <button
            type="button"
            className="status-retry-button"
            onClick={() => void refetch()}
            aria-label="Refresh approvals list"
          >
            ↻ Refresh
          </button>
        </div>
      </div>

      {isLoading && (
        <div className="card empty-state">
          <p>Loading approvals queue…</p>
        </div>
      )}

      {isError && (
        <div className="card empty-state color-red">
          <p>Failed to load approval holds from local server.</p>
        </div>
      )}

      {!isLoading && !isError && (!approvals || approvals.length === 0) && (
        <div className="card empty-state">
          <p>No {filter !== 'all' ? filter : ''} approvals currently waiting.</p>
          <span className="card-hint">
            Proxy requests triggering REQUIRE_APPROVAL rules appear here in real-time.
          </span>
        </div>
      )}

      {!isLoading && approvals && approvals.length > 0 && (
        <div className="approvals-list" role="feed" aria-label="Approvals queue">
          {approvals.map((req) => (
            <ApprovalCard
              key={req.id}
              approval={req}
              onSelect={(id) => setSelectedId(id)}
              onApprove={handleApprove}
              onDeny={handleDeny}
              isActionLoading={approveMutation.isPending || denyMutation.isPending}
            />
          ))}
        </div>
      )}

      {/* Detail Inspection Modal / Drawer */}
      {selectedId && (
        <div className="modal-backdrop" role="dialog" aria-modal="true" aria-labelledby="modal-title">
          <div className="modal-container">
            <div className="modal-header">
              <div className="modal-header-left">
                <h3 id="modal-title">Approval Request Detail</h3>
                <span className="modal-id">ID: {selectedId}</span>
              </div>
              <button
                type="button"
                className="modal-close-button"
                onClick={() => setSelectedId(null)}
                aria-label="Close modal"
              >
                ✕
              </button>
            </div>

            <div className="modal-body">
              {isDetailLoading && <p>Loading detailed payload and findings…</p>}

              {selectedDetail && (
                <>
                  <div className="detail-meta-grid">
                    <div className="detail-meta-item">
                      <span className="card-label">Provider</span>
                      <span className="metric-value-sm">{selectedDetail.provider.toUpperCase()}</span>
                    </div>
                    <div className="detail-meta-item">
                      <span className="card-label">Endpoint</span>
                      <span className="setting-val">{selectedDetail.endpoint}</span>
                    </div>
                    <div className="detail-meta-item">
                      <span className="card-label">Status</span>
                      <span className="metric-value-sm capitalize">{selectedDetail.status}</span>
                    </div>
                    <div className="detail-meta-item">
                      <span className="card-label">Remaining Time</span>
                      <span className="setting-val">{selectedDetail.remaining_seconds.toFixed(0)}s</span>
                    </div>
                  </div>

                  <div className="findings-section">
                    <h4>Protected Findings ({selectedDetail.findings.length})</h4>
                    <div className="findings-detail-list">
                      {selectedDetail.findings.map((f, idx) => (
                        <div key={idx} className="finding-detail-row">
                          <div className="finding-row-header">
                            <span className="finding-chip">🛡️ {f.category}</span>
                            <span className="finding-severity">[{f.severity}]</span>
                            <span className="finding-detector">detector: {f.detector_id}</span>
                          </div>
                          <p className="finding-message">{f.message}</p>
                          <span className="finding-path">
                            JSON Path: <code>{f.path.join('.')}</code>
                          </span>
                        </div>
                      ))}
                    </div>
                  </div>

                  <div className="diff-section">
                    <h4>Payload Comparison Preview</h4>
                    <DiffViewer
                      originalPayload={selectedDetail.raw_payload_masked}
                      redactedPayload={selectedDetail.redacted_payload}
                      originalLabel="Original Request (Masked)"
                      redactedLabel="Redacted Request (Policy Outcome)"
                    />
                  </div>

                  {selectedDetail.status.toLowerCase() === 'pending' && (
                    <div className="modal-decision-footer">
                      <div className="modal-reason-input">
                        <label htmlFor="modal-audit-reason" className="card-label">
                          Operator Audit Note:
                        </label>
                        <input
                          id="modal-audit-reason"
                          type="text"
                          className="input-field"
                          placeholder="Provide optional audit justification"
                          value={modalReason}
                          onChange={(e) => setModalReason(e.target.value)}
                        />
                      </div>
                      <div className="modal-actions">
                        <button
                          type="button"
                          className="button-deny"
                          onClick={handleModalDeny}
                          disabled={denyMutation.isPending}
                        >
                          Deny Request
                        </button>
                        <button
                          type="button"
                          className="button-approve"
                          onClick={handleModalApprove}
                          disabled={approveMutation.isPending}
                        >
                          Approve Request
                        </button>
                      </div>
                    </div>
                  )}
                </>
              )}
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
