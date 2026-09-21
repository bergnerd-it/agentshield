import { useEffect, useState } from 'react';
import type { ApprovalSummary } from '../api/types.ts';

interface Props {
  approval: ApprovalSummary;
  onSelect: (id: string) => void;
  onApprove: (id: string, reason?: string) => void;
  onDeny: (id: string, reason?: string) => void;
  isActionLoading?: boolean;
}

export function ApprovalCard({
  approval,
  onSelect,
  onApprove,
  onDeny,
  isActionLoading = false,
}: Props) {
  const [remainingSec, setRemainingSec] = useState<number>(() => {
    const expiresMs = new Date(approval.expires_at).getTime();
    const nowMs = Date.now();
    return Math.max(0, Math.floor((expiresMs - nowMs) / 1000));
  });

  const [showReasonInput, setShowReasonInput] = useState(false);
  const [reason, setReason] = useState('');

  const isPending = approval.status.toLowerCase() === 'pending';

  // Live countdown timer
  useEffect(() => {
    if (!isPending) return;

    const timer = setInterval(() => {
      const expiresMs = new Date(approval.expires_at).getTime();
      const nowMs = Date.now();
      const diff = Math.max(0, Math.floor((expiresMs - nowMs) / 1000));
      setRemainingSec(diff);
      if (diff <= 0) {
        clearInterval(timer);
      }
    }, 1000);

    return () => clearInterval(timer);
  }, [approval.expires_at, isPending]);

  const handleApprove = () => {
    onApprove(approval.id, reason.trim() || undefined);
    setShowReasonInput(false);
    setReason('');
  };

  const handleDeny = () => {
    onDeny(approval.id, reason.trim() || undefined);
    setShowReasonInput(false);
    setReason('');
  };

  const formatCountdown = (seconds: number) => {
    if (seconds <= 0) return '00:00 (Expired)';
    const m = Math.floor(seconds / 60);
    const s = seconds % 60;
    return `${m.toString().padStart(2, '0')}:${s.toString().padStart(2, '0')}`;
  };

  const statusClass =
    approval.status.toLowerCase() === 'approved'
      ? 'dot-green'
      : approval.status.toLowerCase() === 'denied'
      ? 'dot-red'
      : approval.status.toLowerCase() === 'pending'
      ? 'dot-yellow'
      : 'status-dot';

  return (
    <div
      className={`card approval-card ${isPending ? 'approval-pending' : 'approval-resolved'}`}
      data-testid="approval-card"
    >
      <div className="approval-card-header">
        <div className="approval-header-left">
          <span className={`status-dot ${statusClass}`} aria-hidden="true" />
          <span className="approval-provider-badge">{approval.provider.toUpperCase()}</span>
          <span className="approval-endpoint">{approval.endpoint}</span>
          {approval.model && <span className="approval-model">{approval.model}</span>}
        </div>

        <div className="approval-header-right">
          <span
            className={`approval-timer ${
              remainingSec <= 10 && isPending ? 'timer-warning' : ''
            }`}
            aria-live="polite"
          >
            ⏱️ {isPending ? formatCountdown(remainingSec) : approval.status.toUpperCase()}
          </span>
        </div>
      </div>

      <div className="approval-meta">
        <span className="meta-item">
          <strong>Request ID:</strong> <code>{approval.id.slice(0, 12)}…</code>
        </span>
        <span className="meta-item">
          <strong>Direction:</strong> {approval.direction}
        </span>
        {approval.agent && (
          <span className="meta-item">
            <strong>Agent:</strong> {approval.agent}
          </span>
        )}
        {approval.project && (
          <span className="meta-item">
            <strong>Project:</strong> {approval.project}
          </span>
        )}
      </div>

      <div className="approval-findings-summary">
        <span className="findings-label">
          {approval.finding_count} Protected Finding{approval.finding_count !== 1 ? 's' : ''}:
        </span>
        <div className="finding-chips">
          {approval.finding_categories.map((cat, idx) => (
            <span key={idx} className="finding-chip">
              🛡️ {cat}
            </span>
          ))}
        </div>
      </div>

      {showReasonInput && isPending && (
        <div className="approval-reason-box">
          <label htmlFor={`reason-${approval.id}`} className="card-label">
            Decision Audit Reason (Optional):
          </label>
          <input
            id={`reason-${approval.id}`}
            type="text"
            className="input-field"
            placeholder="e.g. Approved for debugging sandbox session"
            value={reason}
            onChange={(e) => setReason(e.target.value)}
            maxLength={256}
          />
        </div>
      )}

      <div className="approval-actions">
        <button
          type="button"
          className="button-secondary"
          onClick={() => onSelect(approval.id)}
        >
          View Full Payload Diff
        </button>

        {isPending && (
          <div className="approval-decision-buttons">
            {!showReasonInput ? (
              <button
                type="button"
                className="button-secondary text-muted"
                onClick={() => setShowReasonInput(true)}
              >
                + Add Reason
              </button>
            ) : null}

            <button
              type="button"
              className="button-deny"
              onClick={handleDeny}
              disabled={isActionLoading || remainingSec <= 0}
            >
              Deny &amp; Block
            </button>

            <button
              type="button"
              className="button-approve"
              onClick={handleApprove}
              disabled={isActionLoading || remainingSec <= 0}
            >
              Approve &amp; Forward
            </button>
          </div>
        )}
      </div>
    </div>
  );
}
