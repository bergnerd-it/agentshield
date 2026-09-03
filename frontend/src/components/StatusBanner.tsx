import type { SystemStatus } from '../api/types.ts';

interface Props {
  status: SystemStatus | undefined;
  isLoading: boolean;
  isError: boolean;
  error: Error | null;
  onRetry: () => void;
}

export function StatusBanner({ status, isLoading, isError, error, onRetry }: Props) {
  if (isLoading) {
    return (
      <div className="status-banner status-loading" role="status" aria-live="polite">
        <span className="status-dot dot-yellow" />
        <span>Connecting to AgentShield backend...</span>
      </div>
    );
  }

  if (isError || !status) {
    return (
      <div className="status-banner status-error" role="alert">
        <span className="status-dot dot-red" />
        <span>
          Backend Disconnected: {error?.message || 'Failed to connect to 127.0.0.1:8765'}
        </span>
        <button onClick={onRetry} className="status-retry-button">
          Retry
        </button>
      </div>
    );
  }

  return (
    <div className="status-banner status-ready" role="status" aria-live="polite">
      <div className="status-info-group">
        <span className="status-dot dot-green" />
        <span className="status-title">AgentShield v{status.version}</span>
        <span className="status-separator">•</span>
        <span className="status-pill profile-pill">Profile: {status.profile.toUpperCase()}</span>
        <span className="status-separator">•</span>
        <span className="status-host">
          Bound: {status.host}:{status.port}
        </span>
      </div>
      <div className="status-db-group">
        <span className="status-db-badge">
          DB: {status.database.status === 'connected' ? 'SQLite (WAL)' : 'Degraded'}
        </span>
      </div>
    </div>
  );
}
