import { type FormEvent, useState } from 'react';
import {
  fetchSystemStatus,
  getAdminToken,
  setAdminToken,
  useSystemStatus,
} from './api/client.ts';
import { Navigation, type TabId } from './components/Navigation.tsx';
import { StatusBanner } from './components/StatusBanner.tsx';
import { ApprovalsPage } from './pages/ApprovalsPage.tsx';
import { AuditPage } from './pages/AuditPage.tsx';
import { DashboardPage } from './pages/DashboardPage.tsx';
import { IntegrationsPage } from './pages/IntegrationsPage.tsx';
import { PoliciesPage } from './pages/PoliciesPage.tsx';
import { SettingsPage } from './pages/SettingsPage.tsx';
import { TrafficPage } from './pages/TrafficPage.tsx';

import { useLiveEvents } from './hooks/useLiveEvents.ts';

interface AuthGateProps {
  onAuthenticated: () => void;
}

function AuthGate({ onAuthenticated }: AuthGateProps) {
  const [token, setToken] = useState('');
  const [isSubmitting, setIsSubmitting] = useState(false);
  const [error, setError] = useState<string | null>(null);

  async function handleSubmit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setIsSubmitting(true);
    setError(null);
    setAdminToken(token);
    try {
      await fetchSystemStatus();
      setToken('');
      onAuthenticated();
    } catch {
      setAdminToken(null);
      setError('Authentication failed. Check the local administration token.');
    } finally {
      setIsSubmitting(false);
    }
  }

  return (
    <main className="auth-gate">
      <form className="auth-card" onSubmit={(event) => void handleSubmit(event)}>
        <div className="brand-logo" aria-hidden="true">
          🛡️
        </div>
        <h1 className="brand-title">AgentShield</h1>
        <p className="brand-subtitle">Local Security Reverse Proxy</p>
        <p className="auth-description">
          Enter the administration token from the AgentShield data directory. It is kept only in
          this page&apos;s memory and is cleared when the page closes.
        </p>
        <label className="auth-label" htmlFor="admin-token">
          Administration token
        </label>
        <input
          id="admin-token"
          className="auth-input"
          type="password"
          autoComplete="off"
          spellCheck={false}
          value={token}
          onChange={(event) => setToken(event.target.value)}
          required
          autoFocus
        />
        {error && (
          <p className="auth-error" role="alert">
            {error}
          </p>
        )}
        <button className="auth-submit" type="submit" disabled={isSubmitting || !token.trim()}>
          {isSubmitting ? 'Unlocking…' : 'Unlock dashboard'}
        </button>
      </form>
    </main>
  );
}

function AuthenticatedApplication() {
  const [activeTab, setActiveTab] = useState<TabId>('dashboard');
  const { data: status, isLoading, isError, error, refetch } = useSystemStatus();
  const { status: sseStatus } = useLiveEvents();

  return (
    <div className="app-layout">
      <header className="app-header">
        <div className="header-brand">
          <div className="brand-logo">🛡️</div>
          <div>
            <h1 className="brand-title">AgentShield</h1>
            <span className="brand-subtitle">Local Security Reverse Proxy</span>
          </div>
        </div>
        <div className="header-status-group">
          <span className="live-stream-indicator" title={`Live Event Stream: ${sseStatus}`}>
            <span
              className={`status-dot ${
                sseStatus === 'connected'
                  ? 'dot-green'
                  : sseStatus === 'connecting'
                  ? 'dot-yellow'
                  : 'dot-red'
              }`}
              aria-hidden="true"
            />
            <span className="live-stream-text">LIVE</span>
          </span>
          <StatusBanner
            status={status}
            isLoading={isLoading}
            isError={isError}
            error={error}
            onRetry={() => void refetch()}
          />
        </div>
      </header>

      <Navigation activeTab={activeTab} onSelectTab={setActiveTab} />

      <main className="main-content">
        {activeTab === 'dashboard' && <DashboardPage status={status} />}
        {activeTab === 'traffic' && <TrafficPage />}
        {activeTab === 'approvals' && <ApprovalsPage />}
        {activeTab === 'policies' && <PoliciesPage />}
        {activeTab === 'integrations' && <IntegrationsPage />}
        {activeTab === 'audit' && <AuditPage />}
        {activeTab === 'settings' && <SettingsPage status={status} />}
      </main>

      <footer className="app-footer">
        <p>AgentShield Foundation • Strictly bound to 127.0.0.1 • Zero cloud dependencies</p>
      </footer>
    </div>
  );
}

export function App() {
  const [authenticated, setAuthenticated] = useState(() => getAdminToken() !== null);
  if (!authenticated) {
    return <AuthGate onAuthenticated={() => setAuthenticated(true)} />;
  }
  return <AuthenticatedApplication />;
}

export default App;
