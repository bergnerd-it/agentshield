import { useState } from 'react';
import { useSystemStatus } from './api/client.ts';
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

export function App() {
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

export default App;
