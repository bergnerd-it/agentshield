import { describe, it, expect, beforeEach, vi } from 'vitest';
import { render, screen, fireEvent } from '@testing-library/react';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { App } from '../src/App.tsx';
import type { SystemStatus } from '../src/api/types.ts';

const mockStatus: SystemStatus = {
  status: 'ready',
  version: '0.1.0',
  platform: 'darwin',
  profile: 'balanced',
  host: '127.0.0.1',
  port: 8765,
  database: {
    status: 'connected',
    migration_version: '0001_baseline_schema',
  },
  frontend_available: true,
};

describe('AgentShield App', () => {
  let queryClient: QueryClient;

  beforeEach(() => {
    queryClient = new QueryClient({
      defaultOptions: {
        queries: {
          retry: false,
        },
      },
    });
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue({
      ok: true,
      json: async () => mockStatus,
    }));
  });

  it('renders application header and title', async () => {
    render(
      <QueryClientProvider client={queryClient}>
        <App />
      </QueryClientProvider>
    );

    expect(screen.getByText('AgentShield')).toBeInTheDocument();
    expect(screen.getByText('Local Security Reverse Proxy')).toBeInTheDocument();
  });

  it('displays status banner information when ready', async () => {
    render(
      <QueryClientProvider client={queryClient}>
        <App />
      </QueryClientProvider>
    );

    const bannerVersion = await screen.findByText('AgentShield v0.1.0');
    expect(bannerVersion).toBeInTheDocument();
    expect(screen.getByText('Profile: BALANCED')).toBeInTheDocument();
  });

  it('allows navigating between tabs', async () => {
    render(
      <QueryClientProvider client={queryClient}>
        <App />
      </QueryClientProvider>
    );

    // Click Settings tab
    const settingsTab = screen.getByRole('tab', { name: 'Settings' });
    fireEvent.click(settingsTab);

    expect(screen.getByText('System Settings & Limits')).toBeInTheDocument();

    // Click Dashboard tab
    const dashboardTab = screen.getByRole('tab', { name: 'Dashboard' });
    fireEvent.click(dashboardTab);

    expect(screen.getByText('Security Dashboard')).toBeInTheDocument();
  });
});
