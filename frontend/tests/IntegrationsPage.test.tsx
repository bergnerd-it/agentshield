import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { fireEvent, render, screen, waitFor } from '@testing-library/react';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import type { ConfigDiff, IntegrationStatus } from '../src/api/types.ts';
import { IntegrationsPage } from '../src/pages/IntegrationsPage.tsx';

const mockIntegrations: IntegrationStatus[] = [
  {
    agent_type: 'codex',
    configured: true,
    config_path: '/Users/test/.codex/config.toml',
    proxy_url: 'http://127.0.0.1:8765/proxy/openai',
    has_token: true,
    last_backup_path: '/Users/test/.codex/config.toml.bak.20260918_120000',
    updated_at: new Date().toISOString(),
    error: null,
  },
  {
    agent_type: 'claude-code',
    configured: false,
    config_path: '/Users/test/.claude.json',
    proxy_url: 'http://127.0.0.1:8765/proxy/anthropic',
    has_token: false,
    last_backup_path: null,
    updated_at: null,
    error: null,
  },
];

const mockDiff: ConfigDiff = {
  agent_type: 'claude-code',
  config_path: '/Users/test/.claude.json',
  original_content: '{\n  "env": "production"\n}\n',
  modified_content: '{\n  "env": "production",\n  "anthropicBaseUrl": "http://127.0.0.1:8765/proxy/anthropic"\n}\n',
  unified_diff: '--- a/.claude.json\n+++ b/.claude.json\n@@ -1,3 +1,4 @@\n {\n   "env": "production",\n+  "anthropicBaseUrl": "http://127.0.0.1:8765/proxy/anthropic"\n }\n',
  has_changes: true,
};

describe('IntegrationsPage Component', () => {
  let queryClient: QueryClient;

  beforeEach(() => {
    queryClient = new QueryClient({
      defaultOptions: {
        queries: {
          retry: false,
        },
      },
    });

    vi.stubGlobal(
      'fetch',
      vi.fn().mockImplementation((url: string, init?: RequestInit) => {
        if (url === '/api/v1/integrations') {
          return Promise.resolve({
            ok: true,
            status: 200,
            json: () => Promise.resolve(mockIntegrations),
          });
        }
        if (url.includes('/preview')) {
          return Promise.resolve({
            ok: true,
            status: 200,
            json: () => Promise.resolve(mockDiff),
          });
        }
        if (url.includes('/configure') && init?.method === 'POST') {
          return Promise.resolve({
            ok: true,
            status: 200,
            json: () => Promise.resolve({ ...mockIntegrations[1], configured: true, has_token: true }),
          });
        }
        if (url.includes('/test') && init?.method === 'POST') {
          return Promise.resolve({
            ok: true,
            status: 200,
            json: () => Promise.resolve({ status: 'ok', agent: 'codex', latency_ms: 5.2 }),
          });
        }
        return Promise.reject(new Error(`Unhandled URL: ${url}`));
      })
    );
  });

  it('renders cooperative reverse proxy security notice banner', async () => {
    render(
      <QueryClientProvider client={queryClient}>
        <IntegrationsPage />
      </QueryClientProvider>
    );

    expect(screen.getByText('Cooperative Reverse Proxy Security Notice')).toBeInTheDocument();
    expect(screen.getByText(/AgentShield Version 1 is a/)).toBeInTheDocument();
  });

  it('renders integration cards with status and attribution', async () => {
    render(
      <QueryClientProvider client={queryClient}>
        <IntegrationsPage />
      </QueryClientProvider>
    );

    await waitFor(() => {
      expect(screen.getByText('OpenAI Codex CLI')).toBeInTheDocument();
      expect(screen.getByText('Anthropic Claude Code')).toBeInTheDocument();
      expect(screen.getByText('Routed to Proxy')).toBeInTheDocument();
      expect(screen.getByText('Not Configured')).toBeInTheDocument();
    });

    // Rollback button on Codex should be enabled since last_backup_path exists
    const rollbackBtn = screen.getByLabelText('Rollback configuration for codex');
    expect(rollbackBtn).not.toBeDisabled();

    // Rollback button on Claude Code should be disabled
    const claudeRollbackBtn = screen.getByLabelText('Rollback configuration for claude-code');
    expect(claudeRollbackBtn).toBeDisabled();
  });

  it('opens diff preview modal when clicking Preview Diff', async () => {
    render(
      <QueryClientProvider client={queryClient}>
        <IntegrationsPage />
      </QueryClientProvider>
    );

    await waitFor(() => {
      expect(screen.getByLabelText('Preview changes for claude-code')).toBeInTheDocument();
    });

    fireEvent.click(screen.getByLabelText('Preview changes for claude-code'));

    await waitFor(() => {
      expect(screen.getByText('Configuration Diff Preview')).toBeInTheDocument();
      expect(screen.getByText('Confirm and Apply Changes')).toBeInTheDocument();
    });
  });

  it('tests connection when clicking Test Connection', async () => {
    render(
      <QueryClientProvider client={queryClient}>
        <IntegrationsPage />
      </QueryClientProvider>
    );

    await waitFor(() => {
      expect(screen.getByLabelText('Test connection for codex')).toBeInTheDocument();
    });

    fireEvent.click(screen.getByLabelText('Test connection for codex'));

    await waitFor(() => {
      expect(screen.getByText(/Local proxy reachability OK \(5.2 ms\)/)).toBeInTheDocument();
    });
  });
});
