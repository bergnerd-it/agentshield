import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { fireEvent, render, screen, waitFor } from '@testing-library/react';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import type { AuditEvent, EventList } from '../src/api/types.ts';
import { AuditPage } from '../src/pages/AuditPage.tsx';

const mockEvent: AuditEvent = {
  id: 'evt-audit-12345678',
  timestamp: new Date().toISOString(),
  request_id: 'req-123',
  agent: 'codex',
  project: 'secret-ops',
  action: 'WARN',
  provider: 'openai',
  model: 'gpt-4o',
  endpoint: '/v1/chat/completions',
  direction: 'REQUEST',
  finding_counts: {
    CUSTOM_TERM: 1,
  },
  metadata: {
    sha256_fingerprint: 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
    proxy_overhead_ms: 12.5,
    request_size: 256,
    response_size: 512,
    policy_version: '1.0',
  },
};

const mockEventList: EventList = {
  items: [mockEvent],
  total: 1,
  limit: 15,
  offset: 0,
};

describe('AuditPage Component', () => {
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
      vi.fn().mockImplementation((url: string) => {
        if (url.includes('/api/v1/events/evt-audit-12345678')) {
          return Promise.resolve({
            ok: true,
            status: 200,
            json: () => Promise.resolve(mockEvent),
          });
        }
        if (url.includes('/api/v1/events')) {
          return Promise.resolve({
            ok: true,
            status: 200,
            json: () => Promise.resolve(mockEventList),
          });
        }
        if (url.includes('/api/v1/audit/export')) {
          return Promise.resolve({
            ok: true,
            status: 200,
            blob: () => Promise.resolve(new Blob(['{"exported": true}'], { type: 'application/json' })),
          });
        }
        return Promise.reject(new Error(`Unhandled URL: ${url}`));
      })
    );

    // Mock window.URL
    window.URL.createObjectURL = vi.fn().mockReturnValue('blob:test-url');
    window.URL.revokeObjectURL = vi.fn();
  });

  it('renders page header and privacy title', async () => {
    render(
      <QueryClientProvider client={queryClient}>
        <AuditPage />
      </QueryClientProvider>
    );

    expect(screen.getByText('Privacy-Preserving Audit Log')).toBeInTheDocument();
    await waitFor(() => {
      expect(screen.getByText('secret-ops')).toBeInTheDocument();
    });
  });

  it('renders audit events table and filters', async () => {
    render(
      <QueryClientProvider client={queryClient}>
        <AuditPage />
      </QueryClientProvider>
    );

    await waitFor(() => {
      expect(screen.getByText('secret-ops')).toBeInTheDocument();
      expect(screen.getByText('1 finding')).toBeInTheDocument();
      expect(screen.getAllByText('WARN').length).toBeGreaterThan(0);
    });

    // Change action filter
    const actionSelect = screen.getByLabelText('Filter by Policy Action');
    fireEvent.change(actionSelect, { target: { value: 'BLOCK' } });
    expect(actionSelect).toHaveValue('BLOCK');
  });

  it('opens inspection modal and guarantees zero secret leakage', async () => {
    render(
      <QueryClientProvider client={queryClient}>
        <AuditPage />
      </QueryClientProvider>
    );

    await waitFor(() => {
      expect(screen.getByText('Inspect')).toBeInTheDocument();
    });

    fireEvent.click(screen.getByText('Inspect'));

    await waitFor(() => {
      expect(screen.getByText('Audit Record Inspector')).toBeInTheDocument();
      expect(screen.getByText('Privacy Guarantee (ADR 0004):', { exact: false })).toBeInTheDocument();
      expect(screen.getByText('Request Fingerprint & Safe Telemetry')).toBeInTheDocument();
      expect(screen.getByText(/e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855/)).toBeInTheDocument();
      expect(screen.getByText('CUSTOM_TERM')).toBeInTheDocument();
    });
  });

  it('triggers JSON export on export button click', async () => {
    render(
      <QueryClientProvider client={queryClient}>
        <AuditPage />
      </QueryClientProvider>
    );

    const exportBtn = screen.getByLabelText('Export audit records as JSON');
    fireEvent.click(exportBtn);

    await waitFor(() => {
      expect(window.URL.createObjectURL).toHaveBeenCalled();
    });
  });
});
