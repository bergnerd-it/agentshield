import { describe, it, expect, beforeEach, vi } from 'vitest';
import { render, screen, fireEvent, waitFor } from '@testing-library/react';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { ApprovalsPage } from '../src/pages/ApprovalsPage.tsx';
import type { ApprovalSummary, ApprovalDetail } from '../src/api/types.ts';

const mockApprovalSummary: ApprovalSummary = {
  id: 'appr-test-123456',
  request_fingerprint: 'a'.repeat(64),
  provider: 'openai',
  model: 'gpt-4o',
  endpoint: '/v1/chat/completions',
  direction: 'REQUEST',
  status: 'pending',
  finding_count: 1,
  finding_categories: ['CUSTOM_TERM'],
  created_at: new Date().toISOString(),
  expires_at: new Date(Date.now() + 60000).toISOString(),
  remaining_seconds: 59.0,
  agent: 'test-agent',
  project: 'test-proj',
};

const mockApprovalDetail: ApprovalDetail = {
  ...mockApprovalSummary,
  policy_version: 'v1.0',
  findings: [
    {
      category: 'CUSTOM_TERM',
      severity: 'HIGH',
      detector_id: 'custom-terms',
      message: 'Custom term matched: ProjectFalcon',
      path: ['messages', 0, 'content'],
      start_offset: 10,
      end_offset: 23,
      fingerprint: 'b'.repeat(64),
    },
  ],
  raw_payload_masked: {
    model: 'gpt-4o',
    messages: [{ role: 'user', content: 'Specs for ProjectFalcon' }],
  },
  redacted_payload: {
    model: 'gpt-4o',
    messages: [{ role: 'user', content: 'Specs for [CONFIDENTIAL]' }],
  },
  diff_available: true,
};

describe('ApprovalsPage Component', () => {
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
        if (url.includes('/api/v1/approvals/appr-test-123456/approve')) {
          return Promise.resolve({
            ok: true,
            json: async () => ({ id: 'appr-test-123456', status: 'approved', message: 'Approved' }),
          });
        }
        if (url.includes('/api/v1/approvals/appr-test-123456/deny')) {
          return Promise.resolve({
            ok: true,
            json: async () => ({ id: 'appr-test-123456', status: 'denied', message: 'Denied' }),
          });
        }
        if (url.includes('/api/v1/approvals/appr-test-123456')) {
          return Promise.resolve({
            ok: true,
            json: async () => mockApprovalDetail,
          });
        }
        if (url.includes('/api/v1/approvals')) {
          return Promise.resolve({
            ok: true,
            json: async () => [mockApprovalSummary],
          });
        }
        return Promise.resolve({
          ok: true,
          json: async () => ({}),
        });
      })
    );
  });

  it('renders pending approval cards with countdown and metadata', async () => {
    render(
      <QueryClientProvider client={queryClient}>
        <ApprovalsPage />
      </QueryClientProvider>
    );

    const providerBadge = await screen.findByText('OPENAI');
    expect(providerBadge).toBeInTheDocument();
    expect(screen.getByText('/v1/chat/completions')).toBeInTheDocument();
    expect(screen.getByText(/CUSTOM_TERM/)).toBeInTheDocument();
    expect(screen.getByText('Approve & Forward')).toBeInTheDocument();
    expect(screen.getByText('Deny & Block')).toBeInTheDocument();
  });

  it('allows opening payload diff modal and viewing detailed findings', async () => {
    render(
      <QueryClientProvider client={queryClient}>
        <ApprovalsPage />
      </QueryClientProvider>
    );

    const diffButton = await screen.findByText('View Full Payload Diff');
    fireEvent.click(diffButton);

    const modalTitle = await screen.findByText('Approval Request Detail');
    expect(modalTitle).toBeInTheDocument();
    expect(await screen.findByText(/Custom term matched: ProjectFalcon/)).toBeInTheDocument();
    expect(screen.getByText('Payload Comparison Preview')).toBeInTheDocument();
  });

  it('submits approve action when operator clicks Approve', async () => {
    render(
      <QueryClientProvider client={queryClient}>
        <ApprovalsPage />
      </QueryClientProvider>
    );

    const approveButton = await screen.findByText('Approve & Forward');
    fireEvent.click(approveButton);

    await waitFor(() => {
      expect(fetch).toHaveBeenCalledWith(
        expect.stringContaining('/api/v1/approvals/appr-test-123456/approve'),
        expect.objectContaining({ method: 'POST' })
      );
    });
  });

  it('submits deny action when operator clicks Deny', async () => {
    render(
      <QueryClientProvider client={queryClient}>
        <ApprovalsPage />
      </QueryClientProvider>
    );

    const denyButton = await screen.findByText('Deny & Block');
    fireEvent.click(denyButton);

    await waitFor(() => {
      expect(fetch).toHaveBeenCalledWith(
        expect.stringContaining('/api/v1/approvals/appr-test-123456/deny'),
        expect.objectContaining({ method: 'POST' })
      );
    });
  });
});
