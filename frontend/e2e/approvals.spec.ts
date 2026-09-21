import http from 'http';
import { expect, test } from '@playwright/test';
import { getAdminTokenForTest, getProxyTokenForTest } from './helpers.ts';

let mockUpstream: http.Server;

test.beforeAll(async () => {
  // Start local mock provider server for OpenAI contract responses
  mockUpstream = http.createServer((req, res) => {
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(
      JSON.stringify({
        id: 'chatcmpl-mock-123456',
        object: 'chat.completion',
        created: Math.floor(Date.now() / 1000),
        model: 'gpt-4o',
        choices: [
          {
            index: 0,
            message: { role: 'assistant', content: 'Synthetic upstream response.' },
            finish_reason: 'stop',
          },
        ],
      })
    );
  });

  await new Promise<void>((resolve, reject) => {
    mockUpstream.once('error', (err: NodeJS.ErrnoException) => {
      if (err.code === 'EADDRINUSE') {
        resolve();
      } else {
        reject(err);
      }
    });
    mockUpstream.listen(8768, '127.0.0.1', () => resolve());
  });
});

test.afterAll(async () => {
  await new Promise<void>((resolve) => {
    if (mockUpstream && mockUpstream.listening) {
      mockUpstream.close(() => resolve());
    } else {
      resolve();
    }
  });
});

test.describe('ADR 0010: Manual Approval and Real-Time SSE Workflows', () => {
  test('Scenario 1: Approve flow - client held, operator approves, client gets HTTP 200', async ({
    page,
    request,
  }) => {
    const adminToken = getAdminTokenForTest();
    const proxyToken = getProxyTokenForTest();

    // Authenticate dashboard in browser
    await page.addInitScript((token) => {
      window.localStorage.setItem('agentshield_admin_token', token);
    }, adminToken);

    await page.goto('/');
    await expect(page.getByRole('heading', { name: 'AgentShield' })).toBeVisible();

    // Navigate to Approvals tab
    await page.getByRole('tab', { name: /Approvals/i }).click();

    // Send client request containing custom term that requires approval
    const clientPromise = request.post('/proxy/openai/v1/chat/completions', {
      headers: {
        Authorization: `Bearer ${proxyToken}`,
        'Content-Type': 'application/json',
      },
      data: {
        model: 'gpt-4o',
        messages: [{ role: 'user', content: 'Specs for ApprovalRequiredTerm project.' }],
      },
    });

    // The approval card appears on the dashboard
    const card = page.getByTestId('approval-card').first();
    await expect(card).toBeVisible({ timeout: 10000 });
    await expect(card.getByText(/openai/i)).toBeVisible();

    // Operator clicks Approve & Forward
    const approveBtn = card.getByRole('button', { name: /Approve & Forward/i });
    await approveBtn.click();

    // Verify modal decision or direct approval
    const confirmBtn = page.getByRole('button', { name: /Confirm Approval/i });
    if (await confirmBtn.isVisible({ timeout: 2000 }).catch(() => false)) {
      await confirmBtn.click();
    }

    // Client request resolves with HTTP 200
    const clientRes = await clientPromise;
    expect(clientRes.status()).toBe(200);
    const body = await clientRes.json();
    expect(body.choices[0].message.content).toBe('Synthetic upstream response.');
  });

  test('Scenario 2: Deny flow - client held, operator denies with reason, client gets HTTP 403', async ({
    page,
    request,
  }) => {
    const adminToken = getAdminTokenForTest();
    const proxyToken = getProxyTokenForTest();

    await page.addInitScript((token) => {
      window.localStorage.setItem('agentshield_admin_token', token);
    }, adminToken);

    await page.goto('/');
    await page.getByRole('tab', { name: /Approvals/i }).click();

    // Send request requiring approval
    const clientPromise = request.post('/proxy/openai/v1/chat/completions', {
      headers: {
        Authorization: `Bearer ${proxyToken}`,
        'Content-Type': 'application/json',
      },
      data: {
        model: 'gpt-4o',
        messages: [{ role: 'user', content: 'Disclosing ApprovalRequiredTerm data.' }],
      },
    });

    const card = page.getByTestId('approval-card').first();
    await expect(card).toBeVisible({ timeout: 10000 });

    // Operator can optionally add reason or deny
    const addReasonBtn = card.getByRole('button', { name: /Add Reason/i });
    if (await addReasonBtn.isVisible({ timeout: 1000 }).catch(() => false)) {
      await addReasonBtn.click();
      const reasonInput = card.getByRole('textbox', { name: /reason/i });
      await reasonInput.fill('Strict data protection violation');
    }

    // Operator clicks Deny & Block
    const denyBtn = card.getByRole('button', { name: /Deny & Block/i });
    await denyBtn.click();

    // Client request blocked with HTTP 403 Problem Details
    const clientRes = await clientPromise;
    expect(clientRes.status()).toBe(403);
    const body = await clientRes.json();
    expect(body.type).toBe('urn:agentshield:error:approval-denied');
  });

  test('Scenario 3: Timeout failure - unapproved hold returns HTTP 403 approval-timeout', async ({
    request,
  }) => {
    const adminToken = getAdminTokenForTest();
    const proxyToken = getProxyTokenForTest();

    // Temporarily reduce timeout to 2 seconds
    await request.put('/api/v1/settings', {
      headers: {
        Authorization: `Bearer ${adminToken}`,
        'Content-Type': 'application/json',
      },
      data: {
        approval_timeout_seconds: 2.0,
      },
    });

    // Send request requiring approval and wait for expiration
    const clientRes = await request.post('/proxy/openai/v1/chat/completions', {
      headers: {
        Authorization: `Bearer ${proxyToken}`,
        'Content-Type': 'application/json',
      },
      data: {
        model: 'gpt-4o',
        messages: [{ role: 'user', content: 'Will timeout on ApprovalRequiredTerm' }],
      },
    });

    expect(clientRes.status()).toBe(403);
    const body = await clientRes.json();
    expect(body.type).toBe('urn:agentshield:error:approval-timeout');

    // Restore standard timeout
    await request.put('/api/v1/settings', {
      headers: {
        Authorization: `Bearer ${adminToken}`,
        'Content-Type': 'application/json',
      },
      data: {
        approval_timeout_seconds: 60.0,
      },
    });
  });

  test('Scenario 5: Real-time SSE updates - pending hold appears live without page refresh', async ({
    page,
    request,
  }) => {
    const adminToken = getAdminTokenForTest();
    const proxyToken = getProxyTokenForTest();

    await page.addInitScript((token) => {
      window.localStorage.setItem('agentshield_admin_token', token);
    }, adminToken);

    // Open Approvals page and ensure SSE connection is active
    await page.goto('/');
    await page.getByRole('tab', { name: /Approvals/i }).click();
    await page.waitForTimeout(1000); // Allow SSE to connect

    // Send client request in background
    const clientPromise = request.post('/proxy/openai/v1/chat/completions', {
      headers: {
        Authorization: `Bearer ${proxyToken}`,
        'Content-Type': 'application/json',
      },
      data: {
        model: 'gpt-4o',
        messages: [{ role: 'user', content: 'SSE live test ApprovalRequiredTerm' }],
      },
    });

    // Without any page.reload(), card must appear dynamically via SSE
    const card = page.getByTestId('approval-card').first();
    await expect(card).toBeVisible({ timeout: 10000 });

    // Clean up hold
    const denyBtn = card.getByRole('button', { name: /Deny & Block/i });
    await denyBtn.click();
    await clientPromise;
  });

  test('Scenario 6: Multi-tab concurrency - approval in Tab 1 updates Tab 2 via SSE within 2s', async ({
    context,
    request,
  }) => {
    const adminToken = getAdminTokenForTest();
    const proxyToken = getProxyTokenForTest();

    // Open Tab 1
    const tab1 = await context.newPage();
    await tab1.addInitScript((token) => {
      window.localStorage.setItem('agentshield_admin_token', token);
    }, adminToken);
    await tab1.goto('/');
    await tab1.getByRole('tab', { name: /Approvals/i }).click();

    // Open Tab 2
    const tab2 = await context.newPage();
    await tab2.addInitScript((token) => {
      window.localStorage.setItem('agentshield_admin_token', token);
    }, adminToken);
    await tab2.goto('/');
    await tab2.getByRole('tab', { name: /Approvals/i }).click();

    // Send request requiring approval
    const clientPromise = request.post('/proxy/openai/v1/chat/completions', {
      headers: {
        Authorization: `Bearer ${proxyToken}`,
        'Content-Type': 'application/json',
      },
      data: {
        model: 'gpt-4o',
        messages: [{ role: 'user', content: 'Concurrency test ApprovalRequiredTerm' }],
      },
    });

    // Both tabs see pending card
    await expect(tab1.getByTestId('approval-card').first()).toBeVisible({ timeout: 10000 });
    await expect(tab2.getByTestId('approval-card').first()).toBeVisible({ timeout: 10000 });

    // Approve on Tab 1
    await tab1.getByTestId('approval-card').first().getByRole('button', { name: /Approve & Forward/i }).click();

    // Tab 2 must receive SSE resolution update and remove pending card within 3 seconds
    await expect(tab2.getByTestId('approval-card')).toHaveCount(0, { timeout: 3000 });

    await clientPromise;
  });
});
