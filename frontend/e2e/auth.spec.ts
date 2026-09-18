import { expect, test } from '@playwright/test';

test.describe('Scenario 4: Unauthorized Access Security Boundaries', () => {
  test('rejects unauthenticated requests to /api/v1/approvals with HTTP 401', async ({ request }) => {
    const response = await request.get('/api/v1/approvals');
    expect(response.status()).toBe(401);

    const body = await response.json();
    expect(body.type).toBe('urn:agentshield:error:unauthorized');
    expect(body.title).toContain('Unauthorized');
  });

  test('rejects requests with invalid bearer token with HTTP 401', async ({ request }) => {
    const response = await request.get('/api/v1/approvals', {
      headers: {
        Authorization: 'Bearer invalid_synthetic_token_12345',
      },
    });
    expect(response.status()).toBe(401);
  });

  test('rejects unauthenticated requests to /api/v1/integrations with HTTP 401', async ({ request }) => {
    const response = await request.get('/api/v1/integrations');
    expect(response.status()).toBe(401);
  });

  test('rejects unauthenticated requests to /api/v1/audit/export with HTTP 401', async ({ request }) => {
    const response = await request.post('/api/v1/audit/export', {
      data: { format: 'json' },
    });
    expect(response.status()).toBe(401);
  });
});
