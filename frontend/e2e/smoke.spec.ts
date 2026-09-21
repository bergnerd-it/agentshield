import { test, expect } from '@playwright/test';
import { authenticateDashboard, getAdminTokenForTest } from './helpers.ts';

test.describe('Production Build Smoke Test', () => {
  test('serves the single page application and renders system status', async ({ page }) => {
    await authenticateDashboard(page, getAdminTokenForTest());

    // Verify main brand heading
    await expect(page.getByRole('heading', { name: 'AgentShield' })).toBeVisible();

    // Verify status banner and dashboard content
    await expect(page.getByText(/Profile:/i)).toBeVisible();
    await expect(page.getByRole('heading', { name: 'Security Dashboard' })).toBeVisible();
    await expect(page.getByText('Active Security Profile')).toBeVisible();

    // Navigate to tabs
    await page.getByRole('tab', { name: 'Live Traffic' }).click();
    await expect(page.getByRole('heading', { name: 'Live Traffic' })).toBeVisible();

    await page.getByRole('tab', { name: 'Policies' }).click();
    await expect(page.getByRole('heading', { name: 'Security Policies' })).toBeVisible();

    await page.getByRole('tab', { name: 'Settings' }).click();
    await expect(page.getByRole('heading', { name: 'System Settings' })).toBeVisible();
  });
});
