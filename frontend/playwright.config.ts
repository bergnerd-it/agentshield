import { defineConfig, devices } from '@playwright/test';

export default defineConfig({
  testDir: './e2e',
  fullyParallel: false,
  forbidOnly: !!process.env.CI,
  retries: process.env.CI ? 2 : 0,
  workers: 1,
  reporter: 'list',
  use: {
    baseURL: 'http://127.0.0.1:8766',
    trace: 'on-first-retry',
  },
  projects: [
    {
      name: 'chromium',
      use: { ...devices['Desktop Chrome'] },
    },
  ],
  webServer: {
    command: 'cd ../backend && UV_CACHE_DIR=.uv-cache uv run agentshield start --port 8766',
    url: 'http://127.0.0.1:8766/api/v1/health',
    reuseExistingServer: true,
    timeout: 30000,
    env: {
      UV_CACHE_DIR: '.uv-cache',
      AGENTSHIELD_DEV_MODE: 'true',
      AGENTSHIELD_OPENAI_UPSTREAM_BASE_URL: 'http://127.0.0.1:8768',
      AGENTSHIELD_OPENAI_API_KEY: 'sk-synth-mock-key-12345',
      AGENTSHIELD_CUSTOM_TERMS:
        '[{"id":"approval-required","pattern":"ApprovalRequiredTerm","default_action":"REQUIRE_APPROVAL"}]',
    },
  },
});
