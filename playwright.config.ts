import { defineConfig, devices } from '@playwright/test';
export default defineConfig({
  testDir: './tests/e2e', fullyParallel: false, workers: 1,
  use: { baseURL: 'http://127.0.0.1:3101', trace: 'retain-on-failure' },
  webServer: { command: 'node node_modules/next/dist/bin/next dev --hostname 127.0.0.1 --port 3101', url: 'http://127.0.0.1:3101', reuseExistingServer: false, env: { NEXT_TELEMETRY_DISABLED: '1' } },
  projects: [{ name: 'chromium', use: { ...devices['Desktop Chrome'] } }],
});
