import { defineConfig } from "@playwright/test";

export default defineConfig({
  testDir: "apps/web/e2e",
  fullyParallel: false,
  workers: 1,
  retries: process.env.CI ? 1 : 0,
  timeout: 45_000,
  expect: { timeout: 10_000 },
  reporter: "line",
  outputDir: ".tmp/playwright/test-results",
  use: {
    baseURL: "http://127.0.0.1:8789",
    browserName: "chromium",
    headless: true,
    trace: "retain-on-failure"
  },
  webServer: {
    command: "node scripts/local/browser-test-server.mjs",
    url: "http://127.0.0.1:8789/api/v1/health",
    reuseExistingServer: false,
    timeout: 120_000
  }
});
