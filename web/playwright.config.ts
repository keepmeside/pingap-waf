import { defineConfig } from "@playwright/test";
export default defineConfig({
  testDir: "./e2e",
  timeout: 60000,
  workers: 1,
  retries: 0,
  use: {
    baseURL: process.env.PINGAP_E2E_URL || "http://127.0.0.1:3018",
    trace: "off",
    video: "off",
    screenshot: "only-on-failure",
  },
  reporter: "list",
});
