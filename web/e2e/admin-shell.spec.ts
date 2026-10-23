import { test, expect, type Page } from "@playwright/test";
async function login(page: Page) {
  await page.goto("/#/login");
  await page.locator("#account").fill("canary-admin");
  await page.locator("#password").fill(process.env.PINGAP_E2E_PASSWORD!);
  await page.locator("#password").press("Enter");
  await expect
    .poll(() => page.evaluate(() => localStorage.getItem("pingap:loginToken")))
    .toBeTruthy();
}
const row = (metric: string, value: number) => ({
  id: metric,
  node: "fixture-node",
  metric,
  value,
  bucket_start: 1700000000,
  bucket_secs: 60,
});
const fixture = {
  metrics: [
    row("waf.findings", 12),
    row("waf.blocks", 3),
    row("waf.category.sqli", 6),
    row("waf.rule.942100", 6),
  ],
  drift: { status: "in_sync", version_id: "fixture-only" },
};
test("console visual matrix, routes, missing analytics and safe event details", async ({
  page,
}, info) => {
  test.setTimeout(240000);
  await login(page);
  await page.route("**/api/dashboard", (route) =>
    route.fulfill({ json: fixture }),
  );
  await page.reload();
  await expect(page.getByText("12", { exact: true })).toBeVisible();
  for (const width of [390, 768, 1440]) {
    await page.setViewportSize({ width, height: 1000 });
    await page.goto("/#/dashboard");
    await expect(
      page.getByRole("tab", { name: "BASIC", exact: true }),
    ).toBeVisible();
    await page.getByRole("tab", { name: "BASIC", exact: true }).click();
    await expect(
      page.getByText("Geography unavailable", { exact: true }),
    ).toBeVisible();
    await expect(
      page.getByRole("button", { name: "24 hours", exact: true }),
    ).toBeDisabled();
    await expect
      .poll(() =>
        page.evaluate(() => document.documentElement.scrollWidth <= innerWidth),
      )
      .toBe(true);
    await page.screenshot({
      path: info.outputPath(`dashboard-basic-${width}.png`),
      fullPage: true,
      animations: "disabled",
    });
    await page.getByRole("tab", { name: "ADVANCED", exact: true }).click();
    await expect(
      page.getByText("Response Status", { exact: true }),
    ).toBeVisible();
    await page.screenshot({
      path: info.outputPath(`dashboard-advanced-${width}.png`),
      fullPage: true,
      animations: "disabled",
    });
  }
  await page.route("**/api/domains", (r) =>
    r.fulfill({
      json: {
        demo: {
          hostnames: ["fixture.test"],
          listener: "http",
          upstream: "app",
          grpc_web: false,
          policies: [{ waf: "strict" }],
        },
      },
    }),
  );
  await page.route("**/api/listeners", (r) =>
    r.fulfill({ json: { http: { addr: "0.0.0.0:8080", tls: null } } }),
  );
  await page.goto("/#/domains");
  await expect(
    page.getByRole("cell", { name: "fixture.test", exact: true }),
  ).toBeVisible();
  for (const width of [390, 768, 1440]) {
    await page.setViewportSize({ width, height: 1000 });
    await expect
      .poll(() =>
        page.evaluate(() => document.documentElement.scrollWidth <= innerWidth),
      )
      .toBe(true);
    await page.screenshot({
      path: info.outputPath(`sites-populated-${width}.png`),
      fullPage: true,
      animations: "disabled",
    });
  }
  await page.route("**/api/logs/waf-events*", (r) =>
    r.fulfill({
      json: [
        {
          id: "fixture-event",
          node: "fixture-node",
          domain: "fixture.test",
          profile: "waf:strict",
          score: 5,
          blocked: true,
          client_ip: "192.0.2.1",
          method: "GET",
          uri: '/<img src=x onerror="window.bad=1">',
          created_at: 1700000000,
          category: "sqli",
        },
      ],
    }),
  );
  await page.goto("/#/logs");
  await page.getByRole("button", { name: "View event", exact: true }).click();
  await expect(page.getByRole("dialog")).toBeVisible();
  await expect(
    page.getByRole("dialog").getByText(/Headers: not captured/),
  ).toBeVisible();
  await expect(page.getByRole("dialog").locator("img")).toHaveCount(0);
  for (const width of [390, 768, 1440]) {
    await page.setViewportSize({ width, height: 1000 });
    await page.screenshot({
      path: info.outputPath(`event-detail-${width}.png`),
      fullPage: true,
      animations: "disabled",
    });
  }
  await page.getByRole("tab", { name: "Response", exact: true }).click();
  await expect(
    page.getByText("Status: not captured", { exact: false }),
  ).toBeVisible();
  await page.keyboard.press("Escape");
  await expect(page.getByRole("dialog")).toHaveCount(0);
  await page.unroute("**/api/dashboard");
  await page.route("**/api/dashboard", (r) =>
    r.fulfill({ json: { metrics: [], drift: { status: "no_baseline" } } }),
  );
  await page.goto("/#/dashboard");
  await page.reload();
  await expect(page.getByText("No data", { exact: true })).toHaveCount(2);
  for (const width of [390, 768, 1440]) {
    await page.setViewportSize({ width, height: 1000 });
    await page.screenshot({
      path: info.outputPath(`dashboard-empty-${width}.png`),
      fullPage: true,
      animations: "disabled",
    });
  }
  await page.unroute("**/api/domains");
  await page.route("**/api/domains", (r) => r.fulfill({ json: {} }));
  await page.goto("/#/domains");
  await expect(page.getByText("No domains", { exact: true })).toBeVisible();
  for (const width of [390, 768, 1440]) {
    await page.setViewportSize({ width, height: 1000 });
    await page.screenshot({
      path: info.outputPath(`sites-empty-${width}.png`),
      fullPage: true,
      animations: "disabled",
    });
  }
  for (const status of [403, 503]) {
    await page.unroute("**/api/dashboard");
    await page.route("**/api/dashboard", (r) =>
      r.fulfill({
        status,
        json: {
          error:
            status === 503
              ? "Store temporarily unavailable"
              : "Permission denied",
        },
      }),
    );
    await page.goto("/#/dashboard");
    await page.reload();
    await expect(page.getByRole("alert")).toContainText(
      status === 503 ? "Store temporarily unavailable" : "Permission denied",
    );
    await expect(page).not.toHaveURL(/login/);
  }
  await page.unroute("**/api/dashboard");
  for (const path of [
    "dashboard",
    "domains",
    "upstreams",
    "listeners",
    "ssl",
    "waf",
    "acl",
    "access-lists",
    "bot-manager",
    "logs",
    "alerts",
    "performance",
    "backup",
    "nodes",
    "users",
    "account",
    "config-history",
    "basic",
    "servers",
    "locations",
    "upstreams-config",
    "plugins",
    "certificates",
    "storages",
    "config",
  ]) {
    await page.goto("/#/" + path);
    await expect(page.locator("header")).toBeVisible();
    await expect(
      page.getByText("Unexpected Application Error!", { exact: true }),
    ).toHaveCount(0);
  }
  await page.goto("/#/dashboard");
  await page.keyboard.press("Tab");
  await expect
    .poll(() => page.evaluate(() => document.activeElement?.tagName))
    .not.toBe("BODY");
  const adminToken = await page.evaluate(() =>
    localStorage.getItem("pingap:loginToken"),
  );
  const viewer = "shell-viewer";
  expect(
    (
      await page.request.post("/api/users", {
        headers: { Authorization: `Bearer ${adminToken}` },
        data: {
          username: viewer,
          email: "viewer@canary.invalid",
          password: process.env.PINGAP_E2E_PASSWORD,
          role: "viewer",
        },
      })
    ).ok(),
  ).toBeTruthy();
  await page.getByRole("button", { name: "Settings", exact: true }).click();
  await page
    .getByRole("menuitem", { name: /logout|log out|sign out/i })
    .click();
  await expect(page).toHaveURL(/login/);
  await page.locator("#account").fill(viewer);
  await page.locator("#password").fill(process.env.PINGAP_E2E_PASSWORD!);
  await page.locator("#password").press("Enter");
  await expect(page).not.toHaveURL(/login/);
  await page.goto("/#/bot-manager");
  await expect(
    page.getByRole("button", {
      name: "New native scenario profile",
      exact: true,
    }),
  ).toHaveCount(0);
  await expect(
    page.getByRole("button", { name: "Release ban", exact: true }),
  ).toHaveCount(0);
  await page.screenshot({
    path: info.outputPath("native-empty-viewer.png"),
    fullPage: true,
    animations: "disabled",
  });
});
