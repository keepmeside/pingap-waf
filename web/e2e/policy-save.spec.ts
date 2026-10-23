import { test, expect } from "@playwright/test";
const password = process.env.PINGAP_E2E_PASSWORD;
if (!password && !process.argv.includes("--list"))
  throw new Error(
    "PINGAP_E2E_PASSWORD must point to isolated canary credentials",
  );
async function login(page: import("@playwright/test").Page) {
  await expect
    .poll(
      async () => {
        try {
          return (await page.request.get("/api/health")).status();
        } catch {
          return 0;
        }
      },
      { timeout: 30000 },
    )
    .toBe(200);
  expect((await page.goto("/#/login"))?.status()).toBe(200);
  await page.locator("#account").fill("canary-admin");
  await page.locator("#password").fill(password!);
  const response = page.waitForResponse(
    (r) =>
      r.url().includes("/api/auth/login") && r.request().method() === "POST",
  );
  await page.locator("#password").press("Enter");
  expect((await response).status()).toBe(200);
  await expect
    .poll(() => page.evaluate(() => localStorage.getItem("pingap:loginToken")))
    .toBeTruthy();
  await expect(page).not.toHaveURL(/#\/login/);
  await page.goto("/#/waf");
  await expect(page.getByRole("button", { name: "New profile" })).toBeVisible();
}
test("real UI save creates applied policy and survives refresh", async ({
  page,
}) => {
  await login(page);
  await page.getByRole("button", { name: "New profile" }).click();
  const name = `canary-${Date.now()}`;
  await page.locator("#waf-name").fill(name);
  const saved = page.waitForResponse(
    (r) =>
      r.url().includes(`/api/policies/waf%3A${name}`) &&
      r.request().method() === "PUT",
  );
  await page.getByRole("button", { name: "Save profile" }).click();
  const response = await saved;
  expect(response.request().postDataJSON().category).toBe("waf");
  expect(response.status()).toBe(200);
  expect((await response.json()).status).toBe("applied");
  await expect(page.getByRole("cell", { name, exact: true })).toBeVisible();
  await page.reload();
  await expect(page.getByRole("cell", { name, exact: true })).toBeVisible();
  const token = await page.evaluate(() =>
    localStorage.getItem("pingap:loginToken"),
  );
  const versions = await page.request.get("/api/config-versions", {
    headers: { Authorization: `Bearer ${token}` },
  });
  expect(versions.ok()).toBeTruthy();
  expect(
    (await versions.json()).some(
      (v: { status: string }) => v.status === "applied",
    ),
  ).toBeTruthy();
});
test("API rejects mismatched category before version creation", async ({
  page,
}) => {
  await login(page);
  const token = await page.evaluate(() =>
    localStorage.getItem("pingap:loginToken"),
  );
  const headers = { Authorization: `Bearer ${token}` };
  const before = await (
    await page.request.get("/api/config-versions", { headers })
  ).json();
  const result = await page.request.put("/api/policies/waf%3Amismatch", {
    headers,
    data: { category: "acl" },
  });
  expect(result.status()).toBe(400);
  const after = await (
    await page.request.get("/api/config-versions", { headers })
  ).json();
  expect(after).toEqual(before);
});
test("structured errors remain readable without logging out", async ({
  page,
}) => {
  await login(page);
  for (const status of [400, 403, 409, 503]) {
    await page.route("**/api/policies/*", (route) =>
      route.request().method() === "PUT"
        ? route.fulfill({
            status,
            contentType: "application/json",
            body: JSON.stringify({
              error: `canary refusal ${status}`,
              action: "check configuration",
            }),
          })
        : route.continue(),
    );
    await page.getByRole("button", { name: "New profile" }).click();
    await page.locator("#waf-name").fill(`refusal-${status}`);
    await page.getByRole("button", { name: "Save profile" }).click();
    await expect(
      page.getByText(new RegExp(`canary refusal ${status}`)),
    ).toBeVisible();
    expect(
      await page.evaluate(() => localStorage.getItem("pingap:loginToken")),
    ).toBeTruthy();
    await page.getByRole("button", { name: "Cancel", exact: true }).click();
    await page.unroute("**/api/policies/*");
  }
});

test("viewer cannot mutate through UI or direct API after account switch", async ({
  page,
}) => {
  await login(page);
  const token = await page.evaluate(() =>
    localStorage.getItem("pingap:loginToken"),
  );
  const username = `canary-viewer-${Date.now()}`;
  const created = await page.request.post("/api/users", {
    headers: { Authorization: `Bearer ${token}` },
    data: {
      username,
      email: `${username}@canary.invalid`,
      password,
      role: "viewer",
    },
  });
  expect(created.ok()).toBeTruthy();
  await page.getByRole("button", { name: "Settings", exact: true }).click();
  await page
    .getByRole("menuitem", { name: /logout|log out|sign out/i })
    .click();
  await expect(page).toHaveURL(/#\/login/);
  const rawReads: string[] = [];
  page.on("request", (r) => {
    if (r.url().includes("/api/configs")) rawReads.push(r.url());
  });
  await page.locator("#account").fill(username);
  await page.locator("#password").fill(password!);
  await page.locator("#password").press("Enter");
  await expect(page).not.toHaveURL(/#\/login/);
  // Keep the same SPA/provider so old administrator queries cannot mask a role change.
  await page.evaluate(() => {
    window.location.hash = "#/waf";
  });
  await expect(
    page.getByRole("heading", { name: "WAF", exact: true }),
  ).toBeVisible();
  await expect(page.getByRole("button", { name: "New profile" })).toHaveCount(
    0,
  );
  const viewerToken = await page.evaluate(() =>
    localStorage.getItem("pingap:loginToken"),
  );
  const denied = await page.request.put("/api/policies/waf%3Aviewer-denied", {
    headers: { Authorization: `Bearer ${viewerToken}` },
    data: { category: "waf" },
  });
  expect(denied.status()).toBe(403);
  expect(rawReads).toEqual([]);
});

test("timeout reads versions and reports unconfirmed outcome without retrying", async ({
  page,
}) => {
  await login(page);
  let writes = 0,
    versionReads = 0;
  page.on("request", (r) => {
    if (r.url().includes("/api/config-versions")) versionReads++;
  });
  await page.route("**/api/policies/*", async (route) => {
    if (route.request().method() !== "PUT") return route.continue();
    writes++;
    await new Promise((resolve) => setTimeout(resolve, 21000));
    await route.abort().catch(() => undefined);
  });
  await page.getByRole("button", { name: "New profile" }).click();
  await page.locator("#waf-name").fill("timeout-uncertain");
  await page.getByRole("button", { name: "Save profile" }).click();
  await expect(
    page.getByText("Save outcome unconfirmed", { exact: true }),
  ).toBeVisible({ timeout: 30000 });
  expect(writes).toBe(1);
  expect(versionReads).toBeGreaterThan(0);
  expect(
    await page.evaluate(() => localStorage.getItem("pingap:loginToken")),
  ).toBeTruthy();
});
