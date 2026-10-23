import { test, expect } from "@playwright/test";
import { createHmac } from "node:crypto";
function code(secret: string) {
  const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
  let bits = "";
  for (const c of secret.toUpperCase().replace(/=+$/, ""))
    bits += alphabet.indexOf(c).toString(2).padStart(5, "0");
  const key = Buffer.from(
    (bits.match(/.{8}/g) ?? []).map((b) => parseInt(b, 2)),
  );
  const counter = Buffer.alloc(8);
  counter.writeBigUInt64BE(BigInt(Math.floor(Date.now() / 30000)));
  const h = createHmac("sha1", key).update(counter).digest();
  const o = h[19] & 15;
  return String((h.readUInt32BE(o) & 0x7fffffff) % 1000000).padStart(6, "0");
}
test("native scenario UI roundtrip, real ban and authorized release", async ({
  page,
}, info) => {
  test.setTimeout(240000);
  await page.goto("/#/login");
  await page.locator("#account").fill("canary-admin");
  await page.locator("#password").fill(process.env.PINGAP_E2E_PASSWORD!);
  await page.locator("#password").press("Enter");
  await expect
    .poll(() => page.evaluate(() => localStorage.getItem("pingap:loginToken")))
    .toBeTruthy();
  let token = (await page.evaluate(() =>
    localStorage.getItem("pingap:loginToken"),
  ))!;
  let headers = { Authorization: `Bearer ${token}` };
  const put = async (path: string, data: unknown) => {
    const r = await page.request.put("/api" + path, { headers, data });
    expect(r.status(), await r.text()).toBe(200);
    expect((await r.json()).status).toBe("applied");
  };
  await put("/upstreams/app", {
    backends: [{ addr: "fixture:8081", weight: null }],
  });
  await put("/listeners/http", { addr: "0.0.0.0:8080" });
  const setup = await page.request.post("/api/account/2fa/setup", {
    headers,
    data: {},
  });
  expect(setup.status()).toBe(200);
  const secret = new URL((await setup.json()).otpauth_uri).searchParams.get(
    "secret",
  )!;
  expect(
    (
      await page.request.post("/api/account/2fa/enable", {
        headers,
        data: { code: code(secret) },
      })
    ).status(),
  ).toBe(204);
  const relogin = await page.request.post("/api/auth/login", {
    data: {
      username: "canary-admin",
      password: process.env.PINGAP_E2E_PASSWORD,
    },
  });
  expect(relogin.status()).toBe(200);
  token = (await relogin.json()).token;
  headers = { Authorization: `Bearer ${token}` };
  // A TOTP used to enroll cannot be replayed to elevate a new session.
  await page.waitForTimeout(31000);
  expect(
    (
      await page.request.post("/api/auth/totp", {
        headers,
        data: { code: code(secret) },
      })
    ).status(),
  ).toBe(204);
  await page.evaluate(
    (token) => localStorage.setItem("pingap:loginToken", token),
    token,
  );
  await page.goto("/#/bot-manager");
  await page.reload();
  await page
    .getByRole("button", { name: "New native scenario profile", exact: true })
    .click();
  await page
    .getByLabel("Native profile name", { exact: true })
    .fill("browser-native");
  await page
    .getByLabel("Scenario", { exact: true })
    .selectOption("failed_login");
  await page.getByLabel("Scenario mode", { exact: true }).selectOption("block");
  await page.getByLabel("Threshold", { exact: true }).fill("3");
  await page.getByLabel("Observation window", { exact: true }).fill("30s");
  await page.getByLabel("Ban lifetime", { exact: true }).fill("2m");
  await page.getByLabel("Exact login path", { exact: true }).fill("/login");
  await page.getByLabel("Exact login method", { exact: true }).fill("POST");
  await page
    .getByLabel("Upstream failure statuses", { exact: true })
    .fill("401");
  await page.getByLabel("Use direct peer identity", { exact: true }).check();
  const saved = page.waitForResponse(
    (r) =>
      r.url().includes("/api/policies/behaviour%3Abrowser-native") &&
      r.request().method() === "PUT",
  );
  await page
    .getByRole("button", { name: "Save native scenario", exact: true })
    .click();
  expect((await saved).status()).toBe(200);
  await page.reload();
  await page
    .getByRole("button", { name: "Edit behaviour:browser-native", exact: true })
    .click();
  await expect(
    page.getByLabel("Exact login path", { exact: true }),
  ).toHaveValue("/login");
  await expect(page.getByLabel("Threshold", { exact: true })).toHaveValue("3");
  await expect(page.getByLabel("Scenario mode", { exact: true })).toHaveValue(
    "block",
  );
  await page
    .getByRole("button", { name: "Close scenario editor", exact: true })
    .click();
  await put("/domains/site", {
    hostnames: ["site.test"],
    listener: "http",
    upstream: "app",
    grpc_web: false,
    policies: [{ behaviour: "browser-native" }],
  });
  await put("/domains/control", {
    hostnames: ["control.test"],
    listener: "http",
    upstream: "app",
    grpc_web: false,
    policies: [],
  });
  const traffic = async (host: string, path = "/", method = "GET") =>
    page.request.fetch("http://candidate:8080" + path, {
      method,
      headers: { Host: host },
    });
  expect((await traffic("site.test")).status()).toBe(200);
  for (let i = 0; i < 3; i++)
    expect((await traffic("site.test", "/login", "POST")).status()).toBe(401);
  expect((await traffic("site.test")).status()).toBe(403);
  expect((await traffic("control.test")).status()).toBe(200);
  await page.getByRole("button", { name: "Refresh bans", exact: true }).click();
  await expect(
    page.getByRole("button", { name: "Release ban", exact: true }),
  ).toBeVisible();
  for (const width of [390, 768, 1440]) {
    await page.setViewportSize({ width, height: 1000 });
    await expect
      .poll(() =>
        page.evaluate(() => document.documentElement.scrollWidth <= innerWidth),
      )
      .toBe(true);
    await page
      .getByText("Active temporary bans", { exact: true })
      .scrollIntoViewIfNeeded();
    await page.screenshot({
      path: info.outputPath(`native-bans-${width}.png`),
      animations: "disabled",
    });
  }
  await page.getByRole("button", { name: "Release ban", exact: true }).click();
  await expect(
    page.getByRole("status").filter({ hasText: "Ban released" }),
  ).toBeVisible();
  expect((await traffic("site.test")).status()).toBe(200);
  const inspected = await page.request.get(
    "/api/policies/behaviour%3Abrowser-native",
    { headers },
  );
  const conf = await inspected.json();
  expect(conf.abuse.failed_login).toMatchObject({
    path: "/login",
    method: "POST",
    statuses: [401],
    threshold: 3,
    window: "30s",
    ban_ttl: "2m",
    mode: "block",
  });

  await expect
    .poll(
      async () => {
        const r = await page.request.get("/api/activity", { headers });
        return (await r.json()).some(
          (row: { action: string }) => row.action === "native.ban.released",
        );
      },
      { timeout: 10000 },
    )
    .toBe(true);
  await page.getByRole("button", { name: "Refresh bans", exact: true }).click();
  await expect(page.getByText("No active bans", { exact: true })).toBeVisible();
  await page.screenshot({
    path: info.outputPath("native-bans-empty.png"),
    animations: "disabled",
  });
  for (let i = 0; i < 3; i++)
    expect((await traffic("site.test", "/login", "POST")).status()).toBe(401);
  expect((await traffic("site.test")).status()).toBe(403);
  // Leave the isolated admin account in its pre-test state for the following
  // Playwright cases, which intentionally exercise password-only login.
  expect(
    (
      await page.request.post("/api/account/2fa/disable", {
        headers,
        data: { code: code(secret) },
      })
    ).status(),
  ).toBe(204);
  const banPage = await (
    await page.request.get("/api/abuse/bans", { headers })
  ).json();
  const ban = banPage.items[0];
  expect(ban).toBeTruthy();
  expect(
    (
      await page.request.post("/api/users", {
        headers,
        data: {
          username: "native-viewer",
          email: "native@canary.invalid",
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
  await page.locator("#account").fill("native-viewer");
  await page.locator("#password").fill(process.env.PINGAP_E2E_PASSWORD!);
  await page.locator("#password").press("Enter");
  await expect(page).not.toHaveURL(/login/);
  await page.goto("/#/bot-manager");
  await expect(page.getByText("Read only", { exact: true })).toBeVisible();
  await expect(
    page.getByRole("button", { name: "Release ban", exact: true }),
  ).toHaveCount(0);
  await expect(
    page.getByRole("button", {
      name: "New native scenario profile",
      exact: true,
    }),
  ).toHaveCount(0);
  const viewerToken = await page.evaluate(() =>
    localStorage.getItem("pingap:loginToken"),
  );
  expect(
    (
      await page.request.delete("/api/abuse/bans/" + ban.id, {
        headers: { Authorization: `Bearer ${viewerToken}` },
        data: {
          profile: ban.profile,
          domain: ban.domain,
          client_ip: ban.client_ip,
        },
      })
    ).status(),
  ).toBe(403);
});
