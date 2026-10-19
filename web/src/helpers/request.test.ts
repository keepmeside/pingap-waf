import { beforeEach, describe, it, expect, vi } from "vitest";
const activeSession = vi.hoisted(() => ({ token: "fixture" }));
vi.mock("@/states/token", () => ({
  getLoginToken: () => activeSession.token,
  removeLoginToken: vi.fn(),
}));
import request from "./request";
import { removeLoginToken } from "@/states/token";
async function failed(
  status: number | undefined,
  data: unknown,
  code?: string,
) {
  return request
    .get("/test", {
      adapter: async (config) =>
        Promise.reject({
          code,
          config,
          response: status ? { status, data, config } : undefined,
        }),
    })
    .catch((e) => e);
}
describe("request errors", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    activeSession.token = "fixture";
    vi.stubGlobal("window", { location: { hash: "#/waf" } });
  });
  it.each([400, 409, 503])(
    "formats structured backend %i without object coercion",
    async (status) => {
      const e = await failed(status, {
        error: "invalid profile",
        action: "fix category",
      });
      expect(e.status).toBe(status);
      expect(e.message).toContain("invalid profile");
      expect(e.message).toContain("fix category");
      expect(typeof e.message).toBe("string");
      expect(removeLoginToken).not.toHaveBeenCalled();
    },
  );
  it("clears session only for401", async () => {
    await failed(403, { error: "denied" });
    expect(removeLoginToken).not.toHaveBeenCalled();
    await failed(401, { error: "expired" });
    expect(removeLoginToken).toHaveBeenCalledOnce();
  });
  it("handles no-response network errors", async () => {
    const e = await failed(undefined, undefined);
    expect(e.status).toBe(0);
    expect(typeof e.message).toBe("string");
  });
  it("marks timed-out writes as uncertain and keeps session", async () => {
    const e = await failed(undefined, undefined, "ECONNABORTED");
    expect(e.category).toBe("timeout");
    expect(e.message).toMatch(/check|reload|reconcile/i);
    expect(removeLoginToken).not.toHaveBeenCalled();
  });
  it("does not stringify arbitrary object errors", async () => {
    const e = await failed(500, { internal: { token: "must-not-display" } });
    expect(e.message).not.toContain("must-not-display");
    expect(typeof e.message).toBe("string");
  });
});

import { putConfig } from "./config-write";
it("reconciles timed-out writes by reading versions without repeating PUT", async () => {
  const calls: string[] = [];
  const adapter = async (
    config: import("axios").InternalAxiosRequestConfig,
  ) => {
    calls.push(config.method!);
    if (config.method === "put") throw { config, code: "ECONNABORTED" };
    return { config, status: 200, statusText: "OK", headers: {}, data: [] };
  };
  const result = await putConfig(
    "/policies/waf:test",
    { category: "waf" },
    { adapter },
  ).catch((e) => e);
  expect(result).toHaveProperty("category", "timeout");
  expect(calls).toEqual(["put", "get"]);
});

it("an old request401 cannot revoke a replacement login session", async () => {
  vi.clearAllMocks();
  vi.stubGlobal("window", { location: { hash: "#/waf" } });
  activeSession.token = "old-session";
  const error = await request
    .get("/old-request", {
      adapter: async (config) => {
        activeSession.token = "replacement-session";
        throw {
          config,
          response: {
            status: 401,
            data: { error: "expired old session" },
            config,
          },
        };
      },
    })
    .catch((e) => e);
  expect(error.status).toBe(401);
  expect(removeLoginToken).not.toHaveBeenCalled();
});
