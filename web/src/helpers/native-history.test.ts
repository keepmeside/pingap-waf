import { describe, expect, it } from "vitest";
import { parseNativeLifecycle } from "./native-history";
const entry = { version: 1, kind: "released", id: "decision", epoch: "epoch", profile: "behaviour:a", domain: "a.test", client_ip: "::1", scenario: "scan", mode: "block", created_at_ms: 1000, expires_at_ms: 2000, observed_at_ms: 1500, actor: { id: null, username: "former operator" }, reason: "operator_release" };
describe("native lifecycle history", () => {
  it("reads versioned metadata and preserves the authenticated actor snapshot", () => {
    expect(parseNativeLifecycle(JSON.stringify(entry))).toEqual(entry);
  });
  it("refuses malformed, unsupported and incompatible shapes", () => {
    for (const value of [null, "invalid", "null", "[]", JSON.stringify({...entry, version:2}), JSON.stringify({...entry, observed_at_ms:"1500"}), JSON.stringify({...entry,kind:"unknown"}), JSON.stringify({...entry,kind:["released"]}), JSON.stringify({...entry,scenario:["scan"]}), JSON.stringify({...entry,mode:["block"]}), JSON.stringify({...entry,kind:["released"],scenario:["scan"],mode:["block"]})]) expect(parseNativeLifecycle(value)).toBeNull();
  });
  it("returns only known metadata and treats payload-shaped text as plain text", () => {
    const parsed = parseNativeLifecycle(JSON.stringify({...entry, domain:"<img src=x onerror=alert(1)>", body:"credential", cookie:"token"}));
    expect(parsed?.domain).toBe("<img src=x onerror=alert(1)>");
    expect(parsed).not.toHaveProperty("body"); expect(parsed).not.toHaveProperty("cookie");
  });
});
