import { describe, expect, it } from "vitest";
import { mergeNativePluginConfig } from "@/helpers/plugin-config";

describe("mergeNativePluginConfig", () => {
  it("retains native fields omitted by the advanced editor", () => {
    const existing = {
      category: "behaviour",
      enabled: true,
      abuse: { enabled: true, scan: { threshold: 4 } },
      abuse_namespace: "behaviour:edge",
    };
    expect(
      mergeNativePluginConfig("behaviour", existing, {
        category: "behaviour",
        remark: "kept",
      }),
    ).toEqual({ ...existing, remark: "kept" });
  });

  it("keeps replacement semantics for regular plugins and new profiles", () => {
    const existing = { category: "waf", enabled: true, rules: ["old"] };
    const draft = { category: "waf", enabled: false };
    expect(mergeNativePluginConfig("waf", existing, draft)).toBe(draft);
    expect(mergeNativePluginConfig("behaviour", {}, draft)).toBe(draft);
  });
});
