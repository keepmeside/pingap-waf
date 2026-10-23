import { describe, it, expect } from "vitest";
import { renderToStaticMarkup } from "react-dom/server";
import {
  GlobePanel,
  RollupChart,
  metricTotal,
  scenarioPayload,
  configuredModes,
} from "./security-overview";
describe("admin-shell", () => {
  it("distinguishes configured detection, blocking and disabled verification", () => {
    expect(
      configuredModes("waf:edge", {
        categories: { sqli: "block", xss: "detect" },
      }),
    ).toEqual(["block", "detect"]);
    expect(configuredModes("challenge:edge", { enabled: false })).toEqual([
      "off",
    ]);
    expect(
      configuredModes("behaviour:edge", {
        abuse: { scan: { mode: "detect" } },
      }),
    ).toEqual(["detect"]);
  });
  it("does not fabricate missing telemetry and escapes rendered values", () => {
    expect(metricTotal([], "waf.findings")).toBeNull();
    expect(
      metricTotal(
        [
          {
            id: "1",
            node: "a",
            metric: "waf.blocks",
            value: 3,
            bucket_start: 60,
            bucket_secs: 60,
          },
        ],
        "waf.blocks",
      ),
    ).toBe(3);
    expect(renderToStaticMarkup(<GlobePanel />)).toContain(
      "Geography unavailable",
    );
    const empty = renderToStaticMarkup(
      <RollupChart title="Access" rows={[]} metric="requests" />,
    );
    expect(empty).toContain("No series available");
    expect(empty).not.toContain("polyline");
    const hostile = renderToStaticMarkup(
      <RollupChart
        title={"<script>alert(1)</script>"}
        rows={[]}
        metric="requests"
      />,
    );
    expect(hostile).toContain("&lt;script&gt;");
    expect(hostile).not.toContain("<script>");
  });
  it("preserves exact scenario predicates, other scenarios and unknown fields", () => {
    const base = {
      category: "behaviour",
      remark: "keep",
      abuse: {
        enabled: true,
        scan: { mode: "detect", window: "30s", threshold: 4, ban_ttl: "1m" },
      },
    };
    const rule = {
      mode: "block",
      window: "10s",
      threshold: 3,
      ban_ttl: "2m",
      path: "/auth/login",
      method: "POST",
      statuses: [401, 403],
    };
    const updated = scenarioPayload(base, "failed_login", rule, true, false);
    expect(updated).toMatchObject({
      remark: "keep",
      enabled: true,
      client_ip_from_peer: false,
      abuse: { enabled: true, failed_login: rule, scan: base.abuse.scan },
    });
    expect(
      scenarioPayload(
        updated,
        "scan",
        { mode: "detect", window: "3s", threshold: 2, ban_ttl: "9s" },
        true,
        false,
      ),
    ).toMatchObject({
      abuse: { failed_login: rule, scan: { threshold: 2, mode: "detect" } },
    });
  });
});
