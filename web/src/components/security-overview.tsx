import type { PerformanceMetricRecord, PluginConf } from "@/lib/types";
export function metricTotal(
  rows: PerformanceMetricRecord[],
  metric: string,
): number | null {
  const selected = rows.filter(
    (row) => row.metric === metric && Number.isFinite(row.value),
  );
  return selected.length
    ? selected.reduce((sum, row) => sum + row.value, 0)
    : null;
}
export function scenarioPayload(
  base: PluginConf,
  kind: "failed_login" | "scan",
  rule: Record<string, unknown>,
  enabled: boolean,
  peer: boolean,
): PluginConf {
  const abuse =
    typeof base.abuse === "object" &&
    base.abuse !== null &&
    !Array.isArray(base.abuse)
      ? (base.abuse as Record<string, unknown>)
      : {};
  return {
    ...base,
    category: "behaviour",
    enabled,
    client_ip_from_peer: peer,
    abuse: { ...abuse, enabled, [kind]: rule },
  };
}
export function GlobePanel() {
  return (
    <section
      className="console-card geography-panel"
      aria-label="Traffic geography"
    >
      <h2>Traffic geography</h2>
      <div className="globe-layout">
        <svg
          viewBox="0 0 340 340"
          role="img"
          aria-label="Schematic globe; no traffic locations plotted"
          className="globe"
        >
          <defs>
            <radialGradient id="ocean">
              <stop stopColor="#44d3c7" />
              <stop offset="1" stopColor="#10a9a4" />
            </radialGradient>
            <clipPath id="sphere">
              <circle cx="170" cy="170" r="146" />
            </clipPath>
          </defs>
          <circle cx="170" cy="170" r="146" fill="url(#ocean)" />
          <g clipPath="url(#sphere)" stroke="white" fill="none" opacity=".32">
            <ellipse cx="170" cy="170" rx="65" ry="146" />
            <ellipse cx="170" cy="170" rx="120" ry="146" />
            <ellipse cx="170" cy="170" rx="146" ry="45" />
            <ellipse cx="170" cy="170" rx="146" ry="100" />
            <path d="M24 170H316M170 24V316" />
          </g>
          <g fill="white" opacity=".83">
            <path d="M65 91l37-27 34 8 18 26-19 20-27 3-12 29-26-8-15-29zM111 159l31 11 16 33-12 38-22 32-9-31 4-27-17-28zM185 99l22-20 36 8 31 25-2 26-35-8-12 24-22-15-29-10zM180 150l36 2 19 22-11 37-20 29-18-16-10-33zM248 230l24-14 25 19-2 21-34 3z" />
          </g>
        </svg>
        <div className="geo-empty">
          <strong>Geography unavailable</strong>
          <p>No geolocation aggregate is provided by this server.</p>
          <p className="text-xs">
            Schematic illustration · no traffic locations plotted
          </p>
        </div>
      </div>
    </section>
  );
}
export function RollupChart({
  title,
  rows,
  metric,
}: {
  title: string;
  rows: PerformanceMetricRecord[];
  metric: string;
}) {
  const grouped = new Map<number, number>();
  for (const row of rows.filter(
    (r) => r.metric === metric && Number.isFinite(r.value),
  ))
    grouped.set(
      row.bucket_start,
      (grouped.get(row.bucket_start) ?? 0) + row.value,
    );
  const points = [...grouped].sort((a, b) => a[0] - b[0]);
  const max = Math.max(1, ...points.map((p) => p[1]));
  return (
    <section className="console-card trend-card">
      <h2>{title}</h2>
      {points.length ? (
        <>
          <svg
            viewBox="0 0 360 125"
            role="img"
            aria-label={`${title}: ${points.length} recorded buckets`}
          >
            <path d="M8 105H352M8 55H352" stroke="currentColor" opacity=".08" />
            <polyline
              fill="none"
              stroke="var(--console-turquoise)"
              strokeWidth="2.5"
              points={points
                .map(
                  (p, i) =>
                    `${points.length === 1 ? 180 : 8 + (i * 344) / (points.length - 1)},${105 - (p[1] / max) * 90}`,
                )
                .join(" ")}
            />
            {points.map((p, i) => (
              <circle
                key={p[0]}
                cx={
                  points.length === 1
                    ? 180
                    : 8 + (i * 344) / (points.length - 1)
                }
                cy={105 - (p[1] / max) * 90}
                r="3"
                fill="var(--console-turquoise)"
              >
                <title>
                  {new Date(p[0] * 1000).toISOString()}: {p[1]}
                </title>
              </circle>
            ))}
          </svg>
          <p className="text-xs text-muted-foreground">
            Recorded WAF buckets across nodes · {points.length} timestamps
          </p>
        </>
      ) : (
        <div className="chart-empty">
          No series available
          <p>
            {metric === "requests"
              ? "Complete access traffic is not exposed by this API."
              : "No recorded buckets in this response."}
          </p>
        </div>
      )}
    </section>
  );
}

/** Report configured mode, not a promise of effective protection. */
export function configuredModes(
  entry: string,
  conf: PluginConf | undefined,
): string[] {
  if (!conf) return ["Unknown profile"];
  const category = entry.split(":")[0];
  const obj = (v: unknown): Record<string, unknown> =>
    typeof v === "object" && v !== null && !Array.isArray(v)
      ? (v as Record<string, unknown>)
      : {};
  if (category === "limit") return ["Rate limit"];
  if (category === "challenge")
    return [conf.enabled === true ? "challenge" : "off"];
  if (category === "behaviour") {
    if (conf.enabled === false) return ["off"];
    const abuse = obj(conf.abuse);
    const modes = [obj(abuse.failed_login).mode, obj(abuse.scan).mode].filter(
      (v): v is string => typeof v === "string",
    );
    return modes.length ? [...new Set(modes)] : ["detect"];
  }
  if (category === "waf") {
    const modes = Object.values(obj(conf.categories)).filter(
      (v): v is string => typeof v === "string",
    );
    return modes.length ? [...new Set(modes)] : ["detect"];
  }
  return [typeof conf.mode === "string" ? conf.mode : "Configured"];
}
