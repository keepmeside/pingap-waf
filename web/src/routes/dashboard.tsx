import React from "react";
import { PageShell } from "@/components/page-shell";
import { EmptyState, ErrorNote, LoadingCard } from "@/components/data-ui";
import { useDashboard } from "@/queries/admin";
import { formatError } from "@/helpers/util";
import {
  GlobePanel,
  RollupChart,
  metricTotal,
} from "@/components/security-overview";
import type { PerformanceMetricRecord } from "@/lib/types";
function Unavailable({ title, reason }: { title: string; reason: string }) {
  return (
    <section className="console-card">
      <h2>{title}</h2>
      <div className="chart-empty">
        Unavailable<p>{reason}</p>
      </div>
    </section>
  );
}
function Ranking({
  title,
  prefix,
  rows,
}: {
  title: string;
  prefix: string;
  rows: PerformanceMetricRecord[];
}) {
  const values = new Map<string, number>();
  for (const r of rows.filter((r) => r.metric.startsWith(prefix)))
    values.set(
      r.metric.slice(prefix.length),
      (values.get(r.metric.slice(prefix.length)) ?? 0) + r.value,
    );
  return (
    <section className="console-card">
      <h2>{title}</h2>
      {values.size ? (
        <ol className="ranking">
          {[...values]
            .sort((a, b) => b[1] - a[1])
            .map(([name, n]) => (
              <li key={name}>
                <span>{name}</span>
                <strong>{n}</strong>
              </li>
            ))}
        </ol>
      ) : (
        <EmptyState
          title="No recorded rankings"
          hint="No matching WAF aggregates in this response."
        />
      )}
    </section>
  );
}
export default function Dashboard() {
  const query = useDashboard();
  const [advanced, setAdvanced] = React.useState(false);
  const rows = query.data?.data?.metrics ?? [];
  const drift = query.data?.data?.drift;
  return (
    <PageShell title="Dashboard" description="Security operations overview">
      <div className="dashboard-toolbar">
        <div role="tablist" aria-label="Dashboard view">
          <button
            role="tab"
            aria-selected={!advanced}
            onClick={() => setAdvanced(false)}
          >
            BASIC
          </button>
          <button
            role="tab"
            aria-selected={advanced}
            onClick={() => setAdvanced(true)}
          >
            ADVANCED
          </button>
        </div>
        <div className="time-controls" aria-label="Time window">
          <button aria-pressed="true">Latest recorded buckets</button>
          <button
            disabled
            title="A complete 24-hour analytics source is unavailable"
          >
            24 hours
          </button>
          <button
            disabled
            title="A complete 7-day analytics source is unavailable"
          >
            7 days
          </button>
        </div>
      </div>
      {query.isPending ? (
        <LoadingCard />
      ) : query.isError ? (
        <ErrorNote message={formatError(query.error)} />
      ) : query.data?.unavailable ? (
        <EmptyState title="Dashboard unavailable" hint={query.data.message} />
      ) : (
        <>
          <div className="overview-kpis">
            {[
              ["WAF findings", metricTotal(rows, "waf.findings")],
              ["Enforced findings", metricTotal(rows, "waf.blocks")],
              ["Config status", drift?.status ?? "unavailable"],
            ].map(([label, value]) => (
              <section className="console-card" key={label}>
                <p>{label}</p>
                <strong>
                  {value === null
                    ? "No data"
                    : String(value).replace(/_/g, " ")}
                </strong>
                <small>
                  {label === "Config status"
                    ? "Applied baseline comparison"
                    : "Sum of recorded buckets in this response"}
                </small>
              </section>
            ))}
          </div>
          {!advanced ? (
            <div className="overview-grid">
              <GlobePanel />
              <div className="trend-stack">
                <RollupChart title="Access" rows={[]} metric="requests" />
                <RollupChart
                  title="Block · WAF enforced findings"
                  rows={rows}
                  metric="waf.blocks"
                />
              </div>
            </div>
          ) : (
            <div className="advanced-overview">
              <div className="advanced-top">
                <Unavailable
                  title="Client distribution"
                  reason="No client analytics source is available."
                />
                <Unavailable
                  title="Response Status"
                  reason="No response-status aggregate is available."
                />
                <Unavailable
                  title="QPS"
                  reason="Finding counts are not request-rate measurements."
                />
              </div>
              <div className="advanced-rankings">
                <Ranking
                  title="Finding categories"
                  prefix="waf.category."
                  rows={rows}
                />
                <Ranking
                  title="Triggered rules"
                  prefix="waf.rule."
                  rows={rows}
                />
                <Unavailable
                  title="Referring sites"
                  reason="Referrer aggregates are not captured."
                />
                <Unavailable
                  title="Popular pages"
                  reason="Page popularity is not provided by this API."
                />
              </div>
            </div>
          )}
          <p className="mt-4 text-xs text-muted-foreground">
            WAF finding rollups are not total traffic, visitors or unique
            clients. Unsupported analytics are shown as unavailable.
          </p>
          {drift?.status === "detected" && (
            <ErrorNote
              message={`Configuration drift detected: ${drift.differing?.join(", ") ?? "unknown categories"}`}
            />
          )}
        </>
      )}
    </PageShell>
  );
}
