import React from "react";
import { PageShell } from "@/components/page-shell";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Input } from "@/components/ui/input";
import { EmptyState, ErrorNote, LoadingCard } from "@/components/data-ui";
import { usePerformance } from "@/queries/admin";
import { fmtTime } from "@/lib/format";
import { formatError } from "@/helpers/util";
import type { PerformanceMetricRecord } from "@/lib/types";

const ALL_METRICS = "__all__";

/** `datetime-local` yields `"YYYY-MM-DDTHH:mm"` in local time — convert to the unix
 * seconds the store compares against `bucket_start`. An empty field means no bound. */
function toEpoch(value: string): number | null {
  if (!value) return null;
  const ms = new Date(value).getTime();
  return Number.isNaN(ms) ? null : Math.floor(ms / 1000);
}

/**
 * Tiny inline-SVG sparkline — no chart library. Points are scaled into a fixed
 * viewBox; identical values collapse to a flat midline rather than a division
 * by zero. Oldest-first, matching the table's ordering.
 */
function Sparkline({ points }: { points: { value: number; bucket_start: number }[] }) {
  if (points.length < 2) return null;
  const W = 220;
  const H = 40;
  const PAD = 4;
  const values = points.map((p) => p.value);
  const min = Math.min(...values);
  const max = Math.max(...values);
  const span = max - min;
  const x = (i: number) => PAD + (i / (points.length - 1)) * (W - PAD * 2);
  const y = (v: number) => (span === 0 ? H / 2 : PAD + (1 - (v - min) / span) * (H - PAD * 2));
  const d = points.map((p, i) => `${i === 0 ? "M" : "L"}${x(i).toFixed(1)},${y(p.value).toFixed(1)}`).join(" ");
  return (
    <svg
      viewBox={`0 0 ${W} ${H}`}
      width={W}
      height={H}
      role="img"
      aria-label={`Sparkline, ${points.length} buckets, min ${min}, max ${max}`}
      className="text-foreground"
    >
      <path d={d} fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinejoin="round" strokeLinecap="round" />
    </svg>
  );
}

/**
 * Raw store rollup buckets — the same records the dashboard summarises, explorable.
 * The metric filter offers every metric name present in the current page of data
 * plus a free-text field, because the endpoint's own filter is a plain `metric`
 * equality and the full vocabulary is whatever the store happens to hold.
 */
export default function Performance() {
  const [metricFilter, setMetricFilter] = React.useState("");
  const [since, setSince] = React.useState("");
  const [until, setUntil] = React.useState("");
  const [limit, setLimit] = React.useState("100");

  const params = React.useMemo(() => {
    const p = new URLSearchParams();
    if (metricFilter.trim()) p.set("metric", metricFilter.trim());
    const s = toEpoch(since);
    const u = toEpoch(until);
    if (s !== null) p.set("since", String(s));
    if (u !== null) p.set("until", String(u));
    p.set("limit", limit);
    return `?${p.toString()}`;
  }, [metricFilter, since, until, limit]);

  const query = usePerformance(params);
  const records: PerformanceMetricRecord[] = React.useMemo(
    () => query.data?.data ?? [],
    [query.data],
  );

  // Distinct metric names in the returned page — offered as quick picks.
  const knownMetrics = React.useMemo(
    () => [...new Set(records.map((r) => r.metric))].sort(),
    [records],
  );

  // The table reads oldest-first, so the eye follows the trend the same way the
  // sparkline draws it. The API returns newest-first.
  const rows = React.useMemo(() => [...records].reverse(), [records]);

  return (
    <PageShell
      title="Performance"
      eyebrow="Telemetry"
      description="Store rollup buckets per metric and node, oldest first — the trend the dashboard compresses into a count."
    >
      <Card>
        <CardHeader>
          <CardTitle className="text-base">Metric buckets</CardTitle>
          <CardDescription>
            Fixed-width rollups written by each node. Filter to one metric to see its shape over time.
          </CardDescription>
        </CardHeader>
        <CardContent className="space-y-4">
          <div className="flex flex-wrap items-end gap-3">
            <div className="w-56 space-y-1">
              <label htmlFor="p-metric" className="text-xs text-muted-foreground">Metric</label>
              <Input
                id="p-metric"
                list="known-metrics"
                value={metricFilter}
                onChange={(e) => setMetricFilter(e.target.value)}
                placeholder="e.g. requests_total"
                className="machine h-8"
              />
              <datalist id="known-metrics">
                {knownMetrics.map((m) => (
                  <option key={m} value={m} />
                ))}
              </datalist>
            </div>
            {knownMetrics.length > 1 && (
              <div className="w-48 space-y-1">
                <label className="text-xs text-muted-foreground">Quick pick</label>
                <Select
                  value={knownMetrics.includes(metricFilter) ? metricFilter : ALL_METRICS}
                  onValueChange={(v) => setMetricFilter(v === ALL_METRICS ? "" : v)}
                >
                  <SelectTrigger size="sm" className="w-full">
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value={ALL_METRICS}>All metrics</SelectItem>
                    {knownMetrics.map((m) => (
                      <SelectItem key={m} value={m}>
                        <span className="machine">{m}</span>
                      </SelectItem>
                    ))}
                  </SelectContent>
                </Select>
              </div>
            )}
            <div className="w-48 space-y-1">
              <label htmlFor="p-since" className="text-xs text-muted-foreground">Since</label>
              <Input
                id="p-since"
                type="datetime-local"
                value={since}
                onChange={(e) => setSince(e.target.value)}
                className="machine h-8"
              />
            </div>
            <div className="w-48 space-y-1">
              <label htmlFor="p-until" className="text-xs text-muted-foreground">Until</label>
              <Input
                id="p-until"
                type="datetime-local"
                value={until}
                onChange={(e) => setUntil(e.target.value)}
                className="machine h-8"
              />
            </div>
            <div className="w-28 space-y-1">
              <label className="text-xs text-muted-foreground">Limit</label>
              <Select value={limit} onValueChange={setLimit}>
                <SelectTrigger size="sm" className="w-full">
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="50">50</SelectItem>
                  <SelectItem value="100">100</SelectItem>
                  <SelectItem value="500">500</SelectItem>
                </SelectContent>
              </Select>
            </div>
            <div className="ms-auto pb-1">
              <Sparkline points={rows} />
            </div>
          </div>
          {query.isPending ? (
            <LoadingCard />
          ) : query.isError ? (
            <ErrorNote message={formatError(query.error)} />
          ) : query.data?.unavailable ? (
            <EmptyState title="Metrics store unavailable" hint={query.data.message} />
          ) : rows.length === 0 ? (
            <EmptyState
              title="No metric buckets"
              hint={metricFilter ? `No buckets recorded for "${metricFilter}".` : "The store has not rolled up any performance buckets yet."}
            />
          ) : (
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Bucket start</TableHead>
                  <TableHead>Metric</TableHead>
                  <TableHead>Node</TableHead>
                  <TableHead className="text-right">Bucket (s)</TableHead>
                  <TableHead className="text-right">Value</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {rows.map((r) => (
                  <TableRow key={r.id}>
                    <TableCell className="machine whitespace-nowrap text-muted-foreground">
                      {fmtTime(r.bucket_start)}
                    </TableCell>
                    <TableCell className="machine font-medium">{r.metric}</TableCell>
                    <TableCell className="machine text-muted-foreground">{r.node}</TableCell>
                    <TableCell className="machine text-right text-muted-foreground">{r.bucket_secs}</TableCell>
                    <TableCell className="machine text-right">{r.value}</TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          )}
        </CardContent>
      </Card>
    </PageShell>
  );
}
