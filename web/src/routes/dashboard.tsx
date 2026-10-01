import React from "react";
import { PageShell } from "@/components/page-shell";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { Badge } from "@/components/ui/badge";
import { Input } from "@/components/ui/input";
import { EmptyState, ErrorNote, LoadingCard } from "@/components/data-ui";
import { useDashboard } from "@/queries/admin";
import { fmtTime, orDash } from "@/lib/format";
import { formatError } from "@/helpers/util";
import { cn } from "@/lib/utils";
import type { DriftStatus, PerformanceMetricRecord } from "@/lib/types";
import { CheckCircle2, AlertTriangle, MinusCircle } from "lucide-react";

/**
 * Drift is the headline. `in_sync` means the projected config hash matches what the
 * store last applied — nothing drifted out from under the operator. `detected` is the
 * warning: the live config differs from the store's record, and `differing` names the
 * categories that moved. `no_baseline`/`unavailable` are not failures, just a store
 * that has not projected yet or is not wired — muted, not alarming.
 */
function DriftCard({ drift }: { drift: DriftStatus }) {
  const tone =
    drift.status === "in_sync"
      ? { icon: CheckCircle2, label: "In sync", cls: "text-emerald-600 dark:text-emerald-400" }
      : drift.status === "detected"
        ? { icon: AlertTriangle, label: "Drift detected", cls: "text-amber-600 dark:text-amber-400" }
        : { icon: MinusCircle, label: "No baseline", cls: "text-muted-foreground" };
  const Icon = tone.icon;

  return (
    <Card>
      <CardHeader>
        <CardTitle className="text-base">Config drift</CardTitle>
        <CardDescription>
          Whether the running config still matches what the control plane last applied.
        </CardDescription>
      </CardHeader>
      <CardContent className="space-y-3">
        <div className={cn("flex items-center gap-2 font-medium", tone.cls)}>
          <Icon className="size-4" />
          {drift.status === "no_baseline" || drift.status === "unavailable"
            ? "No baseline recorded"
            : tone.label}
        </div>
        {drift.status === "detected" && drift.differing && drift.differing.length > 0 && (
          <div className="flex flex-wrap items-center gap-1.5">
            <span className="text-xs text-muted-foreground">Differing categories:</span>
            {drift.differing.map((category) => (
              <Badge key={category} variant="outline" className="machine border-amber-500/60 text-amber-700 dark:text-amber-400">
                {category}
              </Badge>
            ))}
          </div>
        )}
        {drift.version_id && (
          <p className="text-xs text-muted-foreground">
            Baseline version <span className="machine">{drift.version_id}</span>
          </p>
        )}
      </CardContent>
    </Card>
  );
}

/** Compact metrics readout — one row per record, filterable by metric name. */
function MetricsTable({ metrics }: { metrics: PerformanceMetricRecord[] }) {
  const [filter, setFilter] = React.useState("");
  const rows = filter.trim()
    ? metrics.filter((m) => m.metric.toLowerCase().includes(filter.trim().toLowerCase()))
    : metrics;

  return (
    <Card>
      <CardHeader>
        <CardTitle className="text-base">Recent metrics</CardTitle>
        <CardDescription>
          Store rollup buckets, newest window per metric. Filter by metric name.
        </CardDescription>
      </CardHeader>
      <CardContent className="space-y-3">
        <div className="max-w-xs">
          <Input
            aria-label="Filter by metric name"
            placeholder="Filter metric…"
            value={filter}
            onChange={(e) => setFilter(e.target.value)}
            className="machine h-8"
          />
        </div>
        {rows.length === 0 ? (
          <EmptyState
            title="No metrics recorded"
            hint={filter ? "No metric names match the filter." : "The store has not rolled up any performance buckets yet."}
          />
        ) : (
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>Metric</TableHead>
                <TableHead>Node</TableHead>
                <TableHead className="text-right">Value</TableHead>
                <TableHead>Bucket start</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {rows.map((m) => (
                <TableRow key={m.id}>
                  <TableCell className="machine font-medium">{m.metric}</TableCell>
                  <TableCell className="machine text-muted-foreground">{m.node}</TableCell>
                  <TableCell className="machine text-right">{m.value}</TableCell>
                  <TableCell className="machine text-muted-foreground" title={`${m.bucket_secs}s bucket`}>
                    {fmtTime(m.bucket_start)}
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        )}
      </CardContent>
    </Card>
  );
}

/**
 * The dashboard. Reaching it at all means the store answered — the summary strip
 * reports that fact and the two numbers that matter most (metrics buffered, drift
 * state) rather than duplicating every card below it.
 */
export default function Dashboard() {
  const query = useDashboard();

  return (
    <PageShell
      title="Dashboard"
      eyebrow="Control plane"
      description="Store-backed rollup: recent performance buckets and whether config has drifted from the applied baseline."
    >
      {query.isPending ? (
        <LoadingCard />
      ) : query.isError ? (
        <ErrorNote message={formatError(query.error)} />
      ) : !query.data || query.data.unavailable ? (
        <EmptyState
          title="Dashboard unavailable"
          hint={query.data?.unavailable ? query.data.message : "The control-plane store is not wired on this server."}
        />
      ) : (
        <div className="space-y-4">
          <Card>
            <CardContent className="flex flex-wrap items-center gap-x-6 gap-y-1 py-3 text-sm">
              <span className="flex items-center gap-1.5 text-muted-foreground">
                <CheckCircle2 className="size-4 text-emerald-600 dark:text-emerald-400" />
                Store connected
              </span>
              <span className="text-muted-foreground">
                <span className="machine font-medium text-foreground">{query.data.data.metrics.length}</span> metric rows
              </span>
              <span className="text-muted-foreground">
                Drift <span className="machine font-medium text-foreground">{orDash(query.data.data.drift.status)}</span>
              </span>
            </CardContent>
          </Card>
          <DriftCard drift={query.data.data.drift} />
          <MetricsTable metrics={query.data.data.metrics} />
        </div>
      )}
    </PageShell>
  );
}
