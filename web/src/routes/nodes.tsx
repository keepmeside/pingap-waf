import { PageShell } from "@/components/page-shell";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { Badge } from "@/components/ui/badge";
import { EmptyState, ErrorNote, LoadingCard } from "@/components/data-ui";
import { useNodes } from "@/queries/admin";
import { formatError } from "@/helpers/util";
import { fmtAge, fmtBytes, fmtCpu, orDash } from "@/lib/format";
import type { NodeStatus, NodeView } from "@/lib/types";
import { cn } from "@/lib/utils";

/**
 * Status → badge treatment. The four states are distinct conditions, not shades of one:
 * `healthy` is in-sync and heartbeating, `stale` is convergence lag (still on an older
 * applied config), `drifted` is a hash mismatch (tampering or a partial write), and
 * `offline` is a missed heartbeat. Colour encodes urgency, never decorates.
 */
const STATUS_STYLE: Record<NodeStatus, { variant: "outline" | "secondary"; className: string }> = {
  healthy: {
    variant: "outline",
    className: "border-emerald-500/60 text-emerald-700 dark:text-emerald-400",
  },
  stale: {
    variant: "outline",
    className: "border-amber-500/60 text-amber-700 dark:text-amber-400",
  },
  drifted: {
    variant: "outline",
    className: "border-destructive/60 text-destructive",
  },
  offline: {
    variant: "secondary",
    className: "text-muted-foreground",
  },
};

function StatusBadge({ status }: { status: NodeStatus }) {
  const style = STATUS_STYLE[status] ?? STATUS_STYLE.offline;
  return (
    <Badge variant={style.variant} className={cn("text-[11px] font-semibold uppercase tracking-wide", style.className)}>
      {status}
    </Badge>
  );
}

/** Truncate a config hash/version for the cell — enough to identify, not a wall of hex. */
function truncMachine(value?: string, head = 12): string {
  if (!value) return "—";
  if (value.length <= head) return value;
  return `${value.slice(0, head)}…`;
}

/**
 * The node inventory.
 *
 * Read-only by design: a heartbeat is a fact the peers report, not a thing an operator
 * edits. A single-node deployment has no shared config backend and so no peers — the API
 * answers `unavailable`, and the page says *why* rather than rendering an empty cluster
 * as if it were a healthy one.
 */
export default function Nodes() {
  const nodes = useNodes();

  return (
    <PageShell
      title="Nodes"
      eyebrow="Cluster"
      description="Every peer the inventory knows. `stale` is convergence lag, `drifted` is a config-hash divergence — different conditions, shown differently."
    >
      {nodes.isPending ? (
        <LoadingCard />
      ) : nodes.isError ? (
        <ErrorNote message={formatError(nodes.error)} />
      ) : nodes.data.unavailable ? (
        <Card>
          <CardContent>
            <EmptyState
              title="No peer inventory"
              hint="There is no peer inventory because no shared config backend is configured. A single-node deployment heartbeats only to itself, so there is nothing to list."
            />
          </CardContent>
        </Card>
      ) : (
        <NodeTable nodes={nodes.data.data ?? []} />
      )}
    </PageShell>
  );
}

function NodeTable({ nodes }: { nodes: NodeView[] }) {
  if (nodes.length === 0) {
    return (
      <Card>
        <CardContent>
          <EmptyState
            title="No nodes"
            hint="The shared backend is reachable but reports no peers."
          />
        </CardContent>
      </Card>
    );
  }
  return (
    <Card>
      <CardHeader>
        <CardTitle className="text-base">Peers</CardTitle>
        <CardDescription>
          Last-seen is measured against the liveness threshold; config version and hash are
          compared to the newest applied config.
        </CardDescription>
      </CardHeader>
      <CardContent>
        <Table>
          <TableHeader>
            <TableRow>
              <TableHead>Node</TableHead>
              <TableHead>Version</TableHead>
              <TableHead>Status</TableHead>
              <TableHead>Config</TableHead>
              <TableHead>Last seen</TableHead>
              <TableHead>CPU</TableHead>
              <TableHead>Memory</TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {nodes.map((node) => (
              <TableRow key={node.node_id}>
                <TableCell className="machine font-medium">{node.node_id}</TableCell>
                <TableCell className="machine text-xs">{orDash(node.version)}</TableCell>
                <TableCell>
                  <StatusBadge status={node.status} />
                </TableCell>
                <TableCell className="machine text-xs" title={`${node.config_version ?? ""} ${node.config_hash ?? ""}`.trim()}>
                  <div>{truncMachine(node.config_version)}</div>
                  <div className="text-muted-foreground">{truncMachine(node.config_hash)}</div>
                </TableCell>
                <TableCell className="text-xs text-muted-foreground">{fmtAge(node.last_seen)}</TableCell>
                <TableCell className="machine text-xs">{fmtCpu(node.cpu_millis)}</TableCell>
                <TableCell className="machine text-xs">{fmtBytes(node.memory_bytes)}</TableCell>
              </TableRow>
            ))}
          </TableBody>
        </Table>
      </CardContent>
    </Card>
  );
}
