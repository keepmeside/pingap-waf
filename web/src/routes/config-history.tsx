import React from "react";
import { PageShell } from "@/components/page-shell";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { ConfirmDialog } from "@/components/confirm-dialog";
import { EmptyState, ErrorNote, LoadingCard } from "@/components/data-ui";
import { useConfigVersions, useProfile, useRollback } from "@/queries/admin";
import { can } from "@/lib/rbac";
import { formatError } from "@/helpers/util";
import { fmtTime } from "@/lib/format";
import { toast } from "sonner";
import type { ConfigStatus, VersionView } from "@/lib/types";
import { cn } from "@/lib/utils";
import { History } from "lucide-react";

/**
 * Version status → badge treatment. `applied` is confirmed enforcing; `pending` is
 * mid-apply; `failed` did not hold; `superseded` applied once but is no longer the newest.
 */
const STATUS_STYLE: Record<ConfigStatus, { variant: "outline" | "secondary"; className: string }> = {
  applied: {
    variant: "outline",
    className: "border-emerald-500/60 text-emerald-700 dark:text-emerald-400",
  },
  pending: {
    variant: "outline",
    className: "border-amber-500/60 text-amber-700 dark:text-amber-400",
  },
  failed: {
    variant: "outline",
    className: "border-destructive/60 text-destructive",
  },
  superseded: {
    variant: "secondary",
    className: "text-muted-foreground",
  },
};

function StatusBadge({ status }: { status: ConfigStatus }) {
  const style = STATUS_STYLE[status] ?? STATUS_STYLE.superseded;
  return (
    <Badge variant={style.variant} className={cn("text-[11px] font-semibold uppercase tracking-wide", style.className)}>
      {status}
    </Badge>
  );
}

/** Truncate a version id or hash — enough to identify, not a wall of hex. */
function truncMachine(value: string, head = 12): string {
  if (value.length <= head) return value;
  return `${value.slice(0, head)}…`;
}

/**
 * The config-version ledger, and rollback.
 *
 * Rollback is destructive in intent: it regenerates the running config from an earlier
 * committed intent and applies it — a wrong target rewrites live state. So it is gated on
 * `edit_domain` (the capability the projection treats as "may change config") and on a
 * typed confirmation naming the version id, so the operator commits to a specific
 * version, not to "undo".
 *
 * `rolled_back_to` on the result is surfaced: it is set when the restored config itself
 * failed verification and an *earlier* version was put back — a rollback that did not
 * hold, which the operator must see named rather than read as a success.
 */
export default function ConfigHistory() {
  const profileQuery = useProfile();
  const versions = useConfigVersions();
  const rollback = useRollback();
  const canEdit = can(profileQuery.data?.data, "edit_domain");
  const [target, setTarget] = React.useState<VersionView | null>(null);

  if (versions.isPending) {
    return (
      <PageShell title="Config history" eyebrow="Projection" description="Committed config versions and rollback.">
        <LoadingCard />
      </PageShell>
    );
  }
  if (versions.isError) {
    return (
      <PageShell title="Config history" eyebrow="Projection" description="Committed config versions and rollback.">
        <ErrorNote message={formatError(versions.error)} />
      </PageShell>
    );
  }
  if (versions.data.unavailable) {
    return (
      <PageShell title="Config history" eyebrow="Projection" description="Committed config versions and rollback.">
        <Card>
          <CardContent>
            <EmptyState
              title="Config versions unavailable"
              hint={versions.data.message ?? "The connected server does not expose config versions."}
            />
          </CardContent>
        </Card>
      </PageShell>
    );
  }
  const list = versions.data.data ?? [];

  return (
    <PageShell
      title="Config history"
      eyebrow="Projection"
      description="Every committed config version, who wrote it, and whether it held. Rollback regenerates the running config from a chosen version's stored intent."
    >
      <Card>
        <CardHeader>
          <CardTitle className="text-base">Versions</CardTitle>
          <CardDescription>
            Newest first. `applied` is confirmed enforcing; `superseded` held once but is
            no longer the newest.
          </CardDescription>
        </CardHeader>
        <CardContent>
          {list.length === 0 ? (
            <EmptyState
              title="No config versions"
              hint="A config-shaped write produces a version. None have committed yet."
            />
          ) : (
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Version</TableHead>
                  <TableHead>Status</TableHead>
                  <TableHead>Actor</TableHead>
                  <TableHead>Hash</TableHead>
                  <TableHead>Created</TableHead>
                  <TableHead>Settled</TableHead>
                  <TableHead>Error</TableHead>
                  {canEdit && <TableHead className="text-right">Rollback</TableHead>}
                </TableRow>
              </TableHeader>
              <TableBody>
                {list.map((version) => (
                  <TableRow key={version.id}>
                    <TableCell className="machine text-xs" title={version.id}>
                      {truncMachine(version.id)}
                    </TableCell>
                    <TableCell>
                      <StatusBadge status={version.status} />
                    </TableCell>
                    <TableCell className="text-xs">{version.actor_username}</TableCell>
                    <TableCell className="machine text-xs" title={version.hash}>
                      {truncMachine(version.hash)}
                    </TableCell>
                    <TableCell className="text-xs text-muted-foreground">{fmtTime(version.created_at)}</TableCell>
                    <TableCell className="text-xs text-muted-foreground">{fmtTime(version.settled_at)}</TableCell>
                    <TableCell className="max-w-56">
                      {version.error ? (
                        <span className="text-xs text-destructive">{version.error}</span>
                      ) : (
                        <span className="text-xs text-muted-foreground">—</span>
                      )}
                    </TableCell>
                    {canEdit && (
                      <TableCell className="text-right">
                        <Button size="sm" variant="ghost" onClick={() => setTarget(version)}>
                          <History className="size-4" />
                          Rollback
                        </Button>
                      </TableCell>
                    )}
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          )}
        </CardContent>
      </Card>

      <ConfirmDialog
        open={target !== null}
        onOpenChange={(open) => !open && setTarget(null)}
        title="Roll back config"
        description={
          <p>
            Regenerate the running configuration from version{" "}
            <span className="machine font-semibold">{target?.id}</span> and apply it. The
            restored intent goes through the full validate-commit-verify apply, exactly as
            a fresh write would.
          </p>
        }
        confirmText={target?.id ?? ""}
        confirmLabel="Roll back"
        onConfirm={() => {
          if (!target) return;
          rollback.mutate(target.id, {
            onSuccess: (result) => {
              if (result.rolled_back_to) {
                toast.warning("Rollback did not hold", {
                  description: `The restored config failed verification; version ${result.rolled_back_to} was put back instead.`,
                });
              } else {
                toast.success("Rolled back", {
                  description: `Version ${result.version.id} is now applied.`,
                });
              }
              setTarget(null);
            },
            onError: (e) =>
              toast.error("Rollback failed", { description: formatError(e) }),
          });
        }}
        busy={rollback.isPending}
      />
    </PageShell>
  );
}
