import React from "react";
import { PageShell } from "@/components/page-shell";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Checkbox } from "@/components/ui/checkbox";
import { ConfirmDialog } from "@/components/confirm-dialog";
import { EmptyState, ErrorNote, LoadingCard } from "@/components/data-ui";
import {
  useBackup,
  useCreateSchedule,
  useDeleteSchedule,
  useExportBackup,
  useProfile,
  useRestoreBackup,
} from "@/queries/admin";
import { can } from "@/lib/rbac";
import { formatError } from "@/helpers/util";
import { fmtBytes, fmtTime } from "@/lib/format";
import { toast } from "sonner";
import type { BackupFileRecord, BackupScheduleRecord } from "@/lib/types";
import { ArchiveRestore, Download, Plus, Trash2 } from "lucide-react";

/** Truncate a sha or path-hash for a table cell — enough to identify, short enough to scan. */
function truncMachine(value: string, head = 12): string {
  if (value.length <= head) return value;
  return `${value.slice(0, head)}…`;
}

/**
 * Backup and restore.
 *
 * The two actions have different weights and the page treats them accordingly:
 *
 * - **Export** is additive — it writes a bundle and changes nothing live — so it is a
 *   plain button.
 * - **Restore** is the heaviest action in the product: it stages a bundle whose payload
 *   could replace the running configuration and store. It is gated on `restore_backup`
 *   *and* a typed confirmation that requires typing the bundle's full path — the
 *   operator names the exact artefact they intend, not a reflexive "yes".
 *
 * A deployment without `backup_dir` configured gets an `unavailable` response, rendered
 * as the named missing setting rather than an error state.
 */
export default function Backup() {
  const profileQuery = useProfile();
  const backup = useBackup();
  const exportBackup = useExportBackup();
  const canRun = can(profileQuery.data?.data, "run_backup");
  const canRestore = can(profileQuery.data?.data, "restore_backup");

  const [restoring, setRestoring] = React.useState<BackupFileRecord | null>(null);
  const restore = useRestoreBackup();

  if (backup.isPending) {
    return (
      <PageShell title="Backup" eyebrow="Control plane" description="Schedules, bundles and restore.">
        <LoadingCard />
      </PageShell>
    );
  }
  if (backup.isError) {
    return (
      <PageShell title="Backup" eyebrow="Control plane" description="Schedules, bundles and restore.">
        <ErrorNote message={formatError(backup.error)} />
      </PageShell>
    );
  }
  if (backup.data.unavailable) {
    return (
      <PageShell
        title="Backup"
        eyebrow="Control plane"
        description="Schedules, bundles and restore."
      >
        <Card>
          <CardContent>
            <EmptyState
              title="Backup is not configured"
              hint="Set `backup_dir` on the admin plugin to enable export and restore. Without it there is no bundle directory to write to or stage from."
            />
          </CardContent>
        </Card>
      </PageShell>
    );
  }

  const view = backup.data.data ?? { schedules: [], files: [] };

  return (
    <PageShell
      title="Backup"
      eyebrow="Control plane"
      description="Scheduled and on-demand bundles of the canonical config plus the control-plane store. Restore stages a bundle — it does not swap live state in place."
      actions={
        canRun && (
          <Button
            size="sm"
            onClick={() =>
              exportBackup.mutate(undefined, {
                onSuccess: (file) =>
                  toast.success("Export written", { description: file.path }),
                onError: (e) => toast.error("Export failed", { description: formatError(e) }),
              })
            }
            disabled={exportBackup.isPending}
          >
            <Download className="size-4" />
            {exportBackup.isPending ? "Exporting…" : "Export now"}
          </Button>
        )
      }
    >
      <div className="grid gap-4 lg:grid-cols-2">
        <SchedulesCard schedules={view.schedules} canRun={canRun} />
        <BundlesCard
          files={view.files}
          canRestore={canRestore}
          onRestore={(file) => setRestoring(file)}
        />
      </div>

      <ConfirmDialog
        open={restoring !== null}
        onOpenChange={(open) => !open && setRestoring(null)}
        title="Restore from bundle"
        description={
          <>
            <p>
              Stage the bundle at{" "}
              <span className="machine font-semibold">{restoring?.path}</span> for restore.
              Checksums are re-verified and the payload copied to a staging directory —
              live state is not touched here, but this is the step that commits the
              intention.
            </p>
          </>
        }
        confirmText={restoring?.path ?? ""}
        confirmLabel="Stage restore"
        onConfirm={() => {
          if (!restoring) return;
          restore.mutate(
            { path: restoring.path },
            {
              onSuccess: (result) => {
                const staged = (result as { staged_config?: string } | null)?.staged_config;
                toast.success("Bundle staged", {
                  description: staged
                    ? `Staged config at ${staged}`
                    : "The bundle passed validation and was staged.",
                });
                setRestoring(null);
              },
              onError: (e) =>
                toast.error("Restore failed", { description: formatError(e) }),
            },
          );
        }}
        busy={restore.isPending}
      />
    </PageShell>
  );
}

// ---- schedules -------------------------------------------------------------------------

function SchedulesCard({
  schedules,
  canRun,
}: {
  schedules: BackupScheduleRecord[];
  canRun: boolean;
}) {
  const deleteSchedule = useDeleteSchedule();
  const [creating, setCreating] = React.useState(false);
  const [deleting, setDeleting] = React.useState<BackupScheduleRecord | null>(null);

  return (
    <>
      <Card>
        <CardHeader className="flex-row items-start justify-between gap-4">
          <div>
            <CardTitle className="text-base">Schedules</CardTitle>
            <CardDescription>
              Recurring exports. A schedule is intent — creating the row is what makes it run.
            </CardDescription>
          </div>
          {canRun && (
            <Button size="sm" variant="outline" onClick={() => setCreating((v) => !v)}>
              <Plus className="size-4" /> New schedule
            </Button>
          )}
        </CardHeader>
        <CardContent>
          {schedules.length === 0 ? (
            <EmptyState
              title="No schedules"
              hint="A schedule exports a bundle on a cron expression and keeps `retain` of them."
            />
          ) : (
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Name</TableHead>
                  <TableHead>Cron</TableHead>
                  <TableHead>Retain</TableHead>
                  <TableHead>Enabled</TableHead>
                  <TableHead className="text-right">Actions</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {schedules.map((schedule) => (
                  <TableRow key={schedule.id}>
                    <TableCell className="font-medium">{schedule.name}</TableCell>
                    <TableCell className="machine text-xs">{schedule.cron}</TableCell>
                    <TableCell className="machine text-xs">{schedule.retain}</TableCell>
                    <TableCell>
                      {schedule.enabled ? (
                        <Badge variant="outline">enabled</Badge>
                      ) : (
                        <Badge variant="secondary">disabled</Badge>
                      )}
                    </TableCell>
                    <TableCell className="text-right">
                      {canRun && (
                        <Button
                          size="sm"
                          variant="ghost"
                          onClick={() => setDeleting(schedule)}
                        >
                          <Trash2 className="size-4" />
                        </Button>
                      )}
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          )}
        </CardContent>
        {creating && canRun && (
          <CardContent className="border-t border-border pt-4">
            <ScheduleForm onClose={() => setCreating(false)} />
          </CardContent>
        )}
      </Card>

      <ConfirmDialog
        open={deleting !== null}
        onOpenChange={(open) => !open && setDeleting(null)}
        title="Delete schedule"
        description={
          <p>
            Stop the recurring export named{" "}
            <span className="machine font-semibold">{deleting?.name}</span>. Bundles already
            written are kept — only the schedule is removed.
          </p>
        }
        confirmText={deleting?.name ?? ""}
        confirmLabel="Delete"
        onConfirm={() => {
          if (!deleting) return;
          deleteSchedule.mutate(deleting.id, {
            onSuccess: () => {
              toast.success("Schedule deleted");
              setDeleting(null);
            },
            onError: (e) =>
              toast.error("Delete failed", { description: formatError(e) }),
          });
        }}
        busy={deleteSchedule.isPending}
      />
    </>
  );
}

function ScheduleForm({ onClose }: { onClose: () => void }) {
  const create = useCreateSchedule();
  const [name, setName] = React.useState("");
  const [cron, setCron] = React.useState("0 3 * * *");
  const [retain, setRetain] = React.useState("7");
  const [enabled, setEnabled] = React.useState(true);

  const save = () => {
    const retainNum = Number(retain);
    if (!name.trim() || !cron.trim()) {
      toast.error("A name and cron expression are required");
      return;
    }
    if (!Number.isInteger(retainNum) || retainNum < 1) {
      toast.error("Retain must keep at least one bundle");
      return;
    }
    create.mutate(
      { name: name.trim(), cron: cron.trim(), retain: retainNum, enabled },
      {
        onSuccess: () => {
          toast.success("Schedule created");
          onClose();
        },
        onError: (e) => toast.error("Create failed", { description: formatError(e) }),
      },
    );
  };

  return (
    <div className="grid gap-4 sm:grid-cols-2">
      <div className="space-y-1.5">
        <Label htmlFor="sched-name">Name</Label>
        <Input id="sched-name" value={name} onChange={(e) => setName(e.target.value)} placeholder="nightly" />
      </div>
      <div className="space-y-1.5">
        <Label htmlFor="sched-cron">Cron</Label>
        <Input id="sched-cron" value={cron} onChange={(e) => setCron(e.target.value)} className="machine" />
      </div>
      <div className="space-y-1.5">
        <Label htmlFor="sched-retain">Retain (bundles)</Label>
        <Input id="sched-retain" value={retain} onChange={(e) => setRetain(e.target.value)} inputMode="numeric" className="machine" />
      </div>
      <div className="flex items-end gap-2 pb-1">
        <Checkbox id="sched-enabled" checked={enabled} onCheckedChange={(v) => setEnabled(v === true)} />
        <Label htmlFor="sched-enabled" className="text-sm font-normal">Enabled</Label>
      </div>
      <div className="flex items-center gap-2 sm:col-span-2">
        <Button size="sm" onClick={save} disabled={create.isPending}>
          {create.isPending ? "Creating…" : "Create schedule"}
        </Button>
        <Button size="sm" variant="ghost" onClick={onClose}>Cancel</Button>
      </div>
    </div>
  );
}

// ---- bundles ----------------------------------------------------------------------------

function BundlesCard({
  files,
  canRestore,
  onRestore,
}: {
  files: BackupFileRecord[];
  canRestore: boolean;
  onRestore: (file: BackupFileRecord) => void;
}) {
  return (
    <Card>
      <CardHeader>
        <CardTitle className="text-base">Bundles</CardTitle>
        <CardDescription>
          The export inventory — each bundle's path, size and manifest checksum.
        </CardDescription>
      </CardHeader>
      <CardContent>
        {files.length === 0 ? (
          <EmptyState
            title="No bundles"
            hint="An export writes a bundle here. Scheduled exports appear once the scheduler runs."
          />
        ) : (
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>Path</TableHead>
                <TableHead>Size</TableHead>
                <TableHead>sha256</TableHead>
                <TableHead>Created</TableHead>
                <TableHead className="text-right">Restore</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {files.map((file) => (
                <TableRow key={file.id}>
                  <TableCell className="machine max-w-0 truncate text-xs" title={file.path}>
                    {file.path}
                  </TableCell>
                  <TableCell className="machine text-xs">{fmtBytes(file.size_bytes)}</TableCell>
                  <TableCell className="machine text-xs" title={file.sha256}>
                    {truncMachine(file.sha256)}
                  </TableCell>
                  <TableCell className="text-xs text-muted-foreground">{fmtTime(file.created_at)}</TableCell>
                  <TableCell className="text-right">
                    {canRestore && (
                      <Button size="sm" variant="ghost" onClick={() => onRestore(file)}>
                        <ArchiveRestore className="size-4" />
                        Restore
                      </Button>
                    )}
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
