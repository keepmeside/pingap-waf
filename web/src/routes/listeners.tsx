import React from "react";
import { PageShell } from "@/components/page-shell";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Checkbox } from "@/components/ui/checkbox";
import { ConfirmDialog } from "@/components/confirm-dialog";
import { EmptyState, ErrorNote, FieldList, FieldRow, LoadingCard } from "@/components/data-ui";
import {
  useDeleteListener, useListeners, useProfile, usePutListener,
} from "@/queries/admin";
import { can } from "@/lib/rbac";
import { formatError } from "@/helpers/util";
import { toast } from "sonner";
import type { Listener } from "@/lib/types";
import { Pencil, Plus, Radio, Trash2 } from "lucide-react";

/**
 * Listeners — the sockets domains bind to.
 *
 * A listening socket is shared by every domain on it, so a listener is a first-class
 * object here rather than a `listen` line inside a server block. Deleting one that a
 * domain still binds is refused by the projection, not silently dropped.
 */
export default function Listeners() {
  const profileQuery = useProfile();
  const listeners = useListeners();
  const putListener = usePutListener();
  const deleteListener = useDeleteListener();
  const canEdit = can(profileQuery.data?.data, "edit_domain");

  const [editing, setEditing] = React.useState<string | null>(null);
  const [deleting, setDeleting] = React.useState<string | null>(null);

  const names = Object.keys(listeners.data?.data ?? {}).sort();
  const target = editing ? (listeners.data?.data ?? {})[editing] : undefined;

  return (
    <PageShell
      title="Listeners"
      eyebrow="Traffic · listeners"
      description="Listening sockets — the address each domain binds to, with HTTP/2 and TLS termination settings."
      actions={
        canEdit && (
          <Button size="sm" onClick={() => setEditing("*new*")}>
            <Plus className="size-4" /> New listener
          </Button>
        )
      }
    >
      {listeners.isPending ? (
        <LoadingCard />
      ) : listeners.isError ? (
        <ErrorNote message={formatError(listeners.error)} />
      ) : editing ? (
        <ListenerEditor
          isNew={editing === "*new*"}
          name={editing === "*new*" ? "" : editing}
          listener={target}
          readOnly={!canEdit}
          saving={putListener.isPending}
          onClose={() => setEditing(null)}
          onSave={(draft) => {
            putListener.mutate(
              { name: draft.name, body: draft.listener },
              {
                onSuccess: () => {
                  toast.success(`Listener ${draft.name} saved`);
                  setEditing(null);
                },
                onError: (e) => toast.error("Save failed", { description: formatError(e) }),
              },
            );
          }}
        />
      ) : (
        <Card>
          <CardHeader>
            <CardTitle className="text-base">Configured listeners</CardTitle>
            <CardDescription>{names.length} socket{names.length === 1 ? "" : "s"}</CardDescription>
          </CardHeader>
          <CardContent>
            {names.length === 0 ? (
              <EmptyState
                title="No listeners"
                hint="A listener is the socket a domain binds to. Create one, then point domains at it."
              />
            ) : (
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead>Name</TableHead>
                    <TableHead>Address</TableHead>
                    <TableHead>HTTP/2</TableHead>
                    <TableHead>TLS</TableHead>
                    <TableHead className="text-right">Actions</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {names.map((name) => {
                    const listener = (listeners.data?.data ?? {})[name];
                    return (
                      <TableRow key={name}>
                        <TableCell className="font-medium">{name}</TableCell>
                        <TableCell className="machine">{listener?.addr}</TableCell>
                        <TableCell>{listener?.http2 ? "on" : "off"}</TableCell>
                        <TableCell>
                          {listener?.tls ? (
                            <Badge variant="outline">
                              {listener.tls.min_version ?? "tls"}–
                              {listener.tls.max_version ?? "max"}
                            </Badge>
                          ) : (
                            <span className="text-muted-foreground">—</span>
                          )}
                        </TableCell>
                        <TableCell className="text-right">
                          <Button size="icon" variant="ghost" onClick={() => setEditing(name)}>
                            <Pencil className="size-4" />
                          </Button>
                          {canEdit && (
                            <Button
                              size="icon"
                              variant="ghost"
                              onClick={() => setDeleting(name)}
                            >
                              <Trash2 className="size-4" />
                            </Button>
                          )}
                        </TableCell>
                      </TableRow>
                    );
                  })}
                </TableBody>
              </Table>
            )}
          </CardContent>
        </Card>
      )}

      <ConfirmDialog
        open={deleting !== null}
        onOpenChange={(open) => !open && setDeleting(null)}
        title="Delete listener"
        description={
          <>
            This removes the listener{" "}
            <span className="machine font-semibold">{deleting}</span>. The projection
            refuses if a domain still binds to it.
          </>
        }
        confirmText={deleting ?? ""}
        confirmLabel="Delete"
        busy={deleteListener.isPending}
        onConfirm={() => {
          if (!deleting) return;
          deleteListener.mutate(deleting, {
            onSuccess: () => {
              toast.success(`Listener ${deleting} deleted`);
              setDeleting(null);
            },
            onError: (e) => toast.error("Delete failed", { description: formatError(e) }),
          });
        }}
      />
    </PageShell>
  );
}

function ListenerEditor({
  isNew,
  name,
  listener,
  readOnly,
  saving,
  onClose,
  onSave,
}: {
  isNew: boolean;
  name: string;
  listener?: Listener;
  readOnly: boolean;
  saving: boolean;
  onClose: () => void;
  onSave: (draft: { name: string; listener: Listener }) => void;
}) {
  const [draftName, setDraftName] = React.useState(name);
  const [addr, setAddr] = React.useState(listener?.addr ?? "");
  const [http2, setHttp2] = React.useState(listener?.http2 ?? false);
  const [minVersion, setMinVersion] = React.useState(listener?.tls?.min_version ?? "");
  const [maxVersion, setMaxVersion] = React.useState(listener?.tls?.max_version ?? "");
  const [accessLog, setAccessLog] = React.useState(listener?.access_log ?? "");

  const save = () => {
    const hasTls = Boolean(minVersion || maxVersion);
    onSave({
      name: draftName,
      listener: {
        addr,
        http2,
        tls: hasTls
          ? {
              min_version: minVersion || undefined,
              max_version: maxVersion || undefined,
            }
          : undefined,
        access_log: accessLog || undefined,
        server_timing: listener?.server_timing,
      },
    });
  };

  return (
    <div className="space-y-4">
      <Card>
        <CardHeader>
          <CardTitle className="text-base">{isNew ? "New listener" : name}</CardTitle>
          <CardDescription>
            The socket address and whether it terminates TLS.
          </CardDescription>
        </CardHeader>
        <CardContent>
          <FieldList>
            {isNew && (
              <FieldRow label="Name">
                <Input
                  value={draftName}
                  onChange={(e) => setDraftName(e.target.value)}
                  placeholder="https"
                  className="machine max-w-xs"
                  readOnly={readOnly}
                />
              </FieldRow>
            )}
            <FieldRow label="Address">
              <Input
                value={addr}
                onChange={(e) => setAddr(e.target.value)}
                placeholder="0.0.0.0:443"
                className="machine max-w-xs"
                readOnly={readOnly}
              />
            </FieldRow>
            <FieldRow label="HTTP/2">
              <div className="flex items-center gap-2">
                <Checkbox
                  id="http2"
                  checked={http2}
                  onCheckedChange={(v) => setHttp2(v === true)}
                  disabled={readOnly}
                />
                <label htmlFor="http2" className="text-sm">
                  Enable HTTP/2
                </label>
              </div>
            </FieldRow>
            <FieldRow label="TLS min version">
              <Input
                value={minVersion}
                onChange={(e) => setMinVersion(e.target.value)}
                placeholder="1.2"
                className="machine max-w-xs"
                readOnly={readOnly}
              />
            </FieldRow>
            <FieldRow label="TLS max version">
              <Input
                value={maxVersion}
                onChange={(e) => setMaxVersion(e.target.value)}
                placeholder="1.3"
                className="machine max-w-xs"
                readOnly={readOnly}
              />
            </FieldRow>
            <FieldRow label="Access log">
              <Input
                value={accessLog}
                onChange={(e) => setAccessLog(e.target.value)}
                placeholder="optional"
                className="machine max-w-xs"
                readOnly={readOnly}
              />
            </FieldRow>
          </FieldList>
        </CardContent>
      </Card>

      {!readOnly && (
        <div className="flex items-center gap-2">
          <Button onClick={save} disabled={saving}>
            <Radio className="size-4" />
            {saving ? "Saving…" : "Save listener"}
          </Button>
          <Button variant="ghost" onClick={onClose}>
            Cancel
          </Button>
        </div>
      )}
    </div>
  );
}
