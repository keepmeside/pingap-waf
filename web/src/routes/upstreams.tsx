import React from "react";
import { PageShell } from "@/components/page-shell";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { ConfirmDialog } from "@/components/confirm-dialog";
import { EmptyState, ErrorNote, FieldList, FieldRow, LoadingCard } from "@/components/data-ui";
import {
  useDeleteUpstream, useProfile, usePutUpstream, useUpstreams,
} from "@/queries/admin";
import { can } from "@/lib/rbac";
import { formatError } from "@/helpers/util";
import { toast } from "sonner";
import type { Backend, Upstream } from "@/lib/types";
import { Pencil, Plus, Server, Trash2, X } from "lucide-react";

/**
 * Upstream pools — where a domain's traffic is proxied.
 *
 * Backends carry an optional weight: it is emitted as the second field of the address
 * string, which is how the discovery layer reads it — so a weight is part of the address,
 * not a separate knob. Editing here is the whole pool, not a backend at a time.
 */
export default function Upstreams() {
  const profileQuery = useProfile();
  const upstreams = useUpstreams();
  const putUpstream = usePutUpstream();
  const deleteUpstream = useDeleteUpstream();
  const canEdit = can(profileQuery.data?.data, "edit_upstream");

  const [editing, setEditing] = React.useState<string | null>(null);
  const [deleting, setDeleting] = React.useState<string | null>(null);

  const names = Object.keys(upstreams.data?.data ?? {}).sort();
  const target = editing ? (upstreams.data?.data ?? {})[editing] : undefined;

  return (
    <PageShell
      title="Upstreams"
      eyebrow="Traffic · upstreams"
      description="Origin pools — the backends a domain's traffic is proxied to, with discovery, load balancing and TLS settings."
      actions={
        canEdit && (
          <Button size="sm" onClick={() => setEditing("*new*")}>
            <Plus className="size-4" /> New upstream
          </Button>
        )
      }
    >
      {upstreams.isPending ? (
        <LoadingCard />
      ) : upstreams.isError ? (
        <ErrorNote message={formatError(upstreams.error)} />
      ) : editing ? (
        <UpstreamEditor
          isNew={editing === "*new*"}
          name={editing === "*new*" ? "" : editing}
          upstream={target}
          readOnly={!canEdit}
          saving={putUpstream.isPending}
          onClose={() => setEditing(null)}
          onSave={(draft) => {
            putUpstream.mutate(
              { name: draft.name, body: draft.upstream },
              {
                onSuccess: () => {
                  toast.success(`Upstream ${draft.name} saved`);
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
            <CardTitle className="text-base">Configured upstreams</CardTitle>
            <CardDescription>{names.length} pool{names.length === 1 ? "" : "s"}</CardDescription>
          </CardHeader>
          <CardContent>
            {names.length === 0 ? (
              <EmptyState
                title="No upstreams"
                hint="An upstream is the set of backends a domain proxies to. Create one, then point a domain at it."
              />
            ) : (
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead>Name</TableHead>
                    <TableHead>Backends</TableHead>
                    <TableHead>LB</TableHead>
                    <TableHead>Discovery</TableHead>
                    <TableHead className="text-right">Actions</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {names.map((name) => {
                    const upstream = (upstreams.data?.data ?? {})[name];
                    return (
                      <TableRow key={name}>
                        <TableCell className="font-medium">{name}</TableCell>
                        <TableCell>
                          <div className="flex flex-wrap gap-1">
                            {(upstream?.backends ?? []).map((backend, index) => (
                              <Badge key={index} variant="outline" className="machine">
                                {backend.addr}
                                {backend.weight != null && ` w${backend.weight}`}
                              </Badge>
                            ))}
                          </div>
                        </TableCell>
                        <TableCell>{upstream?.lb_algorithm ?? "round_robin"}</TableCell>
                        <TableCell>{upstream?.discovery ?? "static"}</TableCell>
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
        title="Delete upstream"
        description={
          <>
            This removes the upstream{" "}
            <span className="machine font-semibold">{deleting}</span>. A domain still
            pointing at it will fail projection — the projection refuses a domain that names
            an upstream that does not exist.
          </>
        }
        confirmText={deleting ?? ""}
        confirmLabel="Delete"
        busy={deleteUpstream.isPending}
        onConfirm={() => {
          if (!deleting) return;
          deleteUpstream.mutate(deleting, {
            onSuccess: () => {
              toast.success(`Upstream ${deleting} deleted`);
              setDeleting(null);
            },
            onError: (e) => toast.error("Delete failed", { description: formatError(e) }),
          });
        }}
      />
    </PageShell>
  );
}

function UpstreamEditor({
  isNew,
  name,
  upstream,
  readOnly,
  saving,
  onClose,
  onSave,
}: {
  isNew: boolean;
  name: string;
  upstream?: Upstream;
  readOnly: boolean;
  saving: boolean;
  onClose: () => void;
  onSave: (draft: { name: string; upstream: Upstream }) => void;
}) {
  const [draftName, setDraftName] = React.useState(name);
  const [backends, setBackends] = React.useState<Backend[]>(upstream?.backends ?? []);
  const [lb, setLb] = React.useState(upstream?.lb_algorithm ?? "");
  const [healthCheck, setHealthCheck] = React.useState(upstream?.health_check ?? "");
  const [discovery, setDiscovery] = React.useState(upstream?.discovery ?? "");
  const [tlsSni, setTlsSni] = React.useState(upstream?.tls_sni ?? "");

  const setBackend = (index: number, patch: Partial<Backend>) =>
    setBackends((current) =>
      current.map((b, i) => (i === index ? { ...b, ...patch } : b)),
    );

  const save = () => {
    onSave({
      name: draftName,
      upstream: {
        backends: backends.filter((b) => b.addr.trim()),
        lb_algorithm: lb || undefined,
        health_check: healthCheck || undefined,
        discovery: discovery || undefined,
        tls_sni: tlsSni || undefined,
        verify_cert: upstream?.verify_cert,
      },
    });
  };

  return (
    <div className="space-y-4">
      <Card>
        <CardHeader>
          <CardTitle className="text-base">{isNew ? "New upstream" : name}</CardTitle>
        </CardHeader>
        <CardContent>
          <FieldList>
            {isNew && (
              <FieldRow label="Name">
                <Input
                  value={draftName}
                  onChange={(e) => setDraftName(e.target.value)}
                  placeholder="app"
                  className="machine max-w-xs"
                  readOnly={readOnly}
                />
              </FieldRow>
            )}
            <FieldRow label="LB algorithm">
              <Input
                value={lb}
                onChange={(e) => setLb(e.target.value)}
                placeholder="round_robin"
                className="machine max-w-xs"
                readOnly={readOnly}
              />
            </FieldRow>
            <FieldRow label="Discovery">
              <Input
                value={discovery}
                onChange={(e) => setDiscovery(e.target.value)}
                placeholder="static | dns | docker | transparent"
                className="machine max-w-xs"
                readOnly={readOnly}
              />
            </FieldRow>
            <FieldRow label="Health check">
              <Input
                value={healthCheck}
                onChange={(e) => setHealthCheck(e.target.value)}
                placeholder="optional"
                className="machine max-w-xs"
                readOnly={readOnly}
              />
            </FieldRow>
            <FieldRow label="TLS SNI">
              <Input
                value={tlsSni}
                onChange={(e) => setTlsSni(e.target.value)}
                placeholder="optional"
                className="machine max-w-xs"
                readOnly={readOnly}
              />
            </FieldRow>
          </FieldList>
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle className="text-base">Backends</CardTitle>
          <CardDescription>
            Each backend is an address with an optional weight — the weight travels as the
            second field of the address the discovery layer reads.
          </CardDescription>
        </CardHeader>
        <CardContent className="space-y-2">
          {backends.map((backend, index) => (
            <div key={index} className="flex items-center gap-2">
              <Input
                value={backend.addr}
                onChange={(e) => setBackend(index, { addr: e.target.value })}
                placeholder="10.0.0.1:8080"
                className="machine flex-1"
                readOnly={readOnly}
              />
              <Input
                type="number"
                value={backend.weight ?? ""}
                onChange={(e) =>
                  setBackend(index, {
                    weight: e.target.value ? Number(e.target.value) : undefined,
                  })
                }
                placeholder="weight"
                className="machine w-24"
                readOnly={readOnly}
              />
              {!readOnly && (
                <Button
                  size="icon"
                  variant="ghost"
                  onClick={() =>
                    setBackends((current) => current.filter((_, i) => i !== index))
                  }
                  aria-label="Remove backend"
                >
                  <X className="size-4" />
                </Button>
              )}
            </div>
          ))}
          {!readOnly && (
            <Button
              size="sm"
              variant="outline"
              onClick={() => setBackends((current) => [...current, { addr: "" }])}
            >
              <Plus className="size-4" /> Add backend
            </Button>
          )}
        </CardContent>
      </Card>

      {!readOnly && (
        <div className="flex items-center gap-2">
          <Button onClick={save} disabled={saving}>
            <Server className="size-4" />
            {saving ? "Saving…" : "Save upstream"}
          </Button>
          <Button variant="ghost" onClick={onClose}>
            Cancel
          </Button>
        </div>
      )}
    </div>
  );
}
