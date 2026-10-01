import React from "react";
import { PageShell } from "@/components/page-shell";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { ConfirmDialog } from "@/components/confirm-dialog";
import { EmptyState, ErrorNote, FieldList, FieldRow, LoadingCard } from "@/components/data-ui";
import {
  useDeleteDomain, useDomains, useListeners, usePolicies, useProfile, usePutDomain, useUpstreams,
} from "@/queries/admin";
import { can } from "@/lib/rbac";
import { formatError } from "@/helpers/util";
import { toast } from "sonner";
import type { Domain, PolicyBinding } from "@/lib/types";
import { Globe2, Pencil, Plus, Trash2, X } from "lucide-react";

type Draft = {
  name: string;
  hostnames: string;
  listener: string;
  upstream: string;
  path: string;
  policies: PolicyBinding[];
};

/**
 * The domain editor — the product's mental model in one screen.
 *
 * A domain is not a data-plane object; it is intent projected onto a Location plus a
 * membership in its listener. So the editor composes the four things an operator thinks in
 * — which names it answers (`hostnames`), which socket it listens on (`listener`), where
 * traffic goes (`upstream`), and which policies gate it (`policies`) — rather than making
 * them edit a Location row and an upstream row separately.
 *
 * Policy bindings are ordered: the first to answer terminates the request. The editor
 * preserves that order and surfaces it, because putting the cheapest gate first is the
 * operator's call, not something to normalise away.
 */
export default function Domains() {
  const profileQuery = useProfile();
  const domains = useDomains();
  const upstreams = useUpstreams();
  const listeners = useListeners();
  const policies = usePolicies();
  const putDomain = usePutDomain();
  const deleteDomain = useDeleteDomain();
  const canEdit = can(profileQuery.data?.data, "edit_domain");

  const [editing, setEditing] = React.useState<string | null>(null);
  const [deleting, setDeleting] = React.useState<string | null>(null);

  const names = Object.keys(domains.data?.data ?? {}).sort();
  const target = editing ? (domains.data?.data ?? {})[editing] : undefined;

  return (
    <PageShell
      title="Domains"
      eyebrow="Traffic · domains"
      description="A hostname, where its traffic goes, and what policy applies — the object operators actually think in, projected onto a Location behind the scenes."
      actions={
        canEdit && (
          <Button size="sm" onClick={() => setEditing("*new*")}>
            <Plus className="size-4" /> New domain
          </Button>
        )
      }
    >
      {domains.isPending ? (
        <LoadingCard />
      ) : domains.isError ? (
        <ErrorNote message={formatError(domains.error)} />
      ) : editing ? (
        <DomainEditor
          isNew={editing === "*new*"}
          name={editing === "*new*" ? "" : editing}
          domain={target}
          upstreamNames={Object.keys(upstreams.data?.data ?? {}).sort()}
          listenerNames={Object.keys(listeners.data?.data ?? {}).sort()}
          policyNames={Object.keys(policies.data?.data ?? {}).sort()}
          readOnly={!canEdit}
          saving={putDomain.isPending}
          onClose={() => setEditing(null)}
          onSave={(draft) => {
            putDomain.mutate(
              {
                name: draft.name,
                body: {
                  hostnames: draft.hostnames.split(",").map((h) => h.trim()).filter(Boolean),
                  path: draft.path || undefined,
                  listener: draft.listener,
                  upstream: draft.upstream,
                  grpc_web: target?.grpc_web ?? false,
                  policies: draft.policies,
                },
              },
              {
                onSuccess: () => {
                  toast.success(`Domain ${draft.name} saved`);
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
            <CardTitle className="text-base">Configured domains</CardTitle>
            <CardDescription>
              {names.length} domain{names.length === 1 ? "" : "s"} — each composes a
              listener, an upstream and its policy bindings.
            </CardDescription>
          </CardHeader>
          <CardContent>
            {names.length === 0 ? (
              <EmptyState
                title="No domains"
                hint="A domain ties a hostname to a listener, an upstream and its policies. Create one to begin."
              />
            ) : (
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead>Name</TableHead>
                    <TableHead>Hostnames</TableHead>
                    <TableHead>Upstream</TableHead>
                    <TableHead>Policies</TableHead>
                    <TableHead className="text-right">Actions</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {names.map((name) => {
                    const domain = (domains.data?.data ?? {})[name];
                    return (
                      <TableRow key={name}>
                        <TableCell className="font-medium">{name}</TableCell>
                        <TableCell>{domain?.hostnames.join(", ")}</TableCell>
                        <TableCell>{domain?.upstream}</TableCell>
                        <TableCell>
                          <div className="flex flex-wrap gap-1">
                            {(domain?.policies ?? []).map((binding, index) => (
                              <Badge key={index} variant="outline" className="machine">
                                {bindingKey(binding)}
                              </Badge>
                            ))}
                            {(domain?.policies ?? []).length === 0 && "—"}
                          </div>
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
        title="Delete domain"
        description={
          <>
            This removes the domain <span className="machine font-semibold">{deleting}</span>{" "}
            and its policy bindings. Traffic to its hostnames stops being served by it.
          </>
        }
        confirmText={deleting ?? ""}
        confirmLabel="Delete"
        busy={deleteDomain.isPending}
        onConfirm={() => {
          if (!deleting) return;
          deleteDomain.mutate(deleting, {
            onSuccess: () => {
              toast.success(`Domain ${deleting} deleted`);
              setDeleting(null);
            },
            onError: (e) => toast.error("Delete failed", { description: formatError(e) }),
          });
        }}
      />
    </PageShell>
  );
}

function bindingKey(binding: PolicyBinding): string {
  if ("waf" in binding) return `waf:${binding.waf}`;
  if ("acl" in binding) return `acl:${binding.acl}`;
  if ("bot" in binding) return `bot:${binding.bot}`;
  return "?";
}

function DomainEditor({
  isNew,
  name,
  domain,
  upstreamNames,
  listenerNames,
  policyNames,
  readOnly,
  saving,
  onClose,
  onSave,
}: {
  isNew: boolean;
  name: string;
  domain?: Domain;
  upstreamNames: string[];
  listenerNames: string[];
  policyNames: string[];
  readOnly: boolean;
  saving: boolean;
  onClose: () => void;
  onSave: (draft: Draft) => void;
}) {
  const [draft, setDraft] = React.useState<Draft>({
    name,
    hostnames: domain?.hostnames.join(", ") ?? "",
    listener: domain?.listener ?? (listenerNames[0] ?? ""),
    upstream: domain?.upstream ?? (upstreamNames[0] ?? ""),
    path: domain?.path ?? "",
    policies: domain?.policies ?? [],
  });

  const [newPolicy, setNewPolicy] = React.useState("");

  const addPolicy = () => {
    const [category, ...rest] = newPolicy.split(":");
    const profile = rest.join(":");
    if (!category || !profile) return;
    const binding =
      category === "waf" ? { waf: profile }
      : category === "acl" ? { acl: profile }
      : category === "bot" ? { bot: profile }
      : null;
    if (!binding) return;
    setDraft((d) => ({ ...d, policies: [...d.policies, binding] }));
    setNewPolicy("");
  };

  const removePolicy = (index: number) =>
    setDraft((d) => ({ ...d, policies: d.policies.filter((_, i) => i !== index) }));

  const movePolicy = (index: number, dir: -1 | 1) =>
    setDraft((d) => {
      const policies = [...d.policies];
      const swap = index + dir;
      if (swap < 0 || swap >= policies.length) return d;
      [policies[index], policies[swap]] = [policies[swap], policies[index]];
      return { ...d, policies };
    });

  return (
    <div className="space-y-4">
      <Card>
        <CardHeader>
          <CardTitle className="text-base">{isNew ? "New domain" : name}</CardTitle>
          <CardDescription>
            {isNew
              ? "Names it answers, the socket it listens on, where traffic goes, and the policies that gate it."
              : "Editing the domain's hostnames, routing and policy bindings."}
          </CardDescription>
        </CardHeader>
        <CardContent>
          <FieldList>
            {isNew && (
              <FieldRow label="Name">
                <Input
                  value={draft.name}
                  onChange={(e) => setDraft((d) => ({ ...d, name: e.target.value }))}
                  placeholder="site"
                  className="machine max-w-xs"
                  readOnly={readOnly}
                />
              </FieldRow>
            )}
            <FieldRow label="Hostnames">
              <Input
                value={draft.hostnames}
                onChange={(e) => setDraft((d) => ({ ...d, hostnames: e.target.value }))}
                placeholder="example.com, www.example.com"
                className="machine"
                readOnly={readOnly}
              />
              <p className="mt-1 text-xs text-muted-foreground">
                Comma-separated — one domain can serve several names.
              </p>
            </FieldRow>
            <FieldRow label="Listener">
              <Select
                value={draft.listener}
                onValueChange={(v) => setDraft((d) => ({ ...d, listener: v }))}
                disabled={readOnly}
              >
                <SelectTrigger className="machine max-w-xs">
                  <SelectValue placeholder="a listener" />
                </SelectTrigger>
                <SelectContent>
                  {listenerNames.map((n) => (
                    <SelectItem key={n} value={n}>{n}</SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </FieldRow>
            <FieldRow label="Upstream">
              <Select
                value={draft.upstream}
                onValueChange={(v) => setDraft((d) => ({ ...d, upstream: v }))}
                disabled={readOnly}
              >
                <SelectTrigger className="machine max-w-xs">
                  <SelectValue placeholder="an upstream" />
                </SelectTrigger>
                <SelectContent>
                  {upstreamNames.map((n) => (
                    <SelectItem key={n} value={n}>{n}</SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </FieldRow>
            <FieldRow label="Path prefix">
              <Input
                value={draft.path}
                onChange={(e) => setDraft((d) => ({ ...d, path: e.target.value }))}
                placeholder="/ (all paths)"
                className="machine max-w-xs"
                readOnly={readOnly}
              />
            </FieldRow>
          </FieldList>
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle className="text-base">Policy bindings</CardTitle>
          <CardDescription>
            Evaluated in order — the first policy to answer terminates the request. Order is
            the operator's call; the cheapest gate belongs first.
          </CardDescription>
        </CardHeader>
        <CardContent className="space-y-3">
          {draft.policies.length === 0 && (
            <p className="py-3 text-sm text-muted-foreground">
              No policies bound — the domain proxies unfiltered. Bind a `waf:`, `acl:` or
              `bot:` profile to enforce.
            </p>
          )}
          <ol className="space-y-2">
            {draft.policies.map((binding, index) => (
              <li
                key={index}
                className="flex items-center gap-2 rounded-md border border-border px-3 py-2"
              >
                <span className="machine w-6 text-sm text-muted-foreground">{index + 1}</span>
                <Badge variant="outline" className="machine">
                  {bindingKey(binding)}
                </Badge>
                {!readOnly && (
                  <div className="ml-auto flex items-center gap-1">
                    <Button
                      size="icon"
                      variant="ghost"
                      className="size-7"
                      disabled={index === 0}
                      onClick={() => movePolicy(index, -1)}
                      aria-label="Move up"
                    >
                      ↑
                    </Button>
                    <Button
                      size="icon"
                      variant="ghost"
                      className="size-7"
                      disabled={index === draft.policies.length - 1}
                      onClick={() => movePolicy(index, 1)}
                      aria-label="Move down"
                    >
                      ↓
                    </Button>
                    <Button
                      size="icon"
                      variant="ghost"
                      className="size-7"
                      onClick={() => removePolicy(index)}
                      aria-label="Remove"
                    >
                      <X className="size-3.5" />
                    </Button>
                  </div>
                )}
              </li>
            ))}
          </ol>
          {!readOnly && (
            <div className="flex items-center gap-2 pt-2">
              <Select value={newPolicy} onValueChange={setNewPolicy}>
                <SelectTrigger className="machine max-w-xs">
                  <SelectValue placeholder="bind a policy…" />
                </SelectTrigger>
                <SelectContent>
                  {policyNames.map((n) => (
                    <SelectItem key={n} value={n}>{n}</SelectItem>
                  ))}
                </SelectContent>
              </Select>
              <Button size="sm" variant="outline" onClick={addPolicy} disabled={!newPolicy}>
                <Plus className="size-4" /> Bind
              </Button>
            </div>
          )}
        </CardContent>
      </Card>

      {!readOnly && (
        <div className="flex items-center gap-2">
          <Button onClick={() => onSave(draft)} disabled={saving}>
            <Globe2 className="size-4" />
            {saving ? "Saving…" : "Save domain"}
          </Button>
          <Button variant="ghost" onClick={onClose}>
            Cancel
          </Button>
        </div>
      )}
    </div>
  );
}
