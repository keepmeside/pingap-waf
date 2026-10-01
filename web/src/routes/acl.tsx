import React from "react";
import { PageShell } from "@/components/page-shell";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { ConfirmDialog } from "@/components/confirm-dialog";
import { EmptyState, ErrorNote, LoadingCard } from "@/components/data-ui";
import { Textarea } from "@/components/ui/textarea";
import { useDeletePolicy, usePolicies, useProfile, usePutPolicy } from "@/queries/admin";
import { can } from "@/lib/rbac";
import { orDash } from "@/lib/format";
import { formatError } from "@/helpers/util";
import { toast } from "sonner";
import type { PluginConf } from "@/lib/types";
import { ArrowDown, ArrowUp, Pencil, Plus, ShieldCheck, Trash2 } from "lucide-react";

const CATEGORY = "acl";

/** Every `acl:<profile>` entry in the policies map. */
function aclProfiles(policies: Record<string, PluginConf> | null | undefined) {
  return Object.entries(policies ?? {})
    .filter(([name]) => name.startsWith(`${CATEGORY}:`))
    .map(([name, conf]) => ({ name: name.slice(CATEGORY.length + 1), entry: name, conf }));
}

type UnknownRecord = Record<string, unknown>;
const isRecord = (value: unknown): value is UnknownRecord =>
  typeof value === "object" && value !== null && !Array.isArray(value);
const asStrings = (value: unknown): string[] =>
  Array.isArray(value) ? value.filter((v): v is string => typeof v === "string") : [];

/** Operators each field accepts — the same closed list the engine validates against
 * (`pingap-acl/src/rule.rs`). A combination the engine would refuse is never offered. */
const OPERATORS_BY_FIELD: Record<string, string[]> = {
  ip: ["in_cidr", "equals", "in_list"],
  geo_country: ["equals", "in_list"],
  method: ["equals", "in_list"],
  user_agent: ["equals", "contains", "regex", "in_list"],
  referer: ["equals", "contains", "regex", "in_list"],
  header: ["equals", "contains", "regex", "in_list"],
};
const FIELDS = Object.keys(OPERATORS_BY_FIELD);
const ACTIONS = ["allow", "deny", "challenge", "log"];
const DEFAULT_ACTIONS = ["allow", "deny", "challenge"];
const ACTION_TONES: Record<string, string> = {
  deny: "border-destructive/50 text-destructive",
  allow: "border-emerald-500/50 text-emerald-700 dark:text-emerald-400",
  challenge: "border-violet-500/50 text-violet-700 dark:text-violet-400",
  log: "text-muted-foreground",
};

function ActionBadge({ action }: { action: string }) {
  return (
    <Badge variant="outline" className={`machine text-[11px] uppercase ${ACTION_TONES[action] ?? ""}`}>
      {action}
    </Badge>
  );
}

/** One-line summary of a rule table entry, whatever keys it happens to carry. */
function describeRule(rule: UnknownRecord): string {
  const field = typeof rule.field === "string" ? rule.field : "";
  const header = typeof rule.header === "string" && rule.header ? `(${rule.header})` : "";
  const operator = typeof rule.operator === "string" ? rule.operator : "";
  const values = asStrings(rule.values).join(", ");
  const match = [field + header, operator, values].filter(Boolean).join(" ");
  if (match) return match;
  // Not a {field, operator, values} table — show it rather than guess at it.
  const raw = JSON.stringify(rule);
  return raw.length > 96 ? `${raw.slice(0, 96)}…` : raw;
}

/** The rule list as the engine will see it: `rules` as written, then stably sorted by
 * the optional `order` hint — written position breaking ties, exactly the engine's sort. */
function sortedRules(conf: PluginConf): UnknownRecord[] {
  if (!Array.isArray(conf.rules)) return [];
  return conf.rules
    .map((rule, index) => ({ rule, index }))
    .filter((r): r is { rule: UnknownRecord; index: number } => isRecord(r.rule))
    .sort(
      (a, b) =>
        (typeof a.rule.order === "number" ? a.rule.order : 0) -
          (typeof b.rule.order === "number" ? b.rule.order : 0) || a.index - b.index,
    )
    .map((r) => r.rule);
}

function hasAccessList(conf: PluginConf): boolean {
  return isRecord(conf.access_list) || isRecord(conf["access-lists"]) || isRecord(conf.access_lists);
}

/**
 * The ACL editor. What it must never get wrong:
 *
 * - **The list order is the enforcement order.** Rows are numbered in the sequence the
 *   engine will evaluate, and the up/down controls change that sequence — not a display
 *   order layered over it. Saving writes the rules back in the order shown and
 *   rewrites every `order` hint to match, so no store that later re-sorts by `order`
 *   can resurrect the sequence the operator just replaced.
 * - `log` is not terminal: it is labelled so an operator does not read its position as
 *   a decision boundary.
 * - When `rules` is absent or not an array of tables, nothing is invented — a validated
 *   JSON textarea carries the whole config instead.
 */
export default function Acl() {
  const profileQuery = useProfile();
  const policies = usePolicies();
  const putPolicy = usePutPolicy();
  const deletePolicy = useDeletePolicy();
  const [editing, setEditing] = React.useState<string | null>(null);
  const [deleting, setDeleting] = React.useState<string | null>(null);
  const canEdit = can(profileQuery.data?.data, "edit_policy");

  const profiles = aclProfiles(policies.data?.data);
  const editTarget = editing ? profiles.find((p) => p.name === editing) : null;
  const deleteTarget = deleting ? profiles.find((p) => p.name === deleting) : null;

  return (
    <PageShell
      title="ACL"
      eyebrow="Policy · acl"
      description="Access-control profiles. Rules are first-match: the list order below is the evaluation order — the first rule whose action is terminal decides. `log` observes and the walk continues."
      actions={
        canEdit && (
          <Button size="sm" onClick={() => setEditing("*new*")}>
            <Plus className="size-4" /> New profile
          </Button>
        )
      }
    >
      {policies.isPending ? (
        <LoadingCard />
      ) : policies.isError ? (
        <ErrorNote message={formatError(policies.error)} />
      ) : policies.data?.unavailable ? (
        <EmptyState
          title="Policies unavailable"
          hint="The connected server does not expose the policy store."
        />
      ) : editTarget || editing === "*new*" ? (
        <ProfileEditor
          name={editing === "*new*" ? "" : (editTarget?.name ?? "")}
          entry={editing === "*new*" ? `${CATEGORY}:` : (editTarget?.entry ?? "")}
          conf={editTarget?.conf ?? {}}
          readOnly={!canEdit}
          onClose={() => setEditing(null)}
          onSave={(entryName, conf) => {
            putPolicy.mutate(
              { name: entryName, body: conf },
              {
                onSuccess: () => {
                  toast.success("ACL profile saved");
                  setEditing(null);
                },
                onError: (e) => toast.error("Save failed", { description: formatError(e) }),
              },
            );
          }}
          saving={putPolicy.isPending}
        />
      ) : (
        <Card>
          <CardHeader>
            <CardTitle className="text-base">Profiles</CardTitle>
            <CardDescription>
              Each profile is an `acl:` config entry a domain binds. The rule list reads
              top to bottom the way the engine walks it.
            </CardDescription>
          </CardHeader>
          <CardContent>
            {profiles.length === 0 ? (
              <EmptyState
                title="No ACL profiles"
                hint="A domain binds an `acl:` profile to gate requests by IP, method, headers or geography. Create one to begin."
              />
            ) : (
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead>Profile</TableHead>
                    <TableHead className="w-20">Rules</TableHead>
                    <TableHead>Evaluation order</TableHead>
                    {canEdit && <TableHead className="text-right">Actions</TableHead>}
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {profiles.map((profile) => {
                    const rules = sortedRules(profile.conf);
                    const rawRules = Array.isArray(profile.conf.rules);
                    return (
                      <TableRow key={profile.entry}>
                        <TableCell>
                          <div className="font-medium">{profile.name}</div>
                          <div className="mt-1 flex flex-wrap gap-1.5">
                            {typeof profile.conf.default_action === "string" && (
                              <Badge variant="outline" className="machine text-[11px]">
                                default: {profile.conf.default_action}
                              </Badge>
                            )}
                            {hasAccessList(profile.conf) && (
                              <Badge variant="secondary" className="text-[11px]">
                                access list
                              </Badge>
                            )}
                          </div>
                        </TableCell>
                        <TableCell className="machine text-sm">
                          {rawRules ? rules.length : "—"}
                        </TableCell>
                        <TableCell>
                          {!rawRules ? (
                            <span className="text-xs text-muted-foreground">
                              shape unknown — edit to inspect
                            </span>
                          ) : rules.length === 0 ? (
                            <span className="text-xs text-muted-foreground">no rules</span>
                          ) : (
                            <ol className="space-y-1">
                              {rules.slice(0, 4).map((rule, index) => (
                                <li
                                  key={index}
                                  className="flex max-w-xl items-center gap-2 text-xs"
                                >
                                  <span className="machine w-5 shrink-0 text-muted-foreground">
                                    {index + 1}.
                                  </span>
                                  <ActionBadge
                                    action={
                                      typeof rule.action === "string" ? rule.action : "?"
                                    }
                                  />
                                  <span className="truncate text-muted-foreground">
                                    {describeRule(rule)}
                                  </span>
                                </li>
                              ))}
                              {rules.length > 4 && (
                                <li className="pl-7 text-xs text-muted-foreground">
                                  +{rules.length - 4} more
                                </li>
                              )}
                            </ol>
                          )}
                        </TableCell>
                        {canEdit && (
                          <TableCell className="text-right">
                            <div className="flex justify-end gap-1">
                              <Button
                                size="sm"
                                variant="ghost"
                                aria-label={`Edit acl:${profile.name}`}
                                onClick={() => setEditing(profile.name)}
                              >
                                <Pencil className="size-4" />
                              </Button>
                              <Button
                                size="sm"
                                variant="ghost"
                                aria-label={`Delete acl:${profile.name}`}
                                onClick={() => setDeleting(profile.name)}
                              >
                                <Trash2 className="size-4 text-destructive" />
                              </Button>
                            </div>
                          </TableCell>
                        )}
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
        open={deleteTarget !== null}
        onOpenChange={(open) => {
          if (!open) setDeleting(null);
        }}
        title={`Delete acl:${deleteTarget?.name ?? ""}?`}
        description={
          <p>
            Every domain binding <span className="machine">acl:{deleteTarget?.name}</span>{" "}
            loses this access control on the next apply. This cannot be undone.
          </p>
        }
        confirmText={deleteTarget?.name ?? ""}
        confirmLabel="Delete profile"
        busy={deletePolicy.isPending}
        onConfirm={() => {
          const target = deleteTarget;
          if (!target) return;
          deletePolicy.mutate(target.entry, {
            onSuccess: () => {
              toast.success(`acl:${target.name} deleted`);
              setDeleting(null);
            },
            onError: (e) => toast.error("Delete failed", { description: formatError(e) }),
          });
        }}
      />
    </PageShell>
  );
}

/** The editable rule: the engine's own keys, defaulted to a deny-nothing stub. */
interface RuleDraft {
  field: string;
  operator: string;
  values: string;
  header: string;
  action: string;
  enabled: boolean;
}

function toDraft(rule: UnknownRecord): RuleDraft {
  return {
    field: typeof rule.field === "string" ? rule.field : "ip",
    operator: typeof rule.operator === "string" ? rule.operator : "in_cidr",
    values: asStrings(rule.values).join(", "),
    header: typeof rule.header === "string" ? rule.header : "",
    action: typeof rule.action === "string" ? rule.action : "deny",
    enabled: rule.enabled !== false,
  };
}

function fromDraft(draft: RuleDraft): UnknownRecord {
  const rule: UnknownRecord = {
    field: draft.field,
    operator: draft.operator,
    values: draft.values
      .split(",")
      .map((v) => v.trim())
      .filter(Boolean),
    action: draft.action,
    enabled: draft.enabled,
  };
  if (draft.field === "header" && draft.header.trim()) {
    rule.header = draft.header.trim();
  }
  return rule;
}

/** One profile's ordered rule table. Every row is numbered in evaluation order and
 * carries the up/down pair that moves it — the control the page exists for, because
 * order is policy: moving a `deny` above an `allow` changes what passes. */
function ProfileEditor({
  name,
  entry,
  conf,
  readOnly,
  onClose,
  onSave,
  saving,
}: {
  name: string;
  entry: string;
  conf: PluginConf;
  readOnly: boolean;
  onClose: () => void;
  onSave: (entryName: string, conf: PluginConf) => void;
  saving: boolean;
}) {
  const isNew = entry === `${CATEGORY}:`;
  const [profileName, setProfileName] = React.useState(name);
  const structured = !isRecord(conf) || !("rules" in conf) || Array.isArray(conf.rules);
  const [rules, setRules] = React.useState<RuleDraft[]>(() => sortedRules(conf).map(toDraft));
  const [defaultAction, setDefaultAction] = React.useState(
    typeof conf.default_action === "string" ? conf.default_action : "allow",
  );
  const [rawText, setRawText] = React.useState(() => JSON.stringify(conf ?? {}, null, 2));

  const move = (index: number, delta: -1 | 1) =>
    setRules((current) => {
      const target = index + delta;
      if (target < 0 || target >= current.length) return current;
      const next = [...current];
      [next[index], next[target]] = [next[target], next[index]];
      return next;
    });

  const patch = (index: number, patch: Partial<RuleDraft>) =>
    setRules((current) => {
      const next = [...current];
      const merged = { ...next[index], ...patch };
      // An operator the new field does not accept is left only if still valid.
      if (!OPERATORS_BY_FIELD[merged.field]?.includes(merged.operator)) {
        merged.operator = OPERATORS_BY_FIELD[merged.field]?.[0] ?? "equals";
      }
      next[index] = merged;
      return next;
    });

  const save = () => {
    const entryName = isNew ? `${CATEGORY}:${profileName.trim()}` : entry;
    if (isNew && !profileName.trim()) {
      toast.error("A profile name is required");
      return;
    }
    if (!structured) {
      let parsed: unknown;
      try {
        parsed = JSON.parse(rawText);
      } catch (e) {
        toast.error("Invalid JSON", { description: formatError(e) });
        return;
      }
      if (!isRecord(parsed)) {
        toast.error("The profile must be a JSON object");
        return;
      }
      onSave(entryName, parsed);
      return;
    }
    // `order` is rewritten to the displayed sequence: the engine's stable sort then
    // reproduces exactly this order, and no later re-sort can undo it.
    const out = rules.map((draft, index) => ({ ...fromDraft(draft), order: index }));
    onSave(entryName, { ...conf, default_action: defaultAction, rules: out });
  };

  return (
    <div className="space-y-4">
      {isNew && (
        <Card>
          <CardContent className="grid gap-2 py-4 sm:grid-cols-[160px_1fr] sm:items-center">
            <label htmlFor="acl-name" className="text-xs text-muted-foreground">
              Profile name
            </label>
            <input
              id="acl-name"
              value={profileName}
              onChange={(e) => setProfileName(e.target.value)}
              placeholder="edge"
              className="h-9 rounded-md border border-border bg-background px-3 text-sm"
            />
          </CardContent>
        </Card>
      )}
      <Card>
        <CardHeader>
          <CardTitle className="text-base">{isNew ? "New profile" : `acl:${name}`}</CardTitle>
          <CardDescription>
            {structured
              ? "Row 1 is evaluated first. The first allow, deny or challenge that matches ends the walk; log only observes. When nothing terminal matches, the default action decides."
              : "This profile's `rules` is not a list of rule tables, so it is edited as raw JSON — the plugin validates it on save."}
          </CardDescription>
        </CardHeader>
        <CardContent>
          {structured ? (
            <>
              <div className="mb-4 grid max-w-md gap-2 sm:grid-cols-[160px_1fr] sm:items-center">
                <label htmlFor="acl-default" className="text-xs text-muted-foreground">
                  Default action
                </label>
                <Select
                  value={defaultAction}
                  onValueChange={setDefaultAction}
                  disabled={readOnly}
                >
                  <SelectTrigger id="acl-default" className="w-40">
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    {DEFAULT_ACTIONS.map((action) => (
                      <SelectItem key={action} value={action}>
                        {action}
                      </SelectItem>
                    ))}
                  </SelectContent>
                </Select>
              </div>
              {rules.length === 0 ? (
                <EmptyState
                  title="No rules"
                  hint="With no rules the default action decides every request. Add a rule to start matching."
                />
              ) : (
                <Table>
                  <TableHeader>
                    <TableRow>
                      <TableHead className="w-10">#</TableHead>
                      <TableHead>Field</TableHead>
                      <TableHead>Operator</TableHead>
                      <TableHead>Values</TableHead>
                      <TableHead>Action</TableHead>
                      {!readOnly && <TableHead className="w-28 text-right">Reorder</TableHead>}
                    </TableRow>
                  </TableHeader>
                  <TableBody>
                    {rules.map((rule, index) => (
                      <TableRow key={index} className={rule.enabled ? "" : "opacity-50"}>
                        <TableCell className="machine text-muted-foreground">
                          {index + 1}
                        </TableCell>
                        <TableCell>
                          {readOnly ? (
                            <span className="text-sm">
                              {rule.field}
                              {rule.header ? ` (${rule.header})` : ""}
                            </span>
                          ) : (
                            <div className="flex items-center gap-1.5">
                              <Select
                                value={rule.field}
                                onValueChange={(v) => patch(index, { field: v })}
                              >
                                <SelectTrigger className="w-32">
                                  <SelectValue />
                                </SelectTrigger>
                                <SelectContent>
                                  {FIELDS.map((field) => (
                                    <SelectItem key={field} value={field}>
                                      {field}
                                    </SelectItem>
                                  ))}
                                </SelectContent>
                              </Select>
                              {rule.field === "header" && (
                                <input
                                  aria-label="Header name"
                                  value={rule.header}
                                  onChange={(e) => patch(index, { header: e.target.value })}
                                  placeholder="x-tenant"
                                  className="machine h-9 w-32 rounded-md border border-border bg-background px-2 text-sm"
                                />
                              )}
                            </div>
                          )}
                        </TableCell>
                        <TableCell>
                          {readOnly ? (
                            <span className="machine text-sm">{rule.operator}</span>
                          ) : (
                            <Select
                              value={rule.operator}
                              onValueChange={(v) => patch(index, { operator: v })}
                            >
                              <SelectTrigger className="w-28">
                                <SelectValue />
                              </SelectTrigger>
                              <SelectContent>
                                {(OPERATORS_BY_FIELD[rule.field] ?? []).map((op) => (
                                  <SelectItem key={op} value={op}>
                                    {op}
                                  </SelectItem>
                                ))}
                              </SelectContent>
                            </Select>
                          )}
                        </TableCell>
                        <TableCell>
                          {readOnly ? (
                            <span className="machine block max-w-64 truncate text-sm">
                              {orDash(rule.values)}
                            </span>
                          ) : (
                            <input
                              aria-label="Rule values, comma separated"
                              value={rule.values}
                              onChange={(e) => patch(index, { values: e.target.value })}
                              placeholder="10.0.0.0/8"
                              className="machine h-9 w-full min-w-40 rounded-md border border-border bg-background px-2 text-sm"
                            />
                          )}
                        </TableCell>
                        <TableCell>
                          <div className="flex items-center gap-2">
                            {readOnly ? (
                              <ActionBadge action={rule.action} />
                            ) : (
                              <>
                                <Select
                                  value={rule.action}
                                  onValueChange={(v) => patch(index, { action: v })}
                                >
                                  <SelectTrigger className="w-28">
                                    <SelectValue />
                                  </SelectTrigger>
                                  <SelectContent>
                                    {ACTIONS.map((action) => (
                                      <SelectItem key={action} value={action}>
                                        {action}
                                      </SelectItem>
                                    ))}
                                  </SelectContent>
                                </Select>
                                <ActionBadge action={rule.action} />
                              </>
                            )}
                          </div>
                        </TableCell>
                        {!readOnly && (
                          <TableCell className="text-right">
                            <div className="flex justify-end gap-1">
                              <Button
                                size="icon"
                                variant="ghost"
                                className="size-8"
                                disabled={index === 0}
                                aria-label={`Move rule ${index + 1} up`}
                                onClick={() => move(index, -1)}
                              >
                                <ArrowUp className="size-4" />
                              </Button>
                              <Button
                                size="icon"
                                variant="ghost"
                                className="size-8"
                                disabled={index === rules.length - 1}
                                aria-label={`Move rule ${index + 1} down`}
                                onClick={() => move(index, 1)}
                              >
                                <ArrowDown className="size-4" />
                              </Button>
                              <Button
                                size="icon"
                                variant="ghost"
                                className="size-8"
                                aria-label={`Remove rule ${index + 1}`}
                                onClick={() =>
                                  setRules((current) => current.filter((_, i) => i !== index))
                                }
                              >
                                <Trash2 className="size-4" />
                              </Button>
                            </div>
                          </TableCell>
                        )}
                      </TableRow>
                    ))}
                  </TableBody>
                </Table>
              )}
              {!readOnly && (
                <Button
                  size="sm"
                  variant="outline"
                  className="mt-4"
                  onClick={() =>
                    setRules((current) => [
                      ...current,
                      {
                        field: "ip",
                        operator: "in_cidr",
                        values: "",
                        header: "",
                        action: "deny",
                        enabled: true,
                      },
                    ])
                  }
                >
                  <Plus className="size-4" /> Add rule
                </Button>
              )}
            </>
          ) : (
            <Textarea
              aria-label="Profile config as JSON"
              value={rawText}
              onChange={(e) => setRawText(e.target.value)}
              disabled={readOnly}
              className="machine min-h-64"
            />
          )}
        </CardContent>
      </Card>
      {!readOnly && (
        <div className="flex items-center gap-2">
          <Button onClick={save} disabled={saving}>
            <ShieldCheck className="size-4" />
            {saving ? "Saving…" : "Save profile"}
          </Button>
          <Button variant="ghost" onClick={onClose}>
            Cancel
          </Button>
        </div>
      )}
    </div>
  );
}
