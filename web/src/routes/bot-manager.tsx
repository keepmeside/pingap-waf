import React from "react";
import { PageShell } from "@/components/page-shell";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Checkbox } from "@/components/ui/checkbox";
import { ConfirmDialog } from "@/components/confirm-dialog";
import { EmptyState, ErrorNote, LoadingCard } from "@/components/data-ui";
import { ModeBadge } from "@/components/mode-badge";
import { Textarea } from "@/components/ui/textarea";
import { useDeletePolicy, usePolicies, useProfile, usePutPolicy } from "@/queries/admin";
import { can } from "@/lib/rbac";
import { formatError } from "@/helpers/util";
import { toast } from "sonner";
import type { PluginConf } from "@/lib/types";
import { ArrowDown, ArrowUp, Pencil, Plus, ShieldCheck, Trash2 } from "lucide-react";

const CATEGORY = "bot";

/** Every `bot:<profile>` entry in the policies map. */
function botProfiles(policies: Record<string, PluginConf> | null | undefined) {
  return Object.entries(policies ?? {})
    .filter(([name]) => name.startsWith(`${CATEGORY}:`))
    .map(([name, conf]) => ({ name: name.slice(CATEGORY.length + 1), entry: name, conf }));
}

type UnknownRecord = Record<string, unknown>;
const isRecord = (value: unknown): value is UnknownRecord =>
  typeof value === "object" && value !== null && !Array.isArray(value);

const ACTIONS = ["allow", "deny", "log"];
const MODES = ["detect", "block"];
const ACTION_TONES: Record<string, string> = {
  deny: "border-destructive/50 text-destructive",
  allow: "border-emerald-500/50 text-emerald-700 dark:text-emerald-400",
  log: "text-muted-foreground",
};

function ActionBadge({ action }: { action: string }) {
  return (
    <Badge variant="outline" className={`machine text-[11px] uppercase ${ACTION_TONES[action] ?? ""}`}>
      {action}
    </Badge>
  );
}

/** What a bot rule matches on, in one line. The fingerprint type is spelled out — a
 * JA4H entry has no meaning as any other fingerprint, so it is never rendered bare. */
function describeRule(rule: UnknownRecord): string {
  const parts: string[] = [];
  if (typeof rule.fingerprint === "string" && rule.fingerprint) {
    const kind = typeof rule.fingerprint_type === "string" ? rule.fingerprint_type : "?";
    parts.push(`JA4H (${kind}) ${rule.fingerprint}`);
  }
  if (typeof rule.user_agent === "string" && rule.user_agent) {
    parts.push(`User-Agent ~ ${rule.user_agent}`);
  }
  if (parts.length === 0) {
    const raw = JSON.stringify(rule);
    return raw.length > 96 ? `${raw.slice(0, 96)}…` : raw;
  }
  return parts.join("  AND  ");
}

function rulesOf(conf: PluginConf): UnknownRecord[] {
  return Array.isArray(conf.rules) ? conf.rules.filter(isRecord) : [];
}

/**
 * The bot-manager. What it must never get wrong:
 *
 * - **The fingerprint is JA4H, never JA4.** JA4H fingerprints the HTTP/1.x request
 *   head — method, version, and header names *in the order the client sent them*. It
 *   is a client-behaviour signal, not a TLS-stack identity, and presenting it as JA4
 *   would claim a strength it does not have. HTTP/2 requests get no fingerprint at
 *   all (their header order is arbitrary), so a fingerprint rule can never match h2 —
 *   the UI says so rather than letting an operator believe the list covers it.
 * - `detect` and `block` are not interchangeable: `detect` records what it *would*
 *   have denied and refuses nothing. That is the rollout mechanism, so the mode is
 *   rendered with the same ModeBadge the WAF page uses.
 * - Rules are an ordered, first-terminal-match list, like the ACL — the same numbered
 *   rows and reorder controls.
 */
export default function BotManager() {
  const profileQuery = useProfile();
  const policies = usePolicies();
  const putPolicy = usePutPolicy();
  const deletePolicy = useDeletePolicy();
  const [editing, setEditing] = React.useState<string | null>(null);
  const [deleting, setDeleting] = React.useState<string | null>(null);
  const canEdit = can(profileQuery.data?.data, "edit_policy");

  const profiles = botProfiles(policies.data?.data);
  const editTarget = editing ? profiles.find((p) => p.name === editing) : null;
  const deleteTarget = deleting ? profiles.find((p) => p.name === deleting) : null;

  return (
    <PageShell
      title="Bot Manager"
      eyebrow="Policy · bot"
      description="Bot profiles keyed on JA4H — the HTTP/1.1 header-order fingerprint, a client-behaviour signal rather than a TLS identity. `detect` records verdicts and refuses nothing; `block` enforces. HTTP/2 carries no JA4H, so fingerprint rules cannot match it."
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
                  toast.success("Bot profile saved");
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
              Each profile is a `bot:` config entry a domain binds — a mode, an optional
              crawler exemption, and an ordered rule list whose first terminal match
              decides.
            </CardDescription>
          </CardHeader>
          <CardContent>
            {profiles.length === 0 ? (
              <EmptyState
                title="No bot profiles"
                hint="A domain binds a `bot:` profile to fingerprint clients. Run it in `detect` first — the allowed population's JA4H values are what a deny list is built from."
              />
            ) : (
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead>Profile</TableHead>
                    <TableHead>Mode</TableHead>
                    <TableHead className="w-20">Rules</TableHead>
                    <TableHead>Rule list (evaluation order)</TableHead>
                    {canEdit && <TableHead className="text-right">Actions</TableHead>}
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {profiles.map((profile) => {
                    const rules = rulesOf(profile.conf);
                    const mode =
                      typeof profile.conf.mode === "string" ? profile.conf.mode : "detect";
                    return (
                      <TableRow key={profile.entry}>
                        <TableCell>
                          <div className="font-medium">{profile.name}</div>
                          <div className="mt-1 flex flex-wrap gap-1.5">
                            {profile.conf.allow_known_bots === true && (
                              <Badge variant="secondary" className="text-[11px]">
                                known crawlers exempt
                              </Badge>
                            )}
                            {profile.conf.use_signatures === true && (
                              <Badge variant="secondary" className="text-[11px]">
                                shipped signatures
                              </Badge>
                            )}
                          </div>
                        </TableCell>
                        <TableCell>
                          <ModeBadge mode={mode} />
                        </TableCell>
                        <TableCell className="machine text-sm">{rules.length}</TableCell>
                        <TableCell>
                          {rules.length === 0 ? (
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
                                aria-label={`Edit bot:${profile.name}`}
                                onClick={() => setEditing(profile.name)}
                              >
                                <Pencil className="size-4" />
                              </Button>
                              <Button
                                size="sm"
                                variant="ghost"
                                aria-label={`Delete bot:${profile.name}`}
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
        title={`Delete bot:${deleteTarget?.name ?? ""}?`}
        description={
          <p>
            Every domain binding <span className="machine">bot:{deleteTarget?.name}</span>{" "}
            loses this fingerprint policy on the next apply. This cannot be undone.
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
              toast.success(`bot:${target.name} deleted`);
              setDeleting(null);
            },
            onError: (e) => toast.error("Delete failed", { description: formatError(e) }),
          });
        }}
      />
    </PageShell>
  );
}

interface RuleDraft {
  fingerprint: string;
  user_agent: string;
  action: string;
  enabled: boolean;
  remark: string;
}

function toDraft(rule: UnknownRecord): RuleDraft {
  return {
    fingerprint: typeof rule.fingerprint === "string" ? rule.fingerprint : "",
    user_agent: typeof rule.user_agent === "string" ? rule.user_agent : "",
    action: typeof rule.action === "string" ? rule.action : "deny",
    enabled: rule.enabled !== false,
    remark: typeof rule.remark === "string" ? rule.remark : "",
  };
}

/** A draft back to the engine's shape. A fingerprint is always written with
 * `fingerprint_type = "ja4h"`: it is the only type the engine accepts, and an untyped
 * fingerprint is refused at config load. */
function fromDraft(draft: RuleDraft): UnknownRecord {
  const rule: UnknownRecord = { action: draft.action, enabled: draft.enabled };
  const fingerprint = draft.fingerprint.trim();
  if (fingerprint) {
    rule.fingerprint_type = "ja4h";
    rule.fingerprint = fingerprint;
  }
  const userAgent = draft.user_agent.trim();
  if (userAgent) rule.user_agent = userAgent;
  const remark = draft.remark.trim();
  if (remark) rule.remark = remark;
  return rule;
}

/** One profile's mode, flags and ordered rule list. A rule may carry a JA4H
 * fingerprint, a User-Agent regex, or both — both means "that client *and* that UA". */
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
  const [mode, setMode] = React.useState(
    typeof conf.mode === "string" ? conf.mode : "detect",
  );
  const [allowKnownBots, setAllowKnownBots] = React.useState(conf.allow_known_bots === true);
  const [useSignatures, setUseSignatures] = React.useState(conf.use_signatures === true);
  const [rules, setRules] = React.useState<RuleDraft[]>(() => rulesOf(conf).map(toDraft));
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
      next[index] = { ...next[index], ...patch };
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
    onSave(entryName, {
      ...conf,
      mode,
      allow_known_bots: allowKnownBots,
      use_signatures: useSignatures,
      rules: rules.map(fromDraft),
    });
  };

  return (
    <div className="space-y-4">
      {isNew && (
        <Card>
          <CardContent className="grid gap-2 py-4 sm:grid-cols-[160px_1fr] sm:items-center">
            <label htmlFor="bot-name" className="text-xs text-muted-foreground">
              Profile name
            </label>
            <input
              id="bot-name"
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
          <CardTitle className="text-base">{isNew ? "New profile" : `bot:${name}`}</CardTitle>
          <CardDescription>
            {structured
              ? "Rules are first-match: allow or deny ends the walk, log observes. A JA4H entry matches as a prefix on `_` boundaries — published lists carry `a_b` only."
              : "This profile's `rules` is not a list of rule tables, so it is edited as raw JSON — the plugin validates it on save."}
          </CardDescription>
        </CardHeader>
        <CardContent>
          {structured ? (
            <>
              <div className="mb-4 flex flex-wrap items-center gap-x-6 gap-y-3">
                <div className="flex items-center gap-2">
                  <label htmlFor="bot-mode" className="text-xs text-muted-foreground">
                    Mode
                  </label>
                  <Select value={mode} onValueChange={setMode} disabled={readOnly}>
                    <SelectTrigger id="bot-mode" className="w-32">
                      <SelectValue />
                    </SelectTrigger>
                    <SelectContent>
                      {MODES.map((option) => (
                        <SelectItem key={option} value={option}>
                          {option}
                        </SelectItem>
                      ))}
                    </SelectContent>
                  </Select>
                  <ModeBadge mode={mode} />
                </div>
                <label className="flex items-center gap-2 text-sm">
                  <Checkbox
                    checked={allowKnownBots}
                    onCheckedChange={(v) => setAllowKnownBots(v === true)}
                    disabled={readOnly}
                  />
                  allow_known_bots
                  <span className="text-xs text-muted-foreground">
                    exempt Googlebot &amp; co. by User-Agent
                  </span>
                </label>
                <label className="flex items-center gap-2 text-sm">
                  <Checkbox
                    checked={useSignatures}
                    onCheckedChange={(v) => setUseSignatures(v === true)}
                    disabled={readOnly}
                  />
                  use_signatures
                  <span className="text-xs text-muted-foreground">
                    run the shipped scanner/library signatures after your rules
                  </span>
                </label>
              </div>
              {rules.length === 0 ? (
                <EmptyState
                  title="No rules"
                  hint="A rule matches on a JA4H fingerprint, a User-Agent regex, or both. The first allow or deny that matches decides."
                />
              ) : (
                <Table>
                  <TableHeader>
                    <TableRow>
                      <TableHead className="w-10">#</TableHead>
                      <TableHead>JA4H fingerprint</TableHead>
                      <TableHead>User-Agent regex</TableHead>
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
                            <span className="machine block max-w-64 truncate text-sm">
                              {rule.fingerprint || "—"}
                            </span>
                          ) : (
                            <input
                              aria-label="JA4H fingerprint"
                              value={rule.fingerprint}
                              onChange={(e) => patch(index, { fingerprint: e.target.value })}
                              placeholder="ge11nn040000_5b1e8b5f4d2d"
                              className="machine h-9 w-full min-w-52 rounded-md border border-border bg-background px-2 text-sm"
                            />
                          )}
                        </TableCell>
                        <TableCell>
                          {readOnly ? (
                            <span className="machine block max-w-48 truncate text-sm">
                              {rule.user_agent || "—"}
                            </span>
                          ) : (
                            <input
                              aria-label="User-Agent regex"
                              value={rule.user_agent}
                              onChange={(e) => patch(index, { user_agent: e.target.value })}
                              placeholder="(?i)internal-scraper"
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
                        fingerprint: "",
                        user_agent: "",
                        action: "deny",
                        enabled: true,
                        remark: "",
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
