import React from "react";
import { PageShell } from "@/components/page-shell";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { EmptyState, ErrorNote, LoadingCard } from "@/components/data-ui";
import { Textarea } from "@/components/ui/textarea";
import { usePolicies, useProfile, usePutPolicy } from "@/queries/admin";
import { can } from "@/lib/rbac";
import { formatError } from "@/helpers/util";
import { toast } from "sonner";
import type { PluginConf } from "@/lib/types";
import { Pencil, ShieldCheck } from "lucide-react";

type UnknownRecord = Record<string, unknown>;
const isRecord = (value: unknown): value is UnknownRecord =>
  typeof value === "object" && value !== null && !Array.isArray(value);
const asStrings = (value: unknown): string[] =>
  Array.isArray(value) ? value.filter((v): v is string => typeof v === "string") : [];

interface AccessListView {
  /** The `acl:<profile>` entry that owns this list — a list has no endpoint of its own. */
  profileEntry: string;
  /** The key the list lives under in the owning profile (`access_list` in the engine's
   * spelling; `access_lists`/`access-lists` are accepted on read rather than dropped). */
  confKey: string;
  /** `named` — a list inside an `access_lists` table, addressed by listName;
   *  `inline` — the profile's own single gate at `access_list`. */
  kind: "named" | "inline";
  listName?: string;
  conf: UnknownRecord;
}

/** Every access list found inside `acl:*` profiles. `access_list` is the engine's key —
 * the singular, inline gate each profile may carry once. `access_lists`/`access-lists`,
 * when a table of name → list, are read as named lists; any other shape is still shown
 * (raw) rather than silently absent. */
function findAccessLists(policies: Record<string, PluginConf> | null | undefined): AccessListView[] {
  const out: AccessListView[] = [];
  for (const [entry, conf] of Object.entries(policies ?? {})) {
    if (!entry.startsWith("acl:") || !isRecord(conf)) continue;
    for (const key of ["access_list", "access_lists", "access-lists"]) {
      const value = conf[key];
      if (!isRecord(value)) continue;
      if (key === "access_list") {
        out.push({ profileEntry: entry, confKey: key, kind: "inline", conf: value });
      } else {
        for (const [listName, listConf] of Object.entries(value)) {
          out.push({
            profileEntry: entry,
            confKey: key,
            kind: "named",
            listName,
            conf: isRecord(listConf) ? listConf : { value: listConf },
          });
        }
      }
    }
  }
  return out;
}

/** The three keys the engine's `AccessListConf` knows: an IP allowlist, basic-auth
 * users as `username:sha256hex`, and how the two halves combine. */
function listSummary(conf: UnknownRecord): { ips: string[]; users: string[]; satisfy: string } {
  return {
    ips: asStrings(conf.ip_allowlist ?? conf.ip_whitelist),
    users: asStrings(conf.users).map((entry) => entry.split(":")[0]),
    satisfy: typeof conf.satisfy === "string" ? conf.satisfy : "any",
  };
}

/** Whether a config table reads as an access list at all — its own keys or nothing
 * recognisable, in which case the raw shape is shown. */
function isKnownListShape(conf: UnknownRecord): boolean {
  return (
    "ip_allowlist" in conf ||
    "ip_whitelist" in conf ||
    "users" in conf ||
    "satisfy" in conf
  );
}

/**
 * Named access lists. What it must never get wrong:
 *
 * - **A list is a key inside an `acl:` profile, not a resource.** There is no
 *   `/access-lists` endpoint: editing a list means rewriting the profile entry that
 *   contains it, and saving goes through `usePutPolicy` on that entry — the route
 *   contract records this explicitly so nobody invents a parallel store.
 * - **Empty means shut.** The engine inverts the reference convention: a list with no
 *   `ip_allowlist` and no `users` admits nobody, so an empty list is displayed as a
 *   closed gate, never as "unrestricted".
 * - User entries are `username:sha256hex`. Only the username is rendered in the list —
 *   the hash is in the config and stays there; the row does not display digests.
 */
export default function AccessLists() {
  const profileQuery = useProfile();
  const policies = usePolicies();
  const putPolicy = usePutPolicy();
  const [editing, setEditing] = React.useState<AccessListView | null>(null);
  const canEdit = can(profileQuery.data?.data, "edit_policy");

  const lists = findAccessLists(policies.data?.data);

  return (
    <PageShell
      title="Access Lists"
      eyebrow="Policy · acl"
      description="Named gates inside `acl:` profiles — an IP allowlist plus basic-auth users, evaluated before the rule table. A list no `allow` rule can override: the gate is the boundary, not a suggestion."
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
      ) : editing ? (
        <ListEditor
          list={editing}
          policies={policies.data?.data ?? {}}
          readOnly={!canEdit}
          onClose={() => setEditing(null)}
          onSave={(entryName, conf) => {
            putPolicy.mutate(
              { name: entryName, body: conf },
              {
                onSuccess: () => {
                  toast.success("Access list saved");
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
            <CardTitle className="text-base">Lists</CardTitle>
            <CardDescription>
              Every access list found under `access_list` / `access_lists` in `acl:`
              profiles. An empty list admits nobody — there is no “unrestricted” empty
              gate.
            </CardDescription>
          </CardHeader>
          <CardContent>
            {lists.length === 0 ? (
              <EmptyState
                title="No access lists"
                hint="An access list gates a domain outright — `ip_allowlist` CIDRs and `username:sha256hex` users, combined by `satisfy`. Add one inside an `acl:` profile's config under `access_list` (single) or `access_lists` (named)."
              />
            ) : (
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead>List</TableHead>
                    <TableHead>In profile</TableHead>
                    <TableHead>Entries</TableHead>
                    <TableHead>Satisfy</TableHead>
                    {canEdit && <TableHead className="text-right">Actions</TableHead>}
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {lists.map((list, index) => {
                    const summary = listSummary(list.conf);
                    const known = isKnownListShape(list.conf);
                    const total = summary.ips.length + summary.users.length;
                    return (
                      <TableRow key={`${list.profileEntry}-${list.confKey}-${list.listName ?? index}`}>
                        <TableCell className="font-medium">
                          {list.kind === "inline" ? (
                            <>
                              <span className="machine">{list.confKey}</span>
                              <span className="ml-2 text-xs text-muted-foreground">
                                inline gate
                              </span>
                            </>
                          ) : (
                            <span className="machine">{list.listName}</span>
                          )}
                        </TableCell>
                        <TableCell>
                          <Badge variant="outline" className="machine">
                            {list.profileEntry}
                          </Badge>
                        </TableCell>
                        <TableCell>
                          {known ? (
                            total === 0 ? (
                              <Badge variant="outline" className="border-destructive/50 text-[11px] text-destructive">
                                empty — admits nobody
                              </Badge>
                            ) : (
                              <div className="flex max-w-md flex-wrap gap-1.5">
                                {summary.ips.map((ip) => (
                                  <Badge key={ip} variant="secondary" className="machine text-[11px]">
                                    {ip}
                                  </Badge>
                                ))}
                                {summary.users.map((user) => (
                                  <Badge
                                    key={user}
                                    variant="outline"
                                    className="machine text-[11px]"
                                  >
                                    {user}
                                  </Badge>
                                ))}
                              </div>
                            )
                          ) : (
                            <span className="machine block max-w-md truncate text-xs text-muted-foreground">
                              {JSON.stringify(list.conf)}
                            </span>
                          )}
                        </TableCell>
                        <TableCell>
                          {known && (
                            <span className="machine text-sm">{summary.satisfy}</span>
                          )}
                        </TableCell>
                        {canEdit && (
                          <TableCell className="text-right">
                            <Button
                              size="sm"
                              variant="ghost"
                              aria-label={`Edit ${list.listName ?? list.confKey}`}
                              onClick={() => setEditing(list)}
                            >
                              <Pencil className="size-4" />
                            </Button>
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
    </PageShell>
  );
}

/** One list's editor. The known shape gets three fields — CIDRs, users, satisfy — and
 * anything else falls back to raw JSON for just the list, never the whole profile. The
 * save writes the edited list back under its own key inside the owning profile. */
function ListEditor({
  list,
  policies,
  readOnly,
  onClose,
  onSave,
  saving,
}: {
  list: AccessListView;
  policies: Record<string, PluginConf>;
  readOnly: boolean;
  onClose: () => void;
  onSave: (entryName: string, conf: PluginConf) => void;
  saving: boolean;
}) {
  const summary = listSummary(list.conf);
  const known = isKnownListShape(list.conf);
  const [ips, setIps] = React.useState(summary.ips.join("\n"));
  // Editing keeps `username:sha256hex` whole — splitting it for display must not lose
  // the digest on save. New entries are added as `name:sha256`.
  const [users, setUsers] = React.useState(asStrings(list.conf.users).join("\n"));
  const [satisfy, setSatisfy] = React.useState(summary.satisfy);
  const [rawText, setRawText] = React.useState(() => JSON.stringify(list.conf, null, 2));

  const title =
    list.kind === "inline" ? `${list.profileEntry} · ${list.confKey}` : list.listName;

  const save = () => {
    const profile = policies[list.profileEntry] ?? {};
    let edited: UnknownRecord;
    if (known) {
      edited = {
        ...list.conf,
        ip_allowlist: ips.split("\n").map((v) => v.trim()).filter(Boolean),
        users: users.split("\n").map((v) => v.trim()).filter(Boolean),
        satisfy,
      };
      // The alternate spelling is not written back — the engine reads `ip_allowlist`.
      delete edited.ip_whitelist;
    } else {
      let parsed: unknown;
      try {
        parsed = JSON.parse(rawText);
      } catch (e) {
        toast.error("Invalid JSON", { description: formatError(e) });
        return;
      }
      if (!isRecord(parsed)) {
        toast.error("The list must be a JSON object");
        return;
      }
      edited = parsed;
    }

    const next: PluginConf = { ...profile };
    if (list.kind === "inline") {
      next[list.confKey] = edited;
    } else {
      next[list.confKey] = {
        ...(isRecord(profile[list.confKey]) ? (profile[list.confKey] as UnknownRecord) : {}),
        [list.listName ?? ""]: edited,
      };
    }
    onSave(list.profileEntry, next);
  };

  return (
    <div className="space-y-4">
      <Card>
        <CardHeader>
          <CardTitle className="text-base">{title}</CardTitle>
          <CardDescription>
            Evaluated before the profile's rule table — an `allow` rule cannot admit what
            this gate refuses. `satisfy any` lets either half admit; `all` requires both.
            Users are `username:sha256hex` of the password alone
            (`printf %s 'pass' | sha256sum`).
          </CardDescription>
        </CardHeader>
        <CardContent>
          {known ? (
            <div className="grid gap-4">
              <div className="grid gap-2 sm:grid-cols-[160px_1fr]">
                <label htmlFor="al-ips" className="pt-2 text-xs text-muted-foreground">
                  IP allowlist
                </label>
                <Textarea
                  id="al-ips"
                  value={ips}
                  onChange={(e) => setIps(e.target.value)}
                  disabled={readOnly}
                  placeholder={"203.0.113.0/24\n198.51.100.7"}
                  className="machine min-h-24"
                />
              </div>
              <div className="grid gap-2 sm:grid-cols-[160px_1fr]">
                <label htmlFor="al-users" className="pt-2 text-xs text-muted-foreground">
                  Users
                </label>
                <Textarea
                  id="al-users"
                  value={users}
                  onChange={(e) => setUsers(e.target.value)}
                  disabled={readOnly}
                  placeholder="alice:f52fbd32b2b3b86ff88ef6c490628285f482af15ddcb29541f94bcf526a3f6c7"
                  className="machine min-h-24"
                />
              </div>
              <div className="grid gap-2 sm:grid-cols-[160px_1fr] sm:items-center">
                <label htmlFor="al-satisfy" className="text-xs text-muted-foreground">
                  Satisfy
                </label>
                <Select value={satisfy} onValueChange={setSatisfy} disabled={readOnly}>
                  <SelectTrigger id="al-satisfy" className="w-40">
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value="any">any</SelectItem>
                    <SelectItem value="all">all</SelectItem>
                  </SelectContent>
                </Select>
              </div>
            </div>
          ) : (
            <Textarea
              aria-label="Access list as JSON"
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
            {saving ? "Saving…" : `Save to ${list.profileEntry}`}
          </Button>
          <Button variant="ghost" onClick={onClose}>
            Cancel
          </Button>
        </div>
      )}
    </div>
  );
}
