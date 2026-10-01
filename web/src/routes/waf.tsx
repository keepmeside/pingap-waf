import React from "react";
import { PageShell } from "@/components/page-shell";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { ModeBadge } from "@/components/mode-badge";
import { EmptyState, ErrorNote, LoadingCard } from "@/components/data-ui";
import { usePolicies, usePutPolicy, useWafCategories } from "@/queries/admin";
import { can } from "@/lib/rbac";
import { useProfile } from "@/queries/admin";
import { formatError } from "@/helpers/util";
import { toast } from "sonner";
import type { PluginConf, WafCategory } from "@/lib/types";
import { Pencil, Plus, ShieldCheck } from "lucide-react";

const CATEGORY = "waf";

/** Every `waf:<profile>` entry in the policies map. */
function wafProfiles(policies: Record<string, PluginConf> | null | undefined) {
  return Object.entries(policies ?? {})
    .filter(([name]) => name.startsWith(`${CATEGORY}:`))
    .map(([name, conf]) => ({ name: name.slice(CATEGORY.length + 1), entry: name, conf }));
}

/** The per-category mode table for one profile: each of the engine's categories with the
 * mode this profile assigns — defaulting to `detect`, which is the engine's default. */
function categoryModes(conf: PluginConf, categories: WafCategory[]) {
  const table = (conf?.["categories"] as Record<string, string> | undefined) ?? {};
  return categories.map((category) => ({
    category,
    mode: table[category.key] ?? "detect",
  }));
}

/**
 * The WAF editor. What it must never get wrong:
 *
 * - A response-side category cannot deny. Offering `block` there would let an operator
 *   believe leaking responses are suppressed when they are only body-rewritten — so the
 *   mode list is built from the *category's own* `modes`, which the API returns as
 *   `off`/`detect`/`redact` for 950/955 and `off`/`detect`/`block`/`challenge` for the
 *   request-side rest. `block` is never offered for a response-side category.
 * - `detect` and `block` are visually distinct states, because confusing them is the
 *   security failure this page exists to prevent.
 */
export default function Waf() {
  const profileQuery = useProfile();
  const policies = usePolicies();
  const categories = useWafCategories();
  const putPolicy = usePutPolicy();
  const [editing, setEditing] = React.useState<string | null>(null);
  const canEdit = can(profileQuery.data?.data, "edit_policy");

  const profiles = wafProfiles(policies.data?.data);
  const editTarget = editing ? profiles.find((p) => p.name === editing) : null;

  return (
    <PageShell
      title="WAF"
      eyebrow="Policy · waf"
      description="Web-application-firewall profiles. Per-category mode, in the engine's own vocabulary — a response-side category can never block, only redact."
      actions={
        canEdit && (
          <Button size="sm" onClick={() => setEditing("*new*")}>
            <Plus className="size-4" /> New profile
          </Button>
        )
      }
    >
      {policies.isPending || categories.isPending ? (
        <LoadingCard />
      ) : policies.isError || categories.isError ? (
        <ErrorNote message={formatError(policies.error ?? categories.error)} />
      ) : editTarget || editing === "*new*" ? (
        <ProfileEditor
          name={editing === "*new*" ? "" : (editTarget?.name ?? "")}
          entry={editing === "*new*" ? `${CATEGORY}:` : (editTarget?.entry ?? "")}
          conf={editTarget?.conf ?? {}}
          categories={categories.data?.data ?? []}
          readOnly={!canEdit}
          onClose={() => setEditing(null)}
          onSave={(entryName, conf) => {
            putPolicy.mutate(
              { name: entryName, body: conf },
              {
                onSuccess: () => {
                  toast.success("WAF profile saved");
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
              Each profile is a `waf:` config entry a domain binds. Two domains needing
              independent counters bind two different profiles.
            </CardDescription>
          </CardHeader>
          <CardContent>
            {profiles.length === 0 ? (
              <EmptyState
                title="No WAF profiles"
                hint="A domain binds a `waf:` profile to enforce categories. Create one to begin."
              />
            ) : (
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead>Profile</TableHead>
                    <TableHead>Modes set</TableHead>
                    <TableHead className="text-right">Actions</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {profiles.map((profile) => {
                    const modes = Object.values(
                      (profile.conf?.["categories"] as Record<string, string> | undefined) ?? {},
                    );
                    return (
                      <TableRow key={profile.entry}>
                        <TableCell className="font-medium">{profile.name}</TableCell>
                        <TableCell>
                          <div className="flex flex-wrap gap-1.5">
                            {modes.length === 0 ? (
                              <ModeBadge mode="detect" />
                            ) : (
                              [...new Set(modes)].map((mode) => (
                                <ModeBadge key={mode} mode={mode} />
                              ))
                            )}
                          </div>
                        </TableCell>
                        <TableCell className="text-right">
                          <Button
                            size="sm"
                            variant="ghost"
                            onClick={() => setEditing(profile.name)}
                          >
                            <Pencil className="size-4" />
                          </Button>
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
    </PageShell>
  );
}

/**
 * One profile's category table. Each row is a CRS-lineage category with the mode this
 * profile assigns it — and the mode selector is restricted to the modes that *category*
 * accepts, so a response-side row shows off/detect/redact and nothing that would let an
 * operator believe a leaking response is suppressed.
 */
function ProfileEditor({
  name,
  entry,
  conf,
  categories,
  readOnly,
  onClose,
  onSave,
  saving,
}: {
  name: string;
  entry: string;
  conf: PluginConf;
  categories: WafCategory[];
  readOnly: boolean;
  onClose: () => void;
  onSave: (entryName: string, conf: PluginConf) => void;
  saving: boolean;
}) {
  const isNew = entry === `${CATEGORY}:`;
  const [profileName, setProfileName] = React.useState(name);
  const [modes, setModes] = React.useState<Record<string, string>>(() => {
    const out: Record<string, string> = {};
    for (const { category, mode } of categoryModes(conf, categories)) {
      out[category.key] = mode;
    }
    return out;
  });

  const setMode = (key: string, mode: string) =>
    setModes((current) => ({ ...current, [key]: mode }));

  const save = () => {
    const entryName = isNew ? `${CATEGORY}:${profileName.trim()}` : entry;
    if (isNew && !profileName.trim()) {
      toast.error("A profile name is required");
      return;
    }
    onSave(entryName, { ...conf, categories: modes });
  };

  return (
    <div className="space-y-4">
      {isNew && (
        <Card>
          <CardContent className="grid gap-2 py-4 sm:grid-cols-[160px_1fr] sm:items-center">
            <label htmlFor="waf-name" className="text-xs text-muted-foreground">
              Profile name
            </label>
            <input
              id="waf-name"
              value={profileName}
              onChange={(e) => setProfileName(e.target.value)}
              placeholder="strict"
              className="h-9 rounded-md border border-border bg-background px-3 text-sm"
            />
          </CardContent>
        </Card>
      )}
      <Card>
        <CardHeader>
          <CardTitle className="text-base">
            {isNew ? "New profile" : `waf:${name}`}
          </CardTitle>
          <CardDescription>
            Per-category enforcement mode. Response-side categories (950, 955) cannot
            block — they offer off, detect and redact only.
          </CardDescription>
        </CardHeader>
        <CardContent>
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>Category</TableHead>
                <TableHead>CRS lineage</TableHead>
                <TableHead>Mode</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {categories.map((category) => {
                const mode = modes[category.key] ?? "detect";
                return (
                  <TableRow key={category.key}>
                    <TableCell>
                      <div className="font-medium">{category.key}</div>
                      <div className="text-xs text-muted-foreground">
                        rules {category.id_range[0]}–{category.id_range[1]}
                      </div>
                    </TableCell>
                    <TableCell>
                      <Badge variant="outline" className="machine">
                        {category.crs_group} · {category.crs_file}
                      </Badge>
                    </TableCell>
                    <TableCell>
                      <div className="flex items-center gap-2">
                        {readOnly ? (
                          <ModeBadge mode={mode} />
                        ) : (
                          <>
                            <Select value={mode} onValueChange={(v) => setMode(category.key, v)}>
                              <SelectTrigger className="w-32">
                                <SelectValue />
                              </SelectTrigger>
                              <SelectContent>
                                {category.modes.map((option) => (
                                  <SelectItem key={option} value={option}>
                                    {option}
                                  </SelectItem>
                                ))}
                              </SelectContent>
                            </Select>
                            <ModeBadge mode={mode} />
                          </>
                        )}
                      </div>
                    </TableCell>
                  </TableRow>
                );
              })}
            </TableBody>
          </Table>
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
