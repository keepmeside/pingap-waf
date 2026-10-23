import { parseNativeLifecycle } from "@/helpers/native-history";
import React from "react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { EmptyState, ErrorNote, LoadingCard } from "@/components/data-ui";
import { ModeBadge } from "@/components/mode-badge";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import {
  useActivity,
  useNativeBans,
  useNativeMetrics,
  usePolicies,
  useProfile,
  usePutPolicy,
  useReleaseNativeBan,
} from "@/queries/admin";
import { scenarioPayload } from "@/components/security-overview";
import { can } from "@/lib/rbac";
import { formatError } from "@/helpers/util";
import type { PluginConf } from "@/lib/types";
import { toast } from "sonner";
const record = (v: unknown): Record<string, unknown> =>
  typeof v === "object" && v !== null && !Array.isArray(v)
    ? (v as Record<string, unknown>)
    : {};
export function NativeControls() {
  const metrics = useNativeMetrics();
  const policies = usePolicies();
  const profile = useProfile();
  const editable = can(profile.data?.data, "edit_policy");
  const [editing, setEditing] = React.useState<{
    entry: string;
    conf: PluginConf;
  } | null>(null);
  const entries = Object.entries(policies.data?.data ?? {}).filter(([entry]) =>
    entry.startsWith("behaviour:"),
  );
  return (
    <section aria-label="Native abuse prevention" className="space-y-4 my-5">
      <Card>
        <CardHeader className="pt-5">
          <CardTitle>Native abuse prevention</CardTitle>
        </CardHeader>
        <CardContent className="space-y-3 py-5">
          <p className="text-sm text-muted-foreground">
            Exact failed-login and distinct 404 scan scenarios. Save a profile
            and attach it to a website; detect observes, block temporarily
            refuses matching clients.
          </p>
          {metrics.isError ? (
            <ErrorNote message={formatError(metrics.error)} />
          ) : metrics.data?.data ? (
            <div
              className="flex flex-wrap gap-x-5 gap-y-2 text-xs"
              aria-label="Native delivery counters"
            >
              {Object.entries(metrics.data.data.native_abuse ?? {})
                .filter(([key]) =>
                  [
                    "saturated",
                    "dropped_lifecycle",
                    "stale_observations",
                  ].includes(key),
                )
                .map(([key, value]) => (
                  <span key={key}>
                    {key.replace(/_/g, " ")}: {value}
                  </span>
                ))}
              {Object.entries(
                metrics.data.data.native_event_delivery ?? {},
              ).map(([key, value]) => (
                <span key={key}>
                  {key.replace(/_/g, " ")}: {value}
                </span>
              ))}
            </div>
          ) : (
            <p className="text-xs text-muted-foreground">
              Native delivery counters unavailable
            </p>
          )}
          {policies.isPending ? (
            <LoadingCard />
          ) : policies.isError ? (
            <ErrorNote message={formatError(policies.error)} />
          ) : policies.data?.unavailable ? (
            <EmptyState title="Native policies unavailable" />
          ) : editing ? (
            <ScenarioEditor
              key={editing.entry || "new"}
              {...editing}
              editable={editable}
              onClose={() => setEditing(null)}
            />
          ) : (
            <>
              {entries.map(([entry, conf]) => (
                <div
                  key={entry}
                  className="flex flex-wrap items-center justify-between gap-3 border-b py-3"
                >
                  <span>{entry}</span>
                  <span className="flex gap-2">
                    {["failed_login", "scan"]
                      .map((kind) => record(record(conf.abuse)[kind]).mode)
                      .filter((v) => typeof v === "string")
                      .map((mode, i) => (
                        <ModeBadge key={i} mode={String(mode)} />
                      ))}
                  </span>
                  <Button
                    size="sm"
                    variant="outline"
                    onClick={() => setEditing({ entry, conf })}
                  >
                    {editable ? "Edit" : "View"} {entry}
                  </Button>
                </div>
              ))}
              {entries.length === 0 && (
                <EmptyState
                  title="No native scenarios"
                  hint="No website receives native scenario protection until a configured profile is attached."
                />
              )}
              {editable && (
                <Button
                  variant="outline"
                  onClick={() =>
                    setEditing({
                      entry: "",
                      conf: {
                        category: "behaviour",
                        enabled: true,
                        client_ip_from_peer: false,
                      },
                    })
                  }
                >
                  New native scenario profile
                </Button>
              )}
            </>
          )}
        </CardContent>
      </Card>
      <BanTable editable={editable} />
      <NativeHistory />
    </section>
  );
}
function ScenarioEditor({
  entry,
  conf,
  editable,
  onClose,
}: {
  entry: string;
  conf: PluginConf;
  editable: boolean;
  onClose: () => void;
}) {
  const [name, setName] = React.useState(entry.slice(10));
  const [kind, setKind] = React.useState<"failed_login" | "scan">(
    record(conf.abuse).failed_login ? "failed_login" : "scan",
  );
  const [draft, setDraft] = React.useState<PluginConf>(conf);
  const put = usePutPolicy();
  const abuse = record(draft.abuse);
  const rule = record(abuse[kind]);
  const value = (key: string, fallback: unknown) => rule[key] ?? fallback;
  const update = (key: string, v: unknown) =>
    setDraft((current) => {
      const a = record(current.abuse);
      return {
        ...current,
        abuse: {
          ...a,
          [kind]: {
            mode: "detect",
            window: "30s",
            threshold: 5,
            ban_ttl: "5m",
            ...(kind === "failed_login"
              ? { path: "/login", method: "POST", statuses: [401] }
              : {}),
            ...record(a[kind]),
            [key]: v,
          },
        },
      };
    });
  const save = async () => {
    const complete = {
      mode: "detect",
      window: "30s",
      threshold: 5,
      ban_ttl: "5m",
      ...(kind === "failed_login"
        ? { path: "/login", method: "POST", statuses: [401] }
        : {}),
      ...rule,
    };
    try {
      await put.mutateAsync({
        name: entry || `behaviour:${name.trim()}`,
        body: scenarioPayload(
          draft,
          kind,
          complete,
          draft.enabled !== false,
          draft.client_ip_from_peer === true,
        ),
      });
      toast.success("Native scenario saved and applied");
      onClose();
    } catch (e) {
      toast.error(
        (e as { category?: string }).category === "timeout"
          ? "Save outcome unconfirmed — inspect config versions before retrying"
          : "Save failed",
        { description: formatError(e) },
      );
    }
  };
  return (
    <div className="space-y-4">
      <fieldset
        disabled={!editable || put.isPending}
        className="grid gap-4 sm:grid-cols-2"
      >
        <label>
          Native profile name
          <Input
            value={name}
            disabled={!!entry}
            onChange={(e) => setName(e.target.value)}
          />
        </label>
        <label>
          Scenario
          <select
            aria-label="Scenario"
            className="block h-9 w-full rounded-md border px-3 bg-background"
            value={kind}
            onChange={(e) => setKind(e.target.value as typeof kind)}
          >
            <option value="scan">Distinct 404 scan</option>
            <option value="failed_login">Failed login</option>
          </select>
        </label>
        <label>
          Scenario mode
          <select
            aria-label="Scenario mode"
            className="block h-9 w-full rounded-md border px-3 bg-background"
            value={String(value("mode", "detect"))}
            onChange={(e) => update("mode", e.target.value)}
          >
            <option value="detect">detect</option>
            <option value="block">block</option>
          </select>
        </label>
        {(
          [
            ["threshold", "Threshold", 5],
            ["window", "Observation window", "30s"],
            ["ban_ttl", "Ban lifetime", "5m"],
          ] as const
        ).map(([key, label, fallback]) => (
          <label key={key}>
            {label}
            <Input
              type={key === "threshold" ? "number" : "text"}
              value={String(value(key, fallback))}
              onChange={(e) =>
                update(
                  key,
                  key === "threshold" ? Number(e.target.value) : e.target.value,
                )
              }
            />
          </label>
        ))}
        {kind === "failed_login" && (
          <>
            <label>
              Exact login path
              <Input
                value={String(value("path", "/login"))}
                onChange={(e) => update("path", e.target.value)}
              />
            </label>
            <label>
              Exact login method
              <Input
                value={String(value("method", "POST"))}
                onChange={(e) => update("method", e.target.value)}
              />
            </label>
            <label>
              Upstream failure statuses
              <Input
                value={
                  Array.isArray(value("statuses", [401]))
                    ? (value("statuses", [401]) as number[]).join(",")
                    : ""
                }
                onChange={(e) =>
                  update(
                    "statuses",
                    e.target.value.split(",").map((x) => Number(x.trim())),
                  )
                }
              />
            </label>
          </>
        )}
        <label className="flex items-center gap-2">
          <input
            type="checkbox"
            checked={draft.enabled !== false}
            onChange={(e) =>
              setDraft((c) => ({ ...c, enabled: e.target.checked }))
            }
          />
          Enable native scenarios
        </label>
        <label className="flex items-center gap-2">
          <input
            type="checkbox"
            checked={draft.client_ip_from_peer === true}
            onChange={(e) =>
              setDraft((c) => ({ ...c, client_ip_from_peer: e.target.checked }))
            }
          />
          Use direct peer identity
        </label>
      </fieldset>
      <p className="text-xs text-muted-foreground">
        Configure trusted proxies before enforcement behind a proxy. Scan counts
        distinct paths with upstream 404; query variations do not add distinct
        paths. Existing other scenarios and profile settings are preserved.
        Nothing is attached automatically.
      </p>
      <div className="flex gap-2">
        <Button variant="outline" onClick={onClose}>
          Close scenario editor
        </Button>
        {editable && (
          <Button onClick={save} disabled={put.isPending || !name.trim()}>
            {put.isPending ? "Saving…" : "Save native scenario"}
          </Button>
        )}
      </div>
    </div>
  );
}
function BanTable({ editable }: { editable: boolean }) {
  const [domain, setDomain] = React.useState("");
  const [profile, setProfile] = React.useState("");
  const [cursor, setCursor] = React.useState("");
  const params = new URLSearchParams();
  if (domain) params.set("domain", domain);
  if (profile) params.set("profile", profile);
  if (cursor) params.set("cursor", cursor);
  const query = useNativeBans(`?${params}`);
  const release = useReleaseNativeBan();
  const [epoch, setEpoch] = React.useState<string | null>(null);
  const [reset, setReset] = React.useState(false);
  const [notice, setNotice] = React.useState("");
  React.useEffect(() => {
    const next = query.data?.data?.epoch;
    if (next) {
      if (epoch && epoch !== next) {
        setReset(true);
        setCursor("");
      }
      setEpoch(next);
    }
  }, [query.data?.data?.epoch, epoch]);
  return (
    <Card>
      <CardHeader className="pt-5">
        <CardTitle>Active temporary bans</CardTitle>
      </CardHeader>
      <CardContent className="space-y-4 py-5">
        <p className="text-xs text-muted-foreground">
          Runtime bans clear on restart. Lifecycle history is kept permanently
          in Activity. Epoch:{" "}
          <span className="break-all">{epoch ?? "unavailable"}</span>
        </p>
        {reset && (
          <p role="status">
            Runtime epoch changed — active bans were reset by restart.
          </p>
        )}
        <div className="flex flex-wrap gap-3">
          <label>
            Filter ban domain
            <Input
              value={domain}
              onChange={(e) => {
                setDomain(e.target.value);
                setCursor("");
              }}
            />
          </label>
          <label>
            Filter ban profile
            <Input
              value={profile}
              onChange={(e) => {
                setProfile(e.target.value);
                setCursor("");
              }}
            />
          </label>
          <Button
            variant="outline"
            onClick={() => {
              if (cursor) setCursor("");
              else void query.refetch();
            }}
          >
            Refresh bans
          </Button>
        </div>
        {query.isPending ? (
          <LoadingCard />
        ) : query.isError ? (
          <ErrorNote message={formatError(query.error)} />
        ) : query.data?.unavailable ? (
          <EmptyState title="Bans unavailable" hint={query.data.message} />
        ) : !query.data?.data?.items.length ? (
          <EmptyState title="No active bans" />
        ) : (
          <Table>
            <TableHeader>
              <TableRow>
                {[
                  "Client",
                  "Domain / profile",
                  "Scenario",
                  "Remaining at refresh",
                  "Action",
                ].map((t) => (
                  <TableHead key={t}>{t}</TableHead>
                ))}
              </TableRow>
            </TableHeader>
            <TableBody>
              {query.data.data.items.map((ban) => (
                <TableRow key={ban.id}>
                  <TableCell>{ban.client_ip}</TableCell>
                  <TableCell>
                    {ban.domain}
                    <p className="text-xs text-muted-foreground">
                      {ban.profile}
                    </p>
                  </TableCell>
                  <TableCell>
                    {ban.scenario}
                    <ModeBadge mode={ban.mode} />
                  </TableCell>
                  <TableCell>{Math.ceil(ban.remaining_ms / 1000)}s</TableCell>
                  <TableCell>
                    {editable ? (
                      <Button
                        size="sm"
                        variant="outline"
                        disabled={release.isPending}
                        onClick={async () => {
                          try {
                            const result = await release.mutateAsync(ban);
                            setNotice(
                              `${result.outcome === "released" ? "Ban released" : "Ban already absent"}. Audit ${result.audit}${result.audit === "queued" ? " — queued is not yet a persistence acknowledgement" : ""}.`,
                            );
                          } catch (e) {
                            setNotice(formatError(e));
                          }
                        }}
                      >
                        Release ban
                      </Button>
                    ) : (
                      "Read only"
                    )}
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        )}
        {notice && (
          <p role="status" className="text-sm">
            {notice}
          </p>
        )}
        <div className="flex gap-2">
          {cursor && (
            <Button variant="outline" onClick={() => setCursor("")}>
              First page
            </Button>
          )}
          {query.data?.data?.next_cursor && (
            <Button
              variant="outline"
              onClick={() => setCursor(query.data!.data!.next_cursor!)}
            >
              Next bans
            </Button>
          )}
        </div>
      </CardContent>
    </Card>
  );
}

function NativeHistory() {
  const history = useActivity("?limit=100");
  const rows = (history.data?.data ?? [])
    .map((row) => ({ row, detail: parseNativeLifecycle(row.detail ?? null) }))
    .filter((item) => item.detail !== null);
  return (
    <Card>
      <CardHeader className="pt-5">
        <CardTitle>Native lifecycle history</CardTitle>
      </CardHeader>
      <CardContent className="py-5">
        {history.isPending ? (
          <LoadingCard />
        ) : history.isError ? (
          <ErrorNote message={formatError(history.error)} />
        ) : history.data?.unavailable ? (
          <EmptyState title="History unavailable" />
        ) : !rows.length ? (
          <EmptyState
            title="No native lifecycle records"
            hint="Recent Activity rows have no native transitions. Permanent history is retained on the server."
          />
        ) : (
          <Table>
            <TableHeader>
              <TableRow>
                {[
                  "Time",
                  "Transition",
                  "Client / domain",
                  "Reason",
                  "Actor",
                ].map((t) => (
                  <TableHead key={t}>{t}</TableHead>
                ))}
              </TableRow>
            </TableHeader>
            <TableBody>
              {rows.map(({ row, detail }) => (
                <TableRow key={row.id}>
                  <TableCell>
                    {new Date(detail!.observed_at_ms).toLocaleString()}
                  </TableCell>
                  <TableCell>
                    {detail!.kind}
                    <ModeBadge mode={detail!.mode} />
                  </TableCell>
                  <TableCell>
                    {detail!.client_ip}
                    <p>{detail!.domain}</p>
                  </TableCell>
                  <TableCell>{detail!.reason}</TableCell>
                  <TableCell>{detail!.actor.username}</TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        )}
      </CardContent>
    </Card>
  );
}
