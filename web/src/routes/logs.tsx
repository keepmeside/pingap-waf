import React from "react";
import { PageShell } from "@/components/page-shell";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Badge } from "@/components/ui/badge";
import { Input } from "@/components/ui/input";
import { EmptyState, ErrorNote, LoadingCard } from "@/components/data-ui";
import { useWafEvents } from "@/queries/admin";
import { fmtAge, fmtTime, orDash } from "@/lib/format";
import { formatError } from "@/helpers/util";
import { cn } from "@/lib/utils";
import type { WafEventRecord } from "@/lib/types";

type BlockedFilter = "any" | "blocked" | "not-blocked";

interface Filters {
  domain: string;
  ruleId: string;
  category: string;
  blocked: BlockedFilter;
  since: string;
  until: string;
  limit: string;
}

/** `datetime-local` yields `"YYYY-MM-DDTHH:mm"` in local time — convert to the unix
 * seconds the store compares against `created_at`. An empty field means no bound. */
function toEpoch(value: string): number | null {
  if (!value) return null;
  const ms = new Date(value).getTime();
  return Number.isNaN(ms) ? null : Math.floor(ms / 1000);
}

/** Compose the `?key=val` query string the endpoint accepts — empty filters are
 * simply left out, so the store applies no predicate for them. */
function toParams(f: Filters): string {
  const params = new URLSearchParams();
  if (f.domain.trim()) params.set("domain", f.domain.trim());
  if (f.ruleId.trim()) params.set("rule_id", f.ruleId.trim());
  if (f.category.trim()) params.set("category", f.category.trim());
  if (f.blocked === "blocked") params.set("blocked", "true");
  if (f.blocked === "not-blocked") params.set("blocked", "false");
  const since = toEpoch(f.since);
  const until = toEpoch(f.until);
  if (since !== null) params.set("since", String(since));
  if (until !== null) params.set("until", String(until));
  params.set("limit", f.limit);
  const s = params.toString();
  return s ? `?${s}` : "";
}

/**
 * The blocked column is the one place this page cannot afford ambiguity: `blocked=true`
 * means the request was refused. `blocked=false` covers *both* detect-only findings and
 * redactions — traffic that passed but was rewritten — so it is labelled "passed",
 * not "allowed": some of those requests carried a payload the WAF altered on the way.
 */
function BlockedBadge({ blocked }: { blocked: boolean }) {
  return blocked ? (
    <Badge variant="outline" className="machine border-transparent bg-destructive text-destructive-foreground text-[11px] font-semibold uppercase tracking-wide">
      blocked
    </Badge>
  ) : (
    <Badge
      variant="outline"
      title="Detect-only finding or a redaction — the request passed, possibly rewritten."
      className="machine text-[11px] font-semibold uppercase tracking-wide border-amber-500/60 bg-transparent text-amber-700 dark:text-amber-400"
    >
      passed
    </Badge>
  );
}

function FilterBar({ filters, onChange }: { filters: Filters; onChange: (f: Filters) => void }) {
  const set = (patch: Partial<Filters>) => onChange({ ...filters, ...patch });
  return (
    <div className="flex flex-wrap items-end gap-3">
      <div className="w-44 space-y-1">
        <label htmlFor="f-domain" className="text-xs text-muted-foreground">Domain</label>
        <Input id="f-domain" value={filters.domain} onChange={(e) => set({ domain: e.target.value })} placeholder="example.com" className="machine h-8" />
      </div>
      <div className="w-28 space-y-1">
        <label htmlFor="f-rule" className="text-xs text-muted-foreground">Rule ID</label>
        <Input
          id="f-rule"
          type="number"
          inputMode="numeric"
          min={0}
          value={filters.ruleId}
          onChange={(e) => set({ ruleId: e.target.value })}
          placeholder="942100"
          className="machine h-8"
        />
      </div>
      <div className="w-36 space-y-1">
        <label htmlFor="f-category" className="text-xs text-muted-foreground">Category</label>
        <Input id="f-category" value={filters.category} onChange={(e) => set({ category: e.target.value })} placeholder="sqli" className="machine h-8" />
      </div>
      <div className="w-36 space-y-1">
        <label className="text-xs text-muted-foreground">Verdict</label>
        <Select value={filters.blocked} onValueChange={(v) => set({ blocked: v as BlockedFilter })}>
          <SelectTrigger size="sm" className="w-full">
            <SelectValue />
          </SelectTrigger>
          <SelectContent>
            <SelectItem value="any">Any</SelectItem>
            <SelectItem value="blocked">Blocked</SelectItem>
            <SelectItem value="not-blocked">Not blocked</SelectItem>
          </SelectContent>
        </Select>
      </div>
      <div className="w-48 space-y-1">
        <label htmlFor="f-since" className="text-xs text-muted-foreground">Since</label>
        <Input
          id="f-since"
          type="datetime-local"
          value={filters.since}
          onChange={(e) => set({ since: e.target.value })}
          className="machine h-8"
        />
      </div>
      <div className="w-48 space-y-1">
        <label htmlFor="f-until" className="text-xs text-muted-foreground">Until</label>
        <Input
          id="f-until"
          type="datetime-local"
          value={filters.until}
          onChange={(e) => set({ until: e.target.value })}
          className="machine h-8"
        />
      </div>
      <div className="w-28 space-y-1">
        <label className="text-xs text-muted-foreground">Limit</label>
        <Select value={filters.limit} onValueChange={(v) => set({ limit: v })}>
          <SelectTrigger size="sm" className="w-full">
            <SelectValue />
          </SelectTrigger>
          <SelectContent>
            <SelectItem value="50">50</SelectItem>
            <SelectItem value="100">100</SelectItem>
            <SelectItem value="500">500</SelectItem>
          </SelectContent>
        </Select>
      </div>
    </div>
  );
}

/**
 * WAF findings — the persisted record of what the engine saw. Read-only: there is
 * nothing to mutate on a finding, so the page carries no capability gate.
 */
export default function Logs() {
  const [filters, setFilters] = React.useState<Filters>({
    domain: "",
    ruleId: "",
    category: "",
    blocked: "any",
    since: "",
    until: "",
    limit: "100",
  });
  const params = toParams(filters);
  const query = useWafEvents(params);
  const events: WafEventRecord[] = query.data?.data ?? [];

  return (
    <PageShell
      title="WAF events"
      eyebrow="Logs · waf-events"
      description="Persisted engine findings: blocked requests, detect-only hits and redactions. A `passed` verdict includes redacted traffic — the request went through, possibly rewritten."
    >
      <Card>
        <CardHeader>
          <CardTitle className="text-base">Findings</CardTitle>
          <CardDescription>
            Newest first. Filters apply server-side; empty fields match everything.
          </CardDescription>
        </CardHeader>
        <CardContent className="space-y-4">
          <FilterBar filters={filters} onChange={setFilters} />
          {query.isPending ? (
            <LoadingCard />
          ) : query.isError ? (
            <ErrorNote message={formatError(query.error)} />
          ) : query.data?.unavailable ? (
            <EmptyState title="Event store unavailable" hint={query.data.message} />
          ) : events.length === 0 ? (
            <EmptyState
              title="No findings"
              hint="No WAF events match these filters — or the engine has seen nothing worth recording yet."
            />
          ) : (
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Time</TableHead>
                  <TableHead>Domain</TableHead>
                  <TableHead>Profile</TableHead>
                  <TableHead>Rule</TableHead>
                  <TableHead>Category</TableHead>
                  <TableHead>Severity</TableHead>
                  <TableHead className="text-right">Score</TableHead>
                  <TableHead>Verdict</TableHead>
                  <TableHead>Client</TableHead>
                  <TableHead>Method</TableHead>
                  <TableHead>URI</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {events.map((event) => (
                  <TableRow key={event.id} className={cn(event.blocked && "bg-destructive/5")}>
                    <TableCell className="machine whitespace-nowrap text-muted-foreground" title={fmtTime(event.created_at)}>
                      {fmtAge(event.created_at)}
                    </TableCell>
                    <TableCell className="font-medium">{event.domain}</TableCell>
                    <TableCell className="machine text-muted-foreground">{event.profile}</TableCell>
                    <TableCell className="machine">{orDash(event.rule_id)}</TableCell>
                    <TableCell className="machine text-muted-foreground">{orDash(event.category)}</TableCell>
                    <TableCell>{orDash(event.severity)}</TableCell>
                    <TableCell className="machine text-right">{event.score}</TableCell>
                    <TableCell>
                      <BlockedBadge blocked={event.blocked} />
                    </TableCell>
                    <TableCell className="machine text-muted-foreground">{orDash(event.client_ip)}</TableCell>
                    <TableCell className="machine">{orDash(event.method)}</TableCell>
                    <TableCell className="machine max-w-64 truncate text-muted-foreground" title={event.uri ?? undefined}>
                      {orDash(event.uri)}
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          )}
        </CardContent>
      </Card>
    </PageShell>
  );
}
