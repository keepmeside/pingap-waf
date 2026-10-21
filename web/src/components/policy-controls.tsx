import React from "react";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { usePolicies, useProfile, usePutPolicy } from "@/queries/admin";
import { can } from "@/lib/rbac";
import { formatError } from "@/helpers/util";
import { challengePayload, rateSummary } from "@/helpers/policy-controls";
import type { PluginConf } from "@/lib/types";
import { toast } from "sonner";

type Category = "limit" | "challenge";
const labels = { limit: "Rate limits", challenge: "Verification challenges" };
const fields: Record<Category, { name: string; label: string; type?: string; options?: string[] }[]> = {
  limit: [
    { name: "type", label: "Limit type", options: ["rate", "inflight"] },
    { name: "tag", label: "Count by", options: ["ip", "cookie", "header", "query"] },
    { name: "key", label: "Header, cookie or query name" },
    { name: "max", label: "Request ceiling", type: "number" },
    { name: "interval", label: "Counting window" },
    { name: "weight", label: "Current window weight (%)", type: "number" },
    { name: "step", label: "Apply before", options: ["request", "proxy_upstream"] },
  ],
  challenge: [
    { name: "kind", label: "Verification kind", options: ["pow", "silent"] },
    { name: "prefix", label: "Verification path prefix" },
    { name: "difficulty", label: "Work difficulty (1–10)", type: "number" },
    { name: "token_ttl", label: "Verification ticket lifetime" },
    { name: "pass_ttl", label: "Verified session lifetime" },
  ],
};

/** Native controls use the existing versioned policy mutation and domain binding. */
export function PolicyControls() {
  const query = usePolicies();
  const profile = useProfile();
  const editable = can(profile.data?.data, "edit_policy");
  const [editing, setEditing] = React.useState<{ category: Category; entry: string; conf: PluginConf } | null>(null);
  if (query.isPending || query.isError || query.data?.unavailable) return null;
  return <section aria-label="Rate and challenge policies" className="grid gap-4">
    {editing ? <Editor key={`${editing.category}:${editing.entry}`} {...editing} editable={editable} onClose={() => setEditing(null)} /> :
      <div className="grid gap-4 lg:grid-cols-2">{(["limit", "challenge"] as const).map(category => {
        const entries = Object.entries(query.data?.data ?? {}).filter(([entry]) => entry.startsWith(`${category}:`));
        return <Card key={category}>
          <CardHeader><CardTitle>{labels[category]}</CardTitle><CardDescription>
            {category === "limit" ? "Control request rates or concurrent requests. Profiles share counters across websites; use separate profiles for separate budgets." : "Verify clients with the native challenge engine. Signing keys stay on the server."}
          </CardDescription></CardHeader>
          <CardContent className="space-y-3">
            {entries.length === 0 && <p className="text-sm text-muted-foreground">No profiles configured. Websites are protected only after you attach a profile.</p>}
            {entries.map(([entry, conf]) => <div key={entry} role="group" aria-label={entry} className="flex items-center justify-between gap-3 border-b pb-2">
              <div><p className="font-medium">{entry}</p><p className="text-xs text-muted-foreground">{category === "challenge" ? conf.enabled === true ? "Enabled when attached" : "Disabled" : "Applies when attached"}</p></div>
              <Button size="sm" variant="outline" onClick={() => setEditing({ category, entry, conf })}>{editable ? "Edit" : "View"}</Button>
            </div>)}
            {editable && <Button variant="outline" size="sm" onClick={() => setEditing({ category, entry: "", conf: category === "limit" ? { category, type: "rate", tag: "ip", interval: "10s", weight: 50, step: "request" } : { category, enabled: false, kind: "pow", prefix: "/.pingap/challenge/", difficulty: 4, token_ttl: "5m", pass_ttl: "1h", client_ip_from_peer: false } })}>New {category === "limit" ? "rate limit" : "challenge"} profile</Button>}
          </CardContent>
        </Card>;
      })}</div>}
  </section>;
}

function Editor({ category, entry, conf, editable, onClose }: { category: Category; entry: string; conf: PluginConf; editable: boolean; onClose: () => void }) {
  const [name, setName] = React.useState(entry.slice(category.length + 1));
  const [draft, setDraft] = React.useState<PluginConf>({ ...conf });
  const [reference, setReference] = React.useState(typeof conf.secret_file === "string" ? conf.secret_file : "");
  const put = usePutPolicy();
  const summary = rateSummary(draft);
  const update = (key: string, value: unknown) => setDraft(current => ({ ...current, [key]: value }));
  const save = async () => {
    try {
      const body = category === "challenge" ? challengePayload(conf, draft, reference) : { ...conf, ...draft, category };
      await put.mutateAsync({ name: entry || `${category}:${name}`, body });
      toast.success("Policy saved and applied"); onClose();
    } catch (error) {
      toast.error((error as { category?: string }).category === "timeout" ? "Save outcome unconfirmed — check the configuration version before retrying" : "Save failed", { description: formatError(error) });
    }
  };
  return <Card><CardHeader><CardTitle>{labels[category]} · {entry || "New profile"}</CardTitle><CardDescription>Save the profile, then attach it in Domains. Saving alone does not protect a website.</CardDescription></CardHeader>
    <CardContent className="space-y-4"><fieldset disabled={!editable || put.isPending} className="grid gap-4 sm:grid-cols-2">
      <label className="grid gap-1 text-sm">Profile name<Input value={name} disabled={!!entry} onChange={event => setName(event.target.value)} /></label>
      {fields[category].map(field => <label key={field.name} className="grid gap-1 text-sm">{field.label}
        {field.options ? <select aria-label={field.label} className="h-9 rounded-md border bg-background px-3" value={String(draft[field.name] ?? field.options[0])} onChange={event => update(field.name, event.target.value)}>{field.options.map(option => <option key={option} value={option}>{option}</option>)}</select> :
          <Input type={field.type ?? "text"} step={field.type === "number" ? "1" : undefined} value={String(draft[field.name] ?? "")} onChange={event => update(field.name, field.type === "number" ? Number(event.target.value) : event.target.value)} />}
      </label>)}
      {category === "challenge" && <>
        <label className="flex items-center gap-2 text-sm"><input type="checkbox" checked={draft.enabled === true} onChange={event => update("enabled", event.target.checked)} />Enable challenge responses</label>
        <label className="flex items-center gap-2 text-sm"><input type="checkbox" checked={draft.client_ip_from_peer === true} onChange={event => update("client_ip_from_peer", event.target.checked)} />Use direct peer IP as client identity</label>
        <label className="grid gap-1 text-sm">Provisioned key filename<Input autoComplete="off" value={reference} onChange={event => setReference(event.target.value)} placeholder="challenge-v1" /></label>
      </>}
    </fieldset>
    {category === "limit" ? <div className="text-sm text-muted-foreground" role="status">
      <p>{draft.type === "inflight" ? `Concurrent ceiling: ${summary.effectiveCeiling}` : summary.effectivePerSecond === null ? "The server validates this window; effective requests/second cannot be previewed." : `Effective ceiling: ${summary.effectivePerSecond} requests/second`}{draft.type === "inflight" ? " active requests." : `. Current-window weight: ${summary.weight}%.`}</p>
      {summary.warning && <p className="text-amber-700">{summary.warning}</p>}
      {draft.type !== "inflight" && <p>The engine uses at least one second as the rate divisor. Values and sliding-window behavior remain compatible with existing policies.</p>}
    </div> : <div className="text-sm text-muted-foreground" role="status">
      <p>Signing key: {conf.secret_configured === true ? "Configured on server" : "Not confirmed"}. Leave the filename blank to retain the saved source.</p>
      <p>A preceding WAF or ACL rule must request verification. Attaching this profile alone does not challenge requests.</p>
      <p>An operator must provision an immutable file in the server's read-only secret directory. Enter its filename, never its contents. Keep old versions available for rollback.</p>
      <p>Peer identity is suitable for direct traffic. Behind a trusted proxy, configure trusted proxies first. Tickets bind to the client and website; reload preserves valid signed sessions with the same key.</p>
    </div>}
    <div className="flex gap-2"><Button variant="outline" onClick={onClose}>Cancel</Button>{editable && <Button onClick={save} disabled={put.isPending || !name.trim() || (category === "limit" && typeof draft.max !== "number")}>{put.isPending ? "Saving…" : "Save policy"}</Button>}</div>
    </CardContent></Card>;
}
