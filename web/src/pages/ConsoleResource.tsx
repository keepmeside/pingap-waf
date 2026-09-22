import React from "react";
import { useLocation } from "react-router-dom";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import request from "@/helpers/request";
import { formatError } from "@/helpers/util";
import { toast } from "sonner";

const resources: Record<string, { title: string; description: string; endpoint: string; capability?: string }> = {
  dashboard: { title: "Dashboard", description: "Live process status and operator activity.", endpoint: "/basic" },
  domains: { title: "Domains", description: "Domain intent combines listeners, upstreams and policy bindings.", endpoint: "/domains", capability: "EditDomain" },
  upstreams: { title: "Upstreams", description: "Configured origin pools and their routing targets.", endpoint: "/upstreams", capability: "EditUpstream" },
  waf: { title: "WAF policies", description: "Live policy profiles. Response-side profiles are redaction-only where supported.", endpoint: "/policies" },
  acl: { title: "ACL policies", description: "Access-control policy profiles and their ordered rules.", endpoint: "/policies" },
  "access-lists": { title: "Access lists", description: "Policy profiles used by domain bindings.", endpoint: "/policies" },
  "bot-manager": { title: "Bot manager", description: "Policy profiles for bot and fingerprint controls.", endpoint: "/policies" },
  logs: { title: "Activity", description: "Audited control-plane activity from the live API.", endpoint: "/activity" },
  "config-history": { title: "Config history", description: "Applied and pending configuration versions.", endpoint: "/config-versions" },
  users: { title: "Users", description: "Administrator accounts visible to your role.", endpoint: "/users" },
  nodes: { title: "Nodes", description: "Node inventory is not available in this API version.", endpoint: "" },
  alerts: { title: "Alerts", description: "Alert APIs are not available in this API version.", endpoint: "" },
  performance: { title: "Performance", description: "Metrics APIs are not available in this API version.", endpoint: "" },
  backup: { title: "Backup", description: "Backup APIs are not available in this API version.", endpoint: "" },
};

type RecordValue = Record<string, unknown>;
function scalar(value: unknown): string {
  if (value === null || value === undefined) return "—";
  if (typeof value === "object") return JSON.stringify(value);
  return String(value);
}

export default function ConsoleResource() {
  const name = useLocation().pathname.replace(/^\//, "") || "dashboard";
  const resource = resources[name] ?? resources.dashboard;
  const [data, setData] = React.useState<unknown>(null);
  const [loading, setLoading] = React.useState(true);
  const [filter, setFilter] = React.useState("");
  const [draftName, setDraftName] = React.useState("");
  const [draftBody, setDraftBody] = React.useState("{}");

  const load = React.useCallback(async () => {
    if (!resource.endpoint) { setLoading(false); return; }
    setLoading(true);
    try { const response = await request.get(resource.endpoint); setData(response.data); }
    catch (error) { toast.error("Unable to load live data", { description: formatError(error) }); }
    finally { setLoading(false); }
  }, [resource.endpoint]);
  React.useEffect(() => { void load(); }, [load]);

  const rows = React.useMemo(() => {
    if (Array.isArray(data)) return data.map((value, index) => ({ key: String(index), value }));
    if (data && typeof data === "object") return Object.entries(data as RecordValue).map(([key, value]) => ({ key, value }));
    return [];
  }, [data]);
  const shown = rows.filter(({ key, value }) => `${key} ${scalar(value)}`.toLowerCase().includes(filter.toLowerCase()));
  const canEdit = resource.capability && resource.capability === "EditDomain" && resource.endpoint === "/domains";
  const create = async () => {
    if (!draftName.trim()) return;
    try { const body = JSON.parse(draftBody) as RecordValue; await request.put(`/domains/${encodeURIComponent(draftName.trim())}`, body); setDraftName(""); await load(); toast.success("Domain saved"); }
    catch (error) { toast.error("Unable to save domain", { description: error instanceof SyntaxError ? "Enter valid JSON." : formatError(error) }); }
  };

  return <main className="min-h-0 flex-1 overflow-auto p-4 sm:p-6"><div className="mx-auto max-w-6xl space-y-5">
    <div><h1 className="text-2xl font-semibold tracking-tight">{resource.title}</h1><p className="mt-1 text-sm text-muted-foreground">{resource.description}</p></div>
    {!resource.endpoint ? <Card><CardContent className="py-10 text-center text-sm text-muted-foreground">This feature is not exposed by the current admin API. No placeholder data is shown.</CardContent></Card> : <>
      {canEdit && <Card><CardHeader><CardTitle className="text-base">Compose a domain</CardTitle><CardDescription>Replace the complete domain intent. The server validates and applies it.</CardDescription></CardHeader><CardContent className="grid gap-3 sm:grid-cols-[1fr_2fr_auto] sm:items-end"><div className="space-y-2"><Label htmlFor="domain-name">Name</Label><Input id="domain-name" value={draftName} onChange={e => setDraftName(e.target.value)} placeholder="example.com" /></div><div className="space-y-2"><Label htmlFor="domain-body">Intent JSON</Label><Input id="domain-body" value={draftBody} onChange={e => setDraftBody(e.target.value)} /></div><Button onClick={() => void create()} disabled={!draftName.trim()}>Save</Button></CardContent></Card>}
      <Card><CardHeader className="flex-row items-center justify-between space-y-0"><div><CardTitle className="text-base">Live data</CardTitle><CardDescription>{loading ? "Loading…" : `${shown.length} entries`}</CardDescription></div><Input className="max-w-xs" value={filter} onChange={e => setFilter(e.target.value)} placeholder="Filter entries" aria-label="Filter entries" /></CardHeader><CardContent>{shown.length === 0 && !loading ? <p className="py-8 text-center text-sm text-muted-foreground">No matching live entries.</p> : <div className="grid gap-3 md:grid-cols-2">{shown.map(({ key, value }) => <div className="rounded-lg border border-border p-4" key={key}><div className="mb-2 flex items-center justify-between gap-2"><span className="font-medium break-all">{key}</span><Badge variant="outline">live</Badge></div><pre className="max-h-48 overflow-auto whitespace-pre-wrap break-words text-xs text-muted-foreground">{typeof value === "object" ? JSON.stringify(value, null, 2) : scalar(value)}</pre></div>)}</div>}</CardContent></Card>
    </>}
  </div></main>;
}
