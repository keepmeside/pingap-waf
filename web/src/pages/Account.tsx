import React from "react";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import request from "@/helpers/request";
import { formatError } from "@/helpers/util";
import { toast } from "sonner";

type Profile = { username: string; email: string; role: string; auth_level: string; is_active: boolean; created_at: number; capabilities: string[] };
type Session = { id: string; auth_level: string; ip?: string; user_agent?: string; created_at: number; expires_at: number; revoked_at?: number; usable: boolean; current: boolean };

export default function Account() {
  const [profile, setProfile] = React.useState<Profile | null>(null);
  const [sessions, setSessions] = React.useState<Session[]>([]);
  React.useEffect(() => {
    let cancelled = false;
    Promise.all([request.get<Profile>("/account"), request.get<Session[]>("/account/sessions")]).then(([p, s]) => {
      if (!cancelled) { setProfile(p.data); setSessions(s.data); }
    }).catch(error => toast.error("Unable to load account", { description: formatError(error) }));
    return () => { cancelled = true; };
  }, []);
  return <main className="min-h-0 flex-1 overflow-auto p-4 sm:p-6"><div className="mx-auto max-w-4xl space-y-5">
    <div><h1 className="text-2xl font-semibold tracking-tight">Account</h1><p className="mt-1 text-sm text-muted-foreground">Your identity, session state, and server-authorized capabilities.</p></div>
    <Card><CardHeader><CardTitle className="text-base">Profile</CardTitle></CardHeader><CardContent>{profile ? <div className="grid gap-3 sm:grid-cols-2">{[["Username", profile.username],["Email", profile.email || "—"],["Role", profile.role],["Authentication", profile.auth_level],["Status", profile.is_active ? "Active" : "Inactive"]].map(([label, value]) => <div key={label}><p className="text-xs text-muted-foreground">{label}</p><p className="font-medium">{value}</p></div>)}<div className="sm:col-span-2"><p className="mb-2 text-xs text-muted-foreground">Capabilities</p><div className="flex flex-wrap gap-2">{profile.capabilities.map(cap => <Badge variant="outline" key={cap}>{cap}</Badge>)}</div></div></div> : <p className="text-sm text-muted-foreground">Loading…</p>}</CardContent></Card>
    <Card><CardHeader><CardTitle className="text-base">Sessions</CardTitle><CardDescription>Only sessions belonging to this account are shown. Tokens are never rendered.</CardDescription></CardHeader><CardContent><div className="space-y-3">{sessions.map(session => <div className="rounded-lg border border-border p-4" key={session.id}><div className="flex flex-wrap items-center gap-2"><Badge variant={session.current ? "default" : "outline"}>{session.current ? "Current" : session.usable ? "Active" : "Expired"}</Badge><span className="text-sm">{session.user_agent || "Unknown client"}</span></div><p className="mt-2 text-xs text-muted-foreground">{session.ip || "Unknown address"} · expires {new Date(session.expires_at * 1000).toLocaleString()}</p></div>)}{sessions.length === 0 && <p className="text-sm text-muted-foreground">No sessions available.</p>}</div></CardContent></Card>
    <Card><CardHeader><CardTitle className="text-base">Two-factor authentication</CardTitle><CardDescription>Enrollment controls are not exposed by the current admin API. Complete setup is unavailable rather than simulated.</CardDescription></CardHeader></Card>
  </div></main>;
}
