import { AlertCircle, LoaderCircle } from "lucide-react";
import type { ReactNode } from "react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { useAdminEndpoint, type ApiState } from "@/queries/api";

export function AdminRoutePage<T>({ title, endpoint, path, render }: { title: string; endpoint: string; path: string; render?: (state: ApiState<T>) => ReactNode }) {
  const query = useAdminEndpoint<T>(endpoint, path);
  return (
    <main className="min-h-0 flex-1 overflow-auto p-4 md:p-6">
      <div className="mx-auto max-w-6xl space-y-5">
        <div><p className="eyebrow">Pingap admin</p><h1 className="text-2xl font-semibold tracking-tight">{title}</h1></div>
        {query.isPending && <Card><CardContent className="flex items-center gap-2 py-8 text-muted-foreground"><LoaderCircle className="size-4 animate-spin" />Loading live data…</CardContent></Card>}
        {query.isError && <Card><CardHeader><CardTitle className="flex items-center gap-2 text-destructive"><AlertCircle className="size-4" />Unable to load live data</CardTitle></CardHeader><CardContent>{query.error.message}</CardContent></Card>}
        {query.data && (render ? render(query.data) : query.data.unavailable ? <Card><CardContent className="py-8 text-muted-foreground">{query.data.message}</CardContent></Card> : <Card><CardContent className="py-8"><pre className="overflow-auto text-xs">{JSON.stringify(query.data.data, null, 2)}</pre></CardContent></Card>)}
      </div>
    </main>
  );
}
