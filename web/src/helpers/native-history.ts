import type { NativeLifecycleDetail } from "@/lib/types";

/** Read supported metadata only; render returned strings through ordinary React text. */
export function parseNativeLifecycle(detail: string | null): NativeLifecycleDetail | null {
  if (!detail) return null;
  try {
    const value: unknown = JSON.parse(detail);
    if (typeof value !== "object" || value === null || Array.isArray(value)) return null;
    const row = value as Record<string, unknown>;
    if (row.version !== 1 || !["detected", "created", "released", "expired"].includes(String(row.kind)) ||
        !["failed_login", "scan"].includes(String(row.scenario)) || !["detect", "block"].includes(String(row.mode))) return null;
    for (const key of ["id", "epoch", "profile", "domain", "client_ip", "reason"]) if (typeof row[key] !== "string") return null;
    for (const key of ["created_at_ms", "observed_at_ms"]) if (typeof row[key] !== "number" || !Number.isFinite(row[key]) || row[key] < 0) return null;
    if (row.expires_at_ms !== null && (typeof row.expires_at_ms !== "number" || !Number.isFinite(row.expires_at_ms) || row.expires_at_ms < 0)) return null;
    if (typeof row.actor !== "object" || row.actor === null || Array.isArray(row.actor)) return null;
    const actor = row.actor as Record<string, unknown>;
    if (typeof actor.username !== "string" || (actor.id !== null && typeof actor.id !== "string")) return null;
    return {
      version: 1, kind: row.kind as NativeLifecycleDetail["kind"], id: row.id as string,
      epoch: row.epoch as string, profile: row.profile as string, domain: row.domain as string,
      client_ip: row.client_ip as string, scenario: row.scenario as NativeLifecycleDetail["scenario"],
      mode: row.mode as NativeLifecycleDetail["mode"], created_at_ms: row.created_at_ms as number,
      expires_at_ms: row.expires_at_ms as number | null, observed_at_ms: row.observed_at_ms as number,
      actor: { id: actor.id as string | null, username: actor.username }, reason: row.reason as string,
    };
  } catch { return null; }
}
