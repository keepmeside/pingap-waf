import type { PluginConf, PolicyBinding } from "@/lib/types";
const categories = ["waf", "acl", "bot", "challenge", "behaviour", "adaptive", "limit"] as const;
export function bindingFromEntry(entry: string): PolicyBinding | null {
  const split = entry.indexOf(":");
  const category = entry.slice(0, split);
  if (split < 1 || !entry.slice(split + 1) || !categories.some(c => c === category)) return null;
  return { [category]: entry.slice(split + 1) } as PolicyBinding;
}
export function bindingKey(binding: PolicyBinding): string {
  const entry = Object.entries(binding)[0];
  return entry ? `${entry[0]}:${entry[1]}` : "?";
}
export function challengePayload(base: PluginConf, patch: PluginConf, reference: string): PluginConf {
  const result = { ...base, ...patch, category: "challenge" } as PluginConf;
  delete result.secret_configured; delete result.secret_source; delete result.secret; delete result.secret_file;
  if (reference) {
    if (reference.includes("..") || /[/\\\x00-\x1f\x7f]/.test(reference)) throw new Error("Choose a single provisioned filename, without separators or ..");
    if (reference !== base.secret_file) result.secret_file = reference;
  }
  return result;
}
function seconds(value: unknown): number | null {
  if (value === undefined || value === "") return 10;
  if (typeof value !== "string") return null;
  const units: Record<string, number> = { ns: 1e-9, us: 1e-6, ms: 0.001, s: 1, sec: 1, seconds: 1, m: 60, min: 60, minutes: 60, h: 3600, hours: 3600, d: 86400, days: 86400 };
  const parts = [...value.matchAll(/(\d+(?:\.\d+)?)\s*([a-z]+)/g)];
  if (!parts.length || value.replace(/(\d+(?:\.\d+)?)\s*([a-z]+)/g, "").trim()) return null;
  let total = 0;
  for (const match of parts) { if (!(match[2] in units)) return null; total += Number(match[1]) * units[match[2]]; }
  return total;
}
export function rateSummary(conf: PluginConf) {
  const max = typeof conf.max === "number" && Number.isInteger(conf.max) ? conf.max : 0;
  const interval = seconds(conf.interval);
  const weight = Math.min(100, Math.max(0, typeof conf.weight === "number" && Number.isInteger(conf.weight) ? conf.weight : 50));
  return {
    effectivePerSecond: conf.type === "inflight" || interval === null ? null : max / Math.max(interval, 1),
    weight,
    warning: max <= 0 ? "Zero or negative ceilings can refuse all traffic. Existing engine semantics are retained." : interval === 0 ? "Zero interval is accepted by the engine; use a positive window for an ordinary rate policy." : "",
  };
}
