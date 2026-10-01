// Small formatters shared across the route pages. Each is a pure function with a single
// responsibility — no locale surprises, no layout.

/** Unix seconds → a readable local timestamp, or an em dash for absent/zero. */
export function fmtTime(at?: number | null): string {
  if (!at) return "—";
  return new Date(at * 1000).toLocaleString();
}

/** Unix seconds → "5m ago" style relative text. */
export function fmtAge(at?: number | null): string {
  if (!at) return "—";
  const secs = Math.max(0, Math.floor(Date.now() / 1000) - at);
  if (secs < 60) return `${secs}s ago`;
  if (secs < 3600) return `${Math.floor(secs / 60)}m ago`;
  if (secs < 86400) return `${Math.floor(secs / 3600)}h ago`;
  return `${Math.floor(secs / 86400)}d ago`;
}

/** Bytes → a short human size. */
export function fmtBytes(bytes?: number | null): string {
  if (bytes === null || bytes === undefined) return "—";
  const units = ["B", "KiB", "MiB", "GiB", "TiB"];
  let value = bytes;
  let unit = 0;
  while (value >= 1024 && unit < units.length - 1) {
    value /= 1024;
    unit += 1;
  }
  return `${value.toFixed(value >= 10 || unit === 0 ? 0 : 1)} ${units[unit]}`;
}

/** CPU in millicores → "1.5 cores" or "250m". */
export function fmtCpu(millis?: number | null): string {
  if (millis === null || millis === undefined) return "—";
  return millis >= 1000 ? `${(millis / 1000).toFixed(2)} cores` : `${millis}m`;
}

/** A maybe-empty value → its content or an em dash, so a column never renders `undefined`. */
export function orDash(value?: string | number | null): string {
  if (value === null || value === undefined || value === "") return "—";
  return String(value);
}
