import { Badge } from "@/components/ui/badge";
import { cn } from "@/lib/utils";

/**
 * The one badge that cannot be ambiguous. `detect` means traffic is *logged, not stopped*
 * — the failure the whole WAF UI exists to prevent is an operator believing they are
 * protected while only recording. So `block` and `redact` are solid and assertive, while
 * `detect` is a hollow outline that reads as "watching, not acting". `off` is muted.
 *
 * Response-side categories never get `block` (they cannot deny), so `redact` is their
 * strongest state — shown with the same "acting" weight as `block` but its own label.
 */
const STYLES: Record<string, string> = {
  block:
    "bg-destructive text-destructive-foreground border-transparent",
  redact:
    "bg-amber-500 text-white border-transparent dark:bg-amber-600",
  challenge:
    "bg-violet-500 text-white border-transparent dark:bg-violet-600",
  detect:
    "border-amber-500/60 bg-transparent text-amber-700 dark:text-amber-400",
  off: "border-transparent bg-muted text-muted-foreground",
};

export function ModeBadge({ mode }: { mode: string }) {
  const style = STYLES[mode] ?? STYLES.off;
  return (
    <Badge
      variant={mode === "off" ? "secondary" : "outline"}
      className={cn("machine text-[11px] font-semibold uppercase tracking-wide", style)}
    >
      {mode}
    </Badge>
  );
}
