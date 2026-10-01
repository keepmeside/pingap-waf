import { Card, CardContent } from "@/components/ui/card";
import { LoaderCircle } from "lucide-react";
import type { ReactNode } from "react";

/** A labelled value row — `label` left, `value` right — used in detail cards. */
export function FieldRow({ label, children }: { label: string; children: ReactNode }) {
  return (
    <div className="grid gap-1 py-2 sm:grid-cols-[160px_1fr] sm:items-baseline">
      <dt className="text-xs text-muted-foreground">{label}</dt>
      <dd className="min-w-0 text-sm">{children}</dd>
    </div>
  );
}

/** A set of `FieldRow`s rendered as a definition list. */
export function FieldList({ children }: { children: ReactNode }) {
  return <dl className="divide-y divide-border/60">{children}</dl>;
}

/** The empty state for a list or a card body — a title, an optional hint, optional
 * actions (e.g. a create button). */
export function EmptyState({
  title,
  hint,
  action,
}: {
  title: string;
  hint?: string;
  action?: ReactNode;
}) {
  return (
    <div className="flex flex-col items-center gap-2 py-10 text-center">
      <p className="text-sm font-medium text-foreground">{title}</p>
      {hint && <p className="max-w-sm text-xs text-muted-foreground">{hint}</p>}
      {action}
    </div>
  );
}

/** A full-card loading state, matching the route pages' loading treatment. */
export function LoadingCard() {
  return (
    <Card>
      <CardContent className="flex items-center gap-2 py-8 text-muted-foreground">
        <LoaderCircle className="size-4 animate-spin" />
        Loading live data…
      </CardContent>
    </Card>
  );
}

/** An inline error note for a failed fetch or mutation — small, in-flow, not a toast. */
export function ErrorNote({ message }: { message: string }) {
  return (
    <p className="rounded-md border border-destructive/40 bg-destructive/5 px-3 py-2 text-xs text-destructive">
      {message}
    </p>
  );
}
