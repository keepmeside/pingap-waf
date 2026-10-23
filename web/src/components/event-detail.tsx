import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { ModeBadge } from "@/components/mode-badge";
import { fmtTime } from "@/lib/format";
import type { WafEventRecord } from "@/lib/types";
export function EventDetail({
  event,
  onClose,
}: {
  event: WafEventRecord | null;
  onClose: () => void;
}) {
  return (
    <Dialog open={!!event} onOpenChange={(open) => !open && onClose()}>
      <DialogContent className="w-[calc(100vw-2rem)] sm:max-w-4xl max-h-[90svh] overflow-y-auto">
        <DialogHeader>
          <DialogTitle>Security event details</DialogTitle>
          <DialogDescription>
            Stored metadata only. Request and response bodies or credentials are
            not captured by this view.
          </DialogDescription>
        </DialogHeader>
        {event && (
          <>
            <div className="flex flex-wrap items-center gap-3">
              <ModeBadge mode={event.blocked ? "block" : "detect"} />
              <span className="break-all text-sm">
                {event.category ?? "Uncategorized finding"}
              </span>
            </div>
            <dl className="event-detail-grid text-sm">
              {[
                ["Client IP", event.client_ip ?? "Not captured"],
                ["Time", fmtTime(event.created_at)],
                ["Event ID", event.id],
                ["Domain", event.domain],
                ["Profile", event.profile],
                ["Rule", event.rule_id ?? "Not captured"],
              ].map(([k, v]) => (
                <div key={k}>
                  <dt className="text-xs text-muted-foreground">{k}</dt>
                  <dd className="mt-1">{v}</dd>
                </div>
              ))}
            </dl>
            <Tabs defaultValue="request">
              <TabsList>
                <TabsTrigger value="request">Request</TabsTrigger>
                <TabsTrigger value="response">Response</TabsTrigger>
              </TabsList>
              <TabsContent value="request">
                <pre className="event-inspection rounded-md border bg-muted/30 p-4 text-xs">{`${event.method ?? "Method not captured"} ${event.uri ?? "URI not captured"}\n\nHeaders: not captured\nBody: not captured`}</pre>
              </TabsContent>
              <TabsContent value="response">
                <pre className="event-inspection rounded-md border bg-muted/30 p-4 text-xs">
                  Status: not captured{"\n"}Headers: not captured{"\n"}Body: not
                  captured
                </pre>
              </TabsContent>
            </Tabs>
          </>
        )}
      </DialogContent>
    </Dialog>
  );
}
