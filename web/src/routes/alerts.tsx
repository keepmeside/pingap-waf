import React from "react";
import { PageShell } from "@/components/page-shell";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Checkbox } from "@/components/ui/checkbox";
import { EmptyState, ErrorNote, LoadingCard } from "@/components/data-ui";
import {
  useAlertChannels,
  useAlertHistory,
  useAlertRules,
  useCreateChannel,
  useCreateRule,
  useProfile,
  useTestSend,
} from "@/queries/admin";
import { can } from "@/lib/rbac";
import { formatError } from "@/helpers/util";
import { fmtTime } from "@/lib/format";
import { toast } from "sonner";
import type { AlertHistory, AlertRuleRecord, Comparison, NotificationChannel } from "@/lib/types";
import { Plus, Send } from "lucide-react";

/**
 * The comparators the evaluator accepts, in wire form. Serde serialises the
 * `Comparison` enum snake_case over five variants — `greater`, `greater_or_equal`,
 * `less`, `less_or_equal`, `equal`. The labels spell the symbol out (`>` reads as
 * "greater than") so an operator never has to decode the snake_case key.
 */
type Comparator = Comparison;

const COMPARATORS: { value: Comparator; label: string }[] = [
  { value: "greater", label: "> greater than" },
  { value: "greater_or_equal", label: "≥ greater or equal" },
  { value: "less", label: "< less than" },
  { value: "less_or_equal", label: "≤ less or equal" },
  { value: "equal", label: "= equal" },
];

const SEVERITIES = ["info", "warning", "critical"];

/**
 * Alerting: channels, rules and the delivery history, as three tabs of one page.
 *
 * What it must never get wrong:
 *
 * - A channel's `config` is credentials. The API already returns `"[redacted]"` and the
 *   page renders exactly that — it is never bound to an input, never shown as editable
 *   text. The create form writes `config` once, at creation, into a dedicated field
 *   that is not pre-filled from a listing.
 * - A failed delivery is the alert that did not fire. `delivered=false` rows are styled
 *   distinctly and surface `delivery_error`, because a silent delivery failure is the
 *   alerting failure this page exists to make visible.
 */
export default function Alerts() {
  const profileQuery = useProfile();
  const canEdit = can(profileQuery.data?.data, "edit_alert");

  return (
    <PageShell
      title="Alerts"
      eyebrow="Notifications"
      description="Where alert deliveries go, the rules that trigger them, and what actually sent. A failed delivery is shown as failed — an alert that never arrived is not a resolved alert."
    >
      <Tabs defaultValue="channels">
        <TabsList>
          <TabsTrigger value="channels">Channels</TabsTrigger>
          <TabsTrigger value="rules">Rules</TabsTrigger>
          <TabsTrigger value="history">History</TabsTrigger>
        </TabsList>
        <TabsContent value="channels" className="pt-4">
          <ChannelsTab canEdit={canEdit} />
        </TabsContent>
        <TabsContent value="rules" className="pt-4">
          <RulesTab canEdit={canEdit} />
        </TabsContent>
        <TabsContent value="history" className="pt-4">
          <HistoryTab />
        </TabsContent>
      </Tabs>
    </PageShell>
  );
}

// ---- channels ------------------------------------------------------------------------

function ChannelsTab({ canEdit }: { canEdit: boolean }) {
  const channels = useAlertChannels();
  const testSend = useTestSend();
  const [creating, setCreating] = React.useState(false);
  /** Per-channel test-send result, so one channel's outcome does not bleed into another's. */
  const [sent, setSent] = React.useState<Record<string, "delivered" | "failed">>({});

  if (channels.isPending) return <LoadingCard />;
  if (channels.isError) return <ErrorNote message={formatError(channels.error)} />;
  if (channels.data.unavailable) {
    return (
      <EmptyState
        title="Alert channels unavailable"
        hint={channels.data.message ?? "The connected server does not expose alert channels."}
      />
    );
  }
  const list = channels.data.data ?? [];

  return (
    <div className="space-y-4">
      <Card>
        <CardHeader className="flex-row items-start justify-between gap-4">
          <div>
            <CardTitle className="text-base">Channels</CardTitle>
            <CardDescription>
              Delivery targets — webhook, telegram, and the like. Credentials are write-once
              and return only as `[redacted]`; they are never rendered back.
            </CardDescription>
          </div>
          {canEdit && (
            <Button size="sm" onClick={() => setCreating((v) => !v)}>
              <Plus className="size-4" /> New channel
            </Button>
          )}
        </CardHeader>
        <CardContent>
          {list.length === 0 ? (
            <EmptyState
              title="No channels"
              hint="A channel is where an alert delivery goes. Create one before writing a rule that notifies it."
            />
          ) : (
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Name</TableHead>
                  <TableHead>Kind</TableHead>
                  <TableHead>Config</TableHead>
                  <TableHead>Enabled</TableHead>
                  <TableHead>Created</TableHead>
                  <TableHead className="text-right">Test</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {list.map((channel) => (
                  <ChannelRow
                    key={channel.id}
                    channel={channel}
                    canEdit={canEdit}
                    state={sent[channel.id]}
                    onTest={() =>
                      testSend.mutate(channel.id, {
                        onSuccess: (result) => {
                          setSent((s) => ({ ...s, [channel.id]: result.delivered ? "delivered" : "failed" }));
                          if (result.delivered) {
                            toast.success(`Test delivered to ${channel.name}`);
                          } else {
                            toast.error("Test send failed", { description: channel.name });
                          }
                        },
                        onError: (e) => {
                          setSent((s) => ({ ...s, [channel.id]: "failed" }));
                          toast.error("Test send failed", { description: formatError(e) });
                        },
                      })
                    }
                    testing={testSend.isPending}
                  />
                ))}
              </TableBody>
            </Table>
          )}
        </CardContent>
      </Card>
      {creating && canEdit && <ChannelForm onClose={() => setCreating(false)} />}
    </div>
  );
}

function ChannelRow({
  channel,
  canEdit,
  state,
  onTest,
  testing,
}: {
  channel: NotificationChannel;
  canEdit: boolean;
  state?: "delivered" | "failed";
  onTest: () => void;
  testing: boolean;
}) {
  return (
    <TableRow>
      <TableCell className="font-medium">{channel.name}</TableCell>
      <TableCell>
        <Badge variant="outline" className="machine">{channel.kind}</Badge>
      </TableCell>
      <TableCell>
        {/* The wire value is the literal string "[redacted]" — render it as the fact of
            redaction, not as editable content. */}
        <span className="machine text-xs text-muted-foreground">{channel.config}</span>
      </TableCell>
      <TableCell>
        {channel.enabled ? (
          <Badge variant="outline">enabled</Badge>
        ) : (
          <Badge variant="secondary">disabled</Badge>
        )}
      </TableCell>
      <TableCell className="text-xs text-muted-foreground">{fmtTime(channel.created_at)}</TableCell>
      <TableCell className="text-right">
        <div className="flex items-center justify-end gap-2">
          {state === "delivered" && (
            <span className="text-xs text-emerald-600 dark:text-emerald-400">delivered</span>
          )}
          {state === "failed" && (
            <span className="text-xs text-destructive">failed</span>
          )}
          {canEdit && (
            <Button size="sm" variant="ghost" onClick={onTest} disabled={testing}>
              <Send className="size-4" />
              Test
            </Button>
          )}
        </div>
      </TableCell>
    </TableRow>
  );
}

/**
 * Create a channel. `config` is the credential blob — written once here, returned only
 * ever as `[redacted]`. The field is not populated from any listing value.
 */
function ChannelForm({ onClose }: { onClose: () => void }) {
  const create = useCreateChannel();
  const [name, setName] = React.useState("");
  const [kind, setKind] = React.useState("webhook");
  const [config, setConfig] = React.useState("");
  const [enabled, setEnabled] = React.useState(true);

  const save = () => {
    if (!name.trim() || !config.trim()) {
      toast.error("Name and config are required");
      return;
    }
    create.mutate(
      { name: name.trim(), kind, config, enabled },
      {
        onSuccess: () => {
          toast.success("Channel created");
          onClose();
        },
        onError: (e) => toast.error("Create failed", { description: formatError(e) }),
      },
    );
  };

  return (
    <Card>
      <CardHeader>
        <CardTitle className="text-base">New channel</CardTitle>
        <CardDescription>
          The `config` payload is the channel's credentials — a JSON object the sender
          interprets (token, chat id, webhook URL). It is stored once and returned only as
          `[redacted]`.
        </CardDescription>
      </CardHeader>
      <CardContent className="grid gap-4 sm:grid-cols-2">
        <div className="space-y-1.5">
          <Label htmlFor="ch-name">Name</Label>
          <Input id="ch-name" value={name} onChange={(e) => setName(e.target.value)} placeholder="ops-telegram" />
        </div>
        <div className="space-y-1.5">
          <Label htmlFor="ch-kind">Kind</Label>
          <Select value={kind} onValueChange={setKind}>
            <SelectTrigger id="ch-kind" className="w-full">
              <SelectValue />
            </SelectTrigger>
            <SelectContent>
              <SelectItem value="webhook">webhook</SelectItem>
              <SelectItem value="telegram">telegram</SelectItem>
            </SelectContent>
          </Select>
        </div>
        <div className="space-y-1.5 sm:col-span-2">
          <Label htmlFor="ch-config">Config (credentials JSON — never rendered back)</Label>
          <Input
            id="ch-config"
            value={config}
            onChange={(e) => setConfig(e.target.value)}
            placeholder='{"token":"…","chat_id":"…"}'
            className="machine"
            autoComplete="off"
          />
        </div>
        <div className="flex items-center gap-2">
          <Checkbox id="ch-enabled" checked={enabled} onCheckedChange={(v) => setEnabled(v === true)} />
          <Label htmlFor="ch-enabled" className="text-sm font-normal">Enabled</Label>
        </div>
        <div className="flex items-center gap-2 sm:col-span-2">
          <Button onClick={save} disabled={create.isPending}>
            {create.isPending ? "Creating…" : "Create channel"}
          </Button>
          <Button variant="ghost" onClick={onClose}>Cancel</Button>
        </div>
      </CardContent>
    </Card>
  );
}

// ---- rules -----------------------------------------------------------------------------

function RulesTab({ canEdit }: { canEdit: boolean }) {
  const rules = useAlertRules();
  const channels = useAlertChannels();
  const [creating, setCreating] = React.useState(false);

  if (rules.isPending) return <LoadingCard />;
  if (rules.isError) return <ErrorNote message={formatError(rules.error)} />;
  if (rules.data.unavailable) {
    return (
      <EmptyState
        title="Alert rules unavailable"
        hint={rules.data.message ?? "The connected server does not expose alert rules."}
      />
    );
  }
  const list = rules.data.data ?? [];
  const channelName = new Map(
    (channels.data?.data ?? []).map((c) => [c.id, c.name]),
  );

  return (
    <div className="space-y-4">
      <Card>
        <CardHeader className="flex-row items-start justify-between gap-4">
          <div>
            <CardTitle className="text-base">Rules</CardTitle>
            <CardDescription>
              A metric, a threshold, a window — and the channels a firing rule notifies.
            </CardDescription>
          </div>
          {canEdit && (
            <Button size="sm" onClick={() => setCreating((v) => !v)}>
              <Plus className="size-4" /> New rule
            </Button>
          )}
        </CardHeader>
        <CardContent>
          {list.length === 0 ? (
            <EmptyState
              title="No rules"
              hint="A rule evaluates a metric over a window and notifies its channels when the comparator holds."
            />
          ) : (
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Name</TableHead>
                  <TableHead>Metric</TableHead>
                  <TableHead>Fires when</TableHead>
                  <TableHead>Window</TableHead>
                  <TableHead>Severity</TableHead>
                  <TableHead>Channels</TableHead>
                  <TableHead>Enabled</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {list.map((record) => (
                  <RuleRow key={record.rule.id} record={record} channelName={channelName} />
                ))}
              </TableBody>
            </Table>
          )}
        </CardContent>
      </Card>
      {creating && canEdit && <RuleForm onClose={() => setCreating(false)} channels={[...channelName.entries()]} />}
    </div>
  );
}

function RuleRow({
  record,
  channelName,
}: {
  record: AlertRuleRecord;
  channelName: Map<string, string>;
}) {
  const rule = record.rule;
  const channels = rule.channel_ids.map((id) => channelName.get(id) ?? id);
  return (
    <TableRow>
      <TableCell className="font-medium">{rule.name}</TableCell>
      <TableCell className="machine text-xs">{rule.metric}</TableCell>
      <TableCell className="machine text-xs">
        {rule.comparator.replace(/_/g, " ")} {rule.threshold}
      </TableCell>
      <TableCell className="machine text-xs">{rule.window_secs}s</TableCell>
      <TableCell>
        <Badge variant="outline">{rule.severity}</Badge>
      </TableCell>
      <TableCell className="max-w-56">
        <div className="flex flex-wrap gap-1">
          {channels.length === 0 ? (
            <span className="text-xs text-muted-foreground">—</span>
          ) : (
            channels.map((name) => (
              <Badge key={name} variant="secondary" className="text-[11px]">{name}</Badge>
            ))
          )}
        </div>
      </TableCell>
      <TableCell>
        {rule.enabled ? (
          <Badge variant="outline">enabled</Badge>
        ) : (
          <Badge variant="secondary">disabled</Badge>
        )}
      </TableCell>
    </TableRow>
  );
}

function RuleForm({
  onClose,
  channels,
}: {
  onClose: () => void;
  channels: [string, string][];
}) {
  const create = useCreateRule();
  const [name, setName] = React.useState("");
  const [metric, setMetric] = React.useState("");
  const [comparator, setComparator] = React.useState<Comparator>("greater");
  const [threshold, setThreshold] = React.useState("100");
  const [windowSecs, setWindowSecs] = React.useState("300");
  const [severity, setSeverity] = React.useState("warning");
  const [enabled, setEnabled] = React.useState(true);
  const [channelIds, setChannelIds] = React.useState<Set<string>>(new Set());

  const toggleChannel = (id: string, on: boolean) =>
    setChannelIds((current) => {
      const next = new Set(current);
      if (on) next.add(id); else next.delete(id);
      return next;
    });

  const save = () => {
    const thresholdNum = Number(threshold);
    const windowNum = Number(windowSecs);
    if (!name.trim() || !metric.trim()) {
      toast.error("Name and metric are required");
      return;
    }
    if (!Number.isFinite(thresholdNum) || !Number.isFinite(windowNum) || windowNum <= 0) {
      toast.error("Threshold and a positive window in seconds are required");
      return;
    }
    create.mutate(
      {
        name: name.trim(),
        metric: metric.trim(),
        comparator,
        threshold: thresholdNum,
        window_secs: windowNum,
        severity,
        enabled,
        channel_ids: [...channelIds],
      },
      {
        onSuccess: () => {
          toast.success("Rule created");
          onClose();
        },
        onError: (e) => toast.error("Create failed", { description: formatError(e) }),
      },
    );
  };

  return (
    <Card>
      <CardHeader>
        <CardTitle className="text-base">New rule</CardTitle>
        <CardDescription>
          The comparator and threshold define the firing condition over `window_secs`.
          Channels are the delivery targets — none selected means a rule that fires to nobody.
        </CardDescription>
      </CardHeader>
      <CardContent className="grid gap-4 sm:grid-cols-2">
        <div className="space-y-1.5">
          <Label htmlFor="rule-name">Name</Label>
          <Input id="rule-name" value={name} onChange={(e) => setName(e.target.value)} placeholder="waf-block-spike" />
        </div>
        <div className="space-y-1.5">
          <Label htmlFor="rule-metric">Metric</Label>
          <Input id="rule-metric" value={metric} onChange={(e) => setMetric(e.target.value)} placeholder="waf.blocked" className="machine" />
        </div>
        <div className="space-y-1.5">
          <Label htmlFor="rule-comp">Comparator</Label>
          <Select value={comparator} onValueChange={(v) => setComparator(v as Comparator)}>
            <SelectTrigger id="rule-comp" className="w-full">
              <SelectValue />
            </SelectTrigger>
            <SelectContent>
              {COMPARATORS.map((c) => (
                <SelectItem key={c.value} value={c.value}>{c.label}</SelectItem>
              ))}
            </SelectContent>
          </Select>
        </div>
        <div className="grid grid-cols-2 gap-4">
          <div className="space-y-1.5">
            <Label htmlFor="rule-threshold">Threshold</Label>
            <Input id="rule-threshold" value={threshold} onChange={(e) => setThreshold(e.target.value)} inputMode="decimal" className="machine" />
          </div>
          <div className="space-y-1.5">
            <Label htmlFor="rule-window">Window (s)</Label>
            <Input id="rule-window" value={windowSecs} onChange={(e) => setWindowSecs(e.target.value)} inputMode="numeric" className="machine" />
          </div>
        </div>
        <div className="space-y-1.5">
          <Label htmlFor="rule-severity">Severity</Label>
          <Select value={severity} onValueChange={setSeverity}>
            <SelectTrigger id="rule-severity" className="w-full">
              <SelectValue />
            </SelectTrigger>
            <SelectContent>
              {SEVERITIES.map((s) => (
                <SelectItem key={s} value={s}>{s}</SelectItem>
              ))}
            </SelectContent>
          </Select>
        </div>
        <div className="space-y-1.5">
          <Label>Channels</Label>
          <div className="flex flex-wrap gap-x-4 gap-y-2 rounded-md border border-border p-3">
            {channels.length === 0 ? (
              <span className="text-xs text-muted-foreground">No channels yet — create one in the Channels tab.</span>
            ) : (
              channels.map(([id, label]) => (
                <label key={id} className="flex items-center gap-2 text-sm">
                  <Checkbox
                    checked={channelIds.has(id)}
                    onCheckedChange={(v) => toggleChannel(id, v === true)}
                  />
                  {label}
                </label>
              ))
            )}
          </div>
        </div>
        <div className="flex items-center gap-2">
          <Checkbox id="rule-enabled" checked={enabled} onCheckedChange={(v) => setEnabled(v === true)} />
          <Label htmlFor="rule-enabled" className="text-sm font-normal">Enabled</Label>
        </div>
        <div className="flex items-center gap-2 sm:col-span-2">
          <Button onClick={save} disabled={create.isPending}>
            {create.isPending ? "Creating…" : "Create rule"}
          </Button>
          <Button variant="ghost" onClick={onClose}>Cancel</Button>
        </div>
      </CardContent>
    </Card>
  );
}

// ---- history ---------------------------------------------------------------------------

function HistoryTab() {
  const history = useAlertHistory();

  if (history.isPending) return <LoadingCard />;
  if (history.isError) return <ErrorNote message={formatError(history.error)} />;
  if (history.data.unavailable) {
    return (
      <EmptyState
        title="Alert history unavailable"
        hint={history.data.message ?? "The connected server does not expose alert history."}
      />
    );
  }
  const list = history.data.data ?? [];

  return (
    <Card>
      <CardHeader>
        <CardTitle className="text-base">Delivery history</CardTitle>
        <CardDescription>
          Each firing of a rule. `delivered=false` is an alert that did not reach its
          channel — surfaced, not hidden, because it is the failure that matters most.
        </CardDescription>
      </CardHeader>
      <CardContent>
        {list.length === 0 ? (
          <EmptyState title="No alert history" hint="Rules that fire record a delivery attempt here." />
        ) : (
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>Rule</TableHead>
                <TableHead>Severity</TableHead>
                <TableHead>Observed</TableHead>
                <TableHead>Threshold</TableHead>
                <TableHead>Delivered</TableHead>
                <TableHead>At</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {list.map((entry) => (
                <HistoryRow key={entry.id} entry={entry} />
              ))}
            </TableBody>
          </Table>
        )}
      </CardContent>
    </Card>
  );
}

function HistoryRow({ entry }: { entry: AlertHistory }) {
  return (
    <TableRow className={entry.delivered ? undefined : "bg-destructive/5"}>
      <TableCell className="font-medium">{entry.rule_name}</TableCell>
      <TableCell>
        <Badge variant="outline">{entry.severity}</Badge>
      </TableCell>
      <TableCell className="machine text-xs">{entry.observed}</TableCell>
      <TableCell className="machine text-xs">{entry.threshold}</TableCell>
      <TableCell>
        {entry.delivered ? (
          <Badge variant="outline">delivered</Badge>
        ) : (
          <div className="space-y-0.5">
            <Badge variant="destructive">failed</Badge>
            {entry.delivery_error && (
              <div className="machine text-[11px] text-destructive">{entry.delivery_error}</div>
            )}
          </div>
        )}
      </TableCell>
      <TableCell className="text-xs text-muted-foreground">{fmtTime(entry.created_at)}</TableCell>
    </TableRow>
  );
}
