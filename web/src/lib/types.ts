// API DTO types, mirroring the `pingap-admin-api` views and the `pingap-controlplane`
// records they serialise. Field names match the wire exactly — serde `snake_case` —
// so a rename on either side is a compile break, not a silent `undefined` in the DOM.
//
// These are the contracts the route UIs bind to. Where the API deliberately omits a value
// (a TLS private key, a notification channel's `config`), the type carries the *fact* of
// it — `has_tls_key`, `"[redacted]"` — rather than a field a UI could mistake for the real
// thing.

export type Role = "admin" | "operator" | "viewer";
export type AuthLevel = "password_only" | "two_factor";

// ---- account -----------------------------------------------------------------------

export interface Profile {
  username: string;
  email: string;
  role: Role;
  auth_level: AuthLevel;
  is_active: boolean;
  created_at: number;
  /** What this session may do, derived server-side — the capability list the UI hides
   * controls against. Never longer than `authorize` would allow. */
  capabilities: Capability[];
}

export type Capability =
  | "view_config" | "view_logs" | "view_metrics" | "view_events" | "view_alerts"
  | "view_backups" | "view_nodes" | "view_users" | "view_own_sessions" | "view_raw_config"
  | "edit_domain" | "edit_upstream" | "edit_policy" | "edit_certificate" | "edit_alert"
  | "run_backup" | "restore_backup" | "manage_users" | "revoke_own_session"
  | "edit_own_profile" | "change_own_password" | "manage_own_second_factor"
  | "revoke_any_session" | "enrol_node" | "restart_process" | "write_raw_config";

export interface SessionView {
  id: string;
  auth_level: AuthLevel;
  ip?: string;
  user_agent?: string;
  created_at: number;
  expires_at: number;
  revoked_at?: number;
  usable: boolean;
  current: boolean;
}

export interface SecondFactorStatus {
  enrolled: boolean;
  enabled: boolean;
}

export interface SecondFactorSetup {
  secret: string;
  otpauth_uri: string;
}

// ---- users (admin) -----------------------------------------------------------------

export interface UserView {
  id: string;
  username: string;
  email: string;
  role: Role;
  is_active: boolean;
  created_at: number;
}

// ---- intent resources (projected) ---------------------------------------------------

export interface Backend {
  addr: string;
  weight?: number;
}

export interface Upstream {
  backends: Backend[];
  lb_algorithm?: string;
  health_check?: string;
  discovery?: string;
  tls_sni?: string;
  verify_cert?: boolean;
}

export interface TlsSettings {
  min_version?: string;
  max_version?: string;
  cipher_list?: string;
  ciphersuites?: string;
}

export interface Listener {
  addr: string;
  http2?: boolean;
  tls?: TlsSettings;
  access_log?: string;
  server_timing?: boolean;
}

export type PolicyBinding = { waf: string } | { acl: string } | { bot: string };

export interface Domain {
  hostnames: string[];
  path?: string;
  listener: string;
  upstream: string;
  priority?: number;
  notes?: string;
  client_max_body_size?: string;
  grpc_web: boolean;
  reverse_proxy_headers?: boolean;
  max_processing?: number;
  max_retries?: number;
  policies: PolicyBinding[];
}

/** A policy profile's config table, opaque to the projection — the owning plugin
 * interprets it. Keyed in `policies` by `category:profile`. */
export type PluginConf = Record<string, unknown>;

export interface CertificateView {
  domains: string[];
  tls_cert?: string;
  /** The fact of a key, never the key — named for what it is so a UI cannot bind to a
   * `tls_key` field and quietly receive an empty string it mistook for a redaction. */
  has_tls_key: boolean;
  is_default?: boolean;
  is_ca?: boolean;
  acme?: string;
  dns_challenge?: boolean;
  dns_provider?: string;
  dns_service_url?: string;
  buffer_days?: number;
  remark?: string;
}

// ---- WAF -----------------------------------------------------------------------------

export interface WafCategory {
  key: string;
  crs_group: number;
  crs_file: string;
  /** Response-side categories cannot deny — `redact` is the strongest mode they accept. */
  response_side: boolean;
  id_range: [number, number];
  modes: string[];
}

// ---- telemetry ------------------------------------------------------------------------

export interface WafEventRecord {
  id: string;
  node: string;
  domain: string;
  profile: string;
  rule_id?: number;
  category?: string;
  severity?: string;
  score: number;
  blocked: boolean;
  client_ip?: string;
  method?: string;
  uri?: string;
  created_at: number;
}

export interface PerformanceMetricRecord {
  id: string;
  node: string;
  metric: string;
  value: number;
  bucket_start: number;
  bucket_secs: number;
}

export interface DriftStatus {
  status: "unavailable" | "no_baseline" | "in_sync" | "detected";
  version_id?: string;
  expected_hash?: string;
  actual_hash?: string;
  differing?: string[];
}

export interface Dashboard {
  metrics: PerformanceMetricRecord[];
  drift: DriftStatus;
}

// ---- alerts ---------------------------------------------------------------------------

export interface NotificationChannel {
  id: string;
  name: string;
  kind: string;
  /** Always `"[redacted]"` on the wire — the channel's credentials never leave the store. */
  config: string;
  enabled: boolean;
  created_at: number;
}

/** Wire values of `pingap_controlplane::alerts::Comparison` (serde `snake_case`). These are
 * exactly the five the store's `alert_comparator_key` emits — a sixth would 400 at decode. */
export type Comparison =
  | "greater" | "greater_or_equal" | "less" | "less_or_equal" | "equal";

export interface AlertRule {
  id: string;
  name: string;
  metric: string;
  comparator: Comparison;
  threshold: number;
  window_secs: number;
  severity: string;
  enabled: boolean;
  channel_ids: string[];
}

export interface AlertRuleRecord {
  rule: AlertRule;
  created_at: number;
}

export interface AlertHistory {
  id: string;
  rule_id?: string;
  rule_name: string;
  severity: string;
  observed: number;
  threshold: number;
  delivered: boolean;
  delivery_error?: string;
  created_at: number;
}

// ---- config versions ------------------------------------------------------------------

export type ConfigStatus = "pending" | "applied" | "failed" | "superseded";

export interface VersionView {
  id: string;
  hash: string;
  status: ConfigStatus;
  actor_username: string;
  error?: string;
  created_at: number;
  settled_at?: number;
}

export interface RollbackResult {
  version: VersionView;
  rolled_back_to?: string;
}

// ---- activity -------------------------------------------------------------------------

export interface Activity {
  id: string;
  actor_id?: string;
  actor_username: string;
  action: string;
  target: string;
  config_version?: string;
  ip?: string;
  user_agent?: string;
  detail?: string;
  created_at: number;
}

// ---- nodes ------------------------------------------------------------------------------

export type NodeStatus = "healthy" | "stale" | "drifted" | "offline";

export interface NodeView {
  node_id: string;
  version: string;
  config_version?: string;
  config_hash?: string;
  last_seen: number;
  status: NodeStatus;
  cpu_millis?: number;
  memory_bytes?: number;
}

// ---- backup -----------------------------------------------------------------------------

export interface BackupScheduleRecord {
  id: string;
  name: string;
  cron: string;
  retain: number;
  enabled: boolean;
  created_at: number;
}

export interface BackupFileRecord {
  id: string;
  schedule_id?: string;
  path: string;
  size_bytes: number;
  sha256: string;
  created_at: number;
}

export interface BackupView {
  schedules: BackupScheduleRecord[];
  files: BackupFileRecord[];
}

export interface RestoreResult {
  staged: boolean;
  staged_config: string;
  staged_store: string;
  format_version: number;
}

// ---- system -----------------------------------------------------------------------------

export interface Health {
  status: "ok";
  store: "available" | "unavailable";
}
