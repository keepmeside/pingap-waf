import { AdminRoutePage } from "@/components/admin-route-page";

const route = (title: string, endpoint: string, path: string) => () => <AdminRoutePage title={title} endpoint={endpoint} path={path} />;

export const Dashboard = route("Dashboard", "dashboard", "/dashboard");
export const Domains = route("Domains", "domains", "/domains");
export const NewUpstreams = route("Upstreams", "upstreams", "/upstreams");
export const NewCertificates = route("Certificates", "ssl", "/ssl");
export const Waf = route("WAF", "waf", "/waf/categories");
export const Acl = route("ACL", "policies", "/policies");
export const AccessLists = route("Access Lists", "access-lists", "/access-lists");
export const BotManager = route("Bot Manager", "bot-manager", "/bot-manager");
export const Logs = route("Logs", "logs", "/logs/waf-events");
export const Alerts = route("Alerts", "alerts", "/alerts");
export const Performance = route("Performance", "performance", "/performance");
export const Backup = route("Backup", "backup", "/backup");
export const Nodes = route("Nodes", "nodes", "/nodes");
export const Users = route("Users", "users", "/users");
export const Account = route("Account", "account", "/account");
export const ConfigHistory = route("Config History", "config-history", "/config-versions");
