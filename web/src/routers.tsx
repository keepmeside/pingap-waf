import { createHashRouter } from "react-router-dom";
import { lazy, Suspense, type ReactNode } from "react";
import Root from "@/pages/Root";
import RouteError from "@/pages/RouteError";
import { LoadingPage } from "@/components/loading";

// ---- the product routes -------------------------------------------------------------
//
// The sixteen authenticated routes operators work in, each a purpose-built page over the
// admin API. Lazy-loaded so the bundle a session first downloads stays small.
const Dashboard = lazy(() => import("@/routes/dashboard"));
const Domains = lazy(() => import("@/routes/domains"));
const Upstreams = lazy(() => import("@/routes/upstreams"));
const Listeners = lazy(() => import("@/routes/listeners"));
const Ssl = lazy(() => import("@/routes/ssl"));
const Waf = lazy(() => import("@/routes/waf"));
const Acl = lazy(() => import("@/routes/acl"));
const AccessLists = lazy(() => import("@/routes/access-lists"));
const BotManager = lazy(() => import("@/routes/bot-manager"));
const Logs = lazy(() => import("@/routes/logs"));
const Alerts = lazy(() => import("@/routes/alerts"));
const Performance = lazy(() => import("@/routes/performance"));
const Backup = lazy(() => import("@/routes/backup"));
const Nodes = lazy(() => import("@/routes/nodes"));
const Users = lazy(() => import("@/routes/users"));
const Account = lazy(() => import("@/routes/account"));
const ConfigHistory = lazy(() => import("@/routes/config-history"));

// ---- the retained raw-config surface --------------------------------------------------
//
// pingap's original pages, grouped under "Advanced" in the nav: the escape hatch that
// edits the config as the config rather than as the projected intent. Nothing about them
// changes — they keep their own fetching and their own paths.
const Home = lazy(() => import("@/pages/Home"));
const Basic = lazy(() => import("@/pages/Basic"));
const Servers = lazy(() => import("@/pages/Servers"));
const Locations = lazy(() => import("@/pages/Locations"));
const UpstreamsPage = lazy(() => import("@/pages/Upstreams"));
const Plugins = lazy(() => import("@/pages/Plugins"));
const Certificates = lazy(() => import("@/pages/Certificates"));
const Config = lazy(() => import("@/pages/Config"));
const Storages = lazy(() => import("@/pages/Storages"));
const Login = lazy(() => import("@/pages/Login"));

// ---- product paths --------------------------------------------------------------------
export const DASHBOARD = "/dashboard";
export const DOMAINS = "/domains";
export const UPSTREAMS = "/upstreams";
export const LISTENERS = "/listeners";
export const SSL = "/ssl";
export const WAF = "/waf";
export const ACL = "/acl";
export const ACCESS_LISTS = "/access-lists";
export const BOT_MANAGER = "/bot-manager";
export const LOGS = "/logs";
export const ALERTS = "/alerts";
export const PERFORMANCE = "/performance";
export const BACKUP = "/backup";
export const NODES = "/nodes";
export const USERS = "/users";
export const ACCOUNT = "/account";
export const CONFIG_HISTORY = "/config-history";
export const LOGIN = "/login";

// ---- retained paths ---------------------------------------------------------------------
// The advanced (raw-config) paths the vendored pages and sidebar navigate by. These are
// the constants those pages import for their own `?name=` links, so they keep their
// original top-level values — the product's `upstreams` lives on a distinct path below.
export const HOME = "/";
export const BASIC = "/basic";
export const SERVERS = "/servers";
export const LOCATIONS = "/locations";
// The vendored upstreams page stays at its own path; the product owns `/upstreams`.
export const UPSTREAMS_PAGE = "/upstreams-config";
export const PLUGINS = "/plugins";
export const CERTIFICATES = "/certificates";
export const STORAGES = "/storages";
export const CONFIG = "/config";
export const HISTORY = "/history";

function suspense(element: ReactNode) {
  return <Suspense fallback={<LoadingPage />}>{element}</Suspense>;
}

// The product routes — the primary operator surface.
const product = [
  { path: DASHBOARD, element: suspense(<Dashboard />) },
  { path: DOMAINS, element: suspense(<Domains />) },
  { path: UPSTREAMS, element: suspense(<Upstreams />) },
  { path: LISTENERS, element: suspense(<Listeners />) },
  { path: SSL, element: suspense(<Ssl />) },
  { path: WAF, element: suspense(<Waf />) },
  { path: ACL, element: suspense(<Acl />) },
  { path: ACCESS_LISTS, element: suspense(<AccessLists />) },
  { path: BOT_MANAGER, element: suspense(<BotManager />) },
  { path: LOGS, element: suspense(<Logs />) },
  { path: ALERTS, element: suspense(<Alerts />) },
  { path: PERFORMANCE, element: suspense(<Performance />) },
  { path: BACKUP, element: suspense(<Backup />) },
  { path: NODES, element: suspense(<Nodes />) },
  { path: USERS, element: suspense(<Users />) },
  { path: ACCOUNT, element: suspense(<Account />) },
  { path: CONFIG_HISTORY, element: suspense(<ConfigHistory />) },
];

// The retained raw-config pages. `HOME` renders the legacy dashboard so the root lands
// on the working pingap home; the product dashboard lives at `/dashboard`. The vendored
// `upstreams` page is at `/upstreams-config` because the product owns `/upstreams`.
const advanced = [
  { path: HOME, element: suspense(<Home />) },
  { path: BASIC, element: suspense(<Basic />) },
  { path: SERVERS, element: suspense(<Servers />) },
  { path: LOCATIONS, element: suspense(<Locations />) },
  { path: UPSTREAMS_PAGE, element: suspense(<UpstreamsPage />) },
  { path: PLUGINS, element: suspense(<Plugins />) },
  { path: CERTIFICATES, element: suspense(<Certificates />) },
  { path: STORAGES, element: suspense(<Storages />) },
  { path: CONFIG, element: suspense(<Config />) },
];

const router = createHashRouter([
  {
    element: <Root />,
    errorElement: <RouteError />,
    children: [...product, ...advanced].map((page) => ({
      ...page,
      errorElement: <RouteError />,
    })),
  },
  { path: LOGIN, element: suspense(<Login />), errorElement: <RouteError /> },
]);

export default router;
export function goToHome() { router.navigate(DASHBOARD); }
export function goToConfig() { router.navigate(CONFIG); }
export function goToLogin() { router.navigate(LOGIN); }
