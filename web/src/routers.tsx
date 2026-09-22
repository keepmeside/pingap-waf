import { createHashRouter } from "react-router-dom";
import { lazy, Suspense, type ReactNode } from "react";
import Root from "@/pages/Root";
import RouteError from "@/pages/RouteError";
import { LoadingPage } from "@/components/loading";
import { Dashboard, Domains, NewUpstreams, NewCertificates, Waf, Acl, AccessLists, BotManager, Logs, Alerts, Performance, Backup, Nodes, Users, Account, ConfigHistory } from "@/routes";

const Home = lazy(() => import("@/pages/Home"));
const Basic = lazy(() => import("@/pages/Basic"));
const Servers = lazy(() => import("@/pages/Servers"));
const Locations = lazy(() => import("@/pages/Locations"));
const Upstreams = lazy(() => import("@/pages/Upstreams"));
const Plugins = lazy(() => import("@/pages/Plugins"));
const Certificates = lazy(() => import("@/pages/Certificates"));
const Config = lazy(() => import("@/pages/Config"));
const Storages = lazy(() => import("@/pages/Storages"));
const Login = lazy(() => import("@/pages/Login"));

export const HOME = "/";
export const BASIC = "/basic";
export const SERVERS = "/servers";
export const LOCATIONS = "/locations";
export const UPSTREAMS = "/upstreams";
export const PLUGINS = "/plugins";
export const CERTIFICATES = "/certificates";
export const STORAGES = "/storages";
export const CONFIG = "/config";
export const LOGIN = "/login";
export const DASHBOARD = "/dashboard";
export const DOMAINS = "/domains";
export const WAF = "/waf";
export const ACL = "/acl";
export const LOGS = "/logs";
export const ACCOUNT = "/account";
export const ADVANCED = "/advanced";

function suspense(element: ReactNode) {
  return <Suspense fallback={<LoadingPage />}>{element}</Suspense>;
}

const pages = [
  { path: DASHBOARD, element: suspense(<Dashboard />) },
  { path: DOMAINS, element: suspense(<Domains />) },
  { path: "/upstreams", element: suspense(<NewUpstreams />) },
  { path: "/certificates", element: suspense(<NewCertificates />) },
  { path: WAF, element: suspense(<Waf />) },
  { path: ACL, element: suspense(<Acl />) },
  { path: "/access-lists", element: suspense(<AccessLists />) },
  { path: "/bot-manager", element: suspense(<BotManager />) },
  { path: LOGS, element: suspense(<Logs />) },
  { path: "/alerts", element: suspense(<Alerts />) },
  { path: "/performance", element: suspense(<Performance />) },
  { path: "/backup", element: suspense(<Backup />) },
  { path: "/nodes", element: suspense(<Nodes />) },
  { path: "/users", element: suspense(<Users />) },
  { path: ACCOUNT, element: suspense(<Account />) },
  { path: "/config-history", element: suspense(<ConfigHistory />) },
  { path: HOME, element: suspense(<Home />) },
  { path: BASIC, element: suspense(<Basic />) },
  { path: SERVERS, element: suspense(<Servers />) },
  { path: LOCATIONS, element: suspense(<Locations />) },
  { path: UPSTREAMS, element: suspense(<Upstreams />) },
  { path: PLUGINS, element: suspense(<Plugins />) },
  { path: CERTIFICATES, element: suspense(<Certificates />) },
  { path: CONFIG, element: suspense(<Config />) },
  { path: STORAGES, element: suspense(<Storages />) },
];

const router = createHashRouter([
  {
    element: <Root />,
    errorElement: <RouteError />,
    children: pages.map((page) => ({ ...page, errorElement: <RouteError /> })),
  },
  { path: LOGIN, element: suspense(<Login />), errorElement: <RouteError /> },
]);

export default router;
export function goToHome() { router.navigate(HOME); }
export function goToConfig() { router.navigate(CONFIG); }
export function goToLogin() { router.navigate(LOGIN); }
