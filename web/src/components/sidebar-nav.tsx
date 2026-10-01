import { cn } from "@/lib/utils";
import { LucideIcon } from "lucide-react";
import { Link } from "react-router-dom";
import {
  TrendingUpDown,
  ShieldCheck,
  Search,
  Gauge,
  Globe2,
  Shield,
  ListChecks,
  Bot,
  Activity,
  Users,
  UserCircle,
  History,
  Cog,
  Radio,
  AlertTriangle,
  DatabaseBackup,
  Network,
} from "lucide-react";
import {
  HOME,
  DASHBOARD,
  DOMAINS,
  UPSTREAMS,
  LISTENERS,
  SSL,
  WAF,
  ACL,
  ACCESS_LISTS,
  BOT_MANAGER,
  LOGS,
  ALERTS,
  PERFORMANCE,
  BACKUP,
  NODES,
  USERS,
  ACCOUNT,
  CONFIG_HISTORY,
  BASIC,
  SERVERS,
  LOCATIONS,
  UPSTREAMS_PAGE,
  PLUGINS,
  CERTIFICATES,
  STORAGES,
  CONFIG,
} from "@/routers.tsx";
import { useI18n } from "@/i18n";
import { Input } from "@/components/ui/input";
import React from "react";
import { useLocation } from "react-router-dom";
import {
  SidebarContent,
  SidebarGroup,
  SidebarGroupContent,
  SidebarMenu,
  SidebarMenuButton,
  SidebarMenuItem,
  SidebarMenuSub,
  SidebarMenuSubItem,
  SidebarMenuSubButton,
  useSidebar,
} from "@/components/ui/sidebar";
import {
  Popover,
  PopoverAnchor,
  PopoverContent,
} from "@/components/ui/popover";
import {
  Tooltip,
  TooltipContent,
  TooltipTrigger,
} from "@/components/ui/tooltip";

type NavGroup = "path" | "policy" | "system";

interface NavLink {
  title: string;
  label?: string;
  icon?: LucideIcon;
  path: string;
  variant: "default" | "ghost";
  group: NavGroup;
  children?: NavLink[];
}

/** Highlight the first case-insensitive match of `keyword` inside `text`. */
function HighlightMatch({ text, keyword }: { text: string; keyword: string }) {
  if (!keyword) {
    return <>{text}</>;
  }
  const lower = text.toLowerCase();
  const idx = lower.indexOf(keyword);
  if (idx < 0) {
    return <>{text}</>;
  }
  return (
    <>
      {text.slice(0, idx)}
      <mark className="rounded-sm bg-primary/20 px-0.5 text-inherit">
        {text.slice(idx, idx + keyword.length)}
      </mark>
      {text.slice(idx + keyword.length)}
    </>
  );
}

/** Square icon control for the collapsed rail (centered by SidebarMenu items-center). */
const CollapsedIconLink = React.forwardRef<
  HTMLAnchorElement,
  {
    to: string;
    title: string;
    isActive: boolean;
    children: React.ReactNode;
    className?: string;
    onMouseEnter?: React.MouseEventHandler;
    onMouseLeave?: React.MouseEventHandler;
    onKeyDown?: React.KeyboardEventHandler;
  }
>(function CollapsedIconLink(
  {
    to,
    title,
    isActive,
    children,
    className,
    onMouseEnter,
    onMouseLeave,
    onKeyDown,
  },
  ref,
) {
  return (
    <Link
      ref={ref}
      to={to}
      title={title}
      aria-label={title}
      onMouseEnter={onMouseEnter}
      onMouseLeave={onMouseLeave}
      onKeyDown={onKeyDown}
      className={cn(
        // Fixed square only — no w-full. Parent ul uses items-center when collapsed.
        "flex size-8 shrink-0 items-center justify-center rounded-md outline-none",
        "text-sidebar-foreground transition-colors",
        "hover:bg-sidebar-accent hover:text-sidebar-accent-foreground",
        "focus-visible:ring-2 focus-visible:ring-sidebar-ring",
        isActive &&
          "bg-sidebar-accent font-medium text-sidebar-accent-foreground",
        className,
      )}
    >
      {children}
    </Link>
  );
});

/** Flyout for a nav category when the sidebar is icon-collapsed. */
function CollapsedNavFlyout({
  item,
  isActive,
  currentName,
}: {
  item: NavLink;
  isActive: boolean;
  currentName: string | null;
}) {
  const [open, setOpen] = React.useState(false);
  const closeTimer = React.useRef<ReturnType<typeof setTimeout> | null>(null);
  const contentRef = React.useRef<HTMLDivElement>(null);
  const anchorRef = React.useRef<HTMLAnchorElement>(null);
  const openedByKey = React.useRef(false);
  const Icon = item.icon;

  const clearClose = () => {
    if (closeTimer.current) {
      clearTimeout(closeTimer.current);
      closeTimer.current = null;
    }
  };

  const openNow = () => {
    clearClose();
    setOpen(true);
  };

  const closeLater = () => {
    clearClose();
    closeTimer.current = setTimeout(() => setOpen(false), 120);
  };

  React.useEffect(() => {
    return () => clearClose();
  }, []);

  // Submenu keys, the same shape as a menubar: the rail icon is reachable by
  // Tab and Enter still follows it to the category list, ArrowRight/ArrowDown
  // opens the flyout and moves focus into it, Escape closes and comes back.
  //
  // Opening on plain focus was tried and dropped: two adjacent flyouts are two
  // Radix layers, and tabbing between them left both dismissed.
  const handleKeyDown = (e: React.KeyboardEvent) => {
    if (e.key !== "ArrowRight" && e.key !== "ArrowDown") {
      return;
    }
    e.preventDefault();
    openedByKey.current = true;
    openNow();
    // The content mounts on open, so focus it on the next frame.
    requestAnimationFrame(() => {
      contentRef.current?.querySelector<HTMLElement>("a")?.focus();
    });
  };

  const hasChildren = (item.children?.length ?? 0) > 0;

  // No children: tooltip with the category name.
  if (!hasChildren) {
    return (
      <Tooltip>
        <TooltipTrigger asChild>
          <CollapsedIconLink
            to={item.path}
            title={item.title}
            isActive={isActive}
          >
            {Icon && <Icon className="size-4 shrink-0" />}
          </CollapsedIconLink>
        </TooltipTrigger>
        <TooltipContent side="right" align="center" sideOffset={8}>
          {item.title}
        </TooltipContent>
      </Tooltip>
    );
  }

  // PopoverAnchor on the link itself — no extra inline-flex wrapper to break centering.
  return (
    <Popover open={open} onOpenChange={setOpen}>
      <PopoverAnchor asChild>
        <CollapsedIconLink
          ref={anchorRef}
          to={item.path}
          title={item.title}
          isActive={isActive}
          onMouseEnter={openNow}
          onMouseLeave={closeLater}
          onKeyDown={handleKeyDown}
        >
          {Icon && <Icon className="size-4 shrink-0" />}
        </CollapsedIconLink>
      </PopoverAnchor>
      <PopoverContent
        ref={contentRef}
        side="right"
        align="start"
        sideOffset={10}
        className="w-52 p-1.5"
        onOpenAutoFocus={(e) => e.preventDefault()}
        onCloseAutoFocus={(e) => {
          // Radix returns focus to its trigger, and this popover has only an
          // anchor. Put it back on the rail icon, but only when a key opened
          // the flyout — hovering away must not steal focus.
          e.preventDefault();
          if (openedByKey.current) {
            openedByKey.current = false;
            anchorRef.current?.focus();
          }
        }}
        onMouseEnter={openNow}
        onMouseLeave={closeLater}
        onFocusCapture={clearClose}
        onBlurCapture={closeLater}
      >
        <Link
          to={item.path}
          className={cn(
            "mb-1 flex items-center gap-2 rounded-md px-2 py-1.5 text-sm font-medium outline-none",
            "hover:bg-accent hover:text-accent-foreground",
            isActive && "bg-accent text-accent-foreground",
          )}
          onClick={() => setOpen(false)}
        >
          {Icon && <Icon className="size-4 shrink-0" />}
          <span className="truncate">{item.title}</span>
          {item.label && (
            <span className="ml-auto text-[11px] tabular-nums text-muted-foreground">
              {item.label}
            </span>
          )}
        </Link>
        <div className="max-h-72 space-y-0.5 overflow-y-auto border-t border-border pt-1">
          {item.children!.map((child) => {
            const selected = currentName === child.title;
            return (
              <Link
                key={child.title}
                to={child.path}
                className={cn(
                  "block truncate rounded-md px-2 py-1.5 text-sm outline-none",
                  "hover:bg-accent hover:text-accent-foreground",
                  selected && "bg-accent font-medium text-accent-foreground",
                )}
                onClick={() => setOpen(false)}
              >
                {child.title}
              </Link>
            );
          })}
        </div>
      </PopoverContent>
    </Popover>
  );
}

export function MainSidebar({
  className,
  sidebarOpen,
}: React.HTMLAttributes<HTMLDivElement> & {
  sidebarOpen: boolean;
}) {
  const navI18n = useI18n("nav");
  // The mobile sheet is always full width, so the icon-rail rendering driven by
  // the desktop collapse toggle would strand tiny icon squares at its left edge.
  const { isMobile, setOpenMobile } = useSidebar();
  const expanded = sidebarOpen || isMobile;
  const closeMobileNav = () => {
    if (isMobile) {
      setOpenMobile(false);
    }
  };
  const [keyword, setKeyword] = React.useState("");
  // The search box only renders while expanded. Applying a leftover keyword on
  // the collapsed rail silently empties every flyout with no visible box to
  // clear it, so ignore it there — the input is controlled, so collapsing and
  // expanding again brings both the text and the filter back together.
  // Normalise where it is used, not on the way in, so the box shows exactly
  // what was typed instead of eating case and trailing spaces mid-word.
  const activeKeyword = expanded ? keyword.trim().toLowerCase() : "";

  // Read straight from the router instead of mirroring it into state via an
  // effect: it is derived, so the copy only added a render behind the URL.
  const location = useLocation();
  const pathname = location.pathname;

  const getVariant = (path: string) => {
    if (path === `${pathname}${location.search}`) {
      return "default";
    }
    return "ghost";
  };

  // Dashboard is reached via the Pingap brand in the sidebar header, not a nav item.
  //
  // The product nav is the primary surface; the retained raw-config pages live under a
  // single "Advanced" collapsible rather than as peer routes, because there is one config
  // the operator means and two ways to edit it — the projected intent above, the raw
  // config below. Naming the second "Advanced" is what keeps the first from being
  // mistaken for a second opinion.
  const advanced: NavLink = {
    title: navI18n("advanced"),
    icon: Cog,
    variant: "ghost",
    path: BASIC,
    group: "system",
    children: [
      { title: navI18n("basic"), path: BASIC, variant: "ghost", group: "system" },
      { title: navI18n("server"), path: SERVERS, variant: "ghost", group: "system" },
      { title: navI18n("location"), path: LOCATIONS, variant: "ghost", group: "system" },
      { title: navI18n("upstream"), path: UPSTREAMS_PAGE, variant: "ghost", group: "system" },
      { title: navI18n("plugin"), path: PLUGINS, variant: "ghost", group: "system" },
      { title: navI18n("certificate"), path: CERTIFICATES, variant: "ghost", group: "system" },
      { title: navI18n("storage"), path: STORAGES, variant: "ghost", group: "system" },
      { title: "Config", path: CONFIG, variant: "ghost", group: "system" },
    ],
  };

  const items: NavLink[] = [
    { title: navI18n("dashboard"), icon: Gauge, variant: getVariant(DASHBOARD), path: DASHBOARD, group: "path" },
    { title: navI18n("domains"), icon: Globe2, variant: getVariant(DOMAINS), path: DOMAINS, group: "path" },
    { title: navI18n("upstream"), icon: TrendingUpDown, variant: getVariant(UPSTREAMS), path: UPSTREAMS, group: "path" },
    { title: navI18n("listeners"), icon: Radio, variant: getVariant(LISTENERS), path: LISTENERS, group: "path" },
    { title: navI18n("certificate"), icon: ShieldCheck, variant: getVariant(SSL), path: SSL, group: "path" },
    { title: navI18n("waf"), icon: Shield, variant: getVariant(WAF), path: WAF, group: "policy" },
    { title: navI18n("acl"), icon: ListChecks, variant: getVariant(ACL), path: ACL, group: "policy" },
    { title: navI18n("accessLists"), icon: ListChecks, variant: getVariant(ACCESS_LISTS), path: ACCESS_LISTS, group: "policy" },
    { title: navI18n("botManager"), icon: Bot, variant: getVariant(BOT_MANAGER), path: BOT_MANAGER, group: "policy" },
    { title: navI18n("logs"), icon: Activity, variant: getVariant(LOGS), path: LOGS, group: "system" },
    { title: navI18n("alerts"), icon: AlertTriangle, variant: getVariant(ALERTS), path: ALERTS, group: "system" },
    { title: navI18n("performance"), icon: TrendingUpDown, variant: getVariant(PERFORMANCE), path: PERFORMANCE, group: "system" },
    { title: navI18n("backup"), icon: DatabaseBackup, variant: getVariant(BACKUP), path: BACKUP, group: "system" },
    { title: navI18n("nodes"), icon: Network, variant: getVariant(NODES), path: NODES, group: "system" },
    { title: navI18n("users"), icon: Users, variant: getVariant(USERS), path: USERS, group: "system" },
    { title: navI18n("account"), icon: UserCircle, variant: getVariant(ACCOUNT), path: ACCOUNT, group: "system" },
    { title: navI18n("configHistory"), icon: History, variant: getVariant(CONFIG_HISTORY), path: CONFIG_HISTORY, group: "system" },
    advanced,
  ];

  const groups: { key: NavGroup; label: string }[] = [
    { key: "path", label: navI18n("groupPath") },
    { key: "policy", label: navI18n("groupPolicy") },
    { key: "system", label: navI18n("groupSystem") },
  ];

  const urlParams = new URLSearchParams(location.search);
  const currentName = urlParams.get("name");
  const matchCount = items.reduce(
    (total, item) => total + (item.children?.length ?? 0),
    0,
  );

  const renderMenuSub = (subItems: NavLink[] | undefined) => {
    if (!subItems || subItems.length == 0) {
      return <></>;
    }

    return (
      <SidebarMenuSub>
        {subItems.map((item) => {
          const isSelected = currentName === item.title;
          return (
            <SidebarMenuSubItem key={item.title}>
              <SidebarMenuSubButton isActive={isSelected} asChild>
                <Link
                  to={item.path}
                  className="w-full"
                  onClick={closeMobileNav}
                  aria-current={isSelected ? "page" : undefined}
                >
                  <span className="truncate">
                    <HighlightMatch text={item.title} keyword={activeKeyword} />
                  </span>
                </Link>
              </SidebarMenuSubButton>
            </SidebarMenuSubItem>
          );
        })}
      </SidebarMenuSub>
    );
  };

  return (
    <SidebarContent className={className}>
      <SidebarGroup>
        {expanded && (
          <div className="relative m-2 mt-0">
            <Input
              type="search"
              placeholder={navI18n("searchPlaceholder")}
              className="h-9 border-border bg-card/60 pl-8 focus-visible:bg-card"
              value={keyword}
              onChange={(e) => {
                setKeyword(e.target.value);
              }}
            />
            <Search className="pointer-events-none absolute left-2.5 top-1/2 size-3.5 -translate-y-1/2 select-none text-muted-foreground opacity-70" />
          </div>
        )}
        {expanded && activeKeyword && matchCount === 0 && (
          <p className="mx-2 mb-2 text-xs text-muted-foreground">
            {navI18n("searchEmpty")}
          </p>
        )}
        {groups.map((group, groupIdx) => {
          const groupItems = items.filter((item) => item.group === group.key);
          if (groupItems.length === 0) {
            return null;
          }
          return (
            <SidebarGroupContent key={group.key}>
              {expanded ? (
                <p
                  className={cn("eyebrow px-3 pb-1.5", groupIdx > 0 && "pt-4")}
                >
                  {group.label}
                </p>
              ) : (
                groupIdx > 0 && (
                  <div className="mx-auto my-2 h-px w-5 bg-sidebar-border" />
                )
              )}
              <SidebarMenu>
                {groupItems.map((item) => {
                  const isActive =
                    item.variant === "default" ||
                    (item.path !== HOME && pathname.startsWith(item.path));
                  return (
                    <SidebarMenuItem key={item.title}>
                      {expanded ? (
                        <>
                          <SidebarMenuButton
                            className="h-9 gap-2.5 px-3"
                            isActive={isActive}
                            asChild
                          >
                            <Link
                              to={item.path}
                              onClick={closeMobileNav}
                              aria-current={isActive ? "page" : undefined}
                            >
                              {item.icon && <item.icon />}
                              <span>{item.title}</span>
                              {item.label && (
                                <span
                                  className={cn(
                                    // Fixed min width so badges line up even when counts differ (0 vs 10).
                                    "machine ml-auto inline-flex h-5 min-w-5 shrink-0 items-center justify-center rounded-full bg-sidebar-accent px-1.5 text-[11px] text-muted-foreground",
                                    isActive &&
                                      "bg-sidebar-primary/15 text-sidebar-primary",
                                  )}
                                >
                                  {item.label}
                                </span>
                              )}
                            </Link>
                          </SidebarMenuButton>
                          {renderMenuSub(item.children)}
                        </>
                      ) : (
                        <CollapsedNavFlyout
                          item={item}
                          isActive={isActive}
                          currentName={currentName}
                        />
                      )}
                    </SidebarMenuItem>
                  );
                })}
              </SidebarMenu>
            </SidebarGroupContent>
          );
        })}
      </SidebarGroup>
    </SidebarContent>
  );
}
