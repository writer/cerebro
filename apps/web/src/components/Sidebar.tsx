"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";
import { useMemo, useState, type ReactNode } from "react";

import { useSidebar } from "@/components/providers";
import { appVersionLabel } from "@/lib/app-version";
import { operatorNavLinks, utilityLinks, type NavigationEntry } from "@/lib/navigation";

const icons: Record<string, ReactNode> = {
  "/": <path strokeLinecap="round" strokeLinejoin="round" d="M3.75 6A2.25 2.25 0 0 1 6 3.75h2.25A2.25 2.25 0 0 1 10.5 6v2.25a2.25 2.25 0 0 1-2.25 2.25H6a2.25 2.25 0 0 1-2.25-2.25V6ZM3.75 15.75A2.25 2.25 0 0 1 6 13.5h2.25a2.25 2.25 0 0 1 2.25 2.25V18a2.25 2.25 0 0 1-2.25 2.25H6A2.25 2.25 0 0 1 3.75 18v-2.25ZM13.5 6a2.25 2.25 0 0 1 2.25-2.25H18A2.25 2.25 0 0 1 20.25 6v2.25A2.25 2.25 0 0 1 18 10.5h-2.25a2.25 2.25 0 0 1-2.25-2.25V6ZM13.5 15.75a2.25 2.25 0 0 1 2.25-2.25H18a2.25 2.25 0 0 1 2.25 2.25V18A2.25 2.25 0 0 1 18 20.25h-2.25a2.25 2.25 0 0 1-2.25-2.25v-2.25Z" />,
  "/risk-inbox": <path strokeLinecap="round" strokeLinejoin="round" d="M12 9v3.75m-9.303 3.376c-.866 1.5.217 3.374 1.948 3.374h14.71c1.73 0 2.813-1.874 1.948-3.374L13.949 3.378c-.866-1.5-3.032-1.5-3.898 0L2.697 16.126ZM12 15.75h.007v.008H12v-.008Z" />,
  "/grc": <path strokeLinecap="round" strokeLinejoin="round" d="M9 12.75 11.25 15 15 9.75M4.5 6.75h15M4.5 12h2.25m10.5 0h2.25M4.5 17.25h15M6.75 3.75h10.5A2.25 2.25 0 0 1 19.5 6v12A2.25 2.25 0 0 1 17.25 20.25H6.75A2.25 2.25 0 0 1 4.5 18V6A2.25 2.25 0 0 1 6.75 3.75Z" />,
  "/trends": <path strokeLinecap="round" strokeLinejoin="round" d="M2.25 18 9 11.25l4.306 4.306a11.95 11.95 0 0 1 5.814-5.518l2.74-1.22m0 0-5.94-2.281m5.94 2.28-2.28 5.941" />,
  "/trends/dashboards": <path strokeLinecap="round" strokeLinejoin="round" d="M3.75 5.25A2.25 2.25 0 0 1 6 3h12a2.25 2.25 0 0 1 2.25 2.25v13.5A2.25 2.25 0 0 1 18 21H6a2.25 2.25 0 0 1-2.25-2.25V5.25ZM7.5 8.25h3.75m-3.75 3h3.75m-3.75 3h3.75m3-6h2.25m-2.25 3h2.25m-2.25 3h2.25" />,
  "/ask": <path strokeLinecap="round" strokeLinejoin="round" d="m21 21-5.197-5.197m0 0A7.5 7.5 0 1 0 5.196 5.196a7.5 7.5 0 0 0 10.607 10.607Z" />,
  "/controls": <path strokeLinecap="round" strokeLinejoin="round" d="M9 12.75 11.25 15 15 9.75m-3-7.036A11.959 11.959 0 0 1 3.598 6 11.99 11.99 0 0 0 3 9.749c0 5.592 3.824 10.29 9 11.623 5.176-1.332 9-6.03 9-11.622 0-1.31-.21-2.571-.598-3.751h-.152c-3.196 0-6.1-1.248-8.25-3.285Z" />,
  "/policies": <path strokeLinecap="round" strokeLinejoin="round" d="M19.5 14.25v-2.625a3.375 3.375 0 0 0-3.375-3.375h-1.5A1.125 1.125 0 0 1 13.5 7.125v-1.5a3.375 3.375 0 0 0-3.375-3.375H6.75A2.25 2.25 0 0 0 4.5 4.5v15A2.25 2.25 0 0 0 6.75 21.75h10.5a2.25 2.25 0 0 0 2.25-2.25v-5.25ZM8.25 13.5h7.5M8.25 16.5h4.5M9 9.75l1.5 1.5 3-3" />,
  "/frameworks": <path strokeLinecap="round" strokeLinejoin="round" d="M3.75 6.75h16.5M3.75 12h16.5m-16.5 5.25h16.5M6.75 4.5v15m10.5-15v15" />,
  "/evidence": <path strokeLinecap="round" strokeLinejoin="round" d="M19.5 14.25v-2.625a3.375 3.375 0 0 0-3.375-3.375h-1.5A1.125 1.125 0 0 1 13.5 7.125v-1.5a3.375 3.375 0 0 0-3.375-3.375H8.25m0 12.75h7.5m-7.5 3H12M10.5 2.25H5.625c-.621 0-1.125.504-1.125 1.125v17.25c0 .621.504 1.125 1.125 1.125h12.75c.621 0 1.125-.504 1.125-1.125V11.25a9 9 0 0 0-9-9Z" />,
  "/questionnaires": <path strokeLinecap="round" strokeLinejoin="round" d="M9 12h6m-6 3h6m-8.25 6h10.5A2.25 2.25 0 0 0 19.5 18.75V5.25A2.25 2.25 0 0 0 17.25 3H6.75A2.25 2.25 0 0 0 4.5 5.25v13.5A2.25 2.25 0 0 0 6.75 21ZM8.25 7.5h.008v.008H8.25V7.5Zm2.25 0h5.25" />,
  "/inventory": <path strokeLinecap="round" strokeLinejoin="round" d="M3.75 5.25h16.5M3.75 9.75h16.5M3.75 14.25h16.5M3.75 18.75h16.5M7.5 3v18m9-18v18" />,
  "/vendors": <path strokeLinecap="round" strokeLinejoin="round" d="M3.75 21V8.25A2.25 2.25 0 0 1 6 6h4.5a2.25 2.25 0 0 1 2.25 2.25V21m-9 0h9m-9 0H2.25m10.5 0h9m-9 0V5.25A2.25 2.25 0 0 1 15 3h3a2.25 2.25 0 0 1 2.25 2.25V21m-12-10.5h1.5m-1.5 3h1.5m4.5-4.5h1.5m-1.5 3h1.5m-1.5 3h1.5" />,
  "/impact": <path strokeLinecap="round" strokeLinejoin="round" d="M7.5 14.25v2.25m3-4.5v4.5m3-6.75v6.75m3-9v9M6 20.25h12A2.25 2.25 0 0 0 20.25 18V6A2.25 2.25 0 0 0 18 3.75H6A2.25 2.25 0 0 0 3.75 6v12A2.25 2.25 0 0 0 6 20.25Z" />,
  "/explore": <path strokeLinecap="round" strokeLinejoin="round" d="M9 6.75V15m6-6v8.25m.503-13.498 4.875 2.437c.381.19.622.58.622 1.006v11.21c0 .765-.804 1.262-1.489.92l-4.508-2.254a1.125 1.125 0 0 0-1.006 0l-3.494 1.747a1.125 1.125 0 0 1-1.006 0l-4.875-2.437A1.125 1.125 0 0 1 3 15.37V4.16c0-.765.804-1.262 1.489-.92l4.508 2.254c.317.158.69.158 1.006 0l3.494-1.747a1.125 1.125 0 0 1 1.006 0Z" />,
  "/reports": <path strokeLinecap="round" strokeLinejoin="round" d="M3.75 9.776c.112-.017.227-.026.344-.026h15.812c.117 0 .232.009.344.026m-16.5 0a2.25 2.25 0 0 0-1.883 2.542l.857 6a2.25 2.25 0 0 0 2.227 1.932H19.05a2.25 2.25 0 0 0 2.227-1.932l.857-6a2.25 2.25 0 0 0-1.883-2.542m-16.5 0V6A2.25 2.25 0 0 1 6 3.75h3.879a1.5 1.5 0 0 1 1.06.44l2.122 2.12a1.5 1.5 0 0 0 1.06.44H18A2.25 2.25 0 0 1 20.25 9v.776" />,
  "/reports/audit-packages": <path strokeLinecap="round" strokeLinejoin="round" d="M9 12.75 11.25 15 15 9.75M6.75 3.75h10.5A2.25 2.25 0 0 1 19.5 6v12A2.25 2.25 0 0 1 17.25 20.25H6.75A2.25 2.25 0 0 1 4.5 18V6A2.25 2.25 0 0 1 6.75 3.75Zm0 4.5h10.5m-10.5 8.25h10.5" />,
  "/reports/schedules": <path strokeLinecap="round" strokeLinejoin="round" d="M3.75 9.776c.112-.017.227-.026.344-.026h15.812c.117 0 .232.009.344.026m-16.5 0a2.25 2.25 0 0 0-1.883 2.542l.857 6a2.25 2.25 0 0 0 2.227 1.932H19.05a2.25 2.25 0 0 0 2.227-1.932l.857-6a2.25 2.25 0 0 0-1.883-2.542m-16.5 0V6A2.25 2.25 0 0 1 6 3.75h3.879a1.5 1.5 0 0 1 1.06.44l2.122 2.12a1.5 1.5 0 0 0 1.06.44H18A2.25 2.25 0 0 1 20.25 9v.776" />,
  "/connectors": <path strokeLinecap="round" strokeLinejoin="round" d="M13.19 8.688a4.5 4.5 0 0 1 1.242 7.244l-4.5 4.5a4.5 4.5 0 0 1-6.364-6.364l1.757-1.757m13.35-.622 1.757-1.757a4.5 4.5 0 0 0-6.364-6.364l-4.5 4.5a4.5 4.5 0 0 0 1.242 7.244" />,
  "/credential-stores": <path strokeLinecap="round" strokeLinejoin="round" d="M15.75 10.5V6.75a3.75 3.75 0 1 0-7.5 0v3.75m-.75 11.25h9A2.25 2.25 0 0 0 18.75 19.5v-6.75A2.25 2.25 0 0 0 16.5 10.5h-9a2.25 2.25 0 0 0-2.25 2.25v6.75A2.25 2.25 0 0 0 7.5 21.75Z" />,
  "/connectors/activation": <path strokeLinecap="round" strokeLinejoin="round" d="M13.19 8.688a4.5 4.5 0 0 1 1.242 7.244l-4.5 4.5a4.5 4.5 0 0 1-6.364-6.364l1.757-1.757m13.35-.622 1.757-1.757a4.5 4.5 0 0 0-6.364-6.364l-4.5 4.5a4.5 4.5 0 0 0 1.242 7.244" />,
  "/controls/builder": <path strokeLinecap="round" strokeLinejoin="round" d="M9 12.75 11.25 15 15 9.75m-3-7.036A11.959 11.959 0 0 1 3.598 6 11.99 11.99 0 0 0 3 9.749c0 5.592 3.824 10.29 9 11.623 5.176-1.332 9-6.03 9-11.622 0-1.31-.21-2.571-.598-3.751h-.152c-3.196 0-6.1-1.248-8.25-3.285Z" />,
  "/developer": <path strokeLinecap="round" strokeLinejoin="round" d="M17.25 6.75 22.5 12l-5.25 5.25m-10.5 0L1.5 12l5.25-5.25m7.5-3-4.5 16.5" />,
};

type SidebarNavGroup = {
  href?: string;
  iconHref: string;
  id: string;
  label: string;
  links: NavigationEntry[];
};

const linksFor = (hrefs: string[]) =>
  hrefs.flatMap((href) => {
    const link = operatorNavLinks.find((entry) => entry.href === href);
    return link ? [link] : [];
  });

export const sidebarPrimaryLinks = linksFor(["/", "/risk-inbox"]);
export const sidebarSupportLinks = linksFor(["/ask"]);

export const sidebarNavGroups: SidebarNavGroup[] = [
  {
    id: "grc",
    label: "Compliance",
    href: "/grc",
    iconHref: "/grc",
    links: linksFor(["/controls", "/evidence", "/frameworks", "/reports"]),
  },
  {
    id: "assets",
    label: "Assets",
    iconHref: "/inventory",
    links: linksFor(["/inventory", "/vendors", "/impact", "/credential-stores"]),
  },
  {
    id: "sources",
    label: "Sources",
    iconHref: "/connectors",
    links: linksFor(["/connectors", "/explore"]),
  },
];

export const sidebarNavLinks = [
  ...sidebarPrimaryLinks,
  ...sidebarNavGroups.flatMap((group) => {
    const parent = group.href ? linksFor([group.href]) : [];
    return [...parent, ...group.links];
  }),
  ...sidebarSupportLinks,
  ...utilityLinks,
];

export function hasSidebarIcon(href: string) {
  return Boolean(icons[href]);
}

function matchesPathname(pathname: string, href: string) {
  return href === "/" ? pathname === href : pathname === href || pathname.startsWith(`${href}/`);
}

export function isSidebarLinkActive(pathname: string, href: string, links: { href: string }[] = sidebarNavLinks) {
  if (!matchesPathname(pathname, href)) return false;

  return !links.some(
    (link) => link.href !== href && link.href.length > href.length && matchesPathname(pathname, link.href),
  );
}

function NavIcon({ href }: { href: string }) {
  const d = icons[href];
  if (!d) return <span className="h-[18px] w-[18px]" />;
  return (
    <svg xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" strokeWidth={1.5} stroke="currentColor" className="h-[18px] w-[18px] shrink-0">
      {d}
    </svg>
  );
}

function CollapseIcon({ collapsed }: { collapsed: boolean }) {
  return (
    <svg xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" strokeWidth={1.5} stroke="currentColor" className="h-4 w-4">
      {collapsed
        ? <path strokeLinecap="round" strokeLinejoin="round" d="m8.25 4.5 7.5 7.5-7.5 7.5" />
        : <path strokeLinecap="round" strokeLinejoin="round" d="M15.75 19.5 8.25 12l7.5-7.5" />
      }
    </svg>
  );
}

export default function Sidebar() {
  const pathname = usePathname();
  const { collapsed, toggleSidebar } = useSidebar();

  const isActive = (href: string) => isSidebarLinkActive(pathname, href, sidebarNavLinks);
  const activeGroupIds = useMemo(
    () => new Set(sidebarNavGroups.filter((group) => {
      if (group.href && isSidebarLinkActive(pathname, group.href, sidebarNavLinks)) return true;
      return group.links.some((link) => isSidebarLinkActive(pathname, link.href, sidebarNavLinks));
    }).map((group) => group.id)),
    [pathname],
  );
  const [openGroups, setOpenGroups] = useState<Record<string, boolean>>({});

  const isGroupOpen = (group: SidebarNavGroup) => openGroups[group.id] ?? activeGroupIds.has(group.id);

  const renderLink = (link: { href: string; label: string }, nested = false) => {
    const active = isActive(link.href);
    return (
      <Link
        key={link.href}
        href={link.href}
        title={link.label}
        className={`relative flex items-center gap-2.5 rounded-lg px-2.5 py-[8px] text-[13px] font-medium transition ${
          active
            ? "bg-[var(--nav-active)] text-[var(--sidebar-active)] shadow-[var(--shadow-sm)] before:absolute before:left-0 before:top-2 before:bottom-2 before:w-0.5 before:rounded-full before:bg-[var(--sidebar-active)]"
            : "text-[var(--sidebar-fg)] hover:bg-[var(--sidebar-hover)] hover:text-[var(--text-primary)]"
        } ${nested && !collapsed ? "pl-8" : ""} ${collapsed ? "justify-center" : "max-md:justify-center"}`}
      >
        <NavIcon href={link.href} />
        {!collapsed && <span className="max-md:hidden">{link.label}</span>}
      </Link>
    );
  };

  const renderGroup = (group: SidebarNavGroup) => {
    const active = activeGroupIds.has(group.id);
    const open = isGroupOpen(group);
    const groupHref = group.href;
    if (collapsed && groupHref) {
      return renderLink({ href: groupHref, label: group.label });
    }
    return (
      <div key={group.id} className="space-y-0.5">
        <div
          className={`flex w-full items-center gap-1 rounded-lg px-2.5 py-[8px] text-[13px] font-medium transition ${
            active
              ? "bg-[var(--surface-muted)] text-[var(--text-primary)]"
              : "text-[var(--sidebar-fg)] hover:bg-[var(--sidebar-hover)] hover:text-[var(--text-primary)]"
          } max-md:justify-center`}
        >
          {groupHref ? (
            <Link href={groupHref} title={group.label} className="flex min-w-0 flex-1 items-center gap-2.5">
              <NavIcon href={group.iconHref} />
              <span className="max-md:hidden">{group.label}</span>
            </Link>
          ) : (
            <button
              type="button"
              onClick={() => setOpenGroups((current) => ({ ...current, [group.id]: !open }))}
              aria-expanded={open}
              title={group.label}
              className="flex min-w-0 flex-1 items-center gap-2.5"
            >
              <NavIcon href={group.iconHref} />
              <span className="max-md:hidden">{group.label}</span>
            </button>
          )}
          <button
            type="button"
            onClick={() => setOpenGroups((current) => ({ ...current, [group.id]: !open }))}
            aria-expanded={open}
            aria-label={`${open ? "Collapse" : "Expand"} ${group.label}`}
            className="ml-auto rounded p-0.5 text-[var(--sidebar-muted)] transition hover:bg-[var(--sidebar-hover)] hover:text-[var(--text-primary)] max-md:hidden"
          >
            <svg
              xmlns="http://www.w3.org/2000/svg"
              fill="none"
              viewBox="0 0 24 24"
              strokeWidth={1.7}
              stroke="currentColor"
              className={`ml-auto h-3.5 w-3.5 text-[var(--sidebar-muted)] transition max-md:hidden ${open ? "rotate-90" : ""}`}
            >
              <path strokeLinecap="round" strokeLinejoin="round" d="m8.25 4.5 7.5 7.5-7.5 7.5" />
            </svg>
          </button>
        </div>
        {open && <div className="space-y-0.5">{group.links.map((link) => renderLink(link, true))}</div>}
      </div>
    );
  };

  return (
    <aside className={`flex h-screen flex-col border-r border-[color:var(--border)] bg-[var(--sidebar-bg)] transition-all duration-200 ${collapsed ? "w-[60px]" : "w-[240px] max-md:w-[60px]"}`}>
      <div className={`flex items-center pt-5 pb-4 ${collapsed ? "justify-center px-2" : "px-5"}`}>
        <div className="flex h-8 w-8 shrink-0 items-center justify-center rounded-lg bg-[var(--text-primary)] text-[11px] font-bold text-[var(--surface)]">
          C
        </div>
        {!collapsed && (
          <div className="ml-2 max-md:hidden">
            <span className="block text-[15px] font-semibold text-[var(--text-primary)]">Cerebro</span>
          </div>
        )}
      </div>

      <nav className={`flex-1 space-y-0.5 overflow-y-auto ${collapsed ? "px-1.5" : "px-3 max-md:px-1.5"}`}>
        {sidebarPrimaryLinks.map((link) => renderLink(link))}
        {sidebarNavGroups.map(renderGroup)}
        {sidebarSupportLinks.map((link) => renderLink(link))}

        {collapsed && utilityLinks.length > 0 && <div className="my-3 border-t border-[color:var(--border)]" />}
        {!collapsed && utilityLinks.length > 0 && <div className="my-3 border-t border-[color:var(--border)]" />}
        {!collapsed && <div className="my-3 hidden border-t border-[color:var(--border)] max-md:block" />}
        {utilityLinks.map((link) => renderLink(link))}
      </nav>

      <div className="flex items-center justify-between border-t border-[color:var(--border)] px-3 py-2.5">
        {!collapsed && <div className="text-[11px] text-[var(--sidebar-muted)] max-md:hidden">{appVersionLabel}</div>}
        <button
          type="button"
          onClick={toggleSidebar}
          className={`rounded-md p-1.5 text-[var(--sidebar-muted)] transition hover:bg-[var(--sidebar-hover)] hover:text-[var(--text-primary)] ${collapsed ? "mx-auto" : "max-md:mx-auto"}`}
          title={collapsed ? "Expand sidebar" : "Collapse sidebar"}
        >
          <CollapseIcon collapsed={collapsed} />
        </button>
      </div>
    </aside>
  );
}
