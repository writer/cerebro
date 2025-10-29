"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";
import { cn } from "@/lib/utils";

const NAV_ITEMS = [
  { href: "/analytics/executive", label: "Security Overview" },
  { href: "/agents/review", label: "Review Queue" },
  { href: "/agents/notifications", label: "Notifications" },
  { href: "/agents/policy", label: "Policy Suggestions" },
  { href: "/agents/analytics", label: "Runtime Analytics" },
  { href: "/integrations", label: "Integrations" }
];

export function Sidebar() {
  const pathname = usePathname();

  return (
    <aside className="hidden lg:flex lg:w-64 lg:flex-col lg:border-r lg:border-zinc-900 bg-black/80">
      <div className="flex h-16 items-center border-b border-zinc-900 px-6">
        <span className="text-lg font-semibold text-zinc-100">Cerebro Ops Console</span>
      </div>
      <nav
        className="flex-1 space-y-1 px-4 py-6"
        aria-label="Agent console navigation"
      >
        {NAV_ITEMS.map((item) => {
          const active = pathname.startsWith(item.href);
          return (
            <Link
              key={item.href}
              href={item.href}
              className={cn(
                "block rounded-md px-3 py-2 text-sm font-medium transition focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-zinc-100/60 focus-visible:ring-offset-2 focus-visible:ring-offset-zinc-950",
                active
                  ? "bg-zinc-900 text-white"
                  : "text-zinc-500 hover:bg-zinc-900 hover:text-zinc-100"
              )}
              aria-current={active ? "page" : undefined}
            >
              {item.label}
            </Link>
          );
        })}
      </nav>
    </aside>
  );
}
