"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";
import { cn } from "@/lib/utils";

const NAV_ITEMS = [
  { href: "/agents/review", label: "Review Queue" },
  { href: "/agents/notifications", label: "Notifications" },
  { href: "/agents/policy", label: "Policy Suggestions" },
  { href: "/agents/analytics", label: "Runtime Analytics" }
];

export function Sidebar() {
  const pathname = usePathname();

  return (
    <aside className="hidden lg:flex lg:w-64 lg:flex-col lg:border-r lg:border-slate-800 bg-slate-950/60">
      <div className="flex h-16 items-center border-b border-slate-800 px-6">
        <span className="text-lg font-semibold">Cerebro Ops Console</span>
      </div>
      <nav className="flex-1 space-y-1 px-4 py-6">
        {NAV_ITEMS.map((item) => {
          const active = pathname.startsWith(item.href);
          return (
            <Link
              key={item.href}
              href={item.href}
              className={cn(
                "block rounded-md px-3 py-2 text-sm font-medium transition",
                active
                  ? "bg-slate-800 text-slate-50"
                  : "text-slate-300 hover:bg-slate-900 hover:text-white"
              )}
            >
              {item.label}
            </Link>
          );
        })}
      </nav>
    </aside>
  );
}
