"use client";

import { usePathname } from "next/navigation";
import type { ReactNode } from "react";

/** Routes rendered without the console sidebar, top bar, or overlays (signed-out pages). */
export const isChromelessPath = (pathname: string | null) =>
  pathname === "/login" || Boolean(pathname?.startsWith("/login/"));

export default function AppChrome({
  children,
  sidebar,
  topbar,
  overlays,
}: {
  children: ReactNode;
  sidebar: ReactNode;
  topbar: ReactNode;
  overlays: ReactNode;
}) {
  const pathname = usePathname();
  if (isChromelessPath(pathname)) {
    return <div className="min-h-screen overflow-y-auto">{children}</div>;
  }
  return (
    <>
      <div className="flex h-screen max-w-full overflow-hidden">
        {sidebar}
        <div className="flex min-w-0 flex-1 flex-col overflow-x-hidden">
          {topbar}
          <main className="min-w-0 flex-1 overflow-x-hidden overflow-y-auto px-10 py-8 max-lg:px-6 max-md:px-4 max-md:py-5">
            <div className="mx-auto w-full max-w-[1480px]">{children}</div>
          </main>
        </div>
      </div>
      {overlays}
    </>
  );
}
