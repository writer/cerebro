"use client";

import { useEffect } from "react";
import { usePathname, useSearchParams } from "next/navigation";

import { recordObservation } from "@/lib/telemetry";

export function PageViewObserver() {
  const pathname = usePathname();
  const searchParams = useSearchParams();
  const searchParamsString = searchParams?.toString() ?? "";

  useEffect(() => {
    if (!pathname) {
      return;
    }

    const context: Record<string, unknown> = {
      pathname,
    };

    if (searchParamsString) {
      context.search = searchParamsString;
    }

    void recordObservation({
      eventType: "page_view",
      component: "DashboardLayout",
      context,
    });
  }, [pathname, searchParamsString]);

  return null;
}
