"use client";

import { fetchCachedGRC } from "@/lib/grc-client";

const PREFETCH_FINDING_LIMIT = 2;
const PREFETCH_IDLE_TIMEOUT_MS = 5000;
const PREFETCH_FALLBACK_DELAY_MS = 2500;

type WindowWithIdleCallback = Window & {
  requestIdleCallback?: (callback: () => void, options?: { timeout?: number }) => number;
};

let prefetchScheduled = false;

export const prefetchTopFindings = (findingIDs: string[], apiKey: string | undefined) => {
  if (prefetchScheduled || findingIDs.length === 0) return;
  prefetchScheduled = true;
  const top = findingIDs.filter(Boolean).slice(0, PREFETCH_FINDING_LIMIT);
  const prefetch = () => {
    top.forEach((id) => {
      void fetchCachedGRC(`/grc/audit-packets/${encodeURIComponent(id)}`, apiKey);
    });
    prefetchScheduled = false;
  };

  const browserWindow = typeof window === "undefined" ? null : (window as WindowWithIdleCallback);
  if (browserWindow?.requestIdleCallback) {
    browserWindow.requestIdleCallback(prefetch, { timeout: PREFETCH_IDLE_TIMEOUT_MS });
    return;
  }
  setTimeout(prefetch, PREFETCH_FALLBACK_DELAY_MS);
};
