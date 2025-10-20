"use client";

import { useEffect } from "react";

type DashboardErrorProps = {
  error: Error & { digest?: string };
  reset: () => void;
};

export default function DashboardError({ error, reset }: DashboardErrorProps) {
  useEffect(() => {
    console.error("Dashboard route error", error);
  }, [error]);

  return (
    <div className="rounded-md border border-red-900/40 bg-red-950/40 p-6 text-sm text-red-200">
      <h2 className="text-base font-semibold text-red-100">Unable to load dashboard</h2>
      <p className="mt-2 text-red-200/80">{error.message || "An unexpected error occurred."}</p>
      <button
        type="button"
        className="mt-4 inline-flex items-center rounded-md border border-red-500/40 px-3 py-1 text-xs font-semibold text-red-100 transition hover:bg-red-900/50 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-red-300"
        onClick={() => reset()}
      >
        Try again
      </button>
    </div>
  );
}
