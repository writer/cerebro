"use client";

import { useTheme } from "next-themes";
import { useEffect, useState } from "react";

export function TopBar() {
  const { theme, setTheme } = useTheme();
  const [mounted, setMounted] = useState(false);

  useEffect(() => {
    setMounted(true);
  }, []);

  return (
    <header className="flex h-16 items-center justify-between border-b border-zinc-900 bg-black/80 px-4 lg:px-8">
      <div>
        <h1 className="text-base font-semibold text-zinc-100">Human-in-the-loop Control Center</h1>
        <p className="text-xs text-zinc-500">Review agent actions, tune policies, and monitor runtime intelligence.</p>
      </div>
      <button
        type="button"
        className="inline-flex h-9 items-center rounded-md border border-zinc-800 px-3 text-xs font-medium text-zinc-300 transition hover:bg-zinc-900 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-zinc-100/60 focus-visible:ring-offset-2 focus-visible:ring-offset-zinc-950"
        onClick={() => setTheme(theme === "light" ? "dark" : "light")}
        aria-live="polite"
        aria-pressed={theme === "dark"}
      >
        {mounted ? (theme === "light" ? "Switch to dark" : "Switch to light") : "Toggle theme"}
      </button>
    </header>
  );
}
