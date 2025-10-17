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
    <header className="flex h-16 items-center justify-between border-b border-slate-800 bg-slate-950/60 px-4 lg:px-8">
      <div>
        <h1 className="text-base font-semibold text-slate-100">Human-in-the-loop Control Center</h1>
        <p className="text-xs text-slate-400">Review agent actions, tune policies, and monitor runtime intelligence.</p>
      </div>
      <button
        type="button"
        className="inline-flex h-9 items-center rounded-md border border-slate-700 px-3 text-xs font-medium text-slate-300 transition hover:bg-slate-800"
        onClick={() => setTheme(theme === "light" ? "dark" : "light")}
      >
        {mounted ? (theme === "light" ? "Switch to dark" : "Switch to light") : "Toggle theme"}
      </button>
    </header>
  );
}
