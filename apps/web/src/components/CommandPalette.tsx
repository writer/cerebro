"use client";

import { useRouter } from "next/navigation";
import { useEffect, useMemo, useRef, useState, type KeyboardEvent } from "react";

import { useCerebroAgent } from "@/components/agent/CerebroAgentProvider";
import { useCommandPalette } from "@/components/providers";
import { findSupportedGRCFramework, frameworkRouteSegment } from "@/lib/grc-frameworks";
import { LiveSearchCommand, useLiveSearchCommands } from "@/lib/live-search";
import { NavigationEntry, navigationEntries } from "@/lib/navigation";

type CommandSection = NavigationEntry["section"] | LiveSearchCommand["section"];

type Command = Omit<NavigationEntry, "section"> & {
  id: string;
  section: CommandSection;
  rank?: number;
  onRun?: () => void;
};

const commandText = (command: Command) =>
  [command.label, command.description, command.href, command.section, ...command.keywords].join(" ").toLowerCase();

const commandSectionLabel = (section: CommandSection) => {
  if (section === "Operator") return "Work";
  return section;
};

const searchCommands = (query: string, askGraph: (question: string) => void): Command[] => {
  const trimmed = query.trim();
  if (!trimmed) return [];
  const encoded = encodeURIComponent(trimmed);
  const frameworkMatch = findSupportedGRCFramework(trimmed);
  const riskInboxHref = frameworkMatch
    ? `/risk-inbox?framework=${encodeURIComponent(frameworkMatch.name)}`
    : `/risk-inbox?q=${encoded}`;
  const inventoryHref = frameworkMatch
    ? `/inventory?framework=${encodeURIComponent(frameworkMatch.name)}`
    : `/inventory?q=${encoded}`;
  const controlsHref = frameworkMatch
    ? `/controls?framework=${encodeURIComponent(frameworkMatch.name)}`
    : `/controls?control=${encoded}`;
  const frameworkHref = frameworkMatch
    ? `/frameworks/${frameworkRouteSegment(frameworkMatch)}`
    : "/frameworks";
  const controlsLabel = frameworkMatch
    ? frameworkMatch.lifecycle === "upcoming"
      ? `Plan for upcoming framework ${frameworkMatch.name}`
      : `Filter controls by ${frameworkMatch.name}`
    : `Filter controls by "${trimmed}"`;
  return [
    { id: "ask", label: `Ask: "${trimmed}"`, href: `/ask?q=${encoded}`, description: "Ask about risk, ownership, evidence, or affected assets.", section: "Operator", keywords: ["ask", "question", "owner", "evidence"], onRun: () => askGraph(trimmed) },
    { id: "search-risk-inbox", label: `Search risks for "${trimmed}"`, href: riskInboxHref, description: "Filter findings by title, framework, owner, entity, runtime, source, rule, or status.", section: "Operator", keywords: ["search", "findings", "risk", "framework"] },
    { id: "open-framework", label: frameworkMatch ? `Open ${frameworkMatch.name} framework tracking` : `Open framework catalog for "${trimmed}"`, href: frameworkHref, description: "Open maturity, gaps, planning, controls, findings, and exports.", section: "Operator", keywords: ["framework", "catalog", "maturity", "soc2"] },
    { id: "open-finding", label: `Open finding "${trimmed}"`, href: `/findings/${encoded}`, description: "Jump to a finding detail page by ID.", section: "Operator", keywords: ["finding", "detail"] },
    { id: "open-impact", label: `Open affected assets for "${trimmed}"`, href: `/impact?root_urn=${encoded}`, description: "Use as entity URN or graph root.", section: "Operator", keywords: ["impact", "graph"] },
    { id: "search-inventory", label: `Search inventory for "${trimmed}"`, href: inventoryHref, description: "Filter assets and resources by framework, label, type, owner, or URN.", section: "Operator", keywords: ["inventory", "assets", "resources", "framework", "scope"] },
    { id: "search-controls", label: controlsLabel, href: controlsHref, description: "Find framework names, control IDs, and mapped findings.", section: "Operator", keywords: ["controls", "framework"] },
    { id: "open-report", label: `Build audit packet for "${trimmed}"`, href: `/reports?finding_id=${encoded}`, description: "Use as a finding ID for an audit packet.", section: "Operator", keywords: ["reports", "audit"] },
    { id: "open-evidence", label: `Find evidence for "${trimmed}"`, href: `/evidence?finding_id=${encoded}`, description: "Use as a finding ID in the evidence register.", section: "Operator", keywords: ["evidence", "proof"] },
    { id: "open-connectors", label: `Filter connectors by "${trimmed}"`, href: `/connectors?q=${encoded}`, description: "Search connector sources and runtimes.", section: "Operator", keywords: ["connectors", "runtimes"] },
  ];
};

export default function CommandPalette() {
  const router = useRouter();
  const { openAgent } = useCerebroAgent();
  const { closeCommandPalette, isCommandPaletteOpen } = useCommandPalette();
  const [query, setQuery] = useState("");
  const [activeIndex, setActiveIndex] = useState(0);
  const inputRef = useRef<HTMLInputElement>(null);
  const liveSearch = useLiveSearchCommands(query, isCommandPaletteOpen);

  const askGraph = useMemo(
    () => (question: string) => openAgent({ question, autoSubmit: true }),
    [openAgent],
  );

  const commands = useMemo<Command[]>(() => {
    const base = navigationEntries.map((entry) => ({
      ...entry,
      id: `nav:${entry.href}`,
      section: entry.section,
    }));
    const q = query.trim().toLowerCase();
    const filtered = q ? base.filter((c) => commandText(c).includes(q)) : base;
    const generated = searchCommands(query, askGraph);
    const orderedNavigation = filtered
      .slice()
      .sort((left, right) => left.label.localeCompare(right.label));
    return [...generated, ...orderedNavigation, ...liveSearch.commands];
  }, [askGraph, liveSearch.commands, query]);

  useEffect(() => {
    if (!isCommandPaletteOpen) return;
    const timer = window.setTimeout(() => inputRef.current?.focus(), 0);
    return () => window.clearTimeout(timer);
  }, [isCommandPaletteOpen]);

  if (!isCommandPaletteOpen) return null;

  const safeActiveIndex = Math.min(activeIndex, Math.max(commands.length - 1, 0));

  const dismiss = () => {
    closeCommandPalette();
    setQuery("");
    setActiveIndex(0);
  };

  const run = (c: Command) => {
    if (c.onRun) {
      c.onRun();
    } else {
      router.push(c.href);
    }
    dismiss();
  };

  const onInputKeyDown = (event: KeyboardEvent<HTMLInputElement>) => {
    if (event.key === "Escape") { dismiss(); return; }
    if (event.key === "ArrowDown") { event.preventDefault(); setActiveIndex((i) => Math.min(i + 1, commands.length - 1)); return; }
    if (event.key === "ArrowUp") { event.preventDefault(); setActiveIndex((i) => Math.max(i - 1, 0)); return; }
    if (event.key === "Enter" && commands[safeActiveIndex]) { event.preventDefault(); run(commands[safeActiveIndex]); }
  };

  return (
    <div className="fixed inset-0 z-50 bg-stone-950/45 px-4 py-20 backdrop-blur-sm" onClick={dismiss}>
      <div className="surface-raised mx-auto max-w-2xl overflow-hidden" onClick={(e) => e.stopPropagation()}>
        <div className="flex items-center gap-3 border-b border-[color:var(--border)] px-4 py-3">
          <svg xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" strokeWidth={1.7} stroke="currentColor" className="h-5 w-5 text-[var(--text-muted)]">
            <path strokeLinecap="round" strokeLinejoin="round" d="m21 21-5.197-5.197m0 0A7.5 7.5 0 1 0 5.196 5.196a7.5 7.5 0 0 0 10.607 10.607Z" />
          </svg>
          <input
            ref={inputRef}
            value={query}
            onChange={(e) => { setQuery(e.target.value); setActiveIndex(0); }}
            onKeyDown={onInputKeyDown}
            placeholder="Search risks, controls, evidence, assets, sources..."
            className="flex-1 border-0 bg-transparent text-[15px] text-[var(--text-primary)] outline-none placeholder:text-[var(--text-muted)]"
          />
          <kbd className="rounded border border-[color:var(--border)] bg-[var(--surface-muted)] px-1.5 py-0.5 font-mono text-[11px] text-[var(--text-muted)]">ESC</kbd>
        </div>

        <div className="max-h-[28rem] overflow-y-auto p-1.5">
          {commands.length === 0 ? (
            <div className="flex items-center justify-center p-6 text-[13px] text-[var(--text-muted)]">No matching results.</div>
          ) : (
            commands.map((command, index) => (
              <button
                key={command.id}
                type="button"
                onMouseEnter={() => setActiveIndex(index)}
                onClick={() => run(command)}
                className={`flex w-full items-center justify-between gap-3 rounded-lg px-3 py-2.5 text-left transition ${
                  index === safeActiveIndex ? "bg-[var(--primary-soft)] text-[var(--text-primary)]" : "text-[var(--text-secondary)] hover:bg-[var(--surface-hover)]"
                }`}
              >
                <span>
                  <span className="block text-[13px] font-medium">{command.label}</span>
                  <span className="mt-0.5 block text-[12px] text-[var(--text-muted)]">{command.description}</span>
                </span>
                <span className="shrink-0 rounded-md bg-[var(--surface-muted)] px-2 py-0.5 text-[10px] font-medium uppercase tracking-wider text-[var(--text-muted)]">
                  {commandSectionLabel(command.section)}
                </span>
              </button>
            ))
          )}
        </div>

        {query.trim().length >= 2 && (
          <div className="border-t border-[color:var(--border)] px-4 py-2 text-[12px] text-[var(--text-muted)]">
            {liveSearch.loading && "Page actions are ready. Searching live data..."}
            {!liveSearch.loading && liveSearch.error && liveSearch.error}
            {!liveSearch.loading && !liveSearch.error && liveSearch.searched && `${liveSearch.commands.length} live result${liveSearch.commands.length === 1 ? "" : "s"}`}
          </div>
        )}

        <div className="flex items-center justify-between border-t border-[color:var(--border)] bg-[var(--surface-muted)] px-4 py-2 text-[11px] text-[var(--text-muted)]">
          <span>↑↓ navigate &middot; Enter to open &middot; Esc to close</span>
          <span>⌘K</span>
        </div>
      </div>
    </div>
  );
}
