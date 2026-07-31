"use client";

import Link from "next/link";
import { useEffect, useRef, useState } from "react";

import { useCerebroAgent } from "@/components/agent/CerebroAgentProvider";
import type { GRCGraph } from "@/lib/grc";
import {
  entityDetailHref,
  entityImpactHref,
  entityPivotQuestion,
  entityTypeLabel,
  resolveEntityPeek,
  type EntityTypeKey,
} from "@/lib/entity-chip";

type Props = {
  urn: string;
  /** Preferred chip label, e.g. the cited span text. Falls back to graph label, then URN tail. */
  label?: string;
  /** Turn graph, used to enrich the peek with label, type, and risk when the entity is present. */
  graph?: GRCGraph | null;
  className?: string;
};

const TYPE_DOT: Record<EntityTypeKey, string> = {
  finding: "bg-red-500",
  identity: "bg-blue-500",
  asset: "bg-emerald-500",
  package: "bg-amber-500",
  threat: "bg-pink-500",
  default: "bg-slate-400",
};

const RISK_BADGE: Record<string, string> = {
  critical: "border-[var(--severity-critical)] text-[var(--severity-critical)]",
  high: "border-[var(--severity-high)] text-[var(--severity-high)]",
  medium: "border-[var(--severity-medium)] text-[var(--severity-medium)]",
  low: "border-[var(--severity-low)] text-[var(--severity-low)]",
};

export default function EntityChip({ urn, label, graph, className }: Props) {
  const { openAgent } = useCerebroAgent();
  const [open, setOpen] = useState(false);
  const containerRef = useRef<HTMLSpanElement>(null);
  const peek = resolveEntityPeek(urn, { graph, label });

  useEffect(() => {
    if (!open) return undefined;
    const onPointerDown = (event: PointerEvent) => {
      if (!containerRef.current?.contains(event.target as Node)) {
        setOpen(false);
      }
    };
    const onKeyDown = (event: KeyboardEvent) => {
      if (event.key === "Escape") setOpen(false);
    };
    document.addEventListener("pointerdown", onPointerDown);
    document.addEventListener("keydown", onKeyDown);
    return () => {
      document.removeEventListener("pointerdown", onPointerDown);
      document.removeEventListener("keydown", onKeyDown);
    };
  }, [open]);

  const pivot = () => {
    setOpen(false);
    openAgent({
      question: entityPivotQuestion(urn),
      scopeUrn: urn,
      autoSubmit: true,
    });
  };

  return (
    <span ref={containerRef} className="relative inline-block align-baseline">
      <button
        type="button"
        data-urn={urn}
        aria-expanded={open}
        onClick={() => setOpen((current) => !current)}
        title={urn}
        className={`inline-flex items-center gap-1 rounded-md border border-[var(--primary)] bg-[var(--primary-soft)] px-1 font-mono text-[12px] text-[var(--primary)] transition hover:border-[var(--primary-hover)] hover:text-[var(--primary-hover)] ${className ?? ""}`}
      >
        <span aria-hidden className={`h-1.5 w-1.5 rounded-full ${TYPE_DOT[peek.typeKey]}`} />
        {peek.label}
      </button>
      {open && (
        <span className="absolute left-0 z-30 mt-1 block w-72 rounded-lg border border-slate-200 bg-white p-3 text-left shadow-lg">
          <span className="flex items-center justify-between gap-2">
            <span className="truncate text-[13px] font-semibold text-slate-900">{peek.label}</span>
            <span className="shrink-0 rounded-full border border-slate-200 bg-slate-50 px-2 py-0.5 text-[10px] font-semibold uppercase tracking-wide text-slate-500">
              {entityTypeLabel(peek.typeKey)}
            </span>
          </span>
          <span className="mt-1 block break-all font-mono text-[11px] text-slate-500">{urn}</span>
          <span className="mt-2 flex items-center gap-2">
            {peek.risk !== undefined ? (
              <span
                className={`rounded-full border bg-white px-2 py-0.5 text-[10px] font-semibold uppercase tracking-wide ${RISK_BADGE[peek.riskLevel] ?? "border-slate-200 text-slate-500"}`}
              >
                Risk {peek.riskLevel} · {peek.risk}
              </span>
            ) : (
              <span className="text-[11px] text-slate-400">
                {peek.source === "graph" ? "No risk score on this entity" : "Details from URN only"}
              </span>
            )}
          </span>
          <span className="mt-3 flex flex-wrap items-center gap-2 border-t border-slate-100 pt-3">
            <button
              type="button"
              onClick={pivot}
              className="rounded-md border border-[var(--primary)] bg-[var(--primary-soft)] px-2 py-1 text-[11px] font-semibold uppercase tracking-wide text-[var(--primary)] transition hover:border-[var(--primary-hover)] hover:text-[var(--primary-hover)]"
            >
              Pivot here
            </button>
            <Link
              href={entityImpactHref(urn)}
              onClick={() => setOpen(false)}
              className="rounded-md border border-slate-200 bg-white px-2 py-1 text-[11px] font-semibold uppercase tracking-wide text-slate-600 transition hover:border-slate-300 hover:text-slate-900"
            >
              Blast radius
            </Link>
            <Link
              href={entityDetailHref(urn)}
              onClick={() => setOpen(false)}
              className="rounded-md border border-slate-200 bg-white px-2 py-1 text-[11px] font-semibold uppercase tracking-wide text-slate-600 transition hover:border-slate-300 hover:text-slate-900"
            >
              Open
            </Link>
          </span>
        </span>
      )}
    </span>
  );
}
