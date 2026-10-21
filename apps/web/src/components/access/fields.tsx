"use client";

import { Check, Copy } from "lucide-react";
import { useState, type ReactNode } from "react";

export function Chip({ value }: { value: string }) {
  return (
    <span className="whitespace-nowrap rounded-md border border-[color:var(--border)] bg-[var(--surface-muted)] px-1.5 py-0.5 font-mono text-[11px] text-[var(--text-primary)]">
      {value}
    </span>
  );
}

export function Field({
  label,
  hint,
  error,
  children,
  htmlFor,
}: {
  label: string;
  hint?: ReactNode;
  error?: string;
  children: ReactNode;
  htmlFor?: string;
}) {
  return (
    <div className="space-y-1.5">
      <label htmlFor={htmlFor} className="block text-[12px] font-semibold text-[var(--text-secondary)]">
        {label}
      </label>
      {children}
      {error ? (
        <p className="text-[12px] text-red-700 dark:text-red-300" role="alert">{error}</p>
      ) : (
        hint && <p className="text-[12px] leading-5 text-[var(--text-muted)]">{hint}</p>
      )}
    </div>
  );
}

export const inputClass = "control-input h-9 w-full rounded-md px-3 text-[13px]";
export const textareaClass = "control-input w-full rounded-md px-3 py-2 font-mono text-[12px] leading-5";

export function CopyField({ label, value, hint }: { label: string; value: string; hint?: string }) {
  const [copied, setCopied] = useState(false);
  const copy = async () => {
    try {
      await navigator.clipboard.writeText(value);
      setCopied(true);
      window.setTimeout(() => setCopied(false), 1500);
    } catch {
      setCopied(false);
    }
  };
  return (
    <div className="space-y-1">
      <div className="text-[12px] font-semibold text-[var(--text-secondary)]">{label}</div>
      <div className="flex items-center gap-2 rounded-md border border-[color:var(--border)] bg-[var(--surface-muted)] px-3 py-1.5">
        <code className="min-w-0 flex-1 truncate font-mono text-[12px] text-[var(--text-primary)]" title={value}>
          {value || "—"}
        </code>
        <button
          type="button"
          onClick={() => void copy()}
          disabled={!value}
          className="inline-flex h-7 w-7 shrink-0 items-center justify-center rounded-md text-[var(--text-muted)] transition hover:bg-[var(--surface)] hover:text-[var(--text-primary)] disabled:opacity-40"
          aria-label={`Copy ${label}`}
          title={copied ? "Copied" : `Copy ${label}`}
        >
          {copied ? <Check className="h-3.5 w-3.5 text-emerald-600" /> : <Copy className="h-3.5 w-3.5" />}
        </button>
      </div>
      {hint && <p className="text-[12px] leading-5 text-[var(--text-muted)]">{hint}</p>}
    </div>
  );
}

export function Toggle({
  checked,
  onChange,
  label,
  disabled,
  description,
}: {
  checked: boolean;
  onChange: (value: boolean) => void;
  label: string;
  disabled?: boolean;
  description?: ReactNode;
}) {
  return (
    <div className="flex items-start justify-between gap-4">
      <div className="min-w-0">
        <div className="text-[13px] font-semibold text-[var(--text-primary)]">{label}</div>
        {description && <div className="mt-0.5 text-[12px] leading-5 text-[var(--text-muted)]">{description}</div>}
      </div>
      <button
        type="button"
        role="switch"
        aria-checked={checked}
        aria-label={label}
        disabled={disabled}
        onClick={() => onChange(!checked)}
        className={`relative inline-flex h-6 w-11 shrink-0 items-center rounded-full transition disabled:cursor-not-allowed disabled:opacity-50 ${
          checked ? "bg-[var(--primary)]" : "bg-[var(--border-strong)]"
        }`}
      >
        <span className={`inline-block h-5 w-5 rounded-full bg-white shadow transition ${checked ? "translate-x-5" : "translate-x-0.5"}`} />
      </button>
    </div>
  );
}

export function StatusDot({ tone, label }: { tone: "success" | "warning" | "neutral" | "danger"; label: string }) {
  const color = {
    success: "bg-emerald-50 text-emerald-700 ring-emerald-200 dark:bg-emerald-500/10 dark:text-emerald-200 dark:ring-emerald-500/30",
    warning: "bg-amber-50 text-amber-800 ring-amber-200 dark:bg-amber-500/10 dark:text-amber-100 dark:ring-amber-500/30",
    danger: "bg-red-50 text-red-700 ring-red-200 dark:bg-red-500/10 dark:text-red-200 dark:ring-red-500/30",
    neutral: "bg-[var(--surface-muted)] text-[var(--text-secondary)] ring-[color:var(--border)]",
  }[tone];
  const dot = { success: "bg-emerald-500", warning: "bg-amber-500", danger: "bg-red-500", neutral: "bg-[var(--text-muted)]" }[tone];
  return (
    <span className={`inline-flex items-center gap-1.5 whitespace-nowrap rounded-full px-2 py-0.5 text-[11px] font-semibold ring-1 ${color}`}>
      <span className={`h-1.5 w-1.5 rounded-full ${dot}`} />
      {label}
    </span>
  );
}

export function SegmentedTabs<T extends string>({
  tabs,
  active,
  onChange,
}: {
  tabs: { id: T; label: string; icon?: ReactNode; badge?: ReactNode }[];
  active: T;
  onChange: (tab: T) => void;
}) {
  return (
    <div role="tablist" className="inline-flex flex-wrap rounded-lg border border-[color:var(--border)] bg-[var(--surface-muted)] p-1">
      {tabs.map((tab) => {
        const selected = tab.id === active;
        return (
          <button
            key={tab.id}
            type="button"
            role="tab"
            aria-selected={selected}
            onClick={() => onChange(tab.id)}
            className={`inline-flex h-8 items-center gap-1.5 rounded-md px-3 text-[13px] font-semibold transition ${
              selected
                ? "bg-[var(--surface)] text-[var(--text-primary)] shadow-[var(--shadow-sm)]"
                : "text-[var(--text-secondary)] hover:text-[var(--text-primary)]"
            }`}
          >
            {tab.icon}
            {tab.label}
            {tab.badge}
          </button>
        );
      })}
    </div>
  );
}

export function shortDateTime(value?: string) {
  if (!value) return "Never";
  const date = new Date(value);
  return Number.isNaN(date.getTime())
    ? value
    : date.toLocaleString(undefined, { month: "short", day: "numeric", hour: "numeric", minute: "2-digit" });
}
