"use client";

import { Plus, Trash2 } from "lucide-react";
import type { ReactNode } from "react";

import { newRowID, type NamedPercent } from "@/lib/asset-risk-model";

export const inputClass =
  "w-full rounded-md border border-[color:var(--border)] bg-[var(--surface)] px-2.5 py-1.5 text-[13px] text-[var(--text-primary)] outline-none focus:border-[color:var(--primary)] disabled:opacity-60";
export const labelClass = "text-[12px] font-medium text-[var(--text-secondary)]";
export const hintClass = "mt-1 text-[11px] leading-4 text-[var(--text-muted)]";
export const ghostButtonClass =
  "inline-flex items-center gap-1.5 rounded-md border border-[color:var(--border)] px-2.5 py-1 text-[12px] font-medium text-[var(--text-secondary)] transition hover:border-[color:var(--border-strong)] hover:text-[var(--text-primary)] disabled:cursor-not-allowed disabled:opacity-50";
export const iconButtonClass =
  "inline-flex h-7 w-7 items-center justify-center rounded-md text-[var(--text-muted)] transition hover:bg-rose-50 hover:text-rose-600 disabled:opacity-50 dark:hover:bg-rose-500/10";

const numberFrom = (raw: string) => (raw.trim() === "" ? Number.NaN : Number(raw));

const displayNumber = (value: number) => (Number.isFinite(value) ? String(value) : "");

export function Field({ label, hint, children }: { label: string; hint?: ReactNode; children: ReactNode }) {
  return (
    <label className="block">
      <span className={labelClass}>{label}</span>
      <div className="mt-1">{children}</div>
      {hint && <p className={hintClass}>{hint}</p>}
    </label>
  );
}

export function PercentField({
  label,
  hint,
  value,
  onChange,
  disabled,
}: {
  label: string;
  hint?: ReactNode;
  value: number;
  onChange: (value: number) => void;
  disabled?: boolean;
}) {
  return (
    <Field label={label} hint={hint}>
      <PercentInput value={value} onChange={onChange} disabled={disabled} ariaLabel={label} />
    </Field>
  );
}

export function PercentInput({ value, onChange, disabled, ariaLabel }: { value: number; onChange: (value: number) => void; disabled?: boolean; ariaLabel: string }) {
  return (
    <div className="relative">
      <input
        type="number"
        inputMode="decimal"
        min={0}
        max={100}
        step={0.5}
        value={displayNumber(value)}
        onChange={(event) => onChange(numberFrom(event.target.value))}
        disabled={disabled}
        aria-label={ariaLabel}
        className={`${inputClass} pr-7`}
      />
      <span className="pointer-events-none absolute right-2.5 top-1/2 -translate-y-1/2 text-[12px] text-[var(--text-muted)]">%</span>
    </div>
  );
}

export function NumberField({
  label,
  hint,
  value,
  onChange,
  step = 1,
  disabled,
}: {
  label: string;
  hint?: ReactNode;
  value: number;
  onChange: (value: number) => void;
  step?: number;
  disabled?: boolean;
}) {
  return (
    <Field label={label} hint={hint}>
      <input
        type="number"
        inputMode="decimal"
        step={step}
        value={displayNumber(value)}
        onChange={(event) => onChange(numberFrom(event.target.value))}
        disabled={disabled}
        className={inputClass}
      />
    </Field>
  );
}

export function ListField({
  label,
  hint,
  value,
  onChange,
  placeholder,
  disabled,
}: {
  label: string;
  hint?: ReactNode;
  value: string;
  onChange: (value: string) => void;
  placeholder?: string;
  disabled?: boolean;
}) {
  return (
    <Field label={label} hint={hint}>
      <input
        value={value}
        onChange={(event) => onChange(event.target.value)}
        placeholder={placeholder}
        disabled={disabled}
        spellCheck={false}
        className={`${inputClass} font-mono text-[12px]`}
      />
    </Field>
  );
}

export function NamedPercentTable({
  rows,
  onChange,
  nameLabel,
  valueLabel,
  addLabel,
  disabled,
}: {
  rows: NamedPercent[];
  onChange: (rows: NamedPercent[]) => void;
  nameLabel: string;
  valueLabel: string;
  addLabel: string;
  disabled?: boolean;
}) {
  const update = (id: string, patch: Partial<NamedPercent>) => onChange(rows.map((row) => (row.id === id ? { ...row, ...patch } : row)));
  return (
    <div>
      <div className="grid grid-cols-[1fr_7rem_2rem] gap-2 pb-1.5 text-[11px] font-medium uppercase tracking-wide text-[var(--text-muted)]">
        <span>{nameLabel}</span>
        <span>{valueLabel}</span>
        <span />
      </div>
      <div className="space-y-1.5">
        {rows.map((row) => (
          <div key={row.id} className="grid grid-cols-[1fr_7rem_2rem] items-center gap-2">
            <input
              value={row.name}
              onChange={(event) => update(row.id, { name: event.target.value })}
              aria-label={nameLabel}
              disabled={disabled}
              spellCheck={false}
              className={`${inputClass} font-mono text-[12px]`}
            />
            <PercentInput value={row.percent} onChange={(percent) => update(row.id, { percent })} disabled={disabled} ariaLabel={`${valueLabel} for ${row.name || "new row"}`} />
            <button type="button" className={iconButtonClass} onClick={() => onChange(rows.filter((item) => item.id !== row.id))} disabled={disabled} aria-label={`Remove ${row.name || "row"}`}>
              <Trash2 className="h-3.5 w-3.5" />
            </button>
          </div>
        ))}
      </div>
      <button type="button" className={`${ghostButtonClass} mt-2`} onClick={() => onChange([...rows, { id: newRowID(), name: "", percent: 50 }])} disabled={disabled}>
        <Plus className="h-3.5 w-3.5" />
        {addLabel}
      </button>
    </div>
  );
}
