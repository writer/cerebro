"use client";

import Link from "next/link";
import { useMemo, useState } from "react";

import { looksLikeUrn, shortUrn } from "@/lib/ask";
import { pluralize } from "@/lib/format";

type Row = Record<string, unknown>;

type Props = {
  rows: Row[];
  execMs: number;
};

type SortState = {
  key: string;
  direction: "asc" | "desc";
};

const compareValues = (left: unknown, right: unknown) => {
  if (left == null && right == null) return 0;
  if (left == null) return 1;
  if (right == null) return -1;
  if (typeof left === "number" && typeof right === "number") return left - right;
  if (typeof left === "boolean" && typeof right === "boolean") {
    return Number(left) - Number(right);
  }
  return String(left).localeCompare(String(right));
};

const cellLabel = (value: unknown): string => {
  if (value == null) return "—";
  if (typeof value === "number") return value.toLocaleString();
  if (typeof value === "boolean") return value ? "true" : "false";
  if (typeof value === "object") {
    try {
      return JSON.stringify(value);
    } catch {
      return String(value);
    }
  }
  return String(value);
};

export default function RowsTable({ rows, execMs }: Props) {
  const columns = useMemo(() => {
    const set = new Set<string>();
    rows.forEach((row) => Object.keys(row).forEach((key) => set.add(key)));
    return Array.from(set);
  }, [rows]);

  const [sort, setSort] = useState<SortState | null>(null);

  const sortedRows = useMemo(() => {
    if (!sort) return rows;
    const direction = sort.direction === "asc" ? 1 : -1;
    return [...rows].sort((left, right) => direction * compareValues(left[sort.key], right[sort.key]));
  }, [rows, sort]);

  const toggleSort = (key: string) => {
    setSort((current) => {
      if (current?.key !== key) return { key, direction: "asc" };
      return { key, direction: current.direction === "asc" ? "desc" : "asc" };
    });
  };

  const copyJSON = async () => {
    await navigator.clipboard.writeText(JSON.stringify(sortedRows, null, 2)).catch(() => undefined);
  };

  const copyCSV = async () => {
    const escape = (value: unknown) => `"${cellLabel(value).replaceAll('"', '""')}"`;
    const csv = [
      columns.map(escape).join(","),
      ...sortedRows.map((row) => columns.map((column) => escape(row[column])).join(",")),
    ].join("\n");
    await navigator.clipboard.writeText(csv).catch(() => undefined);
  };

  if (rows.length === 0) {
    return (
      <div className="rounded-lg border border-dashed border-slate-300 bg-slate-50 p-4 text-[13px] text-slate-500">
        Query ran in {execMs} ms but returned no rows.
      </div>
    );
  }

  return (
    <div className="rounded-lg border border-slate-200 bg-white shadow-sm">
      <div className="flex items-center justify-between gap-3 border-b border-slate-200 px-4 py-2 text-xs text-slate-500">
        <span>{rows.length.toLocaleString()} {pluralize(rows.length, "row")} · {columns.length} {pluralize(columns.length, "col")}</span>
        <div className="flex items-center gap-2">
          <button
            type="button"
            onClick={() => void copyCSV()}
            className="rounded border border-slate-200 px-2 py-0.5 text-[11px] font-semibold uppercase tracking-wide text-slate-500 transition hover:border-slate-300 hover:text-slate-900"
          >
            Copy CSV
          </button>
          <button
            type="button"
            onClick={() => void copyJSON()}
            className="rounded border border-slate-200 px-2 py-0.5 text-[11px] font-semibold uppercase tracking-wide text-slate-500 transition hover:border-slate-300 hover:text-slate-900"
          >
            Copy JSON
          </button>
          <span>{execMs} ms</span>
        </div>
      </div>
      <div className="overflow-x-auto">
        <table className="min-w-full divide-y divide-slate-200 text-xs">
          <thead className="bg-slate-50/80">
            <tr>
              {columns.map((column) => {
                const active = sort?.key === column;
                return (
                  <th
                    key={column}
                    onClick={() => toggleSort(column)}
                    className={`cursor-pointer select-none px-3 py-2 text-left text-[11px] font-semibold uppercase tracking-wider ${
                      active ? "text-indigo-700" : "text-slate-500"
                    }`}
                  >
                    <span>{column}</span>
                    {active && (
                      <span className="ml-1 text-[10px]">{sort?.direction === "asc" ? "↑" : "↓"}</span>
                    )}
                  </th>
                );
              })}
            </tr>
          </thead>
          <tbody className="divide-y divide-slate-100 bg-white text-slate-900">
            {sortedRows.slice(0, 200).map((row, rowIndex) => (
              <tr key={rowIndex} className="hover:bg-slate-50">
                {columns.map((column) => {
                  const value = row[column];
                  return (
                    <td key={column} className="px-3 py-2 align-top">
                      <details>
                        <summary className="cursor-pointer list-none">
                          {looksLikeUrn(value) ? (
                            <Link
                              href={`/impact?root_urn=${encodeURIComponent(value)}`}
                              className="font-mono text-[11px] text-indigo-700 hover:text-indigo-900"
                            >
                              {shortUrn(value)}
                            </Link>
                          ) : (
                            <span className="break-words">{cellLabel(value)}</span>
                          )}
                        </summary>
                        <pre className="mt-2 max-w-md overflow-x-auto rounded border border-slate-200 bg-slate-50 p-2 font-mono text-[10px] text-slate-700">
                          {JSON.stringify(value, null, 2)}
                        </pre>
                      </details>
                    </td>
                  );
                })}
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      {sortedRows.length > 200 && (
        <div className="border-t border-slate-200 bg-slate-50/80 px-4 py-2 text-[11px] text-slate-500">
          Showing first 200 of {sortedRows.length.toLocaleString()} rows.
        </div>
      )}
    </div>
  );
}
