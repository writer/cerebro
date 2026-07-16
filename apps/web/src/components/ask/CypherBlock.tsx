"use client";

import { useState } from "react";

import type { AskCypherEvent } from "@/lib/ask";

const CYPHER_KEYWORDS = new Set([
  "MATCH",
  "OPTIONAL",
  "WHERE",
  "WITH",
  "RETURN",
  "ORDER",
  "BY",
  "LIMIT",
  "SKIP",
  "UNWIND",
  "CALL",
  "AS",
  "AND",
  "OR",
  "NOT",
  "IN",
  "STARTS",
  "ENDS",
  "CONTAINS",
  "DISTINCT",
  "COUNT",
  "EXISTS",
  "UNION",
  "ALL",
  "TRUE",
  "FALSE",
  "NULL",
  "IS",
]);

const tokenize = (cypher: string) => {
  const tokens: Array<{ value: string; kind: "kw" | "str" | "num" | "op" | "text" }> = [];
  const regex = /(['"][^'"]*['"]|\d+(?:\.\d+)?|[A-Za-z_][A-Za-z0-9_]*|[{}()\[\]:,.;=<>!+\-*/]|\s+)/g;
  let match: RegExpExecArray | null;
  while ((match = regex.exec(cypher)) !== null) {
    const value = match[0];
    if (/^\s+$/.test(value)) {
      tokens.push({ value, kind: "text" });
    } else if (/^['"]/.test(value)) {
      tokens.push({ value, kind: "str" });
    } else if (/^\d/.test(value)) {
      tokens.push({ value, kind: "num" });
    } else if (CYPHER_KEYWORDS.has(value.toUpperCase())) {
      tokens.push({ value, kind: "kw" });
    } else if (/^[A-Za-z_]/.test(value)) {
      tokens.push({ value, kind: "text" });
    } else {
      tokens.push({ value, kind: "op" });
    }
  }
  return tokens;
};

const tokenClass = (kind: string) => {
  switch (kind) {
    case "kw":
      return "text-indigo-300 font-semibold";
    case "str":
      return "text-emerald-300";
    case "num":
      return "text-amber-300";
    case "op":
      return "text-slate-400";
    default:
      return "text-slate-100";
  }
};

export default function CypherBlock({ cypher, validator }: AskCypherEvent) {
  const [copied, setCopied] = useState(false);

  const copy = async () => {
    try {
      await navigator.clipboard.writeText(cypher);
      setCopied(true);
      window.setTimeout(() => setCopied(false), 1500);
    } catch {
      // ignore clipboard errors
    }
  };

  const tokens = tokenize(cypher);
  const validatorBadge = validator.ok
    ? "border-emerald-200 bg-emerald-50 text-emerald-700"
    : "border-rose-200 bg-rose-50 text-rose-700";

  return (
    <div className="rounded-lg border border-slate-200 bg-[#0f172a] shadow-sm">
      <div className="flex items-center justify-between gap-3 border-b border-slate-800/70 px-4 py-2 text-xs">
        <div className="flex items-center gap-2">
          <span className="text-[10px] uppercase tracking-[0.22em] text-slate-400">Cypher</span>
          <span className={`inline-flex rounded-full border px-2 py-0.5 text-[10px] font-semibold uppercase tracking-wide ${validatorBadge}`}>
            {validator.ok ? "Validated" : "Refused"}
          </span>
          {validator.reason && !validator.ok && (
            <span className="text-[11px] text-rose-200/80">{validator.reason}</span>
          )}
          {validator.code && !validator.ok && (
            <span className="rounded-full border border-rose-300/30 px-2 py-0.5 font-mono text-[10px] text-rose-100">
              {validator.code}
            </span>
          )}
        </div>
        <button
          type="button"
          onClick={() => void copy()}
          className="rounded-md border border-slate-700 bg-slate-800 px-2 py-1 text-[11px] font-semibold uppercase tracking-wide text-slate-200 transition hover:border-slate-500 hover:text-white"
        >
          {copied ? "Copied" : "Copy"}
        </button>
      </div>
      <pre className="overflow-x-auto px-4 py-3 font-mono text-[12px] leading-[18px] text-slate-100">
        <code>
          {tokens.map((token, index) => (
            <span key={index} className={tokenClass(token.kind)}>
              {token.value}
            </span>
          ))}
        </code>
      </pre>
      {validator.warnings?.length ? (
        <div className="border-t border-slate-800/70 px-4 py-3">
          <div className="text-[10px] uppercase tracking-[0.22em] text-amber-200/80">Validator warnings</div>
          <ul className="mt-2 space-y-1 text-[11px] text-amber-100/90">
            {validator.warnings.map((warning) => (
              <li key={warning}>{warning}</li>
            ))}
          </ul>
        </div>
      ) : null}
    </div>
  );
}
