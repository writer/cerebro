"use client";

import { useCerebroAgent } from "@/components/agent/CerebroAgentProvider";
import type { AskAgentContext, AskAgentContextChip } from "@/lib/ask";

type Props = {
  question: string;
  scopeUrn?: string;
  context?: AskAgentContext;
  chips?: AskAgentContextChip[];
  variant?: "link" | "button";
  className?: string;
  title?: string;
  children?: React.ReactNode;
};

const baseLink =
  "inline-flex items-center gap-1 text-[11px] font-semibold uppercase tracking-wide text-indigo-700 hover:text-indigo-900";

const baseButton =
  "inline-flex items-center gap-1 rounded-md border border-indigo-300 bg-indigo-50 px-3 py-2 text-xs font-semibold uppercase tracking-wide text-indigo-700 transition hover:border-indigo-400 hover:bg-indigo-100";

export default function AskAboutLink({
  question,
  scopeUrn,
  context,
  chips,
  variant = "link",
  className,
  title,
  children,
}: Props) {
  const { openAgent } = useCerebroAgent();
  const cls =
    className ?? (variant === "button" ? baseButton : baseLink);
  const askContext = {
    ...(context ?? {}),
    scopeUrn: scopeUrn ?? context?.scopeUrn,
    entityUrn: context?.entityUrn ?? scopeUrn ?? context?.scopeUrn,
    chips: [
      ...(context?.chips ?? []),
      ...(chips ?? []),
      scopeUrn ? { label: "Scope", value: scopeUrn } : null,
    ].filter(Boolean) as AskAgentContextChip[],
  };
  return (
    <button
      type="button"
      className={cls}
      title={title ?? "Ask about this context"}
      onClick={() =>
        openAgent({
          question,
          scopeUrn,
          context: Object.keys(askContext).length > 0 ? askContext : undefined,
          autoSubmit: true,
        })
      }
    >
      {children ?? "Ask about this"}
    </button>
  );
}
