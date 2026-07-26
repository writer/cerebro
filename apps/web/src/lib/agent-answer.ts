import { z } from "zod";

import type { AskCitation, AskSummaryEvent } from "@/lib/ask";

const urnSchema = z.string().trim().regex(/^urn:[^\s]+$/).max(1_024);

export const agentAnswerSchema = z.object({
  markdown: z.string().trim().min(1).max(40_000),
  citations: z.array(urnSchema).max(40).default([]),
  evidence_gaps: z.array(z.string().trim().min(1).max(1_000)).max(12).default([]),
  confidence: z.enum(["high", "medium", "low"]).default("medium"),
});

export type AgentAnswer = z.infer<typeof agentAnswerSchema>;

export const collectUrns = (value: unknown, limit = 200): Set<string> => {
  const urns = new Set<string>();
  const seen = new Set<object>();
  const visit = (current: unknown, depth: number) => {
    if (urns.size >= limit || depth > 10 || current === null || current === undefined) return;
    if (typeof current === "string") {
      for (const match of current.matchAll(/\burn:[a-zA-Z0-9][^\s"'`,;)\]}]{0,1020}/g)) {
        urns.add(match[0]);
        if (urns.size >= limit) return;
      }
      return;
    }
    if (typeof current !== "object" || seen.has(current)) return;
    seen.add(current);
    if (Array.isArray(current)) {
      current.slice(0, 500).forEach((item) => visit(item, depth + 1));
      return;
    }
    Object.entries(current as Record<string, unknown>)
      .slice(0, 500)
      .forEach(([, item]) => visit(item, depth + 1));
  };
  visit(value, 0);
  return urns;
};

export const validateAgentAnswer = (
  output: unknown,
  observedUrns: ReadonlySet<string>,
): AskSummaryEvent => {
  const parsed = agentAnswerSchema.parse(output);
  const cited = [...new Set(parsed.citations)].filter((urn) => observedUrns.has(urn));
  let markdown = parsed.markdown;
  if (cited.length) {
    const missingFromText = cited.filter((urn) => !markdown.includes(urn));
    if (missingFromText.length) {
      markdown = `${markdown}\n\n### Sources\n${missingFromText.map((urn) => `- ${urn}`).join("\n")}`;
    }
  }
  if (parsed.evidence_gaps.length) {
    markdown = `${markdown}\n\n### Evidence gaps\n${parsed.evidence_gaps.map((gap) => `- ${gap}`).join("\n")}`;
  }
  const citations: AskCitation[] = cited
    .map((urn) => {
      const start = markdown.indexOf(urn);
      return start >= 0 ? { urn, span: [start, start + urn.length] as [number, number] } : null;
    })
    .filter((citation): citation is AskCitation => citation !== null);
  return {
    markdown,
    citations,
    evidence_gaps: parsed.evidence_gaps,
    confidence: parsed.confidence,
  };
};
