import type { ModelSettings } from "@openai/agents";

import type { AskAgentContext, AskAgentMode } from "@/lib/ask";

export type AgentImageDetail = "low" | "auto";
export type AgentProfile = "fast" | "balanced" | "deep";
export type AgentToolPack = "finding" | "risk" | "asset" | "source" | "general";

export type AgentModelRoute = {
  profile: AgentProfile;
  model: string;
  selectionReason: string;
  maxTurns: number;
  imageDetail: AgentImageDetail;
  toolPack: AgentToolPack;
  modelSettings: ModelSettings;
};

type AgentRouteInput = {
  question: string;
  mode?: AskAgentMode;
  context?: AskAgentContext;
  scopeUrn?: string;
  imageCount?: number;
};

const DEEP_QUESTION = /\b(compare|correlat|explain why|investigat|root cause|attack path|blast radius|across|prove|validate|trace|remediat)\b/i;
const FAST_QUESTION = /^(what is|who owns|show|get|list|status|is |are |when )/i;

export const selectAgentModelRoute = (
  input: AgentRouteInput,
  modelOverride = "",
): AgentModelRoute => {
  const toolPack = selectToolPack(input.context, input.scopeUrn);
  const explicitDeep = input.mode === "deep";
  const contextualDepth =
    Boolean(input.imageCount) ||
    Boolean(input.context?.findingId) ||
    DEEP_QUESTION.test(input.question);
  const profile: AgentProfile = explicitDeep
    ? "deep"
    : contextualDepth
      ? "balanced"
      : FAST_QUESTION.test(input.question.trim())
        ? "fast"
        : "balanced";
  const settings = profileSettings(profile);
  const selectionReason = explicitDeep
    ? "user_selected_deep"
    : input.imageCount
      ? "image_analysis"
      : input.context?.findingId
        ? "finding_context"
        : DEEP_QUESTION.test(input.question)
          ? "multi_step_question"
          : profile === "fast"
            ? "direct_lookup"
            : "standard_question";

  return {
    profile,
    model: modelOverride.trim() || settings.model,
    selectionReason: modelOverride.trim() ? `${selectionReason}:configured_model` : selectionReason,
    maxTurns: settings.maxTurns,
    imageDetail: profile === "fast" ? "low" : "auto",
    toolPack,
    modelSettings: {
      reasoning: {
        context: profile === "fast" ? "current_turn" : "all_turns",
        effort: settings.reasoningEffort,
        summary: "concise",
      },
      text: { verbosity: settings.verbosity },
      parallelToolCalls: profile !== "fast",
      maxTokens: settings.maxTokens,
      store: true,
      truncation: "auto",
      contextManagement: [{ type: "compaction", compactThreshold: 48_000 }],
    },
  };
};

const profileSettings = (profile: AgentProfile): {
  model: string;
  reasoningEffort: "minimal" | "medium" | "high";
  verbosity: "low" | "medium";
  maxTurns: number;
  maxTokens: number;
} => {
  if (profile === "deep") {
    return {
      model: "gpt-5.6-sol",
      reasoningEffort: "high",
      verbosity: "medium",
      maxTurns: 8,
      maxTokens: 8_000,
    };
  }
  if (profile === "fast") {
    return {
      model: "gpt-5.6-luna",
      reasoningEffort: "minimal",
      verbosity: "low",
      maxTurns: 3,
      maxTokens: 2_500,
    };
  }
  return {
    model: "gpt-5.6-terra",
    reasoningEffort: "medium",
    verbosity: "low",
    maxTurns: 5,
    maxTokens: 5_000,
  };
};

const selectToolPack = (
  context: AskAgentContext | undefined,
  scopeUrn: string | undefined,
): AgentToolPack => {
  const route = context?.route?.toLowerCase() ?? "";
  if (context?.findingId || route.includes("finding")) return "finding";
  if (route.includes("risk") || route.includes("dashboard") || route.includes("inbox")) return "risk";
  if (scopeUrn || context?.scopeUrn || context?.entityUrn || context?.resourceUrn || route.includes("inventory")) {
    return "asset";
  }
  if (route.includes("source") || route.includes("connector") || route.includes("runtime")) return "source";
  return "general";
};

export const AGENT_TOOL_PACKS: Record<AgentToolPack, string[]> = {
  finding: [
    "cerebro.investigation.context",
    "cerebro.findings.get",
    "cerebro.evidence.list",
    "cerebro.evidence.get",
    "cerebro.graph.neighborhood",
    "cerebro.findings.action.propose",
  ],
  risk: [
    "cerebro.risk.summary",
    "cerebro.findings.search",
    "cerebro.findings.get",
    "cerebro.risk.actions.list",
    "cerebro.risk.actions.explain",
    "cerebro.graph.impact",
    "cerebro.graph.paths",
  ],
  asset: [
    "cerebro.assets.get",
    "cerebro.assets.search",
    "cerebro.graph.neighborhood",
    "cerebro.graph.impact",
    "cerebro.graph.paths",
    "cerebro.graph.facts.list",
    "cerebro.graph.facts.explain",
    "cerebro.evidence.get",
  ],
  source: [
    "cerebro.sources.health",
    "cerebro.sources.list",
    "cerebro.sources.check",
    "cerebro.sources.read",
    "cerebro.source_runtimes.list",
    "cerebro.runtimes.status",
    "cerebro.source_runtimes.refresh.propose",
  ],
  general: [
    "cerebro.risk.summary",
    "cerebro.findings.search",
    "cerebro.assets.search",
    "cerebro.investigation.context",
    "cerebro.sources.health",
    "cerebro.graph.reason",
  ],
};
