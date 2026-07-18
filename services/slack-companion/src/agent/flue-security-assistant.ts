import { defineAgent, defineTool, type ThinkingLevel, type ToolDefinition } from "@flue/runtime";
import { local } from "@flue/runtime/node";
import { InMemorySessionStore, initializeRootHarness, resolveModel, type FlueContextConfig } from "@flue/runtime/internal";
import type { AgentTool, AgentToolResult } from "@earendil-works/pi-agent-core";
import * as v from "valibot";
import { containsAssistantProtocolLeak } from "../slack/format.js";
import {
  resolveSpecialistAssignments,
  specialistAssignmentPrompt,
  specialistAssignmentSchema,
  specialistExecutionFields,
  specialistWorkSchema,
  type SpecialistWork,
} from "./specialist-team.js";
import { selectExecutionToolPack } from "./tool-packs.js";
import { boundedToolDetails } from "./tools/tool-result.js";

const executionLaneSchema = v.picklist(["ignore", "converse", "continue", "lookup", "investigate", "act"]);
const domainLensSchema = v.picklist(["identity", "delivery", "cloud", "detection", "compliance", "incident", "self", "general"]);
const teammateDecisionSchema = v.object({
  required: v.boolean(),
  question: v.optional(v.string()),
  reason: v.optional(v.string()),
});
const teammateSchema = v.object({
  objective: v.optional(v.string()),
  desired_outcome: v.optional(v.string()),
  resolved_scope: v.optional(v.array(v.string()), []),
  scope_assumptions: v.optional(v.array(v.string()), []),
  commitments: v.optional(v.array(v.object({
    id: v.pipe(v.string(), v.minLength(1)),
    summary: v.pipe(v.string(), v.minLength(1)),
    status: v.picklist(["planned", "in_progress", "completed", "blocked", "cancelled"]),
    next_action: v.optional(v.string()),
    blocker: v.optional(v.string()),
    artifact_refs: v.optional(v.array(v.string()), []),
    goal_id: v.optional(v.string()),
    goal_status: v.optional(v.picklist(["active", "waiting", "approval_needed", "blocked", "paused", "completed", "cancelled"])),
    acceptance_criteria: v.optional(v.array(v.string()), []),
    next_wake_at: v.optional(v.string()),
    verification: v.optional(v.string()),
  })), []),
  open_loops: v.optional(v.array(v.object({
    id: v.pipe(v.string(), v.minLength(1)),
    summary: v.pipe(v.string(), v.minLength(1)),
    owner: v.picklist(["cerebro", "user", "external"]),
    next_action: v.optional(v.string()),
    blocked_by: v.optional(v.string()),
  })), []),
  user_decision: v.optional(teammateDecisionSchema),
});
const claimEvidenceBindingSchema = v.object({
  claim_id: v.pipe(v.string(), v.minLength(1)),
  claim_text: v.pipe(v.string(), v.minLength(1)),
  temporal_scope: v.optional(v.picklist(["historical", "current"]), "current"),
  evidence_ids: v.optional(v.array(v.string()), []),
  memory_ids: v.optional(v.array(v.string()), []),
});

export const flueSecurityAssistantResultSchema = v.object({
  response_disposition: v.optional(v.picklist(["respond", "ignore"])),
  disposition_reason: v.optional(v.string()),
  execution_lane: v.optional(executionLaneSchema),
  final_ready: v.optional(v.boolean()),
  presentation_ready: v.optional(v.boolean()),
  answer: v.pipe(v.string(), v.minLength(1)),
  messages: v.optional(v.array(v.string()), []),
  reply_messages: v.optional(v.array(v.string()), []),
  reaction: v.optional(v.string()),
  key_points: v.optional(v.array(v.string()), []),
  keyPoints: v.optional(v.array(v.string()), []),
  evidence: v.optional(v.array(v.string()), []),
  actions_taken: v.optional(v.array(v.string()), []),
  actionsTaken: v.optional(v.array(v.string()), []),
  next_actions: v.optional(v.array(v.string()), []),
  nextActions: v.optional(v.array(v.string()), []),
  research: v.optional(v.array(v.string()), []),
  claim_evidence: v.optional(v.array(claimEvidenceBindingSchema)),
  claimEvidence: v.optional(v.array(claimEvidenceBindingSchema)),
  memory_updates: v.optional(v.array(memoryUpdateSchema()), []),
  memoryUpdates: v.optional(v.array(memoryUpdateSchema()), []),
  specialist_work: v.optional(v.array(specialistWorkSchema), []),
  teammate: v.optional(teammateSchema),
});

export const flueSecurityAssistantResearchPlanSchema = v.object({
  response_disposition: v.optional(v.picklist(["respond", "ignore"])),
  disposition_reason: v.optional(v.string()),
  user_intent: v.pipe(v.string(), v.minLength(1)),
  desired_outcome: v.optional(v.string()),
  resolved_scope: v.optional(v.array(v.string()), []),
  scope_assumptions: v.optional(v.array(v.string()), []),
  user_decision: v.optional(teammateDecisionSchema),
  execution_lane: v.optional(executionLaneSchema, "investigate"),
  execution_style: v.optional(v.picklist(["direct", "code"]), "direct"),
  domain_lenses: v.optional(v.array(domainLensSchema), ["general"]),
  selected_tools: v.optional(v.array(v.string()), []),
  direct_response: v.optional(v.string()),
  claims: v.optional(v.array(v.object({
    id: v.pipe(v.string(), v.minLength(1)),
    claim: v.pipe(v.string(), v.minLength(1)),
    required: v.optional(v.boolean(), true),
    source_candidates: v.optional(v.array(v.string()), []),
  })), []),
  research_plan: v.optional(v.array(v.string()), []),
  user_visible_work: v.optional(v.array(v.string()), []),
  required_sources: v.optional(v.array(v.string()), []),
  missing_context_questions: v.optional(v.array(v.string()), []),
  specialists: v.optional(v.array(specialistAssignmentSchema), []),
});

export type FlueSecurityAssistantResult = v.InferOutput<typeof flueSecurityAssistantResultSchema>;
export type FlueSecurityAssistantResearchPlan = v.InferOutput<typeof flueSecurityAssistantResearchPlanSchema>;
export type FlueSecurityAssistantResearchPlanInput = Omit<FlueSecurityAssistantResearchPlan, "execution_lane" | "execution_style" | "domain_lenses" | "selected_tools" | "resolved_scope" | "scope_assumptions" | "specialists">
  & Partial<Pick<FlueSecurityAssistantResearchPlan, "execution_lane" | "execution_style" | "domain_lenses" | "selected_tools" | "resolved_scope" | "scope_assumptions" | "specialists">>;

export interface FlueSecurityAssistantResearchAugmentation {
  distributed_work: Array<{
    packet_id: string;
    status: "completed" | "blocked";
    findings: string[];
    recommendations: string[];
    blockers: string[];
    source_results: Array<{ tool_name: string; status: "completed" | "failed"; evidence_receipt?: string }>;
  }>;
}

export interface FlueToolAdaptationOptions {
  beforeToolCall?: (toolName: string) => Promise<void> | void;
  afterToolCall?: (toolName: string, isError: boolean) => Promise<void> | void;
  toolCallId?: () => string;
}

export interface FlueSecurityAssistantCompleteInput {
  systemPrompt: string;
  userPrompt: string;
  model: string;
  thinkingLevel: ThinkingLevel;
  executionModel?: string;
  executionThinkingLevel?: ThinkingLevel;
  tools: ToolDefinition[];
  codeTools?: ToolDefinition[];
  timeoutMs: number;
  allowIgnore?: boolean;
  onResearchPlan?: (plan: FlueSecurityAssistantResearchPlanInput) => Promise<FlueSecurityAssistantResearchAugmentation | void> | FlueSecurityAssistantResearchAugmentation | void;
}

export type FlueSecurityAssistantExecution = {
  lane: FlueSecurityAssistantResearchPlan["execution_lane"];
  executionStyle?: FlueSecurityAssistantResearchPlan["execution_style"];
  availableToolCount: number;
  selectedToolCount: number;
  stageCount: number;
  fallback?: "draft_after_synthesis_failure";
} & ReturnType<typeof specialistExecutionFields>;

export interface FlueSecurityAssistantCompleteOutput {
  data: FlueSecurityAssistantResult;
  model?: {
    provider: string;
    id: string;
  };
  usage?: unknown;
  execution?: FlueSecurityAssistantExecution;
  stages?: {
    researchPlan: FlueSecurityAssistantResearchPlan;
    draft: FlueSecurityAssistantResult;
  };
}

/**
 * Pi's Bedrock catalog describes foundation models, while Bedrock may require
 * an inference-profile ID for invocation. Preserve the catalog metadata and
 * replace only the ID sent to Bedrock when a regional or global profile is
 * configured.
 */
export function resolveFlueModel(model: Parameters<typeof resolveModel>[0]): ReturnType<typeof resolveModel> {
  if (typeof model !== "string") return resolveModel(model);
  const separator = model.indexOf("/");
  if (separator === -1) return resolveModel(model);
  const provider = model.slice(0, separator);
  const modelId = model.slice(separator + 1);
  if (provider !== "amazon-bedrock") return resolveModel(model);
  const foundationModelId = modelId.replace(/^(?:global|us|eu|apac)\./, "");
  if (foundationModelId === modelId) return resolveModel(model);
  const foundationModel = resolveModel(`${provider}/${foundationModelId}`);
  return foundationModel ? { ...foundationModel, id: modelId } : foundationModel;
}

let toolCallSequence = 0;

export function adaptPiToolsToFlue(tools: AgentTool[], options: FlueToolAdaptationOptions = {}): ToolDefinition[] {
  return tools.map((tool) => defineTool({
    name: tool.name,
    description: tool.description,
    input: typeboxToValibotObject(tool.parameters),
    run: async (context) => {
      const toolCallId = options.toolCallId?.() ?? `flue-tool-${Date.now()}-${++toolCallSequence}`;
      let isError = false;
      await options.beforeToolCall?.(tool.name);
      try {
        const result = await tool.execute(toolCallId, context.input ?? {}, context.signal);
        return agentToolResultToJson(result);
      } catch (error) {
        isError = true;
        throw error;
      } finally {
        await options.afterToolCall?.(tool.name, isError);
      }
    },
  }));
}

export async function completeWithFlueSecurityAssistant(input: FlueSecurityAssistantCompleteInput): Promise<FlueSecurityAssistantCompleteOutput> {
  const startedAt = Date.now();
  const abortController = new AbortController();
  const timeout = setTimeout(() => abortController.abort(new Error(`Flue assistant timed out after ${input.timeoutMs} ms`)), input.timeoutMs);
  timeout.unref?.();
  const stageBudgets = flueStageBudgets(input.timeoutMs);
  const executionModel = input.executionModel ?? input.model;
  const executionThinkingLevel = input.executionThinkingLevel ?? input.thinkingLevel;
  const agent = defineAgent(() => ({
    model: input.model,
    thinkingLevel: input.thinkingLevel,
    instructions: flueStagedSystemPrompt(input.systemPrompt),
    tools: [],
    sandbox: local({ cwd: process.cwd() }),
    compaction: false,
  }));
  const contextConfig: FlueContextConfig = {
    id: `cerebro-security-assistant-${Date.now()}`,
    env: process.env,
    agentConfig: {
      resolveModel: resolveFlueModel,
      thinkingLevel: input.thinkingLevel,
      compaction: false,
    },
    createDefaultEnv: async () => local({ cwd: process.cwd() }).createSessionEnv({ id: "default" }),
    defaultStore: new InMemorySessionStore(),
  };
  let harness: Awaited<ReturnType<typeof initializeRootHarness>> | undefined;
  try {
    harness = await initializeRootHarness(agent, contextConfig, () => undefined);
    const session = await harness.session("slack-answer");
    const planStage = stageSignal(abortController.signal, stageBudgets.plan, "planning");
    const researchPlan = await (async () => {
      try {
        return await settleFlueStage(session.prompt(flueResearchPlanPrompt(input.userPrompt, (input.codeTools?.length ?? 0) > 0), {
          result: flueSecurityAssistantResearchPlanSchema,
          model: input.model,
          thinkingLevel: input.thinkingLevel,
          signal: planStage.signal,
        }), planStage.signal);
      } finally {
        planStage.cleanup();
      }
    })();
    const stagedPlan = {
      ...researchPlan.data,
      execution_style: researchPlan.data.execution_style === "code" && (input.codeTools?.length ?? 0) > 0 ? "code" as const : "direct" as const,
      specialists: resolveSpecialistAssignments(researchPlan.data),
    };
    const researchAugmentation = await input.onResearchPlan?.(stagedPlan);
    if (input.allowIgnore && stagedPlan.response_disposition === "ignore") {
      const ignored = ignoredResult(stagedPlan.disposition_reason);
      return {
        data: ignored,
        model: researchPlan.model,
        execution: flueExecution(stagedPlan, input.tools.length, 0, 1),
        stages: { researchPlan: stagedPlan, draft: ignored },
      };
    }
    if ((stagedPlan.execution_lane === "converse" || stagedPlan.execution_lane === "continue") && stagedPlan.direct_response?.trim() && stagedPlan.specialists.length === 0) {
      const direct = directResult(stagedPlan);
      return {
        data: direct,
        model: researchPlan.model,
        execution: flueExecution(stagedPlan, input.tools.length, 0, 1),
        stages: { researchPlan: stagedPlan, draft: direct },
      };
    }
    const selectedPack = selectExecutionToolPack(input.tools, input.codeTools ?? [], {
      executionLane: stagedPlan.execution_lane,
      executionStyle: stagedPlan.execution_style,
      domainLenses: stagedPlan.domain_lenses,
      selectedTools: stagedPlan.selected_tools,
      sourceCandidates: stagedPlan.required_sources,
    });
    const selectedTools = selectedPack.tools;
    const researchStage = stageSignal(
      abortController.signal,
      flueResearchBudget(input.timeoutMs, Date.now() - startedAt),
      "research",
    );
    const draft = await (async () => {
      try {
        return await settleFlueStage(session.prompt(flueResearchPrompt(input.userPrompt, stagedPlan, researchAugmentation), {
          result: flueSecurityAssistantResultSchema,
          tools: selectedTools,
          model: executionModel,
          thinkingLevel: executionThinkingLevel,
          signal: researchStage.signal,
        }), researchStage.signal);
      } finally {
        researchStage.cleanup();
      }
    })();
    if (input.allowIgnore && draft.data.response_disposition === "ignore") {
      return {
        data: draft.data,
        model: draft.model ?? researchPlan.model,
        execution: flueExecution(stagedPlan, input.tools.length, selectedTools.length, 2, draft.data.specialist_work),
        stages: { researchPlan: stagedPlan, draft: draft.data },
      };
    }
    if (draft.data.final_ready === true) {
      return {
        data: {
          ...draft.data,
          execution_lane: stagedPlan.execution_lane,
          presentation_ready: true,
          teammate: draft.data.teammate ?? teammateFromPlan(stagedPlan),
        },
        model: draft.model ?? researchPlan.model,
        usage: draft.usage,
        execution: flueExecution(stagedPlan, input.tools.length, selectedTools.length, 2, draft.data.specialist_work),
        stages: { researchPlan: stagedPlan, draft: draft.data },
      };
    }
    const synthesisStage = stageSignal(abortController.signal, stageBudgets.synthesis, "synthesis");
    let final;
    try {
      final = await settleFlueStage(session.prompt(flueSlackSynthesisPrompt(input.userPrompt, stagedPlan, draft.data), {
        result: flueSecurityAssistantResultSchema,
        model: input.model,
        thinkingLevel: input.thinkingLevel,
        signal: synthesisStage.signal,
      }), synthesisStage.signal);
    } catch (error) {
      const fallback = slackReadyDraft(draft.data, stagedPlan);
      if (!fallback) throw error;
      return {
        data: fallback,
        model: draft.model ?? researchPlan.model,
        usage: draft.usage,
        execution: flueExecution(stagedPlan, input.tools.length, selectedTools.length, 3, draft.data.specialist_work, "draft_after_synthesis_failure"),
        stages: { researchPlan: stagedPlan, draft: draft.data },
      };
    } finally {
      synthesisStage.cleanup();
    }
    return {
      data: {
        ...final.data,
        execution_lane: stagedPlan.execution_lane,
        presentation_ready: true,
        specialist_work: draft.data.specialist_work,
        teammate: final.data.teammate ?? draft.data.teammate ?? teammateFromPlan(stagedPlan),
      },
      model: final.model ?? draft.model ?? researchPlan.model,
      usage: final.usage,
      execution: flueExecution(stagedPlan, input.tools.length, selectedTools.length, 3, draft.data.specialist_work),
      stages: {
        researchPlan: stagedPlan,
        draft: draft.data,
      },
    };
  } finally {
    clearTimeout(timeout);
    await harness?.close();
  }
}

function flueExecution(
  plan: FlueSecurityAssistantResearchPlan,
  availableToolCount: number,
  selectedToolCount: number,
  stageCount: number,
  work: SpecialistWork[] = [],
  fallback?: FlueSecurityAssistantExecution["fallback"],
): FlueSecurityAssistantExecution {
  return {
    lane: plan.execution_lane,
    executionStyle: plan.execution_style,
    availableToolCount,
    selectedToolCount,
    stageCount,
    ...specialistExecutionFields(plan.specialists, work),
    ...(fallback ? { fallback } : {}),
  };
}

export function flueStageBudgets(timeoutMs: number): { plan: number; research: number; synthesis: number } {
  const total = Math.max(3_000, Math.floor(timeoutMs));
  const plan = Math.max(1_000, Math.min(90_000, Math.floor(total * 0.3)));
  const synthesis = Math.max(1_000, Math.min(45_000, Math.floor(total * 0.15)));
  return { plan, research: Math.max(1_000, total - plan - synthesis), synthesis };
}

export function flueResearchBudget(timeoutMs: number, elapsedMs: number): number {
  const total = Math.max(3_000, Math.floor(timeoutMs));
  const synthesis = flueStageBudgets(total).synthesis;
  return Math.max(1_000, total - Math.max(0, Math.floor(elapsedMs)) - synthesis);
}

export function settleFlueStage<T>(operation: Promise<T>, signal: AbortSignal): Promise<T> {
  if (signal.aborted) return Promise.reject(signal.reason ?? new Error("Flue stage aborted"));
  return new Promise<T>((resolve, reject) => {
    const onAbort = () => reject(signal.reason ?? new Error("Flue stage aborted"));
    signal.addEventListener("abort", onAbort, { once: true });
    operation.then(resolve, reject).finally(() => signal.removeEventListener("abort", onAbort)).catch(() => undefined);
  });
}

function stageSignal(parent: AbortSignal, timeoutMs: number, stage: string): { signal: AbortSignal; cleanup: () => void } {
  const controller = new AbortController();
  const onParentAbort = () => controller.abort(parent.reason);
  if (parent.aborted) onParentAbort();
  else parent.addEventListener("abort", onParentAbort, { once: true });
  const timeout = setTimeout(() => controller.abort(new Error(`Flue ${stage} stage timed out after ${timeoutMs} ms`)), timeoutMs);
  timeout.unref?.();
  return {
    signal: controller.signal,
    cleanup: () => {
      clearTimeout(timeout);
      parent.removeEventListener("abort", onParentAbort);
    },
  };
}

function slackReadyDraft(
  draft: FlueSecurityAssistantResult,
  plan: FlueSecurityAssistantResearchPlan,
): FlueSecurityAssistantResult | undefined {
  const messages = (draft.messages.length > 0 ? draft.messages : [draft.answer])
    .map((message) => message.trim())
    .filter(Boolean);
  if (messages.length === 0 || messages.some((message) => containsAssistantProtocolLeak(message))) return undefined;
  return {
    ...draft,
    execution_lane: plan.execution_lane,
    final_ready: true,
    presentation_ready: true,
    messages,
    teammate: draft.teammate ?? teammateFromPlan(plan),
  };
}

function flueStagedSystemPrompt(systemPrompt: string): string {
  return [
    systemPrompt,
    "",
    "Flue staged execution rules:",
    "This runtime may ask for intermediate typed results before the final answer. Follow the current stage schema exactly.",
    "Intermediate stages are private work products. Do not write Slack-facing prose until the final Slack response stage asks for it.",
    "Narrate work as observable checks and evidence, not hidden chain-of-thought.",
  ].join("\n");
}

function flueResearchPlanPrompt(userPrompt: string, codeModeAvailable: boolean): string {
  return [
    "Stage 1: select an execution lane and build the smallest useful plan for this Slack request.",
    "Do not call tools in this stage.",
    "Infer the user's concrete intent from the question and thread context.",
    "Return desired_outcome, resolved_scope, and scope_assumptions. Resolve scope from the request, thread, durable teammate state, identifiers, and available tools before asking the user.",
    "Set user_decision.required=true only when one precise choice or approval changes the result or is required for safe execution. Do not request generic repository, ticket, project, owner, runtime, or source scope that later stages can inspect.",
    "For a named person without a unique id, plan to resolve them through thread state, Slack AI search or message search, Slack user context, and then memory or graph links. Do not plan to ask for an email or login until those safe reads are unavailable or ambiguous.",
    "Choose exactly one execution_lane: converse for social or capability conversation; continue for a follow-up answer already present in thread state; lookup for one or two current facts; investigate for competing explanations or multiple evidence checks; act for an explicitly requested workflow with safe tool execution; ignore only under the bot-authored rules below.",
    codeModeAvailable
      ? "Choose execution_style=direct for a simple call or two. Choose execution_style=code when the work needs composition, filtering, joins, pagination, or repeated tool calls. This is a model judgment; do not route from keywords."
      : "Set execution_style=direct because bounded code execution is unavailable in this runtime.",
    "Select domain_lenses from identity, delivery, cloud, detection, compliance, incident, self, or general. Lenses define evidence sufficiency and source precedence; they do not replace source checks.",
    "For lookup, investigate, or act, return selected_tools with only the exact tool names needed, normally 1-8 evidence tools. The later stage will receive that bounded tool pack plus investigation controls.",
    "For converse or continue when no current-state check is needed, return direct_response as the complete natural Slack answer. Do not include direct_response when evidence must be refreshed.",
    "A direct_response should make the useful judgment and advance the user's objective. When correcting a security misconception, include the concrete diagnostic action the user should take next. Do not end with a generic offer to help or ask the user to supply more scope when the answer can name the next check.",
    "Return response_disposition=ignore only when sender_kind is bot, there is no explicit request to Cerebro, and a reply would only restate the handoff, repeat existing owner assignments, or report unavailable scope. Otherwise return respond.",
    "A verified new fact, a correction that changes the action, an action Cerebro can complete, or a direct request to Cerebro always requires respond.",
    "Return claims with stable ids, the factual statement to verify, whether it is required, and candidate tool names. Keep research_plan as short user-readable check descriptions.",
    "Return specialists only for work that changes the result. Choose from librarian, researcher, analyst, coordinator, triage, qa, developer, and compliance. Give each role a concrete objective and deliverables; the host will add roles required by the lane, lenses, tools, and claims.",
    "Return user_visible_work as short phrases that would be useful in a Slack answer, such as the sources to check or evidence to verify.",
    "If the user is asking another person or bot to help, preserve who is being asked and what help is needed.",
    "",
    userPrompt,
  ].join("\n");
}

function flueResearchPrompt(
  userPrompt: string,
  researchPlan: FlueSecurityAssistantResearchPlan,
  augmentation?: FlueSecurityAssistantResearchAugmentation | void,
): string {
  return [
    "Stage 2: execute the research plan with tools where useful.",
    "Use the research plan as guidance, then update it based on evidence.",
    `Execution lane: ${researchPlan.execution_lane}. Execution style: ${researchPlan.execution_style}. Domain lenses: ${researchPlan.domain_lenses.join(", ")}. Selected evidence tools: ${researchPlan.selected_tools.join(", ") || "runtime fallback catalog"}.`,
    researchPlan.execution_style === "code"
      ? "Use cerebro_tool_search to discover the compact typed operations, then cerebro_execute to compose only the planned checks. Nested calls retain their normal policy, approval, target, research-budget, and evidence boundaries."
      : "Use the supplied direct tools for the smallest set of simple planned checks.",
    specialistAssignmentPrompt(researchPlan.specialists),
    "Return exactly one specialist_work item for every assigned role. A completed item must satisfy its completion contract; a blocked item must name the concrete blocker. Use exact host-issued evidence receipts, not source names, for evidence_receipts. A partial receipt covers only facts actually returned for its named subjects.",
    "For investigations, call operator_hypothesis_ledger with competing explanations and a falsifier, then run the smallest check that separates them. Update the ledger after evidence arrives.",
    "Call operator_world_state for material facts and distinguish observed, inferred, expected, and desired state. Observed facts require the source tool's evidence receipt.",
    "Keep mutable facts bound to the exact subject returned by the source. For comparisons, make one claim per runtime, repository, identity, finding, or resource and use the narrowest supported identifier. Never transfer a timestamp, lag, status, failure, owner, or count between returned records.",
    "Qualify every negative conclusion with the checked source, population, and time window. Never write an unqualified nothing found, no findings, or all healthy when coverage is partial or any relevant source is stale.",
    "Inspect facts and records before interpreting a tool status. When a partial result returns non-empty facts or records, use them for their exact subjects and scope; only the explicitly missing lookup is unavailable. Never flatten a partial result with returned evidence into a total source failure.",
    "For two or more named source runtimes, call cerebro_source_runtimes separately with runtime_id for each runtime. Keep each runtime_id beside its own health fields in the claim ledger and answer.",
    "For a named person without a unique id, inspect Slack evidence before asking for an email or login. Use Slack AI search or message search to find a user id, then Slack user context; use memory or graph only to link that verified identity to another system. Ask only if the safe reads fail or leave multiple plausible identities.",
    "Use operator_mission_compile for AppSec remediation, identity access risk, and detection response that must resume; use operator_workflow_compile for other dependent work. Use exact registered tool names, arguments, and a read-only verification tool for action steps. Persist unfinished work with operator_goal_create, the selected mission pack and bindings when present, and acceptance criteria. Use operator_agent_run_step_bind to resume a waiting mission with a policy-matched tool and operator_agent_run_step_decide for evidence-backed non-action decisions. Every unfinished Cerebro commitment must include the exact goal_id returned by operator_goal_create; do not claim future ownership without a persisted goal. Before any write recommendation, use operator_action_simulation and include blast radius, risks, rollback, approval, and verification.",
    "Treat human requests as jobs to advance. Inspect before asking, make a recommendation from the evidence, complete safe steps, and represent unfinished assistant-owned work in teammate.commitments or teammate.open_loops with an owner and next action.",
    "When all remaining progress depends on one identifier or decision from the user and no background work can continue, record one user-owned open loop instead of a Cerebro commitment or goal. Ask the precise question without mentioning goal ids, persistence, bookkeeping, or whether the work is parked.",
    "For automated or proactive input, use operator_attention_decision and speak only for a material delta, failed control, ownerless action, decision deadline, or decision request.",
    "For bot-authored input, set response_disposition=ignore when the checks produce no verified new value and only confirm missing access or source scope. Do not turn an access limitation into a Slack reply unless the bot explicitly asked Cerebro to perform that check.",
    "Before returning the draft, call operator_claim_ledger for every planned claim. Cite only source tools with an exact host-issued evidence_receipt. A partial receipt may support its returned facts and subjects, but not the missing lookup or complete coverage.",
    "Use the stable claim ids from the plan. If claims is empty, use claim-1, claim-2, and so on in research_plan order.",
    "Final research gate: after the evidence checks and immediately before returning the draft, call operator_claim_ledger with every required plan claim and its exact host-issued evidence receipt. Keep partial receipts bounded to returned facts. Do not return until that tool succeeds; the host rejects a draft whose claim ledger is still open.",
    "Return a complete Slack-ready draft with evidence, actions_taken, next_actions, and research filled from actual checks. Put concise natural Slack prose in messages and set presentation_ready=true and final_ready=true unless a separate synthesis is genuinely required to remove protocol-shaped or unclear copy.",
    "Return teammate with the objective, desired outcome, resolved scope, bounded assumptions, commitments, open loops, and at most one required user decision. These fields are private continuity state and must not appear as protocol labels in messages.",
    "Specialist assignments and specialist_work are private. Use their conclusions in the answer without role labels or internal handoff narration.",
    augmentation?.distributed_work.length
      ? "Other Cerebros already completed the read-only work packets below in parallel. Their successful source results were imported into this turn and have host-issued evidence_receipts. Use those receipts in the claim ledger and do not repeat a successful source call unless its result conflicts, lacks required scope, or must be refreshed. A blocked packet is a bounded gap, not a reason to suppress the human answer."
      : "No distributed peer evidence is available for this turn. Continue with the bounded local tool pack.",
    augmentation?.distributed_work.length ? `Distributed work receipts:\n${JSON.stringify(augmentation.distributed_work, null, 2)}` : "",
    "Messages may be draft Slack copy, but keep raw tool output, JSON, XML, parameter tags, and hidden reasoning out of user-facing fields.",
    "",
    "Research plan:",
    JSON.stringify(researchPlan, null, 2),
    "",
    userPrompt,
  ].join("\n");
}

function flueSlackSynthesisPrompt(userPrompt: string, researchPlan: FlueSecurityAssistantResearchPlan, draft: FlueSecurityAssistantResult): string {
  return [
    "Stage 3: write the final Slack answer from the structured research draft.",
    "This is the only stage whose messages may be posted to Slack.",
    "Use only the supplied question, research plan, and draft answer. Do not call tools or invent new evidence.",
    "Preserve response_disposition and disposition_reason from the draft. Human-authored questions must respond.",
    `Preserve execution_lane=${researchPlan.execution_lane}. Set presentation_ready=true because this is the final Slack-writing stage.`,
    "Return the complete Slack answer in messages. One focused message is preferred, but longer answers are okay; Slack transport will split them into ordered safe chunks.",
    "Narrate the work productively: checked sources, evidence found, uncertainty, and next concrete action.",
    "Keep each source-scoped fact attached to the same named subject used in the draft. Do not merge status, freshness, failures, ownership, or counts across subjects while shortening the answer.",
    "Keep negative conclusions bounded to the checked source, population, and time window. Preserve any stale-source or incomplete-coverage limit from the draft.",
    "Preserve facts returned by partial sources and the exact missing slice. Do not rewrite a partial result with evidence as a total source outage.",
    "Do not expose hidden chain-of-thought, raw tool JSON, XML tags, parameter tags, schema text, or transcript fragments.",
    "Do not hand assistant-owned work back to the user. Use the resolved scope and safe assumptions from the plan. Ask only the plan's single precise user decision when required; otherwise finish the bounded work and state what Cerebro owns next.",
    "If the draft needs one user identifier or decision and no background work can continue, keep one user-owned open loop and the precise question. Remove Cerebro commitments and all goal or persistence bookkeeping from the Slack copy.",
    "Preserve or improve teammate continuity state from the draft. An unfinished Cerebro commitment must retain its verified goal_id, goal_status, acceptance_criteria, next_wake_at, and verification state. Keep its schema and labels out of messages.",
    "Preserve the substance of completed specialist work, but do not name specialists, describe internal delegation, or expose specialist_work in messages.",
    "",
    "Research plan:",
    JSON.stringify(researchPlan, null, 2),
    "",
    "Draft answer:",
    JSON.stringify(draft, null, 2),
    "",
    userPrompt,
  ].join("\n");
}

function ignoredResult(reason: string | undefined): FlueSecurityAssistantResult {
  const dispositionReason = reason?.replace(/\s+/g, " ").trim().slice(0, 500)
    || "Automated handoff had no explicit request or verified new value.";
  return {
    response_disposition: "ignore",
    disposition_reason: dispositionReason,
    execution_lane: "ignore",
    final_ready: true,
    presentation_ready: true,
    answer: "Automated handoff ignored.",
    messages: [],
    reply_messages: [],
    key_points: [dispositionReason],
    keyPoints: [],
    evidence: [],
    actions_taken: [],
    actionsTaken: [],
    next_actions: [],
    nextActions: [],
    research: [],
    memory_updates: [],
    memoryUpdates: [],
    specialist_work: [],
  };
}

function directResult(plan: FlueSecurityAssistantResearchPlan): FlueSecurityAssistantResult {
  const message = plan.direct_response?.replace(/\s+\n/g, "\n").trim() || "I need one more detail to answer that.";
  return {
    response_disposition: "respond",
    execution_lane: plan.execution_lane,
    final_ready: true,
    presentation_ready: true,
    answer: message,
    messages: [message],
    reply_messages: [],
    key_points: [],
    keyPoints: [],
    evidence: [],
    actions_taken: [],
    actionsTaken: [],
    next_actions: [],
    nextActions: [],
    research: [],
    memory_updates: [],
    memoryUpdates: [],
    specialist_work: [],
    teammate: teammateFromPlan(plan),
  };
}

function teammateFromPlan(plan: FlueSecurityAssistantResearchPlan): v.InferOutput<typeof teammateSchema> {
  return {
    objective: plan.user_intent,
    desired_outcome: plan.desired_outcome,
    resolved_scope: plan.resolved_scope,
    scope_assumptions: plan.scope_assumptions,
    commitments: [],
    open_loops: [],
    user_decision: plan.user_decision ?? { required: false },
  };
}

export function typeboxToValibotObject(schema: unknown): v.GenericSchema<Record<string, unknown>, unknown> {
  const converted = typeboxToValibot(schema);
  return converted.type === "object" ? converted.schema as v.GenericSchema<Record<string, unknown>, unknown> : v.object({});
}

function typeboxToValibot(schema: unknown): { type: string; schema: v.GenericSchema } {
  const record = objectRecord(schema);
  if (!record) return { type: "unknown", schema: v.unknown() };
  const type = record.type;
  if (type === "object") {
    const required = new Set(Array.isArray(record.required) ? record.required.map(String) : []);
    const properties = objectRecord(record.properties) ?? {};
    const entries: Record<string, v.GenericSchema> = {};
    for (const [key, value] of Object.entries(properties)) {
      const child = typeboxToValibot(value).schema;
      entries[key] = required.has(key) ? child : v.optional(child);
    }
    return { type, schema: v.object(entries) };
  }
  if (type === "array") {
    return { type, schema: v.array(typeboxToValibot(record.items).schema) };
  }
  if (type === "string") return { type, schema: v.string() };
  if (type === "number") return { type, schema: v.number() };
  if (type === "integer") return { type, schema: v.pipe(v.number(), v.integer()) };
  if (type === "boolean") return { type, schema: v.boolean() };
  if (type === "null") return { type, schema: v.null() };
  if (Array.isArray(record.anyOf)) {
    const options = record.anyOf.map((item) => typeboxToValibot(item).schema);
    if (options.length === 1) return { type: "union", schema: options[0] ?? v.unknown() };
    return options.length > 1 ? { type: "union", schema: v.union(options as [v.GenericSchema, v.GenericSchema, ...v.GenericSchema[]]) } : { type: "unknown", schema: v.unknown() };
  }
  return { type: String(type ?? "unknown"), schema: v.unknown() };
}

function memoryUpdateSchema(): v.GenericSchema {
  return v.object({
    kind: v.optional(v.string()),
    topic: v.pipe(v.string(), v.minLength(1)),
    summary: v.pipe(v.string(), v.minLength(1)),
    details: v.optional(v.string()),
    tags: v.optional(v.array(v.string()), []),
    confidence: v.optional(v.number()),
    scope: v.optional(v.string()),
    verified_by: v.optional(v.array(v.string()), []),
    verifiedBy: v.optional(v.array(v.string()), []),
    source_artifacts: v.optional(v.array(v.string()), []),
    sourceArtifacts: v.optional(v.array(v.string()), []),
    staleness_policy: v.optional(v.string()),
    stalenessPolicy: v.optional(v.string()),
    promotion_state: v.optional(v.string()),
    promotionState: v.optional(v.string()),
  });
}

function agentToolResultToJson(result: AgentToolResult<unknown>): Record<string, unknown> {
  return {
    content: result.content.map((part) => {
      if (part.type === "text") return { type: "text", text: part.text };
      return { type: "image", mimeType: part.mimeType };
    }),
    details: boundedToolDetails(result.details ?? null),
    terminate: result.terminate ?? false,
  };
}

function objectRecord(value: unknown): Record<string, unknown> | undefined {
  return value && typeof value === "object" && !Array.isArray(value) ? value as Record<string, unknown> : undefined;
}
