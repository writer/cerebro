import { z } from "zod";
import type { SecurityMemoryWriteInput } from "../learning/memory-types.js";
import { redactSecurityText } from "../security/redaction.js";
import { containsAssistantProtocolLeak, trimForSlack } from "../slack/format.js";
import { telemetryEvent } from "../telemetry.js";
import { citationQualityMetrics } from "./evidence.js";
import type { SecurityAssistantAnswer } from "./security-assistant-types.js";
import { parseAssistantTeammateUpdate } from "./teammate-state.js";

export const ANSWER_JSON_SHAPE = '{"execution_lane":"converse|continue|lookup|investigate|act","presentation_ready":true,"answer":"full internal answer summary","messages":["Slack reply text","optional additional Slack reply text"],"reaction":"white_check_mark|eyes|mag|thinking_face|warning|rotating_light","key_points":["important facts"],"evidence":["checked evidence"],"actions_taken":["safe actions completed"],"next_actions":["concrete next step"],"research":["tools checked"],"claim_evidence":[{"claim_id":"id from operator_research_plan and operator_claim_ledger","claim_text":"exact visible claim text copied from answer or messages","temporal_scope":"historical|current","evidence_ids":["evidence ids returned by tools in this run, including decision packet receipt ids"]}],"teammate":{"objective":"job the user needs done","desired_outcome":"observable end state","resolved_scope":["scope resolved from the request, thread, or tools"],"scope_assumptions":["bounded assumption used to keep moving"],"commitments":[{"id":"stable-id","summary":"work Cerebro owns","status":"planned|in_progress|completed|blocked|cancelled","next_action":"next action Cerebro will take","blocker":"specific blocker","artifact_refs":["goal, ticket, PR, run, or evidence ref"],"goal_id":"id returned by operator_goal_create for unfinished work","goal_status":"active|waiting|approval_needed|blocked|paused|completed|cancelled","acceptance_criteria":["observable completion condition"],"next_wake_at":"verified goal wake time","verification":"verified goal or completion receipt"}],"open_loops":[{"id":"stable-id","summary":"unresolved work","owner":"cerebro|user|external","next_action":"owned next action","blocked_by":"specific dependency"}],"user_decision":{"required":false,"question":"one precise decision only when required","reason":"why progress cannot continue safely"}},"memory_updates":[{"kind":"access_context|asset_context|connector_context|detection_context|exception_context|normal_pattern|owner_context|severity_context|team_context|operator_fact|operator_claim|operator_decision|operator_correction|operator_risk|operator_blocker|operator_handoff|source_health_note|investigation_note|runbook_note|skill_improvement","topic":"short topic","summary":"non-secret declarative state","tags":["tag"],"promotion_state":"candidate|promoted|transient","source_artifacts":["source id"]}]}';
const ASSISTANT_ANSWER_MAX_CHARS = 24_000;
const ASSISTANT_MESSAGE_MAX_CHARS = 24_000;
const ASSISTANT_MAX_MESSAGES = 10;
const QUALIFIED_UNCERTAINTY_BLOCKERS = new Set([
  "current_claim_not_live_verified",
  "evidence_conflict_not_disclosed",
]);

const answerOutputSchema = z.object({
  execution_lane: z.enum(["ignore", "converse", "continue", "lookup", "investigate", "act"]).optional(),
  presentation_ready: z.boolean().optional(),
  answer: z.string().min(1),
  messages: stringArraySchema(),
  reply_messages: stringArraySchema(),
  reaction: z.string().optional(),
  key_points: stringArraySchema(),
  keyPoints: stringArraySchema(),
  evidence: stringArraySchema(),
  actions_taken: stringArraySchema(),
  actionsTaken: stringArraySchema(),
  next_actions: stringArraySchema(),
  nextActions: stringArraySchema(),
  research: stringArraySchema(),
  memory_citations: stringArraySchema(),
  memoryCitations: stringArraySchema(),
  claim_evidence: claimEvidenceBindingArraySchema(),
  claimEvidence: claimEvidenceBindingArraySchema(),
  memory_updates: memoryUpdateArraySchema(),
  memoryUpdates: memoryUpdateArraySchema(),
  teammate: z.unknown().optional(),
});

const slackPresentationOutputSchema = z.object({
  messages: stringArraySchema(),
  reply_messages: stringArraySchema(),
});

export function parseSecurityAssistantOutput(raw: string, researchTrail: string[] = []): SecurityAssistantAnswer | undefined {
  const jsonText = extractJsonObject(raw);
  if (!jsonText) return undefined;
  let decoded: unknown;
  try {
    decoded = JSON.parse(jsonText);
  } catch {
    return undefined;
  }
  return normalizeSecurityAssistantOutput(decoded, researchTrail, "pi");
}

export function parseSlackPresentationOutput(raw: string): string[] {
  const jsonText = extractJsonObject(raw);
  if (!jsonText) return [];
  let decoded: unknown;
  try {
    decoded = JSON.parse(jsonText);
  } catch {
    return [];
  }
  const parsed = slackPresentationOutputSchema.safeParse(decoded);
  if (!parsed.success) return [];
  const rawMessages = parsed.data.messages.length > 0 ? parsed.data.messages : parsed.data.reply_messages;
  return rawMessages
    .flatMap((item) => {
      const cleaned = cleanAssistantText(item);
      return cleaned && !isGenericAssistantFiller(cleaned) ? [cleaned] : [];
    })
    .filter(uniqueAssistantLine);
}

export function normalizeSecurityAssistantOutput(decoded: unknown, researchTrail: string[] = [], source: "pi" | "flue" = "pi"): SecurityAssistantAnswer | undefined {
  const parsed = answerOutputSchema.safeParse(decoded);
  if (!parsed.success) return undefined;
  const keyPoints = cleanAssistantList(parsed.data.key_points.length > 0 ? parsed.data.key_points : parsed.data.keyPoints, 400, 6);
  const evidence = cleanAssistantList(parsed.data.evidence, 400, 6);
  const actionsTaken = cleanAssistantList(parsed.data.actions_taken.length > 0 ? parsed.data.actions_taken : parsed.data.actionsTaken, 400, 6);
  const nextActions = cleanAssistantList(parsed.data.next_actions.length > 0 ? parsed.data.next_actions : parsed.data.nextActions, 400, 6);
  const memoryUpdates = parsed.data.memory_updates.length > 0 ? parsed.data.memory_updates : parsed.data.memoryUpdates;
  const memoryCitationIds = parsed.data.memory_citations.length > 0 ? parsed.data.memory_citations : parsed.data.memoryCitations;
  const claimEvidenceBindings = parsed.data.claim_evidence.length > 0 ? parsed.data.claim_evidence : parsed.data.claimEvidence;
  const rawMessages = parsed.data.messages.length > 0 ? parsed.data.messages : parsed.data.reply_messages;
  const answer = cleanAssistantText(parsed.data.answer) ?? synthesizeAnswerFromFields({ keyPoints, evidence, actionsTaken });
  const messages = rawMessages
    .flatMap((item) => {
      const cleaned = cleanAssistantText(item);
      return cleaned && !isGenericAssistantFiller(cleaned) ? [cleaned] : [];
    })
    .filter(uniqueAssistantLine);
  const teammate = parseAssistantTeammateUpdate(parsed.data.teammate);
  return {
    answer,
    messages,
    reaction: normalizeReaction(parsed.data.reaction),
    keyPoints,
    evidence,
    actionsTaken,
    nextActions,
    research: mergeAssistantResearch(parsed.data.research, researchTrail),
    memoryUpdates: memoryUpdates.slice(0, 3),
    memoryCitationIds: cleanMemoryCitationIds(memoryCitationIds),
    claimEvidenceBindings: claimEvidenceBindings.map((binding) => ({
      claimId: binding.claim_id,
      claimText: binding.claim_text,
      temporalScope: binding.temporal_scope,
      evidenceIds: cleanMemoryCitationIds([...binding.evidence_ids, ...binding.memory_ids]),
    })).slice(0, 12),
    source,
    executionLane: parsed.data.execution_lane,
    presentationReady: parsed.data.presentation_ready,
    teammate,
  };
}

export function assistantResultTelemetry(result: SecurityAssistantAnswer): Record<string, unknown> {
  const citationQuality = citationQualityMetrics(result);
  const citationAdvisoryCount = citationQuality.blockers.filter((blocker) => blocker === "citation_claim_not_visible").length;
  const citationBlockerCount = citationQuality.blockers.length - citationAdvisoryCount;
  return {
    "assistant.answer.source": result.source,
    "assistant.answer.message_count": result.messages.length,
    "assistant.answer.evidence_count": result.evidence.length,
    "assistant.answer.action_count": result.actionsTaken.length,
    "assistant.answer.next_action_count": result.nextActions.length,
    "assistant.answer.research_count": result.research.length,
    "assistant.answer.memory_update_count": result.memoryUpdates.length,
    "assistant.answer.memory_citation_count": result.memoryCitations?.length ?? 0,
    "assistant.answer.claim_evidence_count": citationQuality.packetCount,
    "assistant.answer.evidence_ref_count": citationQuality.evidenceCount,
    "assistant.answer.citation_precision": citationQuality.precision,
    "assistant.answer.citation_access": citationQuality.access,
    "assistant.answer.current_state_verification": citationQuality.currentStateVerification,
    "assistant.answer.citation_blocker_count": citationBlockerCount,
    "assistant.answer.citation_advisory_count": citationAdvisoryCount,
    "assistant.answer.reaction": result.reaction ?? "",
    "assistant.answer.delivery": result.delivery ?? "respond",
    "assistant.answer.execution_lane": result.executionLane ?? "unknown",
    "assistant.answer.presentation_ready": result.presentationReady ?? false,
    "assistant.answer.goal_captured": Boolean(result.teammate?.objective),
    "assistant.answer.resolved_scope_count": result.teammate?.resolvedScope.length ?? 0,
    "assistant.answer.commitment_count": result.teammate?.commitments.length ?? 0,
    "assistant.answer.open_loop_count": result.teammate?.openLoops.length ?? 0,
    "assistant.answer.user_decision_required": result.teammate?.userDecision?.required ?? false,
  };
}

export function answerHasGrounding(answer: SecurityAssistantAnswer, researchTrail: string[]): boolean {
  if (answer.source === "blocked") return true;
  if (answer.evidence.length > 0) return true;
  const groundedLines = [...answer.research, ...answer.actionsTaken, ...researchTrail].join("\n");
  return /\b(checked|failed|blocked|unavailable|no matches|not configured|missing|denied|scoped|timeout|timed out)\b/i.test(groundedLines);
}

export function validateSecurityAssistantAnswerContract(answer: SecurityAssistantAnswer, researchTrail: string[]): { ok: boolean; reason?: string } {
  if (answer.source === "blocked") return { ok: true };
  if (!answer.answer.trim() && answer.messages.length === 0) {
    return { ok: false, reason: "missing_answer_text" };
  }
  const qualifiedUncertainty = answer.contractRecovery === "qualified_uncertainty"
    && answerDisclosesQualifiedUncertainty(answer);
  const citationBlocker = citationQualityMetrics(answer).blockers.find((blocker) => !(
    blocker === "citation_claim_not_visible"
    || (qualifiedUncertainty && QUALIFIED_UNCERTAINTY_BLOCKERS.has(blocker))
  ));
  if (citationBlocker) return { ok: false, reason: citationBlocker };
  if (qualifiedUncertainty) return { ok: true };
  if ((answer.executionLane === "converse" || answer.executionLane === "continue") && answer.messages.length > 0) {
    return { ok: true };
  }
  if (!answerHasGrounding(answer, researchTrail)) {
    return { ok: false, reason: "missing_grounding" };
  }
  if (answer.evidence.length === 0 && answer.actionsTaken.length === 0 && answer.research.length === 0 && researchTrail.length === 0) {
    return { ok: false, reason: "missing_evidence_research_or_actions" };
  }
  return { ok: true };
}

export function answerDisclosesQualifiedUncertainty(answer: SecurityAssistantAnswer): boolean {
  return [answer.answer, ...answer.messages].some((message) => /\b(?:i(?:'m| am) not sure|could not(?: \w+){0,3} confirm|couldn't(?: \w+){0,3} confirm|can't(?: \w+){0,3} confirm|cannot(?: \w+){0,3} confirm|did not(?: \w+){0,3} confirm|can't fully vouch|cannot fully vouch|unconfirmed|partial coverage|not fully verified)\b/i.test(message));
}

export function assertSecurityAssistantAnswerContract(answer: SecurityAssistantAnswer, researchTrail: string[], runtime: "pi" | "flue"): void {
  const contract = validateSecurityAssistantAnswerContract(answer, researchTrail);
  if (contract.ok) return;
  telemetryEvent("assistant.answer_contract.failed", {
    component: "security-assistant",
    operation: "answer_contract",
    "assistant.runtime": runtime,
    "assistant.answer_contract.reason": contract.reason ?? "unknown",
    "assistant.research.count": researchTrail.length,
    "assistant.answer.evidence_count": answer.evidence.length,
    "assistant.answer.action_count": answer.actionsTaken.length,
  });
  throw new Error(`${runtime === "flue" ? "Flue" : "Pi"} security assistant returned an answer that failed the evidence contract: ${contract.reason ?? "unknown"}`);
}

function stringArraySchema(): z.ZodType<string[]> {
  return z.preprocess((value) => {
    if (Array.isArray(value)) {
      return value.map((item) => String(item).trim()).filter(Boolean);
    }
    if (typeof value === "string" && value.trim()) {
      return [value.trim()];
    }
    return [];
  }, z.array(z.string()));
}

function memoryUpdateArraySchema(): z.ZodType<SecurityMemoryWriteInput[]> {
  return z.preprocess((value) => {
    if (!Array.isArray(value)) return [];
    return value.flatMap((item) => {
      const record = item as Record<string, unknown>;
      if (typeof record.topic !== "string" || typeof record.summary !== "string") return [];
      const kind = typeof record.kind === "string" ? record.kind : "investigation_note";
      const tags = Array.isArray(record.tags) ? record.tags.map(String) : [];
      return [{
        kind: normalizeMemoryKind(kind),
        topic: record.topic,
        summary: record.summary,
        details: typeof record.details === "string" ? record.details : undefined,
        tags,
        scope: typeof record.scope === "string" ? record.scope : undefined,
        verifiedBy: stringListFrom(record.verified_by ?? record.verifiedBy),
        verifiedAt: typeof record.verified_at === "string" ? record.verified_at : typeof record.verifiedAt === "string" ? record.verifiedAt : undefined,
        sourceArtifacts: stringListFrom(record.source_artifacts ?? record.sourceArtifacts),
        stalenessPolicy: normalizeStalenessPolicy(typeof record.staleness_policy === "string" ? record.staleness_policy : typeof record.stalenessPolicy === "string" ? record.stalenessPolicy : undefined),
        promotionState: normalizePromotionState(typeof record.promotion_state === "string" ? record.promotion_state : typeof record.promotionState === "string" ? record.promotionState : undefined),
        sourceKind: "tool",
      }];
    });
  }, z.array(z.custom<SecurityMemoryWriteInput>()));
}

function cleanMemoryCitationIds(items: string[]): string[] {
  return [...new Set(items.map((item) => item.trim()).filter((item) => /^[A-Za-z0-9_.:-]{1,160}$/.test(item)))].slice(0, 6);
}

function claimEvidenceBindingArraySchema() {
  return z.array(z.object({
    claim_id: z.string().transform((value) => value.trim().slice(0, 200)),
    claim_text: z.string().transform((value) => value.replace(/\s+/g, " ").trim().slice(0, 1_200)),
    temporal_scope: z.enum(["historical", "current"]).default("current"),
    evidence_ids: stringArraySchema(),
    memory_ids: stringArraySchema(),
  })).default([]);
}

function normalizeMemoryKind(value: string): SecurityMemoryWriteInput["kind"] {
  const normalized = value.trim().toLowerCase();
  if (normalized === "access_context" || normalized === "asset_context" || normalized === "connector_context" || normalized === "detection_context" || normalized === "exception_context" || normalized === "normal_pattern" || normalized === "owner_context" || normalized === "severity_context" || normalized === "team_context" || normalized === "explicit_memory" || normalized === "triage_outcome" || normalized === "assistant_answer" || normalized === "encounter_story" || normalized === "investigation_note" || normalized === "runbook_note" || normalized === "skill_improvement" || normalized === "operator_fact" || normalized === "operator_claim" || normalized === "operator_decision" || normalized === "operator_correction" || normalized === "operator_risk" || normalized === "operator_blocker" || normalized === "operator_handoff" || normalized === "source_health_note") {
    return normalized;
  }
  return "investigation_note";
}

function normalizePromotionState(value: string | undefined): SecurityMemoryWriteInput["promotionState"] | undefined {
  const normalized = value?.trim().toLowerCase();
  if (normalized === "transient" || normalized === "candidate" || normalized === "promoted" || normalized === "rejected") {
    return normalized;
  }
  return undefined;
}

function normalizeStalenessPolicy(value: string | undefined): SecurityMemoryWriteInput["stalenessPolicy"] | undefined {
  const normalized = value?.trim().toLowerCase();
  if (normalized === "ephemeral" || normalized === "short_lived" || normalized === "until_reverified" || normalized === "durable") {
    return normalized;
  }
  return undefined;
}

function stringListFrom(value: unknown): string[] | undefined {
  if (Array.isArray(value)) {
    const cleaned = value.map(String).map((item) => item.trim()).filter(Boolean);
    return cleaned.length > 0 ? cleaned : undefined;
  }
  if (typeof value === "string" && value.trim()) return [value.trim()];
  return undefined;
}

function extractJsonObject(raw: string): string | undefined {
  const trimmed = raw.trim().replace(/^```(?:json)?\s*/i, "").replace(/\s*```$/i, "");
  const start = trimmed.indexOf("{");
  const end = trimmed.lastIndexOf("}");
  if (start === -1 || end === -1 || end <= start) return undefined;
  return trimmed.slice(start, end + 1);
}

function normalizeReaction(value: string | undefined): string | undefined {
  if (!value) return undefined;
  const normalized = value.replace(/:/g, "").trim().toLowerCase();
  if (/^[a-z0-9_+-]+$/.test(normalized)) return normalized.slice(0, 80);
  return undefined;
}

function isGenericAssistantFiller(value: string): boolean {
  return /\b(please )?(let me know|tell me) if you (need|want|would like)|\bneed more details or assistance\b|\bhappy to help\b/i.test(value.trim());
}

function cleanAssistantList(items: string[], maxLength: number, maxItems: number): string[] {
  return items
    .flatMap((item) => {
      const cleaned = cleanAssistantText(item, maxLength);
      return cleaned ? [cleaned] : [];
    })
    .filter(uniqueAssistantLine)
    .slice(0, maxItems);
}

function mergeAssistantResearch(modelResearch: string[], runtimeResearch: string[]): string[] {
  const runtimeItems = cleanAssistantList(runtimeResearch, 240, 64);
  const runtimeStatuses = new Map<string, { item: string; status: "checked" | "failed" }>();
  const runtimeDetails: string[] = [];
  for (const item of runtimeItems) {
    const match = item.match(/^([a-z][a-z0-9_.-]{1,159}):\s*(checked|failed)$/i);
    if (!match?.[1] || !match[2]) {
      runtimeDetails.push(item);
      continue;
    }
    runtimeStatuses.set(match[1].toLowerCase(), {
      item,
      status: match[2].toLowerCase() as "checked" | "failed",
    });
  }

  const modelItems = cleanAssistantList(modelResearch, 240, 64).filter((item) => {
    const observedTool = item.match(/^([a-z][a-z0-9_.-]{1,159})(?:\s*:\s*(?:checked|failed))?$/i)?.[1]?.toLowerCase();
    return !observedTool || !runtimeStatuses.has(observedTool);
  });
  const statuses = [...runtimeStatuses.values()];
  return cleanAssistantList([
    ...statuses.filter((entry) => entry.status === "failed").map((entry) => entry.item),
    ...statuses.filter((entry) => entry.status === "checked").map((entry) => entry.item),
    ...runtimeDetails,
    ...modelItems,
  ], 240, 8);
}

function cleanAssistantText(value: string, maxLength?: number): string | undefined {
  const normalized = redactSecurityText(value).replace(/\s+\n/g, "\n").trim();
  const cleaned = maxLength === undefined ? normalized : trimForSlack(normalized, maxLength);
  if (!cleaned || containsAssistantProtocolLeak(cleaned) || looksLikeRawStructuredOutput(cleaned)) return undefined;
  return cleaned;
}

function looksLikeRawStructuredOutput(value: string): boolean {
  const trimmed = value.trim();
  return /^```(?:json)?/i.test(trimmed) || /^\{\s*"?(answer|messages|reply_messages|key_points|evidence)"?\s*:/i.test(trimmed) || /^\[\s*"/.test(trimmed);
}

function synthesizeAnswerFromFields(input: {
  keyPoints: string[];
  evidence: string[];
  actionsTaken: string[];
}): string {
  const lines = [
    input.keyPoints[0] ?? input.evidence[0] ?? input.actionsTaken[0] ?? "I checked the available context but do not have enough evidence to answer yet.",
    input.evidence.length > 0 ? evidenceSentence(input.evidence[0]!) : "",
  ].filter(Boolean).filter(uniqueAssistantLine);
  return trimForSlack(lines.join("\n"), 1600);
}

function evidenceSentence(evidence: string): string {
  const cleaned = evidence.replace(/\s+/g, " ").trim().replace(/\.+$/, "");
  return cleaned ? sentenceWithPeriod(`The evidence I have is ${cleaned.charAt(0).toLowerCase()}${cleaned.slice(1)}`) : "";
}

function sentenceWithPeriod(value: string): string {
  const trimmed = value.trim();
  if (!trimmed) return trimmed;
  return /[.!?]$/.test(trimmed) ? trimmed : `${trimmed}.`;
}

function uniqueAssistantLine(value: string, index: number, values: string[]): boolean {
  const normalized = value.toLowerCase().replace(/[^a-z0-9]+/g, " ").trim();
  return values.findIndex((item) => item.toLowerCase().replace(/[^a-z0-9]+/g, " ").trim() === normalized) === index;
}
