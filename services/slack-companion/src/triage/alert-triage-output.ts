import { z } from "zod";
import { redactSecurityText } from "../security/redaction.js";
import { trimForSlack } from "../slack/format.js";
import { defaultShouldRespond } from "./alert-triage-response.js";
import type { AlertTriageResult } from "./alert-triage-types.js";

const triageOutputSchema = z.object({
  topic: z.enum(["security_alert", "assistant_follow_up", "operational_update", "other"]).optional(),
  classification: z.enum(["likely_security_issue", "needs_context", "likely_noise"]),
  severity: z.enum(["critical", "high", "medium", "low", "info"]).optional(),
  confidence: z.coerce.number().min(0).max(1),
  should_respond: optionalBooleanSchema(),
  shouldRespond: optionalBooleanSchema(),
  response_reason: z.string().optional(),
  responseReason: z.string().optional(),
  summary: z.string().min(1),
  evidence: stringArraySchema(),
  actions_taken: stringArraySchema(),
  actionsTaken: stringArraySchema(),
  recommended_actions: stringArraySchema(),
  recommendedActions: stringArraySchema(),
  research: stringArraySchema(),
});

export function parseTriageAgentOutput(raw: string, researchTrail: string[] = []): AlertTriageResult | undefined {
  const jsonText = extractJsonObject(raw);
  if (!jsonText) return undefined;
  let decoded: unknown;
  try {
    decoded = JSON.parse(jsonText);
  } catch {
    return undefined;
  }
  const parsed = triageOutputSchema.safeParse(decoded);
  if (!parsed.success) return undefined;
  const recommendedActions = parsed.data.recommended_actions.length > 0
    ? parsed.data.recommended_actions
    : parsed.data.recommendedActions;
  const actionsTaken = parsed.data.actions_taken.length > 0 ? parsed.data.actions_taken : parsed.data.actionsTaken;
  const research = parsed.data.research.length > 0 ? parsed.data.research : researchTrail;
  const responseReason = trimForSlack(parsed.data.response_reason ?? parsed.data.responseReason ?? "", 400);
  return {
    topic: parsed.data.topic,
    classification: parsed.data.classification,
    severity: parsed.data.severity,
    confidence: clampConfidence(parsed.data.confidence),
    shouldRespond: parsed.data.should_respond ?? parsed.data.shouldRespond ?? defaultShouldRespond(parsed.data.classification, parsed.data.evidence, recommendedActions),
    responseReason: responseReason || undefined,
    summary: trimForSlack(parsed.data.summary, 900),
    evidence: parsed.data.evidence.map((item) => trimForSlack(item, 400)).slice(0, 6),
    actionsTaken: actionsTaken.map((item) => trimForSlack(item, 400)).slice(0, 6),
    recommendedActions: recommendedActions.map((item) => trimForSlack(item, 400)).slice(0, 6),
    research: research.map((item) => trimForSlack(item, 240)).slice(0, 8),
    source: "pi",
  };
}

export function redactAlertText(value: string): string {
  return redactSecurityText(value);
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

function optionalBooleanSchema(): z.ZodType<boolean | undefined> {
  return z.preprocess((value) => {
    if (typeof value === "boolean") return value;
    if (typeof value === "number") return value !== 0;
    if (typeof value !== "string") return undefined;
    const normalized = value.trim().toLowerCase();
    if (["true", "yes", "1"].includes(normalized)) return true;
    if (["false", "no", "0"].includes(normalized)) return false;
    return undefined;
  }, z.boolean().optional());
}

function extractJsonObject(raw: string): string | undefined {
  const trimmed = raw.trim().replace(/^```(?:json)?\s*/i, "").replace(/\s*```$/i, "");
  const start = trimmed.indexOf("{");
  const end = trimmed.lastIndexOf("}");
  if (start === -1 || end === -1 || end <= start) return undefined;
  return trimmed.slice(start, end + 1);
}

function clampConfidence(value: number): number {
  if (Number.isNaN(value)) return 0;
  return Math.max(0, Math.min(1, value));
}
