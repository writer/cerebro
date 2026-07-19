import type {
  AlertTriageClassificationV1,
  AlertTriageSeverityV1,
} from "./contracts.js";

const MAX_INPUT_CODE_UNITS = 65_536;
const MAX_SUMMARY_CODE_POINTS = 900;
const MAX_REASON_CODE_POINTS = 400;
const MAX_ITEM_CODE_POINTS = 400;
const MAX_RESEARCH_CODE_POINTS = 240;
const MAX_ITEMS = 6;
const MAX_RESEARCH_ITEMS = 8;

const SLACK_TOKEN_PATTERN = /xox[baprs]-[A-Za-z0-9-]+/g;
const CLOUD_ACCESS_KEY_PATTERN = /\b(?:AKIA|ASIA)[A-Z0-9]{16}\b/g;
const PRIVATE_KEY_PATTERN =
  /-----BEGIN ([A-Z0-9 ]{1,32}) PRIVATE KEY-----[\s\S]*?-----END \1 PRIVATE KEY-----/g;
const ASSIGNED_SECRET_PATTERN =
  /\b(bearer|api[_-]?key|token|secret|password)\b["']?\s*[:=]\s*(?:"[^"\r\n]*"|'[^'\r\n]*'|[^\s,;]+)/gi;
const UNSAFE_CONTROL_PATTERN = /[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f]/g;

export type TriageAgentTopicV1 =
  | "security_alert"
  | "assistant_follow_up"
  | "operational_update"
  | "other";

export interface TriageAgentOutputV1 {
  actions_taken: string[];
  classification: AlertTriageClassificationV1;
  confidence: number;
  evidence: string[];
  recommended_actions: string[];
  redaction_state: "redacted";
  research: string[];
  response_reason?: string;
  schema_version: "triage-agent-output/v1";
  severity?: AlertTriageSeverityV1;
  should_respond: boolean;
  summary: string;
  topic?: TriageAgentTopicV1;
}

export type TriageOutputRejectionReasonV1 =
  | "input_too_large"
  | "json_envelope_invalid"
  | "json_invalid"
  | "schema_invalid";

export type TriageOutputParseResultV1 =
  | {
      disposition: "accepted";
      output: TriageAgentOutputV1;
      schema_version: "triage-output-parse-result/v1";
    }
  | {
      disposition: "rejected";
      reason_code: TriageOutputRejectionReasonV1;
      schema_version: "triage-output-parse-result/v1";
    };

export interface ParseTriageAgentOutputOptionsV1 {
  research_trail?: readonly string[];
}

/**
 * Parse one untrusted agent result into bounded, redacted triage data.
 *
 * The returned value is not a durable triage decision. Evidence receipts and
 * decision identity must still be bound by the triage lifecycle before policy
 * can plan a suggestion or delivery.
 */
export function parseTriageAgentOutput(
  raw: string,
  options: ParseTriageAgentOutputOptionsV1 = {},
): TriageOutputParseResultV1 {
  if (typeof raw !== "string" || raw.length > MAX_INPUT_CODE_UNITS) {
    return rejected("input_too_large");
  }

  const jsonText = unwrapJsonObject(raw);
  if (jsonText === undefined) return rejected("json_envelope_invalid");

  let decoded: unknown;
  try {
    decoded = JSON.parse(jsonText);
  } catch {
    return rejected("json_invalid");
  }
  if (!isRecord(decoded)) return rejected("schema_invalid");

  const classification = classificationValue(decoded.classification);
  const confidence = confidenceValue(decoded.confidence);
  const summary = requiredString(decoded.summary);
  if (classification === undefined || confidence === undefined || summary === undefined) {
    return rejected("schema_invalid");
  }

  const topic = topicValue(decoded.topic);
  if (decoded.topic !== undefined && topic === undefined) return rejected("schema_invalid");
  const severity = severityValue(decoded.severity);
  if (decoded.severity !== undefined && severity === undefined) return rejected("schema_invalid");

  const evidence = stringList(decoded.evidence);
  const actionsSnake = stringList(decoded.actions_taken);
  const actionsCamel = stringList(decoded.actionsTaken);
  const recommendationsSnake = stringList(decoded.recommended_actions);
  const recommendationsCamel = stringList(decoded.recommendedActions);
  const research = stringList(decoded.research);
  if (
    evidence === undefined ||
    actionsSnake === undefined ||
    actionsCamel === undefined ||
    recommendationsSnake === undefined ||
    recommendationsCamel === undefined ||
    research === undefined
  ) {
    return rejected("schema_invalid");
  }

  const responseReason = optionalString(decoded.response_reason ?? decoded.responseReason);
  if (
    (decoded.response_reason !== undefined || decoded.responseReason !== undefined) &&
    responseReason === undefined
  ) {
    return rejected("schema_invalid");
  }
  const explicitShouldRespond = optionalBoolean(
    decoded.should_respond ?? decoded.shouldRespond,
  );
  if (
    (decoded.should_respond !== undefined || decoded.shouldRespond !== undefined) &&
    explicitShouldRespond === undefined
  ) {
    return rejected("schema_invalid");
  }

  const boundedEvidence = boundedList(evidence, MAX_ITEMS, MAX_ITEM_CODE_POINTS);
  const actions = actionsSnake.length > 0 ? actionsSnake : actionsCamel;
  const recommendations = recommendationsSnake.length > 0
    ? recommendationsSnake
    : recommendationsCamel;
  const boundedRecommendations = boundedList(
    recommendations,
    MAX_ITEMS,
    MAX_ITEM_CODE_POINTS,
  );
  const researchTrail = research.length > 0
    ? research
    : stringList(options.research_trail ?? []);
  if (researchTrail === undefined) return rejected("schema_invalid");

  const output: TriageAgentOutputV1 = {
    actions_taken: boundedList(actions, MAX_ITEMS, MAX_ITEM_CODE_POINTS),
    classification,
    confidence,
    evidence: boundedEvidence,
    recommended_actions: boundedRecommendations,
    redaction_state: "redacted",
    research: boundedList(
      researchTrail,
      MAX_RESEARCH_ITEMS,
      MAX_RESEARCH_CODE_POINTS,
    ),
    schema_version: "triage-agent-output/v1",
    should_respond: explicitShouldRespond ?? defaultShouldRespond(
      classification,
      boundedEvidence,
      boundedRecommendations,
    ),
    summary: boundedText(summary, MAX_SUMMARY_CODE_POINTS),
    ...(topic === undefined ? {} : { topic }),
    ...(severity === undefined ? {} : { severity }),
  };
  const boundedReason = responseReason === undefined
    ? ""
    : boundedText(responseReason, MAX_REASON_CODE_POINTS);
  if (boundedReason !== "") output.response_reason = boundedReason;

  return {
    disposition: "accepted",
    output,
    schema_version: "triage-output-parse-result/v1",
  };
}

function rejected(reasonCode: TriageOutputRejectionReasonV1): TriageOutputParseResultV1 {
  return {
    disposition: "rejected",
    reason_code: reasonCode,
    schema_version: "triage-output-parse-result/v1",
  };
}

function unwrapJsonObject(raw: string): string | undefined {
  let value = raw.trim();
  if (value.startsWith("```")) {
    const match = /^```(?:json)?[ \t]*\r?\n([\s\S]*?)\r?\n```$/i.exec(value);
    if (match === null) return undefined;
    value = match[1]?.trim() ?? "";
  }
  if (!value.startsWith("{") || !value.endsWith("}")) return undefined;
  return value;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function classificationValue(value: unknown): AlertTriageClassificationV1 | undefined {
  switch (value) {
    case "actionable":
    case "likely_security_issue":
      return "actionable";
    case "needs_context":
      return "needs_context";
    case "non_actionable":
    case "likely_noise":
      return "non_actionable";
    default:
      return undefined;
  }
}

function severityValue(value: unknown): AlertTriageSeverityV1 | undefined {
  switch (value) {
    case undefined:
      return undefined;
    case "critical":
    case "high":
    case "medium":
    case "low":
    case "informational":
      return value;
    case "info":
      return "informational";
    default:
      return undefined;
  }
}

function topicValue(value: unknown): TriageAgentTopicV1 | undefined {
  switch (value) {
    case undefined:
      return undefined;
    case "security_alert":
    case "assistant_follow_up":
    case "operational_update":
    case "other":
      return value;
    default:
      return undefined;
  }
}

function confidenceValue(value: unknown): number | undefined {
  const parsed = typeof value === "number"
    ? value
    : typeof value === "string" && value.trim() !== ""
      ? Number(value)
      : Number.NaN;
  return Number.isFinite(parsed) && parsed >= 0 && parsed <= 1 ? parsed : undefined;
}

function requiredString(value: unknown): string | undefined {
  return typeof value === "string" && value.trim() !== "" ? value : undefined;
}

function optionalString(value: unknown): string | undefined {
  return value === undefined || typeof value === "string" ? value : undefined;
}

function stringList(value: unknown): string[] | undefined {
  if (value === undefined || value === null || value === "") return [];
  if (typeof value === "string") return value.trim() === "" ? [] : [value];
  if (!Array.isArray(value) || value.some((item) => typeof item !== "string")) {
    return undefined;
  }
  return value.filter((item) => item.trim() !== "");
}

function optionalBoolean(value: unknown): boolean | undefined {
  if (value === undefined) return undefined;
  if (typeof value === "boolean") return value;
  if (typeof value === "number") {
    if (value === 1) return true;
    if (value === 0) return false;
    return undefined;
  }
  if (typeof value !== "string") return undefined;
  switch (value.trim().toLowerCase()) {
    case "true":
    case "yes":
    case "1":
      return true;
    case "false":
    case "no":
    case "0":
      return false;
    default:
      return undefined;
  }
}

function defaultShouldRespond(
  classification: AlertTriageClassificationV1,
  evidence: readonly string[],
  recommendations: readonly string[],
): boolean {
  return classification !== "non_actionable" &&
    (evidence.length > 0 || recommendations.length > 0);
}

function boundedList(values: readonly string[], maximum: number, textLimit: number): string[] {
  return values
    .map((value) => boundedText(value, textLimit))
    .filter((value) => value !== "")
    .slice(0, maximum);
}

function boundedText(value: string, maximumCodePoints: number): string {
  const redacted = redactCredentialShapes(value)
    .replace(UNSAFE_CONTROL_PATTERN, " ")
    .trim();
  return [...redacted].slice(0, maximumCodePoints).join("");
}

function redactCredentialShapes(value: string): string {
  return value
    .replace(SLACK_TOKEN_PATTERN, "[redacted_token]")
    .replace(CLOUD_ACCESS_KEY_PATTERN, "[redacted_access_key]")
    .replace(PRIVATE_KEY_PATTERN, "[redacted_private_key]")
    .replace(ASSIGNED_SECRET_PATTERN, "$1=[redacted_secret]");
}
