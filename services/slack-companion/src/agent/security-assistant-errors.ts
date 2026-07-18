import type { AppConfig } from "../config/index.js";
import { redactSecurityText } from "../security/redaction.js";

export interface LlmErrorSummary {
  category: string;
  label: string;
  detail: string;
  modelRef: string;
  actionTaken: string;
  nextAction: string;
}

export function summarizeLlmError(reason: unknown, config: AppConfig): LlmErrorSummary {
  const modelRef = `${config.triage.pi.provider}/${config.triage.pi.model}`;
  const assistantName = config.triage.assistantRuntime === "flue" ? "Flue assistant" : "Pi assistant";
  const detail = shortError(redactSecurityText(errorText(reason))).replace(/[.]+$/, "") || "No error message returned";
  const normalized = detail.toLowerCase();
  const base = { detail, modelRef };
  if (/pi disabled by configuration|disabled by configuration/.test(normalized)) {
    return {
      ...base,
      category: "disabled",
      label: `${assistantName} is disabled by configuration`,
      actionTaken: "Stopped before starting a model request because assistant LLM access is disabled.",
      nextAction: "Enable assistant LLM configuration, then retry the Slack question.",
    };
  }
  if (/pi model .* is not available|model .* is not available|model is not available/.test(normalized)) {
    return {
      ...base,
      category: "model_unavailable",
      label: "Configured model is not available",
      actionTaken: "Stopped before tool research because the configured model could not be loaded.",
      nextAction: "Check the Pi provider/model setting and Bedrock model access, then retry.",
    };
  }
  if (/\babort(ed)?\b|\btimeout\b|\btimed out\b|deadline/i.test(detail)) {
    return {
      ...base,
      category: "timeout",
      label: "Model request timed out or was aborted",
      actionTaken: "Stopped after the model request exceeded its allowed runtime.",
      nextAction: "Check model latency, provider health, and the Pi timeout setting, then retry.",
    };
  }
  if (/valid answer json|invalid json|json/.test(normalized)) {
    return {
      ...base,
      category: "invalid_response",
      label: "Model response was not valid answer JSON",
      actionTaken: "Stopped after the model returned output that did not match the required answer schema.",
      nextAction: "Inspect the Pi trace or model output for malformed JSON, then retry.",
    };
  }
  if (/research contract|claim_ledger_not_closed|research_plan_has_no_claims/.test(normalized)) {
    return {
      ...base,
      category: "research_contract",
      label: "Assistant did not verify its planned claims",
      actionTaken: "Stopped after evidence research because the required claim ledger was not closed.",
      nextAction: "Inspect the assistant trace for the missing claim ledger, then retry.",
    };
  }
  if (/without evidence|without tool research|without evidence or tool research|grounding/.test(normalized)) {
    return {
      ...base,
      category: "ungrounded_response",
      label: "Model response lacked required evidence",
      actionTaken: "Stopped after the model answer lacked evidence or tool research.",
      nextAction: "Inspect the Pi trace for missing tool use or evidence, then retry.",
    };
  }
  if (/accessdenied|unauthorized|forbidden|credential|signature|expired token|throttl|rate|quota|bedrock|provider/.test(normalized)) {
    return {
      ...base,
      category: "provider_error",
      label: "Model provider request failed",
      actionTaken: "Stopped after the model provider returned an error.",
      nextAction: "Check Bedrock credentials, model access, quota, and provider status, then retry.",
    };
  }
  return {
    ...base,
    category: "unknown",
    label: "Model request failed",
    actionTaken: `Stopped after the ${assistantName} returned an error.`,
    nextAction: `Check the ${assistantName} logs for this request, then retry.`,
  };
}

export function shortError(error: unknown): string {
  const message = error instanceof Error ? error.message : String(error);
  return message.replace(/\s+/g, " ").slice(0, 160);
}

function errorText(error: unknown): string {
  if (error instanceof Error) {
    return error.name && error.name !== "Error" ? `${error.name}: ${error.message}` : error.message;
  }
  return String(error);
}
