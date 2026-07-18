import { telemetryEvent } from "../telemetry.js";
import { citationQualityMetrics } from "./evidence.js";
import type { SecurityResearchState } from "./research-state.js";
import { answerDisclosesQualifiedUncertainty, validateSecurityAssistantAnswerContract } from "./security-assistant-output.js";
import type { SecurityAssistantAnswer } from "./security-assistant-types.js";

const RECOVERABLE_UNCERTAINTY_BLOCKERS = new Set([
  "current_claim_not_live_verified",
  "evidence_conflict_not_disclosed",
]);
const CURRENT_UNCERTAINTY_NOTICE = "I'm not sure every current detail above is still accurate. The completed checks did not verify each one against a current source.";
const CONFLICT_UNCERTAINTY_NOTICE = "I'm not sure which record is current. The checked sources disagree on at least one detail.";
const GROUNDING_UNCERTAINTY_NOTICE = "I'm not sure this is complete because I could not verify every part against an available source.";
const RESTRICTED_EVIDENCE_NOTICE = "I can't use one of the checked sources in this channel. I can re-check that part against a source available here or continue in an authorized channel.";

export function blockedSlackMessage(category: string): string {
  if (/disabled|model_unavailable|configuration/i.test(category)) {
    return "Cerebro could not start the source check. The failed run records the unavailable assistant configuration; no substitute result was posted.";
  }
  if (/timeout|rate|capacity|unavailable|network/i.test(category)) {
    return "The source checks did not finish before the run ended. The failed run is recorded, and a retry from this conversation will keep the current mission and source subjects.";
  }
  if (/auth|permission|credential/i.test(category)) {
    return "The required source rejected the check. The failed run records which source needs access restored; no unverified result was posted.";
  }
  return "I'm not sure yet. The source checks did not return a usable result, so I did not fill the gap with an unverified answer.";
}

export function recoverIncompleteResearch(
  answer: SecurityAssistantAnswer,
  researchState: SecurityResearchState,
  runtime: "pi" | "flue",
): SecurityAssistantAnswer {
  const issue = researchState.completionIssue();
  if (!issue) return answer;
  telemetryEvent("assistant.research.contract_failed", {
    component: "security-assistant",
    operation: "research_contract",
    "assistant.runtime": runtime,
    "assistant.research.contract_issue": issue,
    ...researchState.telemetryAttributes(),
  });
  const notice = "I'm not sure about every detail above. The completed source checks did not verify one planned detail, so that part remains unconfirmed.";
  const messages = answer.messages.length > 0 ? [...answer.messages] : [answer.answer];
  if (!messages.some((message) => message.includes(notice))) messages.push(notice);
  return {
    ...answer,
    answer: [answer.answer, notice].filter(Boolean).join("\n\n"),
    messages,
  };
}

export function recoverQualifiedUncertainty(
  answer: SecurityAssistantAnswer,
  runtime: "pi" | "flue",
): SecurityAssistantAnswer {
  const quality = citationQualityMetrics(answer);
  const uncertaintyBlockers = quality.blockers.filter((blocker) => blocker !== "citation_claim_not_visible");
  const recoverable = uncertaintyBlockers.length > 0
    && uncertaintyBlockers.every((blocker) => RECOVERABLE_UNCERTAINTY_BLOCKERS.has(blocker))
    && answer.source !== "blocked"
    && Boolean(answer.answer.trim() || answer.messages.some((message) => message.trim()))
    && (quality.evidenceCount > 0 || answer.evidence.length > 0 || answer.actionsTaken.length > 0)
    && (answer.claimEvidence ?? []).every((packet) =>
      packet.evidence.every((evidence) => evidence.access === "allowed")
      && (packet.evidence.length > 0 || (packet.verification === "blocked" && packet.visible)));
  if (!recoverable) return answer;

  const notice = uncertaintyNotice(uncertaintyBlockers);
  telemetryEvent("assistant.answer_contract.recovered", {
    component: "security-assistant",
    operation: "answer_contract",
    "assistant.runtime": runtime,
    "assistant.answer_contract.reason": "qualified_uncertainty",
    "assistant.answer_contract.blockers": uncertaintyBlockers.join(","),
    "assistant.answer_contract.preserved_evidence_count": quality.evidenceCount,
  });
  const messages = answer.messages.length > 0 ? [...answer.messages] : [answer.answer];
  const disclosed = answerDisclosesQualifiedUncertainty(answer);
  if (!disclosed && !messages.some((message) => message.includes(notice))) messages.push(notice);
  return {
    ...answer,
    answer: disclosed || answer.answer.includes(notice) ? answer.answer : [answer.answer, notice].filter(Boolean).join("\n\n"),
    messages,
    contractRecovery: "qualified_uncertainty",
  };
}

/**
 * Turn evidence quality failures into a useful human answer. Presentation,
 * freshness, coverage, and grounding gaps are quality signals; they must not
 * replace a completed draft with an internal contract error. Access boundaries
 * remain hard and are removed before any answer reaches Slack.
 */
export function prepareDeliverableAnswer(
  answer: SecurityAssistantAnswer,
  researchTrail: string[],
  runtime: "pi" | "flue",
): SecurityAssistantAnswer {
  if (answer.source === "blocked") return answer;
  let deliverable = removeRestrictedEvidence(answer, runtime);
  deliverable = recoverQualifiedUncertainty(deliverable, runtime);
  const contract = validateSecurityAssistantAnswerContract(deliverable, researchTrail);
  if (contract.ok) return deliverable;

  const notice = contract.reason === "missing_answer_text"
    ? "I'm not sure yet. The completed checks did not produce an answer I can use."
    : GROUNDING_UNCERTAINTY_NOTICE;
  const existing = deliverable.messages.length > 0 ? [...deliverable.messages] : [deliverable.answer].filter(Boolean);
  const messages = existing.some((message) => message.includes(notice)) ? existing : [...existing, notice];
  const recovered = {
    ...deliverable,
    answer: deliverable.answer.includes(notice)
      ? deliverable.answer
      : [deliverable.answer, notice].filter(Boolean).join("\n\n"),
    messages,
    contractRecovery: "qualified_uncertainty" as const,
  };
  telemetryEvent("assistant.answer_contract.advisory", {
    component: "security-assistant",
    operation: "answer_contract",
    "assistant.runtime": runtime,
    "assistant.answer_contract.reason": contract.reason ?? "unknown",
    "assistant.answer_contract.delivery": "qualified_answer",
  });
  return recovered;
}

function removeRestrictedEvidence(
  answer: SecurityAssistantAnswer,
  runtime: "pi" | "flue",
): SecurityAssistantAnswer {
  const packets = answer.claimEvidence ?? [];
  if (!packets.some((packet) => packet.evidence.some((evidence) => evidence.access !== "allowed"))) return answer;

  const safePackets = packets.filter((packet) => packet.evidence.length > 0
    && packet.evidence.every((evidence) => evidence.access === "allowed"));
  const safeClaims = [...new Set(safePackets
    .filter((packet) => packet.verification === "verified" || packet.verification === "contradicted")
    .map((packet) => packet.claimText.trim())
    .filter(Boolean))];
  const visible = safeClaims.length > 0
    ? [`${safeClaims.join("\n")}\n\n${RESTRICTED_EVIDENCE_NOTICE}`]
    : [RESTRICTED_EVIDENCE_NOTICE];
  const safeClaimIds = new Set(safePackets.map((packet) => packet.claimId));
  const safeEvidenceIds = new Set(safePackets.flatMap((packet) => packet.evidence.map((evidence) => evidence.id)));
  telemetryEvent("assistant.answer_contract.access_boundary", {
    component: "security-assistant",
    operation: "answer_contract",
    "assistant.runtime": runtime,
    "assistant.answer_contract.removed_claim_count": packets.length - safePackets.length,
    "assistant.answer_contract.preserved_claim_count": safePackets.length,
  });
  return {
    ...answer,
    answer: visible.join("\n\n"),
    messages: visible,
    keyPoints: safeClaims.slice(0, 6),
    evidence: [],
    actionsTaken: [],
    nextActions: ["Re-check the restricted part against a source available in this channel."],
    research: [...answer.research, "evidence_access: blocked"],
    memoryUpdates: [],
    memoryCitationIds: (answer.memoryCitationIds ?? []).filter((id) => safeEvidenceIds.has(id)),
    memoryCitations: (answer.memoryCitations ?? []).filter((citation) => safeEvidenceIds.has(citation.id)),
    claimEvidenceBindings: (answer.claimEvidenceBindings ?? []).filter((binding) => safeClaimIds.has(binding.claimId)),
    claimEvidence: safePackets.map((packet) => ({ ...packet, visible: safeClaims.includes(packet.claimText.trim()) })),
  };
}

function uncertaintyNotice(blockers: string[]): string {
  if (blockers.includes("evidence_conflict_not_disclosed")) return CONFLICT_UNCERTAINTY_NOTICE;
  return CURRENT_UNCERTAINTY_NOTICE;
}
