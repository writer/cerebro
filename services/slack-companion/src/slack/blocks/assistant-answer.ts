import type { SecurityAssistantAnswer } from "../../agent/security-assistant.js";
import { renderClaimEvidence } from "../../agent/evidence.js";
import { trimForSlack } from "../format.js";
import {
  cleanConversationalReply,
  composeReplyParts,
} from "./conversation.js";
import { context, escapeMrkdwn, header, listSection, section, type SlackBlock } from "./primitives.js";

export function securityAnswerBlocks(question: string, answer: SecurityAssistantAnswer): SlackBlock[] {
  return [
    header("Cerebro answer"),
    context([`Question: ${question}`, `Research: ${securityAnswerSourceLabel(answer.source)}`]),
    section(escapeMrkdwn(trimForSlack(answer.answer, 1600))),
    ...listSection("Key points", answer.keyPoints),
    ...listSection("Evidence", answer.evidence),
    ...listSection("Done", answer.actionsTaken),
    ...listSection("Next actions", answer.nextActions),
    ...listSection("Checked", answer.research),
  ];
}

export function securityAnswerMessages(question: string, answer: SecurityAssistantAnswer): string[] {
  void question;
  const explicit = answer.messages.map((message) => cleanConversationalReply(message)).filter((message): message is string => Boolean(message));
  if (explicit.length > 0) {
    return composeReplyParts(renderClaimEvidence(explicit, answer.claimEvidence));
  }

  const lines = [cleanConversationalReply(answer.answer)].filter((message): message is string => Boolean(message));
  if (lines.length === 0 && answer.keyPoints.length > 0) {
    lines.push(...answer.keyPoints.slice(0, 2).map((item) => cleanConversationalReply(item, 220)).filter((message): message is string => Boolean(message)));
  }
  return composeReplyParts(renderClaimEvidence(
    lines.length > 0 ? lines : ["I checked the available context but do not have enough evidence to answer yet."],
    answer.claimEvidence,
  ));
}

function securityAnswerSourceLabel(source: SecurityAssistantAnswer["source"]): string {
  if (source === "pi") return "Pi agent with Cerebro tools and memory";
  if (source === "flue") return "Flue agent with Cerebro tools and memory";
  return "agent blocked";
}
