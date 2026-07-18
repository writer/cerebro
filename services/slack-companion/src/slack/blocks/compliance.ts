import type { CompliancePacket } from "../../compliance/work-packets.js";
import { trimForSlack } from "../format.js";
import { context, escapeMrkdwn, header, listSection, section, type SlackBlock } from "./primitives.js";

export function compliancePacketReviewBlocks(packet: CompliancePacket): SlackBlock[] {
  return [
    header("Compliance packet"),
    section(`*${escapeMrkdwn(packet.title)}*\n${escapeMrkdwn(packet.packet_id)}`),
    context([
      `Type: ${packet.packet_type}`,
      `Readiness: ${packet.readiness}`,
      packet.ready_for_review ? "Review state: ready" : "Review state: blocked",
    ]),
    ...listSection("Gaps", packet.gaps),
    ...listSection("Review actions", packet.review_actions.map((item) => trimForSlack(item, 360))),
    ...listSection("Evidence", refs(packet, "evidence_refs")),
    ...listSection("Tickets", refs(packet, "ticket_refs")),
  ];
}

function refs(packet: CompliancePacket, key: string): string[] {
  const value = packet[key];
  return Array.isArray(value) ? value.map(String).filter(Boolean).slice(0, 6) : [];
}
