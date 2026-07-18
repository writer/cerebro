import type { SecurityMemoryWriteInput } from "../learning/memory-types.js";
import type { CompliancePacket } from "./work-packets.js";

export function compliancePacketMemoryCandidates(
  packet: CompliancePacket,
  input: { channelId?: string; sourceTs?: string; now?: Date } = {},
): SecurityMemoryWriteInput[] {
  const refs = unique([
    packet.packet_id,
    ...arrayField(packet, "evidence_refs"),
    ...arrayField(packet, "ticket_refs"),
    ...arrayField(packet, "exception_refs"),
    ...arrayField(packet, "approval_refs"),
  ]);
  return [{
    kind: "investigation_note",
    topic: `Compliance ${packet.packet_type}: ${packet.title}`,
    summary: `${packet.readiness}; ${packet.gaps.length ? `gaps: ${packet.gaps.join(", ")}` : "no packet gaps"}.`,
    details: [
      `Packet ID: ${packet.packet_id}`,
      `Ready for review: ${packet.ready_for_review}`,
      packet.review_actions.length ? `Review actions: ${packet.review_actions.join("; ")}` : "",
    ].filter(Boolean).join("\n"),
    tags: unique(["compliance", packet.packet_type, packet.readiness, ...packet.gaps]).slice(0, 12),
    channelId: input.channelId,
    sourceTs: input.sourceTs,
    classification: packet.ready_for_review ? "compliance_packet_ready" : "compliance_packet_gap",
    confidence: packet.ready_for_review ? 0.82 : 0.68,
    sourceKind: "tool",
    entities: unique([
      ...arrayField(packet, "control_ids"),
      stringField(packet, "control_id"),
      stringField(packet, "runtime_id"),
      stringField(packet, "finding_id"),
      ...arrayField(packet, "runtime_ids"),
      ...arrayField(packet, "system_refs"),
      ...arrayField(packet, "policy_refs"),
    ].filter((value): value is string => Boolean(value))).slice(0, 20),
    sourceArtifacts: refs.slice(0, 16),
    stalenessPolicy: packet.ready_for_review ? "until_reverified" : "short_lived",
    promotionState: packet.ready_for_review ? "candidate" : "transient",
    verifiedBy: ["cerebro_compliance_packet"],
    verifiedAt: (input.now ?? new Date()).toISOString(),
  }];
}

function arrayField(packet: CompliancePacket, key: string): string[] {
  const value = packet[key];
  return Array.isArray(value) ? value.map(String).filter(Boolean) : [];
}

function stringField(packet: CompliancePacket, key: string): string | undefined {
  const value = packet[key];
  return typeof value === "string" && value.trim() ? value.trim() : undefined;
}

function unique<T>(values: T[]): T[] {
  return [...new Set(values)];
}
