import type { AppConfig } from "../config/index.js";
import { redactSecurityText } from "../security/redaction.js";
import { buildCompliancePacket, type CompliancePacket, type CompliancePacketInput } from "./work-packets.js";

export interface ComplianceGapJiraDraftInput extends CompliancePacketInput {
  project_key?: string;
  issue_type?: string;
  labels?: string[];
}

export function complianceGapJiraDraft(config: AppConfig, input: ComplianceGapJiraDraftInput): Record<string, unknown> {
  const packet = buildCompliancePacket(input);
  if (!isCompliancePacket(packet)) return packet;
  const projectKey = clean(input.project_key) ?? config.ticketing.jira.defaultProjectKey;
  const issueType = clean(input.issue_type) ?? config.ticketing.jira.defaultIssueType;
  const gaps = packet.gaps;
  const labels = unique([
    "cerebro",
    "compliance",
    "gap",
    packet.packet_type,
    packet.readiness,
    ...cleanList(input.labels),
  ].map(labelValue).filter(Boolean));
  const summary = `${packet.title}: ${gaps.length ? gaps.slice(0, 2).join(", ") : "no open gaps"}`;
  return {
    system: "jira",
    created: false,
    ready_for_operator: Boolean(projectKey && gaps.length > 0),
    missing: [
      projectKey ? "" : "project_key",
      gaps.length ? "" : "packet_gaps",
    ].filter(Boolean),
    packet: packetSummary(packet),
    duplicate_search: projectKey
      ? { jql: `project = ${projectKey} AND labels = compliance AND text ~ "${packet.packet_id}" ORDER BY updated DESC` }
      : undefined,
    issue: {
      project_key: projectKey,
      issue_type: issueType,
      summary: redactSecurityText(summary).slice(0, 255),
      description: issueDescription(config, packet),
      labels,
    },
    note: gaps.length
      ? "Review this draft, search for duplicates, then create or update Jira through the approved ticket tool."
      : "No Jira gap ticket is needed unless review finds a missing control, evidence, owner, or disposition.",
  };
}

function issueDescription(config: AppConfig, packet: CompliancePacket): string {
  return redactSecurityText([
    `Compliance packet: ${packet.title}`,
    `Packet ID: ${packet.packet_id}`,
    `Packet type: ${packet.packet_type}`,
    `Readiness: ${packet.readiness}`,
    "",
    "Gaps:",
    ...bulletList(packet.gaps),
    "",
    "Review actions:",
    ...bulletList(packet.review_actions),
    "",
    `Evidence refs: ${refs(packet, "evidence_refs").join(", ") || "none"}`,
    `Ticket refs: ${refs(packet, "ticket_refs").join(", ") || "none"}`,
    `Exception refs: ${refs(packet, "exception_refs").join(", ") || "none"}`,
  ].join("\n")).slice(0, config.ticketing.maxDescriptionChars);
}

function packetSummary(packet: CompliancePacket): Record<string, unknown> {
  return {
    packet_id: packet.packet_id,
    packet_type: packet.packet_type,
    title: packet.title,
    readiness: packet.readiness,
    ready_for_review: packet.ready_for_review,
    gaps: packet.gaps,
    review_actions: packet.review_actions,
    secret_values_stored: false,
  };
}

function refs(packet: CompliancePacket, key: string): string[] {
  const value = packet[key];
  return Array.isArray(value) ? value.map(String).filter(Boolean).slice(0, 20) : [];
}

function bulletList(values: string[]): string[] {
  return values.length ? values.map((value) => `- ${value}`) : ["- none"];
}

function isCompliancePacket(value: CompliancePacket | { error: string }): value is CompliancePacket {
  return !("error" in value);
}

function labelValue(value: string | undefined): string | undefined {
  const label = value?.toLowerCase().replace(/[^a-z0-9_-]+/g, "-").replace(/^-+|-+$/g, "").slice(0, 50);
  return label || undefined;
}

function cleanList(values: string[] | undefined): string[] {
  return unique((values ?? []).map(clean).filter((value): value is string => Boolean(value)));
}

function clean(value: string | undefined): string | undefined {
  const trimmed = value?.replace(/\s+/g, " ").trim();
  return trimmed || undefined;
}

function unique<T>(values: T[]): T[] {
  return [...new Set(values)];
}
