import type { SecurityMemoryFreshness, SecurityMemoryQuality } from "../learning/memory-types.js";
import { redactSecurityText } from "../security/redaction.js";
import { escapeMrkdwn } from "../slack/blocks/primitives.js";
import { trimForSlack } from "../slack/format.js";
import type {
  SecurityAssistantAnswer,
  SecurityAssistantClaimEvidencePacket,
  SecurityAssistantClaimTemporalScope,
  SecurityAssistantEvidenceRef,
  SecurityAssistantMemoryCitation,
} from "./security-assistant-types.js";

const MEMORY_EVIDENCE_TOOLS = new Set([
  "security_memory_read",
  "security_memory_search",
  "security_session_recall",
  "security_memory_intelligence",
]);
const HISTORICAL_EVIDENCE_TOOLS = new Set([
  ...MEMORY_EVIDENCE_TOOLS,
  "company_library_search",
  "company_library_read",
]);
const EVIDENCE_LIMIT = 12;
const CLAIM_LIMIT = 12;
const CITED_REPLY_TEXT_MAX_CHARS = 24_000;
const LEGACY_MEMORY_MARKER = /\[\[memory:[A-Za-z0-9_.:-]{1,160}\]\]/g;

export interface EvidenceLedgerClaim {
  id: string;
  status: "supported" | "contradicted" | "unverified" | "blocked";
  source_tools: string[];
  evidence_receipts: string[];
  evidence_refs: string[];
  verified: boolean;
}

export interface CitationQualityMetrics {
  packetCount: number;
  evidenceCount: number;
  precision: number;
  access: number;
  currentStateVerification: number;
  conflictDisclosure: number;
  blockers: string[];
}

export function evidenceCandidatesFromToolResult(
  toolName: string,
  details: unknown,
  audienceChannelId?: string,
): SecurityAssistantEvidenceRef[] {
  const result = objectValue(details);
  if (!result) return [];
  if (MEMORY_EVIDENCE_TOOLS.has(toolName)) {
    return memoryEvidence(result, toolName, audienceChannelId);
  }
  if (toolName === "company_library_search") {
    return libraryEvidence(Array.isArray(result.records) ? result.records : [], toolName, audienceChannelId);
  }
  if (toolName === "company_library_read") {
    return libraryEvidence(result.record ? [result.record] : [], toolName, audienceChannelId);
  }
  if (toolName === "cerebro_decision_packet") {
    return decisionPacketEvidence(result, toolName);
  }
  return [];
}

export function reconcileClaimEvidence(
  answer: SecurityAssistantAnswer,
  candidates: SecurityAssistantEvidenceRef[],
  ledgerClaims: EvidenceLedgerClaim[],
): SecurityAssistantAnswer {
  const cleanAnswer = stripLegacyMarkers(answer);
  const candidateAliases = evidenceAliases(candidates);
  const ledgerById = new Map(ledgerClaims.map((claim) => [claim.id, claim]));
  const visibleText = [cleanAnswer.answer, ...cleanAnswer.messages].join("\n");
  const bindings = (cleanAnswer.claimEvidenceBindings ?? []).slice(0, CLAIM_LIMIT).flatMap((binding) => {
    const claimId = cleanId(binding.claimId);
    const claimText = cleanText(binding.claimText, 1_200);
    const temporalScope = claimTemporalScope(binding.temporalScope);
    const ledger = claimId ? ledgerById.get(claimId) : undefined;
    if (!claimId || !claimText || !ledger) return [];
    return [{
      claimId,
      claimText,
      temporalScope,
      evidenceIds: uniqueIds(binding.evidenceIds).slice(0, EVIDENCE_LIMIT),
    }];
  });

  const packets = bindings.map((binding): SecurityAssistantClaimEvidencePacket => {
    const ledger = ledgerById.get(binding.claimId) as EvidenceLedgerClaim;
    const selected = binding.evidenceIds
      .flatMap((id) => candidateAliases.get(id) ?? [])
      .filter((evidence) => evidence.access === "allowed");
    const liveEvidence = liveEvidenceFromLedger(ledger, candidates);
    const evidence = uniqueEvidence([...selected, ...liveEvidence]).slice(0, EVIDENCE_LIMIT);
    const hasLiveVerification = ledger.source_tools.some((tool) => !HISTORICAL_EVIDENCE_TOOLS.has(tool));
    const conflicted = evidence.some((item) => item.conflicted);
    const verification = ledger.status === "contradicted" || conflicted
      ? "contradicted"
      : ledger.status === "blocked"
        ? "blocked"
        : !ledger.verified
          ? "unverified"
          : binding.temporalScope === "current" && !hasLiveVerification
            ? "historical_only"
            : "verified";
    return {
      claimId: binding.claimId,
      claimText: binding.claimText,
      temporalScope: binding.temporalScope,
      verification,
      sourceTools: [...ledger.source_tools],
      evidenceReceipts: [...ledger.evidence_receipts],
      evidence,
      visible: visibleText.includes(binding.claimText),
    };
  });
  const memoryEvidenceRefs = uniqueEvidence(packets.flatMap((packet) => packet.evidence.filter((item) => item.kind === "memory")));
  return {
    ...cleanAnswer,
    claimEvidenceBindings: bindings,
    claimEvidence: packets,
    memoryCitationIds: memoryEvidenceRefs.map((item) => item.id),
    memoryCitations: memoryEvidenceRefs.map(memoryCitationFromEvidence),
  };
}

export async function resolveClaimEvidencePermalinks(
  client: unknown,
  packets: SecurityAssistantClaimEvidencePacket[] | undefined,
  audienceChannelId: string,
): Promise<SecurityAssistantClaimEvidencePacket[]> {
  const getPermalink = objectValue(objectValue(client)?.chat)?.getPermalink;
  if (typeof getPermalink !== "function") return packets ?? [];
  return Promise.all((packets ?? []).map(async (packet) => ({
    ...packet,
    evidence: await Promise.all(packet.evidence.map(async (evidence) => {
      if (evidence.kind !== "memory" || evidence.access !== "allowed" || !evidence.channelId || !evidence.sourceTs) return evidence;
      if (evidence.channelId !== audienceChannelId) return { ...evidence, access: "restricted" as const, permalink: undefined };
      try {
        const result = objectValue(await getPermalink.call(objectValue(client)?.chat, {
          channel: evidence.channelId,
          message_ts: evidence.sourceTs,
        }));
        const permalink = safeUrl(result?.permalink);
        return permalink ? { ...evidence, permalink } : evidence;
      } catch {
        return evidence;
      }
    })),
  })));
}

export function renderClaimEvidence(
  messages: string[],
  packets: SecurityAssistantClaimEvidencePacket[] | undefined,
): string[] {
  const rendered = messages.map((message) => stripLegacyMarkerText(message));
  const visiblePackets = (packets ?? []).filter((packet) => packet.visible && packet.evidence.length > 0).slice(0, CLAIM_LIMIT);
  const usedEvidence: SecurityAssistantEvidenceRef[] = [];
  for (const packet of visiblePackets) {
    const messageIndex = rendered.findIndex((message) => message.includes(packet.claimText));
    if (messageIndex < 0) continue;
    const allowedEvidence = packet.evidence.filter((evidence) => evidence.access === "allowed");
    if (allowedEvidence.length === 0) continue;
    const numbers = allowedEvidence.map((evidence) => {
      const existing = usedEvidence.findIndex((item) => item.id === evidence.id);
      if (existing >= 0) return existing + 1;
      usedEvidence.push(evidence);
      return usedEvidence.length;
    });
    const marker = ` [${numbers.join(", ")}]`;
    const message = rendered[messageIndex] as string;
    const at = message.indexOf(packet.claimText);
    const end = at + packet.claimText.length;
    if (!/^\s*\[\d/.test(message.slice(end))) {
      rendered[messageIndex] = `${message.slice(0, end)}${marker}${message.slice(end)}`;
    }
  }
  if (usedEvidence.length === 0) return rendered;
  const lines = usedEvidence.slice(0, EVIDENCE_LIMIT).map((evidence, index) => trimForSlack(
    `[${index + 1}] ${evidenceLabel(evidence)}${evidenceDetails(evidence)}`,
    600,
  ));
  return [...fitMessageBudget(rendered, CITED_REPLY_TEXT_MAX_CHARS), `*Sources*\n${lines.join("\n")}`];
}

export function citationQualityMetrics(answer: SecurityAssistantAnswer): CitationQualityMetrics {
  const packets = answer.claimEvidence ?? [];
  if (packets.length === 0) {
    return { packetCount: 0, evidenceCount: 0, precision: 1, access: 1, currentStateVerification: 1, conflictDisclosure: 1, blockers: [] };
  }
  const visible = packets.filter((packet) => packet.visible && packet.evidence.length > 0).length;
  const accessible = packets.filter((packet) => packet.evidence.every((evidence) => evidence.access === "allowed")).length;
  const current = packets.filter((packet) => packet.temporalScope === "current");
  const currentVerified = current.filter((packet) => packet.verification === "verified" || packet.verification === "contradicted").length;
  const conflicts = packets.filter((packet) => packet.evidence.some((evidence) => evidence.conflicted));
  const conflictDisclosed = conflicts.filter((packet) => /\b(conflict|contradict|disagree|earlier|supersed)\b/i.test(packet.claimText)).length;
  const blockers = [
    visible < packets.length ? "citation_claim_not_visible" : "",
    accessible < packets.length ? "citation_source_not_accessible" : "",
    currentVerified < current.length ? "current_claim_not_live_verified" : "",
    conflictDisclosed < conflicts.length ? "evidence_conflict_not_disclosed" : "",
  ].filter(Boolean);
  return {
    packetCount: packets.length,
    evidenceCount: uniqueEvidence(packets.flatMap((packet) => packet.evidence)).length,
    precision: ratio(visible, packets.length),
    access: ratio(accessible, packets.length),
    currentStateVerification: ratio(currentVerified, current.length),
    conflictDisclosure: ratio(conflictDisclosed, conflicts.length),
    blockers,
  };
}

function memoryEvidence(result: Record<string, unknown>, toolName: string, audienceChannelId?: string): SecurityAssistantEvidenceRef[] {
  const memories = Array.isArray(result.memories) ? result.memories : [];
  const diagnostics = objectValue(result.diagnostics);
  const diagnosticRows = Array.isArray(diagnostics?.results) ? diagnostics.results : [];
  const diagnosticsById = new Map(diagnosticRows.flatMap((item) => {
    const row = objectValue(item);
    const id = cleanId(row?.id);
    return id ? [[id, row] as const] : [];
  }));
  const conflictedIds = new Set((Array.isArray(diagnostics?.conflicts) ? diagnostics.conflicts : []).flatMap((item) => {
    const conflict = objectValue(item);
    return Array.isArray(conflict?.recordIds) ? conflict.recordIds.flatMap((id) => cleanId(id) ?? []) : [];
  }));
  return memories.flatMap((item) => {
    const record = objectValue(item);
    const id = cleanId(record?.id);
    const title = cleanText(record?.topic, 240);
    if (!id || !title) return [];
    const channelId = cleanChannelId(record?.channelId);
    const access = channelId && audienceChannelId && channelId !== audienceChannelId ? "restricted" : "allowed";
    const diagnostic = diagnosticsById.get(id);
    return [{
      id,
      kind: "memory" as const,
      title,
      basis: "historical" as const,
      access,
      sourceTool: toolName,
      sourceRef: id,
      channelId,
      sourceTs: cleanSlackTs(record?.sourceTs),
      createdAt: cleanIso(record?.createdAt),
      verifiedAt: cleanIso(record?.verifiedAt),
      verifiedBy: cleanList(record?.verifiedBy, 120, 8),
      sourceArtifacts: cleanList(record?.sourceArtifacts, 500, 8),
      quality: memoryQuality(diagnostic?.quality),
      freshness: memoryFreshness(diagnostic?.freshness),
      conflicted: conflictedIds.has(id),
    }];
  });
}

function libraryEvidence(items: unknown[], toolName: string, audienceChannelId?: string): SecurityAssistantEvidenceRef[] {
  return items.flatMap((item) => {
    const record = objectValue(item);
    const recordId = cleanId(record?.id);
    const title = cleanText(record?.title, 240);
    if (!recordId || !title) return [];
    const channelIds = cleanList(record?.channelIds, 32, 24);
    const access = channelIds.length === 0 || (Boolean(audienceChannelId) && channelIds.every((id) => id === audienceChannelId))
      ? "allowed"
      : "restricted";
    const claims = Array.isArray(record?.claims) ? record.claims : [];
    const conflicted = claims.some((claim) => objectValue(claim)?.basis === "conflicted")
      || (Array.isArray(record?.contradictions) && record.contradictions.length > 0);
    return [{
      id: `library:${recordId}`,
      kind: "company_library" as const,
      title,
      basis: "historical" as const,
      access,
      sourceTool: toolName,
      sourceRef: recordId,
      createdAt: cleanIso(record?.updatedAt) ?? cleanIso(record?.createdAt),
      verifiedBy: [],
      sourceArtifacts: cleanList(record?.sourceArtifacts, 500, 12),
      version: cleanPositiveInteger(record?.version),
      conflicted,
    }];
  });
}

function decisionPacketEvidence(result: Record<string, unknown>, toolName: string): SecurityAssistantEvidenceRef[] {
  const packets = [result.decision_packet, result.left_packet, result.right_packet]
    .flatMap((item) => {
      const packet = objectValue(item);
      return packet ? [packet] : [];
    });
  return packets.flatMap((packet) => {
    const id = cleanId(packet.id);
    const workflow = objectValue(packet.workflow);
    const provenance = objectValue(packet.provenance);
    const scope = objectValue(packet.scope);
    if (!id || !workflow || !provenance) return [];
    const workflowId = cleanId(workflow.id) ?? "decision";
    const scopeUrn = cleanText(scope?.urn, 500) ?? "tenant";
    const evidenceDigest = cleanText(provenance.evidence_digest, 160) ?? "evidence:unknown";
    const coverageDigest = cleanText(provenance.coverage_digest, 160) ?? "coverage:unknown";
    const contradictions = Array.isArray(packet.contradictions) ? packet.contradictions : [];
    return [{
      id,
      kind: "live_source" as const,
      title: `Decision packet ${id}`,
      basis: "live" as const,
      access: "allowed" as const,
      sourceTool: toolName,
      sourceRef: `decision-packet:${workflowId}:${scopeUrn}`,
      verifiedAt: cleanIso(packet.generated_at),
      version: `${evidenceDigest}:${coverageDigest}`,
      conflicted: contradictions.some((item) => objectValue(item)?.resolution_state !== "resolved"),
      verifiedBy: cleanList(provenance.resolver_ids, 160, 12),
      sourceArtifacts: [id, evidenceDigest, coverageDigest],
    }];
  });
}

function liveEvidenceFromLedger(claim: EvidenceLedgerClaim, candidates: SecurityAssistantEvidenceRef[]): SecurityAssistantEvidenceRef[] {
  const tools = claim.source_tools.filter((tool) => !HISTORICAL_EVIDENCE_TOOLS.has(tool));
  if (tools.length === 0) return [];
  const refs = new Set(claim.evidence_refs.map((ref) => cleanText(ref, 500)).filter((ref): ref is string => Boolean(ref)));
  const normalized = candidates.filter((evidence) => evidence.kind === "live_source"
    && Boolean(evidence.sourceTool && tools.includes(evidence.sourceTool))
    && (refs.size === 0 || [...refs].some((ref) => subjectRefMatches(ref, evidence))));
  if (normalized.length > 0) return uniqueEvidence(normalized).slice(0, EVIDENCE_LIMIT);
  const fallbackRefs = claim.evidence_refs.length > 0 ? claim.evidence_refs : tools;
  return fallbackRefs.slice(0, EVIDENCE_LIMIT).map((ref, index) => ({
    id: `live:${cleanId(tools[index % tools.length]) ?? "source"}:${stableToken(ref)}`,
    kind: "live_source",
    title: cleanText(ref, 240) || tools[index % tools.length] || "Live source",
    basis: "live",
    access: "allowed",
    sourceTool: tools[index % tools.length],
    sourceRef: cleanText(ref, 500),
    verifiedBy: [tools[index % tools.length] as string],
    sourceArtifacts: cleanText(ref, 500) ? [cleanText(ref, 500) as string] : [],
  }));
}

function subjectRefMatches(ref: string, evidence: SecurityAssistantEvidenceRef): boolean {
  const aliases = [evidence.sourceRef, evidence.subjectId, evidence.id].filter((value): value is string => Boolean(value));
  return aliases.some((alias) => ref === alias || ref.endsWith(`:${alias}`) || alias.endsWith(`:${ref}`));
}

function evidenceAliases(candidates: SecurityAssistantEvidenceRef[]): Map<string, SecurityAssistantEvidenceRef[]> {
  const aliases = new Map<string, SecurityAssistantEvidenceRef[]>();
  for (const evidence of candidates) {
    for (const alias of uniqueIds([evidence.id, evidence.sourceRef ?? ""])) {
      aliases.set(alias, uniqueEvidence([...(aliases.get(alias) ?? []), evidence]));
    }
  }
  return aliases;
}

function memoryCitationFromEvidence(evidence: SecurityAssistantEvidenceRef): SecurityAssistantMemoryCitation {
  return {
    id: evidence.id,
    topic: evidence.title,
    channelId: evidence.channelId,
    sourceTs: evidence.sourceTs,
    sourceKind: evidence.sourceTool,
    createdAt: evidence.createdAt ?? new Date(0).toISOString(),
    verifiedAt: evidence.verifiedAt,
    verifiedBy: evidence.verifiedBy,
    sourceArtifacts: evidence.sourceArtifacts,
    quality: evidence.quality,
    freshness: evidence.freshness,
    permalink: evidence.permalink,
  };
}

function stripLegacyMarkers(answer: SecurityAssistantAnswer): SecurityAssistantAnswer {
  return {
    ...answer,
    answer: stripLegacyMarkerText(answer.answer),
    messages: answer.messages.map(stripLegacyMarkerText).filter(Boolean),
  };
}

function stripLegacyMarkerText(value: string): string {
  return value.replace(LEGACY_MEMORY_MARKER, "").replace(/[ \t]+([.,;:!?])/g, "$1").replace(/[ \t]{2,}/g, " ").trim();
}

function evidenceLabel(evidence: SecurityAssistantEvidenceRef): string {
  const label = escapeLinkLabel(evidence.title);
  if (evidence.permalink) return `<${evidence.permalink}|${label}>`;
  const artifactUrl = evidence.sourceArtifacts.map(safeUrl).find(Boolean);
  return artifactUrl ? `<${artifactUrl}|${label}>` : escapeMrkdwn(evidence.title);
}

function evidenceDetails(evidence: SecurityAssistantEvidenceRef): string {
  const details = evidence.kind === "memory"
    ? [
        `memory \`${evidence.id}\``,
        evidence.createdAt ? `saved ${evidence.createdAt.slice(0, 10)}` : "",
        evidence.quality?.replace(/_/g, " ") ?? "",
        evidence.freshness?.replace(/_/g, " ") ?? "",
      ]
    : evidence.kind === "company_library"
      ? [
          evidence.sourceRef ? `library \`${inlineValue(evidence.sourceRef)}\`` : "company library",
          evidence.version ? `version ${evidence.version}` : "",
          evidence.createdAt ? `updated ${evidence.createdAt.slice(0, 10)}` : "",
          "historical",
        ]
      : [
          evidence.sourceTool ? `checked \`${inlineValue(evidence.sourceTool)}\`` : "live source",
          evidence.sourceRef && evidence.sourceRef !== evidence.sourceTool ? `source \`${inlineValue(evidence.sourceRef)}\`` : "",
        ];
  if (evidence.conflicted) details.push("conflicted");
  return details.filter(Boolean).length > 0 ? ` · ${details.filter(Boolean).join(" · ")}` : "";
}

function inlineValue(value: string): string {
  return escapeMrkdwn(redactSecurityText(value).replace(/`/g, "'").slice(0, 180));
}

function uniqueEvidence(values: SecurityAssistantEvidenceRef[]): SecurityAssistantEvidenceRef[] {
  return [...new Map(values.map((value) => [value.id, value])).values()];
}

function uniqueIds(values: string[]): string[] {
  return [...new Set(values.map((value) => cleanId(value)).filter((value): value is string => Boolean(value)))];
}

function claimTemporalScope(value: unknown): SecurityAssistantClaimTemporalScope {
  return value === "historical" ? "historical" : "current";
}

function cleanId(value: unknown): string | undefined {
  if (typeof value !== "string") return undefined;
  const cleaned = value.trim();
  return /^[A-Za-z0-9_.:-]{1,200}$/.test(cleaned) ? cleaned : undefined;
}

function cleanChannelId(value: unknown): string | undefined {
  if (typeof value !== "string") return undefined;
  const cleaned = value.trim();
  return /^[A-Z0-9]{2,32}$/i.test(cleaned) ? cleaned : undefined;
}

function cleanSlackTs(value: unknown): string | undefined {
  if (typeof value !== "string") return undefined;
  const cleaned = value.trim();
  return /^\d{1,16}(?:\.\d{1,6})?$/.test(cleaned) ? cleaned : undefined;
}

function cleanText(value: unknown, max: number): string | undefined {
  if (typeof value !== "string") return undefined;
  const cleaned = redactSecurityText(value).replace(/\s+/g, " ").trim().slice(0, max);
  return cleaned || undefined;
}

function cleanIso(value: unknown): string | undefined {
  if (typeof value !== "string" || !value.trim()) return undefined;
  const parsed = Date.parse(value);
  return Number.isNaN(parsed) ? undefined : new Date(parsed).toISOString();
}

function cleanList(value: unknown, max: number, limit: number): string[] {
  if (!Array.isArray(value)) return [];
  return [...new Set(value.flatMap((item) => cleanText(item, max) ?? []))].slice(0, limit);
}

function cleanPositiveInteger(value: unknown): number | undefined {
  return typeof value === "number" && Number.isInteger(value) && value > 0 ? value : undefined;
}

function memoryQuality(value: unknown): SecurityMemoryQuality | undefined {
  return value === "source_verified" || value === "source_backed" || value === "promoted"
    || value === "candidate" || value === "transient" || value === "unverified"
    || value === "stale" || value === "rejected" ? value : undefined;
}

function memoryFreshness(value: unknown): SecurityMemoryFreshness | undefined {
  return value === "current" || value === "recent" || value === "aging"
    || value === "stale" || value === "expired" ? value : undefined;
}

function safeUrl(value: unknown): string | undefined {
  if (typeof value !== "string") return undefined;
  try {
    const parsed = new URL(value);
    if (parsed.protocol !== "https:" && parsed.protocol !== "http:") return undefined;
    parsed.username = "";
    parsed.password = "";
    parsed.search = "";
    parsed.hash = "";
    return parsed.toString();
  } catch {
    return undefined;
  }
}

function escapeLinkLabel(value: string): string {
  return redactSecurityText(value).replace(/[|<>]/g, "").slice(0, 120) || "Source";
}

function fitMessageBudget(messages: string[], limit: number): string[] {
  let remaining = limit;
  return messages.flatMap((message) => {
    if (remaining <= 0) return [];
    const bounded = trimForSlack(message, remaining);
    remaining -= bounded.length + 1;
    return bounded ? [bounded] : [];
  });
}

function stableToken(value: string): string {
  let hash = 2166136261;
  for (const char of value) hash = Math.imul(hash ^ char.charCodeAt(0), 16777619);
  return (hash >>> 0).toString(16);
}

function ratio(numerator: number, denominator: number): number {
  return denominator > 0 ? numerator / denominator : 1;
}

function objectValue(value: unknown): Record<string, unknown> | undefined {
  return value && typeof value === "object" && !Array.isArray(value) ? value as Record<string, unknown> : undefined;
}
