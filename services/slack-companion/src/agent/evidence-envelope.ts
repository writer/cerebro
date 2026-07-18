import { createHash } from "node:crypto";
import { redactSecurityText } from "../security/redaction.js";
import type { SecurityAssistantEvidenceRef } from "./security-assistant-types.js";

const MAX_DEPTH = 5;
const MAX_SUBJECTS = 24;
const IDENTIFIER_KEYS = [
  "finding_id", "findingId", "runtime_id", "runtimeId", "issue_key", "issueKey", "resource_id", "resourceId",
  "repository_id", "repositoryId", "arn", "id", "key",
] as const;
const URL_KEYS = ["web_url", "webUrl", "html_url", "htmlUrl", "permalink", "url"] as const;
const LABEL_KEYS = ["title", "name", "display_name", "displayName", "summary", "repository", "repo"] as const;
const KIND_KEYS = ["resource_type", "resourceType", "subject_type", "subjectType", "type", "kind"] as const;
const TIME_KEYS = ["observed_at", "observedAt", "verified_at", "verifiedAt", "updated_at", "updatedAt", "last_synced_at", "lastSyncedAt"] as const;

export interface SourceEvidenceEnvelope {
  sourceTool: string;
  evidenceReceipt: string;
  subjects: SecurityAssistantEvidenceRef[];
  coverage: {
    returnedSubjects: number;
    truncated: boolean;
  };
}

export function sourceEvidenceEnvelope(
  sourceTool: string,
  evidenceReceipt: string,
  result: unknown,
): SourceEvidenceEnvelope {
  const subjects = new Map<string, SecurityAssistantEvidenceRef>();
  let observedCandidates = 0;

  const visit = (value: unknown, depth: number): void => {
    if (depth > MAX_DEPTH || value === null || value === undefined) return;
    if (Array.isArray(value)) {
      for (const item of value) visit(item, depth + 1);
      return;
    }
    if (typeof value !== "object") return;
    const record = value as Record<string, unknown>;
    const identifier = firstText(record, IDENTIFIER_KEYS);
    const repository = firstText(record, ["repository", "repo"]);
    const number = firstText(record, ["number", "issue_number", "issueNumber"]);
    const url = firstUrl(record, URL_KEYS);
    const compoundId = repository && number ? `${repository}#${number}` : "";
    const subjectId = cleanText(identifier || compoundId || url, 500);
    if (subjectId) {
      observedCandidates += 1;
      const kind = cleanToken(firstText(record, KIND_KEYS) || inferredKind(record, sourceTool));
      const label = cleanText(firstText(record, LABEL_KEYS) || compoundId || identifier || url, 300);
      const stableId = stableToken(`${sourceTool}\0${subjectId}`);
      const sourceArtifacts = unique([url, evidenceReceipt].filter((item): item is string => Boolean(item)), 8);
      const existing = subjects.get(subjectId);
      const candidate: SecurityAssistantEvidenceRef = {
        id: `live:${cleanToken(sourceTool)}:${stableId}`,
        kind: "live_source",
        title: label || subjectId,
        basis: "live",
        access: "allowed",
        sourceTool,
        sourceRef: subjectId,
        subjectId,
        subjectKind: kind || "source",
        subjectLabel: label || subjectId,
        createdAt: cleanIso(firstText(record, TIME_KEYS)),
        verifiedAt: cleanIso(firstText(record, TIME_KEYS)),
        verifiedBy: [sourceTool],
        sourceArtifacts,
        permalink: url,
      };
      subjects.set(subjectId, existing ? {
        ...existing,
        ...candidate,
        title: candidate.title || existing.title,
        subjectLabel: candidate.subjectLabel || existing.subjectLabel,
        permalink: candidate.permalink ?? existing.permalink,
        createdAt: candidate.createdAt ?? existing.createdAt,
        verifiedAt: candidate.verifiedAt ?? existing.verifiedAt,
        sourceArtifacts: unique([...existing.sourceArtifacts, ...candidate.sourceArtifacts], 8),
      } : candidate);
    }
    for (const child of Object.values(record)) visit(child, depth + 1);
  };

  visit(result, 0);
  return {
    sourceTool,
    evidenceReceipt,
    subjects: [...subjects.values()].slice(0, MAX_SUBJECTS),
    coverage: {
      returnedSubjects: observedCandidates,
      truncated: subjects.size > MAX_SUBJECTS,
    },
  };
}

function firstText(record: Record<string, unknown>, keys: readonly string[]): string {
  for (const key of keys) {
    const value = record[key];
    if (typeof value === "string" && value.trim()) return value;
    if (typeof value === "number" && Number.isFinite(value)) return String(value);
  }
  return "";
}

function firstUrl(record: Record<string, unknown>, keys: readonly string[]): string | undefined {
  for (const key of keys) {
    const value = safeUrl(record[key]);
    if (value) return value;
  }
  return undefined;
}

function inferredKind(record: Record<string, unknown>, sourceTool: string): string {
  if ("finding_id" in record || "findingId" in record) return "finding";
  if ("runtime_id" in record || "runtimeId" in record) return "runtime";
  if ("issue_key" in record || "issueKey" in record || "issue_number" in record) return "issue";
  if ("arn" in record || "resource_id" in record || "resourceId" in record) return "resource";
  if ("repository" in record || "repo" in record) return "repository";
  return sourceTool.replace(/^cerebro_/, "").replace(/[^a-z0-9]+/gi, "_");
}

function cleanText(value: unknown, max: number): string {
  return typeof value === "string" ? redactSecurityText(value).replace(/\s+/g, " ").trim().slice(0, max) : "";
}

function cleanToken(value: string): string {
  return value.toLowerCase().replace(/[^a-z0-9_.:-]+/g, "-").replace(/^-+|-+$/g, "").slice(0, 120);
}

function cleanIso(value: string): string | undefined {
  if (!value) return undefined;
  const time = Date.parse(value);
  return Number.isFinite(time) ? new Date(time).toISOString() : undefined;
}

function safeUrl(value: unknown): string | undefined {
  if (typeof value !== "string") return undefined;
  try {
    const url = new URL(value);
    return url.protocol === "https:" ? url.toString() : undefined;
  } catch {
    return undefined;
  }
}

function stableToken(value: string): string {
  return createHash("sha256").update(value).digest("hex").slice(0, 20);
}

function unique(values: string[], limit: number): string[] {
  return [...new Set(values)].slice(0, limit);
}
