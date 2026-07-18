import { createHash } from "node:crypto";
import { DynamoDBClient } from "@aws-sdk/client-dynamodb";
import { DynamoDBDocumentClient, GetCommand, PutCommand, QueryCommand } from "@aws-sdk/lib-dynamodb";
import { z } from "zod";
import type { AppConfig } from "../config/index.js";
import { redactSecurityText } from "../security/redaction.js";
import { hashTelemetryId, recordMetric, telemetryEvent } from "../telemetry.js";
import type { SecurityAssistantAnswer, SecurityAssistantClaimEvidencePacket, SecurityAssistantEvidenceRef } from "./security-assistant-types.js";

const RECEIPT_RETENTION_DAYS = 365;
const HISTORICAL_VALIDITY_MS = 30 * 86_400_000;
const LIVE_VALIDITY_MS = 15 * 60_000;
const SOURCE_FEEDBACK_THRESHOLD = 2;

export type EvidenceGovernanceStatus = "current" | "expired" | "needs_reverification" | "contradicted";
export type EvidenceSourceFeedbackReason = "wrong_source" | "source_outdated" | "source_inaccessible";

export interface EvidenceGovernanceSource {
  sourceKey: string;
  evidenceId: string;
  kind: SecurityAssistantEvidenceRef["kind"];
  title: string;
  sourceTool?: string;
  sourceRefHash?: string;
  version: string;
  contentHash: string;
  observedAt: string;
  validUntil: string;
  status: EvidenceGovernanceStatus;
}

export interface EvidenceGovernanceClaim {
  revisionId: string;
  claimKey: string;
  claimId: string;
  summary: string;
  temporalScope: SecurityAssistantClaimEvidencePacket["temporalScope"];
  verification: SecurityAssistantClaimEvidencePacket["verification"];
  evidenceKeys: string[];
  status: EvidenceGovernanceStatus;
}

export interface EvidenceAnswerReceipt {
  receiptId: string;
  answerHash: string;
  channelId: string;
  threadHash: string;
  createdAt: string;
  validUntil: string;
  manifestHash: string;
  status: EvidenceGovernanceStatus;
  claims: EvidenceGovernanceClaim[];
  sources: EvidenceGovernanceSource[];
  secretValuesStored: false;
}

export interface EvidenceReceiptView {
  receiptId: string;
  createdAt: string;
  validUntil: string;
  status: EvidenceGovernanceStatus;
  claims: Array<Pick<EvidenceGovernanceClaim, "summary" | "temporalScope" | "status">>;
  sources: Array<Pick<EvidenceGovernanceSource, "evidenceId" | "kind" | "title" | "sourceTool" | "observedAt" | "validUntil" | "status">>;
}

export interface EvidenceSourceOption {
  evidenceId: string;
  title: string;
}

export interface EvidenceGovernanceOptions {
  dynamo?: { send(command: unknown): Promise<unknown> };
  now?: () => Date;
  feedbackThreshold?: number;
}

interface SourceState {
  sourceKey: string;
  currentVersion: string;
  status: EvidenceGovernanceStatus;
  reason?: EvidenceSourceFeedbackReason | "source_version_changed";
  updatedAt: string;
}

interface EvidenceDependency {
  sourceKey: string;
  sourceTitle: string;
  receiptId: string;
  channelId: string;
  threadHash: string;
  claimRevisionId: string;
  claimSummary: string;
  sourceVersion: string;
  validUntil: string;
}

interface ThreadInvalidation {
  sourceKey: string;
  sourceTitle: string;
  claimRevisionId: string;
  claimSummary: string;
  reason: EvidenceSourceFeedbackReason | "source_version_changed";
  invalidatedAt: string;
}

const sourceSchema = z.object({
  sourceKey: z.string(), evidenceId: z.string(), kind: z.enum(["memory", "company_library", "live_source"]), title: z.string(),
  sourceTool: z.string().optional(), sourceRefHash: z.string().optional(), version: z.string(), contentHash: z.string(), observedAt: z.string().datetime(),
  validUntil: z.string().datetime(), status: z.enum(["current", "expired", "needs_reverification", "contradicted"]),
});
const claimSchema = z.object({
  revisionId: z.string(), claimKey: z.string(), claimId: z.string(), summary: z.string(), temporalScope: z.enum(["historical", "current"]),
  verification: z.enum(["verified", "historical_only", "contradicted", "unverified", "blocked"]), evidenceKeys: z.array(z.string()),
  status: z.enum(["current", "expired", "needs_reverification", "contradicted"]),
});
const receiptSchema = z.object({
  receiptId: z.string(), answerHash: z.string(), channelId: z.string(), threadHash: z.string(), createdAt: z.string().datetime(), validUntil: z.string().datetime(),
  manifestHash: z.string(), status: z.enum(["current", "expired", "needs_reverification", "contradicted"]), claims: z.array(claimSchema), sources: z.array(sourceSchema),
  secretValuesStored: z.literal(false),
});

export class EvidenceGovernanceService {
  private readonly dynamo?: { send(command: unknown): Promise<unknown> };
  private readonly tableName?: string;
  private readonly now: () => Date;
  private readonly feedbackThreshold: number;
  private readonly receipts = new Map<string, EvidenceAnswerReceipt>();
  private readonly dependencies = new Map<string, EvidenceDependency[]>();
  private readonly sourceStates = new Map<string, SourceState>();
  private readonly sourceSignals = new Map<string, Set<string>>();
  private readonly threadInvalidations = new Map<string, ThreadInvalidation[]>();

  constructor(private readonly config: AppConfig, options: EvidenceGovernanceOptions = {}) {
    this.tableName = config.learning.tableName;
    this.now = options.now ?? (() => new Date());
    this.feedbackThreshold = Math.max(2, Math.min(options.feedbackThreshold ?? SOURCE_FEEDBACK_THRESHOLD, 10));
    if (options.dynamo) this.dynamo = options.dynamo;
    else if (config.learning.enabled && this.tableName) {
      this.dynamo = DynamoDBDocumentClient.from(new DynamoDBClient({}), { marshallOptions: { removeUndefinedValues: true } });
    }
  }

  async recordAnswer(input: {
    answerId: string;
    channelId: string;
    threadTs: string;
    answer: SecurityAssistantAnswer;
  }): Promise<EvidenceAnswerReceipt | undefined> {
    const packets = (input.answer.claimEvidence ?? []).filter((packet) => packet.evidence.length > 0).slice(0, 12);
    if (packets.length === 0) return undefined;
    const createdAt = this.now().toISOString();
    const sources = uniqueSources(packets.flatMap((packet) => packet.evidence), packets, createdAt);
    for (const source of sources) await this.observeSourceVersion(source);
    const claims = packets.map((packet) => governedClaim(packet, sources));
    const validUntil = earliestDate(sources.map((source) => source.validUntil), createdAt);
    const receiptSeed = {
      answerHash: digest(input.answerId),
      channelId: cleanId(input.channelId, 160),
      threadHash: digest(input.threadTs),
      createdAt,
      validUntil,
      claims,
      sources,
    };
    const manifestHash = digest(canonicalJson(receiptSeed));
    const receipt = receiptSchema.parse({
      receiptId: `receipt-${manifestHash.slice(0, 24)}`,
      ...receiptSeed,
      manifestHash,
      status: receiptStatus(claims, sources, this.now()),
      secretValuesStored: false,
    });
    await this.putReceipt(receipt);
    await Promise.all(claims.flatMap((claim) => claim.evidenceKeys.map((sourceKey) => {
      const source = sources.find((item) => item.sourceKey === sourceKey);
      if (!source) return Promise.resolve();
      return this.putDependency({
        sourceKey,
        sourceTitle: source.title,
        receiptId: receipt.receiptId,
        channelId: receipt.channelId,
        threadHash: receipt.threadHash,
        claimRevisionId: claim.revisionId,
        claimSummary: claim.summary,
        sourceVersion: source.version,
        validUntil: source.validUntil,
      });
    })));
    telemetryEvent("assistant.evidence_receipt.recorded", {
      component: "evidence-governance",
      operation: "record_receipt",
      "evidence.receipt_id_hash": hashTelemetryId(receipt.receiptId),
      "evidence.claim_count": receipt.claims.length,
      "evidence.source_count": receipt.sources.length,
      "evidence.status": receipt.status,
    });
    recordMetric("cerebro_slack_companion_evidence_receipts_total", { status: receipt.status }, 1);
    return receipt;
  }

  async receiptForAnswer(answerId: string, audienceChannelId: string): Promise<EvidenceReceiptView | undefined> {
    const receipt = await this.getReceipt(digest(answerId));
    if (!receipt || receipt.channelId !== audienceChannelId) return undefined;
    const states = new Map((await Promise.all(receipt.sources.map((source) => this.getSourceState(source.sourceKey))))
      .filter((state): state is SourceState => Boolean(state)).map((state) => [state.sourceKey, state]));
    const sources = receipt.sources.map((source) => applySourceState(source, states.get(source.sourceKey), this.now()));
    const claims = receipt.claims.map((claim) => ({
      ...claim,
      status: governedClaimStatus(claim, sources),
    }));
    return {
      receiptId: receipt.receiptId,
      createdAt: receipt.createdAt,
      validUntil: receipt.validUntil,
      status: receiptStatus(claims, sources, this.now()),
      claims: claims.map(({ summary, temporalScope, status }) => ({ summary, temporalScope, status })),
      sources: sources.map(({ evidenceId, kind, title, sourceTool, observedAt, validUntil, status }) => ({ evidenceId, kind, title, sourceTool, observedAt, validUntil, status })),
    };
  }

  async evidenceOptionsForAnswer(answerId: string, audienceChannelId: string): Promise<EvidenceSourceOption[]> {
    const receipt = await this.receiptForAnswer(answerId, audienceChannelId);
    return receipt?.sources.slice(0, 12).map((source) => ({ evidenceId: source.evidenceId, title: source.title })) ?? [];
  }

  async recordSourceFeedback(input: {
    answerId: string;
    audienceChannelId: string;
    evidenceId: string;
    reporterId: string;
    reason: EvidenceSourceFeedbackReason;
  }): Promise<{ accepted: boolean; corroborated: boolean; affectedClaims: number }> {
    const receipt = await this.getReceipt(digest(input.answerId));
    if (!receipt || receipt.channelId !== input.audienceChannelId) return { accepted: false, corroborated: false, affectedClaims: 0 };
    const source = receipt.sources.find((item) => item.evidenceId === input.evidenceId);
    if (!source) return { accepted: false, corroborated: false, affectedClaims: 0 };
    const reporterHash = digest(input.reporterId);
    const count = await this.putSourceSignal(source.sourceKey, reporterHash, input.reason);
    if (count < this.feedbackThreshold) return { accepted: true, corroborated: false, affectedClaims: 0 };
    const dependencies = await this.markSourceNeedsReverification(source, input.reason);
    telemetryEvent("assistant.evidence_source.invalidated", {
      component: "evidence-governance",
      operation: "source_feedback",
      "evidence.source_key_hash": hashTelemetryId(source.sourceKey),
      "evidence.feedback.reason": input.reason,
      "evidence.feedback.reporter_count": count,
      "evidence.affected_claim_count": dependencies.length,
    });
    recordMetric("cerebro_slack_companion_evidence_invalidations_total", { reason: input.reason }, 1);
    return { accepted: true, corroborated: true, affectedClaims: dependencies.length };
  }

  async promptBlockForThread(channelId: string, threadTs: string): Promise<string> {
    const invalidations = await this.getThreadInvalidations(channelId, digest(threadTs));
    if (invalidations.length === 0) return "";
    return [
      "Evidence requiring re-verification:",
      "Do not reuse these claims as current facts. Recheck the owning source before answering and state any correction plainly.",
      JSON.stringify(invalidations.slice(0, 12).map((item) => ({
        claim: item.claimSummary,
        source: item.sourceTitle,
        reason: item.reason,
        invalidated_at: item.invalidatedAt,
      }))),
    ].join("\n");
  }

  private async observeSourceVersion(source: EvidenceGovernanceSource): Promise<void> {
    const previous = await this.getSourceState(source.sourceKey);
    if (previous && previous.currentVersion !== source.version) {
      await this.markSourceNeedsReverification(source, "source_version_changed");
    }
    await this.putSourceState({ sourceKey: source.sourceKey, currentVersion: source.version, status: "current", updatedAt: this.now().toISOString() });
  }

  private async markSourceNeedsReverification(
    source: EvidenceGovernanceSource,
    reason: EvidenceSourceFeedbackReason | "source_version_changed",
  ): Promise<EvidenceDependency[]> {
    const dependencies = await this.getDependencies(source.sourceKey);
    await this.putSourceState({ sourceKey: source.sourceKey, currentVersion: source.version, status: "needs_reverification", reason, updatedAt: this.now().toISOString() });
    await Promise.all(dependencies.filter((item) => item.sourceVersion !== source.version || reason !== "source_version_changed")
      .map((dependency) => this.putThreadInvalidation(dependency, reason)));
    return dependencies;
  }

  private async putReceipt(receipt: EvidenceAnswerReceipt): Promise<void> {
    this.receipts.set(receipt.answerHash, clone(receipt));
    if (!this.dynamo || !this.tableName) return;
    await this.dynamo.send(new PutCommand({
      TableName: this.tableName,
      Item: { pk: this.rootPartition(), sk: `receipt#${receipt.answerHash}`, recordType: "evidence_answer_receipt", expires_at: expiresAt(receipt.createdAt, RECEIPT_RETENTION_DAYS), ...receipt },
    }));
  }

  private async getReceipt(answerHash: string): Promise<EvidenceAnswerReceipt | undefined> {
    const cached = this.receipts.get(answerHash);
    if (cached) return clone(cached);
    if (!this.dynamo || !this.tableName) return undefined;
    const response = await this.dynamo.send(new GetCommand({ TableName: this.tableName, Key: { pk: this.rootPartition(), sk: `receipt#${answerHash}` } })) as { Item?: unknown };
    const parsed = receiptSchema.safeParse(response.Item);
    if (!parsed.success) return undefined;
    this.receipts.set(answerHash, parsed.data);
    return clone(parsed.data);
  }

  private async putDependency(dependency: EvidenceDependency): Promise<void> {
    const current = this.dependencies.get(dependency.sourceKey) ?? [];
    this.dependencies.set(dependency.sourceKey, [...current.filter((item) => item.claimRevisionId !== dependency.claimRevisionId), clone(dependency)]);
    if (!this.dynamo || !this.tableName) return;
    await this.dynamo.send(new PutCommand({
      TableName: this.tableName,
      Item: { pk: this.sourcePartition(dependency.sourceKey), sk: `claim#${dependency.claimRevisionId}`, recordType: "evidence_dependency", ...dependency },
    }));
  }

  private async getDependencies(sourceKey: string): Promise<EvidenceDependency[]> {
    if (!this.dynamo || !this.tableName) return clone(this.dependencies.get(sourceKey) ?? []);
    const response = await this.dynamo.send(new QueryCommand({
      TableName: this.tableName,
      KeyConditionExpression: "pk = :pk AND begins_with(sk, :prefix)",
      ExpressionAttributeValues: { ":pk": this.sourcePartition(sourceKey), ":prefix": "claim#" },
      Limit: 100,
    })) as { Items?: EvidenceDependency[] };
    return clone(response.Items ?? []);
  }

  private async putSourceSignal(sourceKey: string, reporterHash: string, reason: EvidenceSourceFeedbackReason): Promise<number> {
    const reporters = this.sourceSignals.get(sourceKey) ?? new Set<string>();
    reporters.add(reporterHash);
    this.sourceSignals.set(sourceKey, reporters);
    if (!this.dynamo || !this.tableName) return reporters.size;
    await this.dynamo.send(new PutCommand({
      TableName: this.tableName,
      Item: { pk: this.sourcePartition(sourceKey), sk: `signal#${reporterHash}`, recordType: "evidence_source_feedback", reason, reporterHash, createdAt: this.now().toISOString(), expires_at: expiresAt(this.now().toISOString(), 120) },
    }));
    const response = await this.dynamo.send(new QueryCommand({
      TableName: this.tableName,
      KeyConditionExpression: "pk = :pk AND begins_with(sk, :prefix)",
      ExpressionAttributeValues: { ":pk": this.sourcePartition(sourceKey), ":prefix": "signal#" },
      Select: "COUNT",
      Limit: this.feedbackThreshold,
    })) as { Count?: number };
    return response.Count ?? 0;
  }

  private async putSourceState(state: SourceState): Promise<void> {
    this.sourceStates.set(state.sourceKey, clone(state));
    if (!this.dynamo || !this.tableName) return;
    await this.dynamo.send(new PutCommand({ TableName: this.tableName, Item: { pk: this.sourcePartition(state.sourceKey), sk: "state", recordType: "evidence_source_state", ...state } }));
  }

  private async getSourceState(sourceKey: string): Promise<SourceState | undefined> {
    const cached = this.sourceStates.get(sourceKey);
    if (cached) return clone(cached);
    if (!this.dynamo || !this.tableName) return undefined;
    const response = await this.dynamo.send(new GetCommand({ TableName: this.tableName, Key: { pk: this.sourcePartition(sourceKey), sk: "state" } })) as { Item?: SourceState };
    if (!response.Item?.sourceKey || !response.Item.currentVersion) return undefined;
    this.sourceStates.set(sourceKey, response.Item);
    return clone(response.Item);
  }

  private async putThreadInvalidation(dependency: EvidenceDependency, reason: ThreadInvalidation["reason"]): Promise<void> {
    const key = `${dependency.channelId}:${dependency.threadHash}`;
    const invalidation: ThreadInvalidation = {
      sourceKey: dependency.sourceKey,
      sourceTitle: dependency.sourceTitle,
      claimRevisionId: dependency.claimRevisionId,
      claimSummary: dependency.claimSummary,
      reason,
      invalidatedAt: this.now().toISOString(),
    };
    const current = this.threadInvalidations.get(key) ?? [];
    this.threadInvalidations.set(key, [...current.filter((item) => item.claimRevisionId !== invalidation.claimRevisionId), invalidation]);
    if (!this.dynamo || !this.tableName) return;
    await this.dynamo.send(new PutCommand({
      TableName: this.tableName,
      Item: { pk: this.threadPartition(dependency.channelId, dependency.threadHash), sk: `invalidation#${dependency.claimRevisionId}`, recordType: "evidence_thread_invalidation", ...invalidation },
    }));
  }

  private async getThreadInvalidations(channelId: string, threadHash: string): Promise<ThreadInvalidation[]> {
    const cached = this.threadInvalidations.get(`${channelId}:${threadHash}`);
    if (!this.dynamo || !this.tableName) return clone(cached ?? []);
    const response = await this.dynamo.send(new QueryCommand({
      TableName: this.tableName,
      KeyConditionExpression: "pk = :pk AND begins_with(sk, :prefix)",
      ExpressionAttributeValues: { ":pk": this.threadPartition(channelId, threadHash), ":prefix": "invalidation#" },
      Limit: 20,
    })) as { Items?: ThreadInvalidation[] };
    return clone(response.Items ?? []);
  }

  private rootPartition(): string { return `tenant#${this.config.cerebro.tenantId}#evidence-governance`; }
  private sourcePartition(sourceKey: string): string { return `${this.rootPartition()}#source#${sourceKey}`; }
  private threadPartition(channelId: string, threadHash: string): string { return `${this.rootPartition()}#thread#${digest(channelId)}#${threadHash}`; }
}

function uniqueSources(evidence: SecurityAssistantEvidenceRef[], packets: SecurityAssistantClaimEvidencePacket[], createdAt: string): EvidenceGovernanceSource[] {
  const seen = new Set<string>();
  return evidence.flatMap((item) => {
    const sourceKey = digest(`${item.kind}:${item.sourceRef ?? item.id}`);
    if (seen.has(sourceKey)) return [];
    seen.add(sourceKey);
    const packet = packets.find((candidate) => candidate.evidence.some((source) => source.id === item.id));
    const observedAt = safeDate(item.verifiedAt ?? item.createdAt, createdAt);
    const validityMs = item.basis === "live" && packet?.temporalScope === "current" ? LIVE_VALIDITY_MS : HISTORICAL_VALIDITY_MS;
    const validUntil = new Date(Date.parse(observedAt) + validityMs).toISOString();
    const title = cleanText(item.title, 240);
    const contentHash = digest(canonicalJson({ title, kind: item.kind, sourceTool: item.sourceTool, version: item.version, observedAt, artifacts: item.sourceArtifacts.map(digest) }));
    return [{
      sourceKey,
      evidenceId: cleanId(item.id, 150),
      kind: item.kind,
      title,
      sourceTool: cleanOptional(item.sourceTool, 160),
      sourceRefHash: item.sourceRef ? digest(item.sourceRef) : undefined,
      version: item.version ? String(item.version) : contentHash.slice(0, 24),
      contentHash,
      observedAt,
      validUntil,
      status: item.conflicted ? "contradicted" as const : Date.parse(validUntil) <= Date.parse(createdAt) ? "expired" as const : "current" as const,
    }];
  });
}

function governedClaim(packet: SecurityAssistantClaimEvidencePacket, sources: EvidenceGovernanceSource[]): EvidenceGovernanceClaim {
  const summary = cleanText(packet.claimText, 1_200);
  const evidenceKeys = packet.evidence.map((item) => digest(`${item.kind}:${item.sourceRef ?? item.id}`)).filter((key) => sources.some((source) => source.sourceKey === key));
  const claimKey = digest(`${packet.temporalScope}:${normalizeClaim(summary)}`);
  return {
    revisionId: digest(`${claimKey}:${packet.verification}:${evidenceKeys.sort().join(":")}`).slice(0, 32),
    claimKey,
    claimId: cleanId(packet.claimId, 200),
    summary,
    temporalScope: packet.temporalScope,
    verification: packet.verification,
    evidenceKeys,
    status: packet.verification === "contradicted" ? "contradicted" : packet.verification === "verified" ? "current" : "needs_reverification",
  };
}

function governedClaimStatus(claim: EvidenceGovernanceClaim, sources: EvidenceGovernanceSource[]): EvidenceGovernanceStatus {
  if (claim.status === "contradicted") return "contradicted";
  const dependencies = sources.filter((source) => claim.evidenceKeys.includes(source.sourceKey));
  if (dependencies.some((source) => source.status === "contradicted")) return "contradicted";
  if (dependencies.some((source) => source.status === "needs_reverification")) return "needs_reverification";
  if (dependencies.length === 0 || dependencies.every((source) => source.status === "expired")) return "expired";
  return "current";
}

function applySourceState(source: EvidenceGovernanceSource, state: SourceState | undefined, now: Date): EvidenceGovernanceSource {
  if (state?.status === "needs_reverification" || (state && state.currentVersion !== source.version)) return { ...source, status: "needs_reverification" };
  if (source.status === "contradicted") return source;
  return { ...source, status: Date.parse(source.validUntil) <= now.getTime() ? "expired" : "current" };
}

function receiptStatus(claims: EvidenceGovernanceClaim[], sources: EvidenceGovernanceSource[], now: Date): EvidenceGovernanceStatus {
  const states = claims.map((claim) => governedClaimStatus(claim, sources));
  if (states.includes("contradicted")) return "contradicted";
  if (states.includes("needs_reverification")) return "needs_reverification";
  if (states.includes("expired") || sources.some((source) => Date.parse(source.validUntil) <= now.getTime())) return "expired";
  return "current";
}

function earliestDate(values: string[], fallback: string): string {
  return values.sort((left, right) => Date.parse(left) - Date.parse(right))[0] ?? fallback;
}

function canonicalJson(value: unknown): string {
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(",")}]`;
  if (value && typeof value === "object") return `{${Object.entries(value as Record<string, unknown>).sort(([a], [b]) => a.localeCompare(b)).map(([key, item]) => `${JSON.stringify(key)}:${canonicalJson(item)}`).join(",")}}`;
  return JSON.stringify(value);
}

function normalizeClaim(value: string): string { return value.toLowerCase().replace(/[^a-z0-9]+/g, " ").trim(); }
function digest(value: string): string { return createHash("sha256").update(value).digest("hex"); }
function cleanId(value: string, max: number): string { return redactSecurityText(value).replace(/\s+/g, " ").trim().slice(0, max); }
function cleanText(value: string, max: number): string { return redactSecurityText(value).replace(/\s+/g, " ").trim().slice(0, max); }
function cleanOptional(value: string | undefined, max: number): string | undefined { return value ? cleanText(value, max) : undefined; }
function safeDate(value: string | undefined, fallback: string): string { return value && Number.isFinite(Date.parse(value)) ? new Date(value).toISOString() : fallback; }
function expiresAt(createdAt: string, days: number): number { return Math.floor((Date.parse(createdAt) + days * 86_400_000) / 1_000); }
function clone<T>(value: T): T { return JSON.parse(JSON.stringify(value)) as T; }
