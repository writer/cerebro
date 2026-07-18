import { DynamoDBClient } from "@aws-sdk/client-dynamodb";
import { DynamoDBDocumentClient, PutCommand, QueryCommand, UpdateCommand } from "@aws-sdk/lib-dynamodb";
import type { AppConfig } from "../../config/index.js";
import { logger } from "../../logger.js";
import { LearningDocsFiles, type LearningDocFile, type LearningDocWriteInput, type LearningDocWriteResult } from "../learning-docs.js";
import type { SecurityMemoryKind, SecurityMemoryPromotionState, SecurityMemoryRecallInput, SecurityMemoryRecallResult, SecurityMemoryRecord, SecurityMemoryStalenessPolicy, SecurityMemoryWriteInput } from "../memory-types.js";
import { toMemoryRecord } from "./codec.js";
import { curateMemoryWrite, rememberManyCurated } from "./curation-write.js";
import { isExpired } from "./hygiene.js";
import { memoryIntelligence } from "./intelligence.js";
import { boundedLimit, normalizeSearchText, parseSince } from "./normalization.js";
import { activeMemoryItems, curatedMemoryExpirations, curatedMemoryHygieneResult, memoryHygieneResult, planMemoryHygieneExpirations, recordCuratedMemoryHygieneTelemetry, recordMemoryHygieneTelemetry } from "./hygiene-runner.js";
import { curatedRecall as buildCuratedRecall, lexicalRecall } from "./recall.js";
import { emptyRecallDiagnostics, extractMemoryEntities, scoreRecordDetail, termsFor } from "./scoring.js";
import type { MemoryRecordItem, SecurityMemoryBatchWriteResult, SecurityMemoryHygieneResult, SecurityMemoryPromotionInput, SecurityMemoryPromotionResult, SecurityMemoryStoreOptions } from "./types.js";
import { buildSecurityMemoryRecord } from "./write.js";
import { WorkingMemoryFiles, type WorkingMemoryWriteInput, type WorkingMemoryWriteResult, type WorkingMemoryEntrySet } from "../working-memory.js";
import { CompanyLibraryStore } from "../company-library.js";

export type {
  MemoryQueryIntent,
  SecurityMemoryKind,
  SecurityMemoryPromotionState,
  SecurityMemoryRecallDiagnostics,
  SecurityMemoryRecallInput,
  SecurityMemoryRecallMatch,
  SecurityMemoryRecallResult,
  SecurityMemoryRecord,
  SecurityMemorySourceKind,
  SecurityMemoryStalenessPolicy,
  SecurityMemoryWriteInput,
} from "../memory-types.js";
export type { SecurityMemoryBatchWriteResult, SecurityMemoryHygieneResult, SecurityMemoryPromotionInput, SecurityMemoryPromotionResult, SecurityMemoryStoreOptions } from "./types.js";

export class SecurityMemoryStore {
  private readonly client?: DynamoDBDocumentClient;
  private readonly tableName?: string;
  private readonly partitionKey: string;
  private readonly inMemoryRecords: SecurityMemoryRecord[] = [];
  private readonly workingMemory: WorkingMemoryFiles;
  private readonly learningDocs: LearningDocsFiles;
  readonly companyLibrary: CompanyLibraryStore;

  constructor(private readonly config: AppConfig, private readonly options: SecurityMemoryStoreOptions = {}) {
    this.tableName = config.learning.tableName;
    this.partitionKey = `tenant#${config.cerebro.tenantId}#security`;
    this.workingMemory = new WorkingMemoryFiles({
      enabled: config.learning.workingMemoryEnabled,
      directory: config.learning.workingMemoryDir,
      memoryCharLimit: config.learning.workingMemoryCharLimit,
      teamCharLimit: config.learning.teamMemoryCharLimit,
    });
    this.learningDocs = new LearningDocsFiles({
      enabled: config.learning.learningDocsEnabled,
      directory: config.learning.learningDocsDir,
      fallbackDirectory: config.learning.workingMemoryDir ? `${config.learning.workingMemoryDir}/docs` : undefined,
      charLimit: config.learning.learningDocsCharLimit,
    });
    this.companyLibrary = new CompanyLibraryStore(config);
    if (config.learning.enabled && this.tableName) {
      this.client = DynamoDBDocumentClient.from(new DynamoDBClient({}));
    }
  }

  workingMemoryPromptBlock(): string {
    return [this.workingMemory.promptBlock(), this.learningDocs.promptBlock()].filter(Boolean).join("\n\n");
  }

  readWorkingMemory(target?: string): WorkingMemoryEntrySet[] {
    return target ? [this.workingMemory.read(target)] : this.workingMemory.readAll();
  }

  writeWorkingMemory(input: WorkingMemoryWriteInput): WorkingMemoryWriteResult {
    return this.workingMemory.write(input);
  }

  readLearningDocs(target?: string): LearningDocFile[] {
    return target ? [this.learningDocs.read(target)] : this.learningDocs.readAll();
  }

  writeLearningDocs(input: LearningDocWriteInput): LearningDocWriteResult {
    return this.learningDocs.write(input);
  }

  async recordsBySourceKind(sourceKind: SecurityMemoryRecord["sourceKind"], limit = 5_000): Promise<SecurityMemoryRecord[]> {
    return (await this.recentRecords(limit)).filter((record) => record.sourceKind === sourceKind);
  }

  async search(query: string, limit = this.config.learning.maxSearchResults, audienceChannelId?: string): Promise<SecurityMemoryRecord[]> {
    if (!this.config.learning.enabled) return [];
    if (this.options.curator) {
      return (await this.recallWithDiagnostics({ query, limit, audienceChannelId })).memories;
    }
    const normalizedLimit = boundedLimit(limit, this.config.learning.maxSearchResults);
    const records = await this.recentRecords(Math.max(150, normalizedLimit * 30));
    const audience = audienceChannelId?.trim();
    const terms = termsFor(query);
    const entities = extractMemoryEntities(query);
    return records
      .filter((record) => !isExpired(record))
      .filter((record) => !audience || !record.channelId || record.channelId === audience)
      .map((record) => {
        const detail = scoreRecordDetail(record, terms, query, entities);
        const intelligence = memoryIntelligence(record);
        return {
          record,
          baseScore: detail.score,
          score: detail.score + intelligence.trustBoost,
        };
      })
      .filter((item) => item.baseScore > 0 || terms.length === 0)
      .sort((left, right) => right.score - left.score || right.record.createdAt.localeCompare(left.record.createdAt))
      .slice(0, normalizedLimit)
      .map((item) => item.record);
  }

  async recall(input: SecurityMemoryRecallInput = {}): Promise<SecurityMemoryRecord[]> {
    return (await this.recallWithDiagnostics(input)).memories;
  }

  async recallWithDiagnostics(input: SecurityMemoryRecallInput = {}): Promise<SecurityMemoryRecallResult> {
    if (!this.config.learning.enabled) return {
      memories: [],
      diagnostics: emptyRecallDiagnostics("memory disabled"),
    };
    const normalizedLimit = boundedLimit(input.limit ?? this.config.learning.maxSearchResults, this.config.learning.maxSearchResults);
    const records = await this.recentRecords(Math.max(200, normalizedLimit * 40));
    const kindSet = input.kinds?.length ? new Set(input.kinds) : undefined;
    const channelId = input.channelId?.trim();
    const audienceChannelId = input.audienceChannelId?.trim();
    const sinceMs = parseSince(input.since);
    const candidates = records
      .filter((record) => !isExpired(record))
      .filter((record) => !kindSet || kindSet.has(record.kind))
      .filter((record) => !audienceChannelId || !record.channelId || record.channelId === audienceChannelId)
      .filter((record) => !channelId || record.channelId === channelId)
      .filter((record) => sinceMs === undefined || Date.parse(record.createdAt) >= sinceMs);

    if (this.options.curator) {
      try {
        return await this.curatedRecall(input, candidates, normalizedLimit);
      } catch (error) {
        logger.warn("memory curator recall failed; using lexical recall", { error: shortError(error) });
        const recalled = lexicalRecall({ recall: input, candidates, limit: normalizedLimit });
        recalled.diagnostics.warnings = [
          `Memory curator recall failed; using lexical memory recall. ${shortError(error)}`,
          ...recalled.diagnostics.warnings,
        ].slice(0, 8);
        return recalled;
      }
    }

    return lexicalRecall({ recall: input, candidates, limit: normalizedLimit });
  }

  async remember(input: SecurityMemoryWriteInput): Promise<SecurityMemoryRecord | undefined> {
    if (!this.config.learning.enabled) return undefined;
    const rawInput = this.options.curator ? await this.curatedWrite(input) : input;
    if (!rawInput) return undefined;
    return (await this.persistPreparedWrite(rawInput, !this.options.curator)).record;
  }
  async rememberWithRequiredCuration(input: SecurityMemoryWriteInput): Promise<SecurityMemoryRecord | undefined> {
    return this.options.curator ? this.remember(input) : undefined;
  }
  async rememberManyWithRequiredCuration(input: SecurityMemoryWriteInput): Promise<SecurityMemoryBatchWriteResult> {
    return rememberManyCurated({
      enabled: this.config.learning.enabled,
      candidate: input,
      curator: this.options.curator,
      recent: (limit) => this.recentRecords(limit),
      persist: (prepared, extractEntities) => this.persistPreparedWrite(prepared, extractEntities),
    });
  }

  private async persistPreparedWrite(
    rawInput: SecurityMemoryWriteInput,
    extractEntities: boolean,
  ): Promise<{ record: SecurityMemoryRecord; inserted: boolean }> {
    const { record, contentHash } = buildSecurityMemoryRecord(rawInput, {
      now: new Date(),
      extractEntities,
    });
    const duplicate = await this.findDuplicate(contentHash, rawInput.kind, rawInput.channelId);
    if (duplicate) return { record: duplicate, inserted: false };

    if (this.client && this.tableName) {
      await this.client.send(new PutCommand({
        TableName: this.tableName,
        Item: {
          pk: this.partitionKey,
          sk: `${record.createdAt}#${record.id}`,
          ...record,
        },
      }));
      this.updateLearningDocs(record);
      return { record, inserted: true };
    }

    this.inMemoryRecords.push(record);
    this.inMemoryRecords.sort((left, right) => right.createdAt.localeCompare(left.createdAt));
    this.inMemoryRecords.splice(250);
    this.updateLearningDocs(record);
    return { record, inserted: true };
  }
  async promoteToLearningDocs(input: SecurityMemoryPromotionInput): Promise<SecurityMemoryPromotionResult> {
    if (!this.config.learning.enabled) return { promoted: false, error: "memory_disabled" };
    const needleId = input.id?.trim();
    const needleTopic = normalizeSearchText(input.topic ?? "");
    if (!needleId && !needleTopic) return { promoted: false, error: "id_or_topic_required" };
    const items = await this.recentRecordItems(500);
    const matches = items
      .filter((item) => !isExpired(item.record))
      .filter((item) => (needleId && item.record.id === needleId) || (needleTopic && normalizeSearchText(item.record.topic).includes(needleTopic)));
    if (matches.length === 0) return { promoted: false, error: "memory_not_found" };
    if (matches.length > 1 && !needleId) return { promoted: false, error: "topic_matched_multiple_records" };
    const item = matches[0]!;
    const record = {
      ...item.record,
      promotionState: "promoted" as SecurityMemoryPromotionState,
      verifiedAt: item.record.verifiedAt ?? new Date().toISOString(),
      stalenessPolicy: "durable" as SecurityMemoryStalenessPolicy,
      expiresAt: undefined,
    };
    const learningDoc = this.learningDocs.remember(record);
    if (learningDoc?.success) {
      await this.promoteMemoryItem(item, record.verifiedAt);
    }
    return { promoted: Boolean(learningDoc?.success), record, learningDoc, error: learningDoc?.success === false ? learningDoc.error : undefined };
  }

  async runHygiene(input: { dryRun?: boolean; now?: Date } = {}): Promise<SecurityMemoryHygieneResult> {
    if (!this.config.learning.enabled) return { checked: 0, expired: 0, duplicateExpired: 0, staleTransientExpired: 0, dryRun: Boolean(input.dryRun) };
    const now = input.now ?? new Date();
    const items = await this.recentRecordItems(500);
    if (this.options.curator) {
      return this.curatedHygiene(items, { dryRun: input.dryRun, now });
    }
    const expirations = planMemoryHygieneExpirations(items, now);
    if (!input.dryRun) {
      const expiresAt = now.toISOString();
      for (const expiration of expirations) {
        await this.expireMemoryItem(expiration.item, expiresAt);
      }
    }
    const result = memoryHygieneResult(items, expirations, Boolean(input.dryRun));
    recordMemoryHygieneTelemetry(result);
    return result;
  }
  private async findDuplicate(contentHash: string, kind: SecurityMemoryKind, channelId: string | undefined): Promise<SecurityMemoryRecord | undefined> {
    const recent = await this.recentRecords(100).catch(() => []);
    return recent
      .filter((record) => !isExpired(record))
      .find((record) => record.contentHash === contentHash && record.kind === kind && (record.channelId ?? "") === (channelId ?? ""));
  }

  private async curatedWrite(input: SecurityMemoryWriteInput): Promise<SecurityMemoryWriteInput | undefined> {
    return curateMemoryWrite(input, this.options.curator!, await this.recentRecords(40));
  }

  private async curatedRecall(input: SecurityMemoryRecallInput, candidates: SecurityMemoryRecord[], limit: number): Promise<SecurityMemoryRecallResult> {
    const considered = candidates.slice(0, Math.max(40, Math.min(120, limit * 30)));
    const decision = await this.options.curator!.curateRecall({
      query: input.query,
      candidates: considered,
      limit,
      now: new Date(),
    });
    return buildCuratedRecall({ recall: input, candidates, limit, consideredCount: considered.length, decision });
  }

  private async curatedHygiene(items: MemoryRecordItem[], input: { dryRun?: boolean; now: Date }): Promise<SecurityMemoryHygieneResult> {
    const active = activeMemoryItems(items);
    const decision = await this.options.curator!.curateHygiene({
      records: active.map((item) => item.record),
      now: input.now,
    });
    const expirations = curatedMemoryExpirations(active, decision);
    if (!input.dryRun) {
      const expiresAt = input.now.toISOString();
      for (const item of expirations) {
        await this.expireMemoryItem(item, expiresAt);
      }
    }
    const result = curatedMemoryHygieneResult(active, expirations, Boolean(input.dryRun));
    recordCuratedMemoryHygieneTelemetry(result);
    return result;
  }

  private updateLearningDocs(record: SecurityMemoryRecord): void {
    try {
      this.learningDocs.remember(record);
    } catch (error) {
      logger.warn("learning doc update failed", { error: String(error), kind: record.kind, topic: record.topic });
    }
  }

  private async recentRecords(limit: number): Promise<SecurityMemoryRecord[]> {
    return (await this.recentRecordItems(limit)).map((item) => item.record);
  }

  private async recentRecordItems(limit: number): Promise<MemoryRecordItem[]> {
    const normalizedLimit = Math.min(Math.max(limit, 1), 5_000);
    if (this.client && this.tableName) {
      const records: MemoryRecordItem[] = [];
      let exclusiveStartKey: Record<string, unknown> | undefined;
      while (records.length < normalizedLimit) {
        const response = await this.client.send(new QueryCommand({
          TableName: this.tableName,
          KeyConditionExpression: "pk = :pk",
          ExpressionAttributeValues: { ":pk": this.partitionKey },
          ScanIndexForward: false,
          Limit: Math.min(100, normalizedLimit - records.length),
          ExclusiveStartKey: exclusiveStartKey,
        }));
        records.push(...((response.Items ?? [])
          .map((item) => {
            const record = toMemoryRecord(item);
            if (!record) return undefined;
            return { record, sk: typeof item.sk === "string" ? item.sk : undefined };
          })
          .filter(Boolean) as MemoryRecordItem[]));
        exclusiveStartKey = response.LastEvaluatedKey as Record<string, unknown> | undefined;
        if (!exclusiveStartKey) break;
      }
      return records;
    }
    return this.inMemoryRecords.slice(0, normalizedLimit).map((record) => ({ record }));
  }

  private async expireMemoryItem(item: MemoryRecordItem, expiresAt: string): Promise<void> {
    item.record.expiresAt = expiresAt;
    if (this.client && this.tableName && item.sk) {
      await this.client.send(new UpdateCommand({
        TableName: this.tableName,
        Key: { pk: this.partitionKey, sk: item.sk },
        UpdateExpression: "SET expiresAt = :expiresAt, expires_at = :ttl",
        ExpressionAttributeValues: {
          ":expiresAt": expiresAt,
          ":ttl": Math.floor(Date.parse(expiresAt) / 1000),
        },
      }));
    }
  }

  private async promoteMemoryItem(item: MemoryRecordItem, verifiedAt: string): Promise<void> {
    item.record.promotionState = "promoted";
    item.record.verifiedAt = verifiedAt;
    item.record.stalenessPolicy = "durable";
    item.record.expiresAt = undefined;
    if (this.client && this.tableName && item.sk) {
      await this.client.send(new UpdateCommand({
        TableName: this.tableName,
        Key: { pk: this.partitionKey, sk: item.sk },
        UpdateExpression: "SET promotionState = :promotionState, verifiedAt = :verifiedAt, stalenessPolicy = :stalenessPolicy REMOVE expiresAt, expires_at",
        ExpressionAttributeValues: {
          ":promotionState": "promoted",
          ":verifiedAt": verifiedAt,
          ":stalenessPolicy": "durable",
        },
      }));
    }
  }
}

function shortError(error: unknown): string {
  const message = error instanceof Error ? error.message : String(error);
  return message.replace(/\s+/g, " ").slice(0, 240);
}
