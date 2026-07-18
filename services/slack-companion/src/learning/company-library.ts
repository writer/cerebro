import { createHash, randomUUID } from "node:crypto";
import { DynamoDBClient } from "@aws-sdk/client-dynamodb";
import {
  DynamoDBDocumentClient,
  GetCommand,
  PutCommand,
  QueryCommand,
  TransactWriteCommand,
  UpdateCommand,
} from "@aws-sdk/lib-dynamodb";
import type { AppConfig } from "../config/index.js";

export type CompanyLibraryRecordKind = "dossier" | "thesis";
export type CompanyLibraryClaimBasis = "observed" | "inferred" | "conflicted";

export interface CompanyLibraryClaim {
  text: string;
  basis: CompanyLibraryClaimBasis;
  scope?: string;
  asOf?: string;
  sourceMemoryIds: string[];
  sourceArtifacts: string[];
}

export interface CompanyLibraryRecord {
  id: string;
  kind: CompanyLibraryRecordKind;
  domainKey: string;
  title: string;
  summary: string;
  principles: string[];
  procedures: string[];
  ownership: string[];
  decisions: string[];
  exceptions: string[];
  contradictions: string[];
  openQuestions: string[];
  claims: CompanyLibraryClaim[];
  sourceMemoryIds: string[];
  sourceArtifacts: string[];
  channelIds: string[];
  confidence: number;
  status: "candidate";
  stalenessPolicy: "until_reverified";
  version: number;
  createdAt: string;
  updatedAt: string;
}

export interface CompanyLibraryBatch {
  fingerprint: string;
  sourceMemoryIds: string[];
  records: CompanyLibraryRecord[];
  processedAt: string;
}

export interface CompanyLibraryState {
  activeGenerationId?: string;
  lastSourceCreatedAt?: string;
  lastRunId?: string;
  lastCompletedAt?: string;
}

export interface CompanyLibraryRunReceipt {
  runId: string;
  status: "completed" | "failed" | "skipped";
  startedAt: string;
  completedAt: string;
  sourceRecords: number;
  batchesProcessed: number;
  batchesReused: number;
  dossiers: number;
  theses: number;
  errorType?: string;
}

type DocumentClient = Pick<DynamoDBDocumentClient, "send">;

export class CompanyLibraryStore {
  private readonly client?: DocumentClient;
  private readonly tableName?: string;
  private readonly partitionKey: string;
  private readonly records = new Map<string, CompanyLibraryRecord>();
  private readonly snapshots = new Map<string, Map<string, CompanyLibraryRecord>>();
  private readonly batches = new Map<string, CompanyLibraryBatch>();
  private readonly runs = new Map<string, CompanyLibraryRunReceipt>();
  private memoryState: CompanyLibraryState = {};
  private memoryLease?: { owner: string; expiresAt: number };

  constructor(config: AppConfig, options: { client?: DocumentClient } = {}) {
    this.tableName = config.learning.tableName;
    this.partitionKey = `tenant#${config.cerebro.tenantId}#company-library`;
    if (this.tableName) {
      this.client = options.client ?? DynamoDBDocumentClient.from(new DynamoDBClient({}), {
        marshallOptions: { removeUndefinedValues: true },
      });
    }
  }

  async list(limit = 160): Promise<CompanyLibraryRecord[]> {
    const bounded = Math.max(1, Math.min(500, Math.floor(limit)));
    const state = await this.state();
    if (state.activeGenerationId) return this.listGeneration(state.activeGenerationId, bounded);
    if (!this.client || !this.tableName) {
      return [...this.records.values()]
        .sort((left, right) => right.updatedAt.localeCompare(left.updatedAt))
        .slice(0, bounded)
        .map((record) => structuredClone(record));
    }
    const response = await this.client.send(new QueryCommand({
      TableName: this.tableName,
      KeyConditionExpression: "pk = :pk AND begins_with(sk, :prefix)",
      ExpressionAttributeValues: { ":pk": this.partitionKey, ":prefix": "record#" },
      Limit: bounded,
    }));
    return (response.Items ?? [])
      .map(decodeRecord)
      .filter((record): record is CompanyLibraryRecord => Boolean(record))
      .sort((left, right) => right.updatedAt.localeCompare(left.updatedAt));
  }

  async listGeneration(generationIdInput: string, limit = 160): Promise<CompanyLibraryRecord[]> {
    const generationId = clean(generationIdInput, 80);
    if (!generationId) return [];
    const bounded = Math.max(1, Math.min(500, Math.floor(limit)));
    if (!this.client || !this.tableName) {
      return [...(this.snapshots.get(generationId)?.values() ?? [])]
        .sort((left, right) => right.updatedAt.localeCompare(left.updatedAt))
        .slice(0, bounded)
        .map((record) => structuredClone(record));
    }
    const response = await this.client.send(new QueryCommand({
      TableName: this.tableName,
      KeyConditionExpression: "pk = :pk AND begins_with(sk, :prefix)",
      ExpressionAttributeValues: { ":pk": snapshotPartition(this.partitionKey, generationId), ":prefix": "record#" },
      Limit: bounded,
    }));
    return (response.Items ?? [])
      .map(decodeRecord)
      .filter((record): record is CompanyLibraryRecord => Boolean(record))
      .sort((left, right) => right.updatedAt.localeCompare(left.updatedAt));
  }

  async search(query: string, limit = 8): Promise<CompanyLibraryRecord[]> {
    const terms = normalizeTerms(query);
    const records = await this.list(500);
    return records
      .map((record) => ({ record, score: libraryScore(record, terms) }))
      .filter((item) => terms.length === 0 || item.score > 0)
      .sort((left, right) => right.score - left.score || right.record.updatedAt.localeCompare(left.record.updatedAt))
      .slice(0, Math.max(1, Math.min(20, Math.floor(limit))))
      .map((item) => item.record);
  }

  async read(idOrDomainKey: string): Promise<CompanyLibraryRecord | undefined> {
    const needle = idOrDomainKey.trim().toLowerCase();
    if (!needle) return undefined;
    return (await this.list(500)).find((record) => record.id.toLowerCase() === needle || record.domainKey === needle);
  }

  async put(recordInput: CompanyLibraryRecord): Promise<CompanyLibraryRecord> {
    const record = normalizeRecord(recordInput);
    const key = recordKey(record.kind, record.domainKey);
    const existing = await this.read(record.id).catch(() => undefined);
    const stored: CompanyLibraryRecord = {
      ...record,
      createdAt: existing?.createdAt ?? record.createdAt,
      version: Math.max(record.version, (existing?.version ?? 0) + 1),
    };
    if (!this.client || !this.tableName) {
      this.records.set(key, structuredClone(stored));
      return stored;
    }
    await this.client.send(new PutCommand({
      TableName: this.tableName,
      Item: {
        pk: this.partitionKey,
        sk: key,
        recordType: "company_library_record",
        ...stored,
      },
    }));
    return stored;
  }

  async publishSnapshot(
    generationIdInput: string,
    recordInputs: CompanyLibraryRecord[],
    state: CompanyLibraryState,
    receipt: CompanyLibraryRunReceipt,
  ): Promise<CompanyLibraryRecord[]> {
    const generationId = clean(generationIdInput, 80);
    if (!generationId) throw new Error("Company library snapshot generation id is required.");
    const existing = new Map((await this.list(500)).map((record) => [recordKey(record.kind, record.domainKey), record]));
    const normalized = new Map<string, CompanyLibraryRecord>();
    for (const input of recordInputs) {
      const record = normalizeRecord(input);
      normalized.set(recordKey(record.kind, record.domainKey), record);
    }
    const stored = [...normalized.entries()].map(([key, record]) => {
      const prior = existing.get(key);
      return {
        ...record,
        createdAt: prior?.createdAt ?? record.createdAt,
        updatedAt: receipt.completedAt,
        version: prior ? prior.version + 1 : Math.max(1, record.version),
      };
    });
    const activeState: CompanyLibraryState = { ...state, activeGenerationId: generationId };

    if (!this.client || !this.tableName) {
      if (this.memoryLease?.owner !== generationId) throw new Error("Company library snapshot publisher does not hold the lease.");
      this.snapshots.set(generationId, new Map(stored.map((record) => [recordKey(record.kind, record.domainKey), structuredClone(record)])));
      this.runs.set(receipt.runId, structuredClone(receipt));
      this.memoryState = structuredClone(activeState);
      return stored.map((record) => structuredClone(record));
    }

    const partition = snapshotPartition(this.partitionKey, generationId);
    for (const record of stored) {
      await this.client.send(new PutCommand({
        TableName: this.tableName,
        Item: {
          pk: partition,
          sk: recordKey(record.kind, record.domainKey),
          recordType: "company_library_record",
          generationId,
          ...record,
        },
      }));
    }
    await this.client.send(new TransactWriteCommand({
      ClientRequestToken: createHash("sha256").update(generationId).digest("hex").slice(0, 36),
      TransactItems: [{
        Update: {
          TableName: this.tableName,
          Key: { pk: this.partitionKey, sk: "state" },
          UpdateExpression: "SET recordType = :recordType, activeGenerationId = :generationId, lastSourceCreatedAt = :lastSourceCreatedAt, lastRunId = :lastRunId, lastCompletedAt = :lastCompletedAt",
          ConditionExpression: "leaseOwner = :generationId",
          ExpressionAttributeValues: {
            ":recordType": "company_library_state",
            ":generationId": generationId,
            ":lastSourceCreatedAt": activeState.lastSourceCreatedAt ?? "",
            ":lastRunId": activeState.lastRunId ?? "",
            ":lastCompletedAt": activeState.lastCompletedAt ?? "",
          },
        },
      }, {
        Put: {
          TableName: this.tableName,
          Item: {
            pk: this.partitionKey,
            sk: `run#${receipt.runId}`,
            recordType: "company_library_run",
            ...receipt,
          },
        },
      }],
    }));
    return stored;
  }

  async batch(fingerprint: string): Promise<CompanyLibraryBatch | undefined> {
    if (!this.client || !this.tableName) return clone(this.batches.get(fingerprint));
    const response = await this.client.send(new GetCommand({
      TableName: this.tableName,
      Key: { pk: this.partitionKey, sk: batchKey(fingerprint) },
    }));
    return decodeBatch(response.Item);
  }

  async saveBatch(batch: CompanyLibraryBatch): Promise<void> {
    const normalized: CompanyLibraryBatch = {
      fingerprint: clean(batch.fingerprint, 64),
      sourceMemoryIds: cleanList(batch.sourceMemoryIds, 80, 80),
      records: batch.records.map(normalizeRecord).slice(0, 12),
      processedAt: batch.processedAt,
    };
    if (!this.client || !this.tableName) {
      this.batches.set(normalized.fingerprint, structuredClone(normalized));
      return;
    }
    await this.client.send(new PutCommand({
      TableName: this.tableName,
      Item: {
        pk: this.partitionKey,
        sk: batchKey(normalized.fingerprint),
        recordType: "company_library_batch",
        ...normalized,
        expires_at: Math.floor(Date.now() / 1_000) + 400 * 86_400,
      },
    }));
  }

  async state(): Promise<CompanyLibraryState> {
    if (!this.client || !this.tableName) return structuredClone(this.memoryState);
    const response = await this.client.send(new GetCommand({
      TableName: this.tableName,
      Key: { pk: this.partitionKey, sk: "state" },
    }));
    return decodeState(response.Item);
  }

  async saveState(state: CompanyLibraryState): Promise<void> {
    if (!this.client || !this.tableName) {
      this.memoryState = structuredClone(state);
      return;
    }
    await this.client.send(new UpdateCommand({
      TableName: this.tableName,
      Key: { pk: this.partitionKey, sk: "state" },
      UpdateExpression: "SET recordType = :recordType, activeGenerationId = :activeGenerationId, lastSourceCreatedAt = :lastSourceCreatedAt, lastRunId = :lastRunId, lastCompletedAt = :lastCompletedAt",
      ExpressionAttributeValues: {
        ":recordType": "company_library_state",
        ":activeGenerationId": state.activeGenerationId ?? "",
        ":lastSourceCreatedAt": state.lastSourceCreatedAt ?? "",
        ":lastRunId": state.lastRunId ?? "",
        ":lastCompletedAt": state.lastCompletedAt ?? "",
      },
    }));
  }

  async acquireLease(owner: string = randomUUID(), now = new Date(), leaseMs = 30 * 60_000): Promise<string | undefined> {
    const expiresAt = now.getTime() + leaseMs;
    if (!this.client || !this.tableName) {
      if (this.memoryLease && this.memoryLease.expiresAt > now.getTime() && this.memoryLease.owner !== owner) return undefined;
      this.memoryLease = { owner, expiresAt };
      return owner;
    }
    try {
      await this.client.send(new UpdateCommand({
        TableName: this.tableName,
        Key: { pk: this.partitionKey, sk: "state" },
        UpdateExpression: "SET recordType = :recordType, leaseOwner = :owner, leaseExpiresAt = :expiresAt",
        ConditionExpression: "attribute_not_exists(leaseExpiresAt) OR leaseExpiresAt < :now OR leaseOwner = :owner",
        ExpressionAttributeValues: {
          ":recordType": "company_library_state",
          ":owner": owner,
          ":expiresAt": expiresAt,
          ":now": now.getTime(),
        },
      }));
      return owner;
    } catch (error) {
      if ((error as { name?: string }).name === "ConditionalCheckFailedException") return undefined;
      throw error;
    }
  }

  async releaseLease(owner: string): Promise<void> {
    if (!this.client || !this.tableName) {
      if (this.memoryLease?.owner === owner) this.memoryLease = undefined;
      return;
    }
    try {
      await this.client.send(new UpdateCommand({
        TableName: this.tableName,
        Key: { pk: this.partitionKey, sk: "state" },
        UpdateExpression: "REMOVE leaseOwner, leaseExpiresAt",
        ConditionExpression: "leaseOwner = :owner",
        ExpressionAttributeValues: { ":owner": owner },
      }));
    } catch (error) {
      if ((error as { name?: string }).name !== "ConditionalCheckFailedException") throw error;
    }
  }

  async saveRun(receipt: CompanyLibraryRunReceipt): Promise<void> {
    if (!this.client || !this.tableName) {
      this.runs.set(receipt.runId, structuredClone(receipt));
      return;
    }
    await this.client.send(new PutCommand({
      TableName: this.tableName,
      Item: {
        pk: this.partitionKey,
        sk: `run#${receipt.runId}`,
        recordType: "company_library_run",
        ...receipt,
      },
    }));
  }
}

export function companyLibraryBatchFingerprint(sourceMemoryIds: string[]): string {
  return createHash("sha256").update([...sourceMemoryIds].sort().join("|")).digest("hex").slice(0, 24);
}

export function companyLibraryRecordId(kind: CompanyLibraryRecordKind, domainKey: string): string {
  return createHash("sha256").update(`${kind}|${normalizeDomainKey(domainKey)}`).digest("hex").slice(0, 32);
}

export function normalizeCompanyLibraryRecord(input: Omit<CompanyLibraryRecord, "id" | "createdAt" | "updatedAt" | "version" | "status" | "stalenessPolicy">, now = new Date()): CompanyLibraryRecord {
  const domainKey = normalizeDomainKey(input.domainKey);
  return normalizeRecord({
    ...input,
    id: companyLibraryRecordId(input.kind, domainKey),
    domainKey,
    status: "candidate",
    stalenessPolicy: "until_reverified",
    version: 1,
    createdAt: now.toISOString(),
    updatedAt: now.toISOString(),
  });
}

function normalizeRecord(input: CompanyLibraryRecord): CompanyLibraryRecord {
  const domainKey = normalizeDomainKey(input.domainKey);
  const claims = input.claims.map((claim) => ({
    text: clean(claim.text, 900),
    basis: isClaimBasis(claim.basis) ? claim.basis : "inferred",
    scope: claim.scope ? clean(claim.scope, 200) : undefined,
    asOf: claim.asOf ? clean(claim.asOf, 48) : undefined,
    sourceMemoryIds: cleanList(claim.sourceMemoryIds, 80, 40),
    sourceArtifacts: cleanList(claim.sourceArtifacts, 180, 40),
  })).filter((claim) => claim.text && claim.sourceMemoryIds.length > 0).slice(0, 40);
  return {
    id: companyLibraryRecordId(input.kind, domainKey),
    kind: input.kind === "thesis" ? "thesis" : "dossier",
    domainKey,
    title: clean(input.title, 180),
    summary: clean(input.summary, 1_200),
    principles: cleanList(input.principles, 500, 20),
    procedures: cleanList(input.procedures, 800, 20),
    ownership: cleanList(input.ownership, 500, 20),
    decisions: cleanList(input.decisions, 600, 20),
    exceptions: cleanList(input.exceptions, 600, 20),
    contradictions: cleanList(input.contradictions, 700, 20),
    openQuestions: cleanList(input.openQuestions, 500, 20),
    claims,
    sourceMemoryIds: cleanList(input.sourceMemoryIds, 80, 160),
    sourceArtifacts: cleanList(input.sourceArtifacts, 180, 160),
    channelIds: cleanList(input.channelIds, 40, 40),
    confidence: Math.max(0, Math.min(1, Number(input.confidence) || 0)),
    status: "candidate",
    stalenessPolicy: "until_reverified",
    version: Math.max(1, Math.floor(input.version) || 1),
    createdAt: input.createdAt,
    updatedAt: input.updatedAt,
  };
}

function decodeRecord(item: Record<string, unknown>): CompanyLibraryRecord | undefined {
  const listFields = ["principles", "procedures", "ownership", "decisions", "exceptions", "contradictions", "openQuestions", "claims", "sourceMemoryIds", "sourceArtifacts", "channelIds"];
  if (
    (item.kind !== "dossier" && item.kind !== "thesis")
    || typeof item.domainKey !== "string"
    || typeof item.title !== "string"
    || typeof item.summary !== "string"
    || typeof item.createdAt !== "string"
    || typeof item.updatedAt !== "string"
    || listFields.some((field) => !Array.isArray(item[field]))
    || !(item.claims as unknown[]).every(validStoredClaim)
  ) return undefined;
  return normalizeRecord(item as unknown as CompanyLibraryRecord);
}

function validStoredClaim(value: unknown): boolean {
  if (!value || typeof value !== "object" || Array.isArray(value)) return false;
  const claim = value as Record<string, unknown>;
  return typeof claim.text === "string"
    && (claim.scope === undefined || typeof claim.scope === "string")
    && (claim.asOf === undefined || typeof claim.asOf === "string")
    && Array.isArray(claim.sourceMemoryIds)
    && Array.isArray(claim.sourceArtifacts);
}

function decodeBatch(item: Record<string, unknown> | undefined): CompanyLibraryBatch | undefined {
  if (!item || typeof item.fingerprint !== "string" || typeof item.processedAt !== "string" || !Array.isArray(item.records)) return undefined;
  return {
    fingerprint: item.fingerprint,
    sourceMemoryIds: Array.isArray(item.sourceMemoryIds) ? item.sourceMemoryIds.map(String) : [],
    records: item.records.map((value) => decodeRecord(value as Record<string, unknown>)).filter((record): record is CompanyLibraryRecord => Boolean(record)),
    processedAt: item.processedAt,
  };
}

function decodeState(item: Record<string, unknown> | undefined): CompanyLibraryState {
  return {
    activeGenerationId: typeof item?.activeGenerationId === "string" && item.activeGenerationId ? item.activeGenerationId : undefined,
    lastSourceCreatedAt: typeof item?.lastSourceCreatedAt === "string" && item.lastSourceCreatedAt ? item.lastSourceCreatedAt : undefined,
    lastRunId: typeof item?.lastRunId === "string" && item.lastRunId ? item.lastRunId : undefined,
    lastCompletedAt: typeof item?.lastCompletedAt === "string" && item.lastCompletedAt ? item.lastCompletedAt : undefined,
  };
}

function libraryScore(record: CompanyLibraryRecord, terms: string[]): number {
  const title = `${record.domainKey} ${record.title}`.toLowerCase();
  const body = [record.summary, ...record.principles, ...record.procedures, ...record.ownership, ...record.decisions, ...record.exceptions, ...record.claims.map((claim) => claim.text)].join(" ").toLowerCase();
  return terms.reduce((score, term) => score + (title.includes(term) ? 4 : 0) + (body.includes(term) ? 1 : 0), 0) + (record.kind === "dossier" ? 0.25 : 0);
}

function normalizeTerms(value: string): string[] {
  return [...new Set(value.toLowerCase().normalize("NFKD").replace(/[^a-z0-9]+/g, " ").split(/\s+/).filter((term) => term.length >= 2))].slice(0, 24);
}

function normalizeDomainKey(value: string): string {
  return value.toLowerCase().normalize("NFKD").replace(/[^a-z0-9]+/g, "-").replace(/^-|-$/g, "").slice(0, 100) || "general-company-knowledge";
}

function clean(value: string, max: number): string {
  return value.replace(/\s+/g, " ").trim().slice(0, max);
}

function cleanList(values: string[], maxChars: number, maxItems: number): string[] {
  return [...new Set(values.map((value) => clean(String(value), maxChars)).filter(Boolean))].slice(0, maxItems);
}

function recordKey(kind: CompanyLibraryRecordKind, domainKey: string): string {
  return `record#${kind}#${normalizeDomainKey(domainKey)}`;
}

function snapshotPartition(partitionKey: string, generationId: string): string {
  return `${partitionKey}#snapshot#${clean(generationId, 80)}`;
}

function batchKey(fingerprint: string): string {
  return `batch#${clean(fingerprint, 64)}`;
}

function isClaimBasis(value: string): value is CompanyLibraryClaimBasis {
  return value === "observed" || value === "inferred" || value === "conflicted";
}

function clone<T>(value: T | undefined): T | undefined {
  return value === undefined ? undefined : structuredClone(value);
}
