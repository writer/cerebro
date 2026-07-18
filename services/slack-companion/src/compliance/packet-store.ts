import { DynamoDBClient } from "@aws-sdk/client-dynamodb";
import { DynamoDBDocumentClient, GetCommand, PutCommand, QueryCommand } from "@aws-sdk/lib-dynamodb";
import type { SlackActor } from "../auth.js";
import type { AppConfig } from "../config/index.js";
import { redactSecurityText } from "../security/redaction.js";
import type { CompliancePacket, CompliancePacketType } from "./work-packets.js";

export interface CommandSender {
  send(command: unknown): Promise<unknown>;
}

export interface CompliancePacketStoreOptions {
  dynamo?: CommandSender;
  now?: () => Date;
}

export interface StoredCompliancePacket {
  packet_id: string;
  packet_type: CompliancePacketType;
  title: string;
  readiness: CompliancePacket["readiness"];
  ready_for_review: boolean;
  gaps: string[];
  review_actions: string[];
  packet: CompliancePacket;
  createdAt: string;
  updatedAt: string;
  createdBy?: SlackActor;
  storage_mode: "dynamodb" | "memory";
  secret_values_stored: false;
}

const storeCache = new WeakMap<AppConfig, CompliancePacketStore>();

export function compliancePacketStore(config: AppConfig, options?: CompliancePacketStoreOptions): CompliancePacketStore {
  if (options) return new CompliancePacketStore(config, options);
  const cached = storeCache.get(config);
  if (cached) return cached;
  const store = new CompliancePacketStore(config);
  storeCache.set(config, store);
  return store;
}

export class CompliancePacketStore {
  private readonly dynamo?: CommandSender;
  private readonly tableName?: string;
  private readonly now: () => Date;
  private readonly inMemoryPackets = new Map<string, StoredCompliancePacket>();

  constructor(
    private readonly config: AppConfig,
    options: CompliancePacketStoreOptions = {},
  ) {
    this.now = options.now ?? (() => new Date());
    this.tableName = config.schedules.tableName;
    if (this.tableName) {
      this.dynamo = options.dynamo ?? DynamoDBDocumentClient.from(new DynamoDBClient({}));
    }
  }

  get storageMode(): "dynamodb" | "memory" {
    return this.dynamo && this.tableName ? "dynamodb" : "memory";
  }

  async put(packet: CompliancePacket, actor?: SlackActor): Promise<StoredCompliancePacket> {
    const now = this.now().toISOString();
    const existing = await this.get(packet.packet_id);
    const sanitized = sanitizePacket(packet);
    const record: StoredCompliancePacket = {
      packet_id: sanitized.packet_id,
      packet_type: sanitized.packet_type,
      title: sanitized.title,
      readiness: sanitized.readiness,
      ready_for_review: sanitized.ready_for_review,
      gaps: sanitized.gaps,
      review_actions: sanitized.review_actions,
      packet: sanitized,
      createdAt: existing?.createdAt ?? now,
      updatedAt: now,
      createdBy: existing?.createdBy ?? actor,
      storage_mode: this.storageMode,
      secret_values_stored: false,
    };
    if (this.dynamo && this.tableName) {
      await this.dynamo.send(new PutCommand({
        TableName: this.tableName,
        Item: {
          pk: partitionKey(this.config),
          sk: sortKey(record.packet_id),
          ...record,
        },
      }));
      return record;
    }
    this.inMemoryPackets.set(record.packet_id, clone(record));
    return record;
  }

  async get(packetId: string): Promise<StoredCompliancePacket | undefined> {
    if (this.dynamo && this.tableName) {
      const response = await this.dynamo.send(new GetCommand({
        TableName: this.tableName,
        Key: {
          pk: partitionKey(this.config),
          sk: sortKey(packetId),
        },
      })) as { Item?: Record<string, unknown> };
      return toStoredCompliancePacket(response.Item, this.storageMode);
    }
    const record = this.inMemoryPackets.get(packetId);
    return record ? clone(record) : undefined;
  }

  async list(limit = 25): Promise<StoredCompliancePacket[]> {
    const safeLimit = Math.max(1, Math.min(Math.trunc(limit), 100));
    if (this.dynamo && this.tableName) {
      const response = await this.dynamo.send(new QueryCommand({
        TableName: this.tableName,
        KeyConditionExpression: "pk = :pk AND begins_with(sk, :prefix)",
        ExpressionAttributeValues: {
          ":pk": partitionKey(this.config),
          ":prefix": "packet#",
        },
        Limit: safeLimit,
        ScanIndexForward: false,
      })) as { Items?: Record<string, unknown>[] };
      return (response.Items ?? [])
        .map((item) => toStoredCompliancePacket(item, this.storageMode))
        .filter(isStoredCompliancePacket)
        .sort(comparePackets)
        .slice(0, safeLimit);
    }
    return [...this.inMemoryPackets.values()].map(clone).sort(comparePackets).slice(0, safeLimit);
  }
}

function partitionKey(config: AppConfig): string {
  return `tenant#${config.cerebro.tenantId}#compliance-packets`;
}

function sortKey(packetId: string): string {
  return `packet#${packetId}`;
}

function sanitizePacket(packet: CompliancePacket): CompliancePacket {
  const sanitized = sanitizeJson(packet) as CompliancePacket;
  return {
    ...sanitized,
    secret_values_stored: false,
  };
}

function sanitizeJson(value: unknown): unknown {
  if (typeof value === "string") return redactSecurityText(value);
  if (Array.isArray(value)) return value.map(sanitizeJson);
  if (!value || typeof value !== "object") return value;
  return Object.fromEntries(Object.entries(value).map(([key, item]) => [key, sanitizeJson(item)]));
}

function toStoredCompliancePacket(item: Record<string, unknown> | undefined, storageMode: "dynamodb" | "memory"): StoredCompliancePacket | undefined {
  if (!item) return undefined;
  if (typeof item.packet_id !== "string" || typeof item.packet_type !== "string" || typeof item.title !== "string") return undefined;
  if (typeof item.readiness !== "string" || typeof item.ready_for_review !== "boolean") return undefined;
  if (typeof item.createdAt !== "string" || typeof item.updatedAt !== "string") return undefined;
  const packet = objectValue(item.packet) as CompliancePacket | undefined;
  if (!packet || packet.secret_values_stored !== false) return undefined;
  const createdBy = objectValue(item.createdBy);
  return {
    packet_id: item.packet_id,
    packet_type: item.packet_type as CompliancePacketType,
    title: item.title,
    readiness: item.readiness as CompliancePacket["readiness"],
    ready_for_review: item.ready_for_review,
    gaps: Array.isArray(item.gaps) ? item.gaps.map(String) : [],
    review_actions: Array.isArray(item.review_actions) ? item.review_actions.map(String) : [],
    packet,
    createdAt: item.createdAt,
    updatedAt: item.updatedAt,
    createdBy: actorValue(createdBy),
    storage_mode: storageMode,
    secret_values_stored: false,
  };
}

function actorValue(value: Record<string, unknown> | undefined): SlackActor | undefined {
  if (!value || typeof value.slackUserId !== "string" || typeof value.actorId !== "string") return undefined;
  return {
    slackUserId: value.slackUserId,
    actorId: value.actorId,
    displayName: typeof value.displayName === "string" ? value.displayName : undefined,
  };
}

function objectValue(value: unknown): Record<string, unknown> | undefined {
  return value && typeof value === "object" && !Array.isArray(value) ? value as Record<string, unknown> : undefined;
}

function isStoredCompliancePacket(value: StoredCompliancePacket | undefined): value is StoredCompliancePacket {
  return Boolean(value);
}

function comparePackets(left: StoredCompliancePacket, right: StoredCompliancePacket): number {
  return right.updatedAt.localeCompare(left.updatedAt);
}

function clone<T>(value: T): T {
  return JSON.parse(JSON.stringify(value)) as T;
}
