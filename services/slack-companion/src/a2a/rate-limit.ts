import { randomUUID } from "node:crypto";
import { AsyncLocalStorage } from "node:async_hooks";
import { DynamoDBClient } from "@aws-sdk/client-dynamodb";
import { DeleteCommand, DynamoDBDocumentClient, GetCommand, PutCommand, UpdateCommand } from "@aws-sdk/lib-dynamodb";
import { captureTelemetryError, telemetryEvent } from "../telemetry.js";

export interface SharedRateLimitStore {
  cooldownUntil(resource: string): Promise<number | undefined>;
  claimSlot(resource: string, slot: number, owner: string, expiresAt: number, now: number): Promise<boolean>;
  releaseSlot(resource: string, slot: number, owner: string): Promise<void>;
  setCooldown(resource: string, until: number): Promise<void>;
}

interface CommandSender {
  send(command: unknown): Promise<unknown>;
}

export class DynamoSharedRateLimitStore implements SharedRateLimitStore {
  private readonly dynamo: CommandSender;
  private readonly pk: string;

  constructor(private readonly tableName: string, tenantId: string, dynamo?: CommandSender) {
    this.dynamo = dynamo ?? DynamoDBDocumentClient.from(new DynamoDBClient({}));
    this.pk = `tenant#${tenantId}#a2a-rate-limit`;
  }

  async cooldownUntil(resource: string): Promise<number | undefined> {
    const response = await this.dynamo.send(new GetCommand({
      TableName: this.tableName,
      Key: { pk: this.pk, sk: `${resourceKey(resource)}#cooldown` },
      ConsistentRead: true,
    })) as { Item?: { cooldown_until?: unknown } };
    return finiteNumber(response.Item?.cooldown_until);
  }

  async claimSlot(resource: string, slot: number, owner: string, expiresAt: number, now: number): Promise<boolean> {
    try {
      await this.dynamo.send(new PutCommand({
        TableName: this.tableName,
        Item: {
          pk: this.pk,
          sk: `${resourceKey(resource)}#slot#${slot}`,
          owner,
          lease_until: expiresAt,
          expires_at: Math.ceil(expiresAt / 1_000),
        },
        ConditionExpression: "attribute_not_exists(pk) OR lease_until < :now",
        ExpressionAttributeValues: { ":now": now },
      }));
      return true;
    } catch (error) {
      if ((error as { name?: string }).name === "ConditionalCheckFailedException") return false;
      throw error;
    }
  }

  async releaseSlot(resource: string, slot: number, owner: string): Promise<void> {
    try {
      await this.dynamo.send(new DeleteCommand({
        TableName: this.tableName,
        Key: { pk: this.pk, sk: `${resourceKey(resource)}#slot#${slot}` },
        ConditionExpression: "#owner = :owner",
        ExpressionAttributeNames: { "#owner": "owner" },
        ExpressionAttributeValues: { ":owner": owner },
      }));
    } catch (error) {
      if ((error as { name?: string }).name !== "ConditionalCheckFailedException") throw error;
    }
  }

  async setCooldown(resource: string, until: number): Promise<void> {
    try {
      await this.dynamo.send(new UpdateCommand({
        TableName: this.tableName,
        Key: { pk: this.pk, sk: `${resourceKey(resource)}#cooldown` },
        UpdateExpression: "SET cooldown_until = :until, expires_at = :expires",
        ConditionExpression: "attribute_not_exists(cooldown_until) OR cooldown_until < :until",
        ExpressionAttributeValues: { ":until": until, ":expires": Math.ceil(until / 1_000) },
      }));
    } catch (error) {
      if ((error as { name?: string }).name !== "ConditionalCheckFailedException") throw error;
    }
  }
}

export class InMemorySharedRateLimitStore implements SharedRateLimitStore {
  private readonly slots = new Map<string, { owner: string; expiresAt: number }>();
  private readonly cooldowns = new Map<string, number>();

  async cooldownUntil(resource: string): Promise<number | undefined> {
    return this.cooldowns.get(resource);
  }

  async claimSlot(resource: string, slot: number, owner: string, expiresAt: number, now: number): Promise<boolean> {
    const key = `${resource}:${slot}`;
    const current = this.slots.get(key);
    if (current && current.expiresAt >= now) return false;
    this.slots.set(key, { owner, expiresAt });
    return true;
  }

  async releaseSlot(resource: string, slot: number, owner: string): Promise<void> {
    const key = `${resource}:${slot}`;
    if (this.slots.get(key)?.owner === owner) this.slots.delete(key);
  }

  async setCooldown(resource: string, until: number): Promise<void> {
    this.cooldowns.set(resource, until);
  }
}

export interface SharedRateLimitOptions {
  maxConcurrent: number;
  leaseMs: number;
  waitMs: number;
}

export interface SharedRateLimitLease {
  resource: string;
  slot: number;
  waitedMs: number;
  release(): Promise<void>;
}

export class SharedRateLimitCoordinator {
  private readonly heldResources = new AsyncLocalStorage<Set<string>>();

  constructor(
    private readonly store: SharedRateLimitStore,
    private readonly instanceId: string,
    private readonly now: () => number = Date.now,
    private readonly sleep: (milliseconds: number) => Promise<void> = (milliseconds) => new Promise((resolve) => setTimeout(resolve, milliseconds)),
  ) {}

  async acquire(resource: string, options: SharedRateLimitOptions): Promise<SharedRateLimitLease> {
    const startedAt = this.now();
    const deadline = startedAt + Math.max(0, options.waitMs);
    const maxConcurrent = Math.min(Math.max(Math.floor(options.maxConcurrent), 1), 32);
    const leaseMs = Math.min(Math.max(Math.floor(options.leaseMs), 1_000), 10 * 60_000);
    const owner = `${this.instanceId}:${randomUUID()}`;
    let attempt = 0;
    while (true) {
      const now = this.now();
      const cooldownUntil = await this.store.cooldownUntil(resource);
      if (!cooldownUntil || cooldownUntil <= now) {
        for (let offset = 0; offset < maxConcurrent; offset += 1) {
          const slot = (attempt + offset) % maxConcurrent;
          if (!await this.store.claimSlot(resource, slot, owner, now + leaseMs, now)) continue;
          const waitedMs = Math.max(0, now - startedAt);
          telemetryEvent("companion.rate_limit.acquired", {
            component: "shared-rate-limit",
            operation: "acquire",
            "rate_limit.resource": resourceKey(resource),
            "rate_limit.slot": slot,
            "rate_limit.waited_ms": waitedMs,
          });
          let released = false;
          return {
            resource,
            slot,
            waitedMs,
            release: async () => {
              if (released) return;
              released = true;
              try {
                await this.store.releaseSlot(resource, slot, owner);
              } catch (error) {
                captureTelemetryError("companion.rate_limit.release_failed", error, {
                  component: "shared-rate-limit",
                  operation: "release",
                  "rate_limit.resource": resourceKey(resource),
                  "rate_limit.slot": slot,
                });
              }
            },
          };
        }
      }
      if (now >= deadline) throw new Error(`Shared rate limit capacity unavailable for ${resourceKey(resource)}.`);
      attempt += 1;
      const cooldownWait = cooldownUntil && cooldownUntil > now ? cooldownUntil - now : 0;
      await this.sleep(Math.max(10, Math.min(250, cooldownWait || 50, deadline - now)));
    }
  }

  async withPermit<T>(resource: string, options: SharedRateLimitOptions, work: () => Promise<T>): Promise<T> {
    const held = this.heldResources.getStore();
    if (held?.has(resource)) return work();
    const lease = await this.acquire(resource, options);
    try {
      return await this.heldResources.run(new Set([...(held ?? []), resource]), work);
    } catch (error) {
      if (isRateLimitError(error)) await this.recordRateLimit(resource, retryAfterMs(error));
      throw error;
    } finally {
      await lease.release();
    }
  }

  async recordRateLimit(resource: string, retryMs = 30_000): Promise<void> {
    const boundedRetryMs = Math.min(Math.max(Math.floor(retryMs), 1_000), 10 * 60_000);
    await this.store.setCooldown(resource, this.now() + boundedRetryMs);
    telemetryEvent("companion.rate_limit.cooldown", {
      component: "shared-rate-limit",
      operation: "cooldown",
      "rate_limit.resource": resourceKey(resource),
      "rate_limit.retry_after_ms": boundedRetryMs,
    });
  }
}

export function isRateLimitError(error: unknown): boolean {
  const record = error as { name?: string; message?: string; statusCode?: number; $metadata?: { httpStatusCode?: number } };
  return record?.statusCode === 429
    || record?.$metadata?.httpStatusCode === 429
    || /\b(429|rate.?limit|throttl|too many requests)\b/i.test(`${record?.name ?? ""} ${record?.message ?? String(error)}`);
}

function retryAfterMs(error: unknown): number {
  const match = `${(error as { message?: string })?.message ?? ""}`.match(/retry(?:-|\s)?after[^0-9]{0,8}(\d+)/i);
  return match?.[1] ? Number(match[1]) * 1_000 : 30_000;
}

function resourceKey(value: string): string {
  return value.toLowerCase().replace(/[^a-z0-9._:-]+/g, "-").replace(/^-+|-+$/g, "").slice(0, 120) || "unknown";
}

function finiteNumber(value: unknown): number | undefined {
  return typeof value === "number" && Number.isFinite(value) ? value : undefined;
}
