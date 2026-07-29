import { DynamoDBClient } from "@aws-sdk/client-dynamodb";
import {
  DynamoDBDocumentClient,
  GetCommand,
  UpdateCommand,
} from "@aws-sdk/lib-dynamodb";

const RELEASE_PARTITION_SUFFIX = "#release-receipts";
const MAX_LINK_LENGTH = 300;
const MAX_TEXT_LENGTH = 300;

export type ReleaseStatus =
  | "deploying"
  | "failed"
  | "rolled_back"
  | "superseded"
  | "verified";

export interface ReleaseReceipt {
  changedFileCount: number;
  checks: { slack: { status: string } };
  commitSubject?: string;
  commitUrl: string;
  components: readonly string[];
  deployMode: "ecs" | "pulumi";
  deployRunUrl: string;
  failedChecks: readonly string[];
  notificationClaims: Readonly<Record<string, number>>;
  notifications: Readonly<Record<string, string>>;
  previousVersion?: string;
  pullRequestUrl?: string;
  runningVersion?: string;
  status: ReleaseStatus;
  statusDetail: string;
  threadTsByChannel: Readonly<Record<string, string>>;
  version: string;
}

export interface ReleaseNoticeStore {
  activeReceipt(): Promise<ReleaseReceipt | undefined>;
  claim(input: {
    channelId: string;
    leaseSeconds: number;
    state: string;
    version: string;
  }): Promise<boolean>;
  complete(input: {
    channelId: string;
    state: string;
    threadTs?: string;
    version: string;
  }): Promise<void>;
  markSlackPassed(version: string, detail: string): Promise<void>;
}

export interface ReleaseNoticeSlackClient {
  chat: {
    postMessage(input: {
      channel: string;
      text: string;
      thread_ts?: string;
      unfurl_links?: boolean;
      unfurl_media?: boolean;
    }): Promise<{ ts?: string }>;
  };
}

export interface ReleaseNoticeMonitor {
  stop(): void;
}

export function createReleaseNoticeStore(input: {
  tableName: string;
  tenantId: string;
}): ReleaseNoticeStore {
  return new DynamoReleaseNoticeStore(
    DynamoDBDocumentClient.from(new DynamoDBClient({})),
    input.tableName,
    releasePartition(input.tenantId),
  );
}

export function startReleaseNoticeMonitor(input: {
  channels: ReadonlySet<string>;
  client: ReleaseNoticeSlackClient;
  intervalMs?: number;
  onError?: (error: unknown) => void;
  store: ReleaseNoticeStore;
}): ReleaseNoticeMonitor {
  let stopped = false;
  let running = false;
  const tick = async (): Promise<void> => {
    if (stopped || running) return;
    running = true;
    try {
      const receipt = await input.store.activeReceipt();
      if (receipt) {
        await postReleaseState(
          input.store,
          input.client,
          receipt,
          [...input.channels],
          input.onError,
        );
      }
    } catch (error) {
      input.onError?.(error);
    } finally {
      running = false;
    }
  };
  const timer = setInterval(
    () => void tick(),
    Math.max(1_000, input.intervalMs ?? 10_000),
  );
  timer.unref();
  void tick();
  return {
    stop(): void {
      stopped = true;
      clearInterval(timer);
    },
  };
}

export async function postReleaseState(
  store: ReleaseNoticeStore,
  client: ReleaseNoticeSlackClient,
  receipt: ReleaseReceipt,
  channels: readonly string[],
  onError?: (error: unknown) => void,
): Promise<void> {
  let connectedChannels = 0;
  await Promise.all(channels.map(async (channel) => {
    let threadTs = receipt.threadTsByChannel[channel];
    if (!threadTs) {
      const claimed = await store.claim({
        channelId: channel,
        leaseSeconds: 15,
        state: "started",
        version: receipt.version,
      });
      if (claimed) {
        try {
          const response = await client.chat.postMessage({
            channel,
            text: releaseStartedText(receipt),
            unfurl_links: false,
            unfurl_media: false,
          });
          if (!response.ts) throw new Error("Slack did not return a message timestamp.");
          threadTs = response.ts;
          await store.complete({
            channelId: channel,
            state: "started",
            threadTs,
            version: receipt.version,
          });
        } catch (error) {
          onError?.(error);
          return;
        }
      }
    }
    if (!threadTs) return;
    connectedChannels += 1;
    if (receipt.status === "deploying") return;
    const claimed = await store.claim({
      channelId: channel,
      leaseSeconds: 120,
      state: receipt.status,
      version: receipt.version,
    });
    if (!claimed) return;
    try {
      await client.chat.postMessage({
        channel,
        text: releaseTerminalText(receipt),
        thread_ts: threadTs,
        unfurl_links: false,
        unfurl_media: false,
      });
      await store.complete({
        channelId: channel,
        state: receipt.status,
        version: receipt.version,
      });
    } catch (error) {
      onError?.(error);
      return;
    }
  }));
  if (
    receipt.status === "deploying"
    && connectedChannels === channels.length
    && receipt.checks.slack.status !== "passed"
  ) {
    await store.markSlackPassed(
      receipt.version,
      `Release thread created in ${connectedChannels}/${channels.length} configured channel(s).`,
    );
  }
}

export function releaseStartedText(receipt: ReleaseReceipt): string {
  const subject = safeText(receipt.commitSubject, 160)?.replace(/[.!?]+$/u, "");
  const commit = subject
    ? `commit ${safeText(receipt.version, 80)}: ${subject}`
    : `version ${safeText(receipt.version, 80)}`;
  const mode = receipt.deployMode === "pulumi"
    ? "infrastructure update"
    : "ECS application update";
  const components = receipt.components
    .map((item) => safeText(item, 80))
    .filter(Boolean)
    .join(", ") || "companion runtime";
  return [
    `Deployment started for ${commit}.`,
    `Mode: ${mode}. Components: ${components}. Changed files: ${receipt.changedFileCount}.`,
    "Checks running: Slack release message, ECS image, runtime configuration, and Cerebro API.",
    releaseLinks(receipt),
  ].filter(Boolean).join("\n");
}

export function releaseTerminalText(receipt: ReleaseReceipt): string {
  const links = releaseLinks(receipt);
  if (receipt.status === "verified") {
    return [
      `Deployment verified. Running version ${safeText(receipt.runningVersion ?? receipt.version, 80)}.`,
      "Checks passed: Slack release message, ECS image, runtime configuration, and Cerebro API.",
      links,
    ].filter(Boolean).join("\n");
  }
  if (receipt.status === "superseded") {
    return [
      `Deployment superseded. Running version: ${safeText(receipt.runningVersion, 80) ?? "unknown"}.`,
      safeText(receipt.statusDetail, MAX_TEXT_LENGTH),
      links,
    ].filter(Boolean).join("\n");
  }
  const failed = receipt.failedChecks
    .map((item) => safeText(item, 80))
    .filter(Boolean)
    .join(", ") || "deployment verification";
  if (receipt.status === "rolled_back") {
    return [
      `Deployment rolled back. Restored version ${safeText(receipt.runningVersion ?? receipt.previousVersion, 80) ?? "unknown"}.`,
      `Failed checks: ${failed}.`,
      safeText(receipt.statusDetail, MAX_TEXT_LENGTH),
      links,
    ].filter(Boolean).join("\n");
  }
  return [
    `Deployment failed verification. Running version: ${safeText(receipt.runningVersion, 80) ?? "unknown"}.`,
    `Failed checks: ${failed}.`,
    safeText(receipt.statusDetail, MAX_TEXT_LENGTH),
    links,
  ].filter(Boolean).join("\n");
}

class DynamoReleaseNoticeStore implements ReleaseNoticeStore {
  constructor(
    private readonly dynamo: DynamoDBDocumentClient,
    private readonly tableName: string,
    private readonly partitionKey: string,
    private readonly now: () => Date = () => new Date(),
  ) {}

  async activeReceipt(): Promise<ReleaseReceipt | undefined> {
    const pointerResponse = await this.dynamo.send(new GetCommand({
      ConsistentRead: true,
      Key: { pk: this.partitionKey, sk: "current" },
      TableName: this.tableName,
    }));
    const version = stringValue(pointerResponse.Item?.version, 80);
    if (!version) return undefined;
    const receiptResponse = await this.dynamo.send(new GetCommand({
      ConsistentRead: true,
      Key: { pk: this.partitionKey, sk: `release#${cleanKey(version, 80)}` },
      TableName: this.tableName,
    }));
    return releaseReceiptFrom(receiptResponse.Item);
  }

  async claim(input: {
    channelId: string;
    leaseSeconds: number;
    state: string;
    version: string;
  }): Promise<boolean> {
    const notice = noticeKey(input.channelId, input.state);
    const nowSeconds = Math.floor(this.now().getTime() / 1_000);
    try {
      await this.dynamo.send(new UpdateCommand({
        ConditionExpression:
          "attribute_exists(pk) AND attribute_not_exists(#notifications.#notice) AND (attribute_not_exists(#claims.#notice) OR #claims.#notice < :now)",
        ExpressionAttributeNames: {
          "#claims": "notificationClaims",
          "#notice": notice,
          "#notifications": "notifications",
        },
        ExpressionAttributeValues: {
          ":lease": nowSeconds + Math.max(10, input.leaseSeconds),
          ":now": nowSeconds,
        },
        Key: {
          pk: this.partitionKey,
          sk: `release#${cleanKey(input.version, 80)}`,
        },
        TableName: this.tableName,
        UpdateExpression: "SET #claims.#notice = :lease",
      }));
      return true;
    } catch (error) {
      if (isConditionalCheckFailure(error)) return false;
      throw error;
    }
  }

  async complete(input: {
    channelId: string;
    state: string;
    threadTs?: string;
    version: string;
  }): Promise<void> {
    const notice = noticeKey(input.channelId, input.state);
    const names: Record<string, string> = {
      "#claims": "notificationClaims",
      "#notice": notice,
      "#notifications": "notifications",
    };
    const values: Record<string, unknown> = {
      ":sentAt": this.now().toISOString(),
    };
    let update = "SET #notifications.#notice = :sentAt REMOVE #claims.#notice";
    if (input.threadTs) {
      names["#channel"] = cleanKey(input.channelId, 120);
      names["#threads"] = "threadTsByChannel";
      values[":threadTs"] = input.threadTs;
      update =
        "SET #notifications.#notice = :sentAt, #threads.#channel = :threadTs REMOVE #claims.#notice";
    }
    await this.dynamo.send(new UpdateCommand({
      ExpressionAttributeNames: names,
      ExpressionAttributeValues: values,
      Key: {
        pk: this.partitionKey,
        sk: `release#${cleanKey(input.version, 80)}`,
      },
      TableName: this.tableName,
      UpdateExpression: update,
    }));
  }

  async markSlackPassed(version: string, detail: string): Promise<void> {
    await this.dynamo.send(new UpdateCommand({
      ExpressionAttributeNames: {
        "#checks": "checks",
        "#slack": "slack",
      },
      ExpressionAttributeValues: {
        ":check": {
          detail: detail.replace(/\s+/gu, " ").slice(0, MAX_TEXT_LENGTH),
          status: "passed",
        },
        ":updatedAt": this.now().toISOString(),
      },
      Key: {
        pk: this.partitionKey,
        sk: `release#${cleanKey(version, 80)}`,
      },
      TableName: this.tableName,
      UpdateExpression: "SET #checks.#slack = :check, updatedAt = :updatedAt",
    }));
  }
}

function releaseReceiptFrom(value: unknown): ReleaseReceipt | undefined {
  if (!record(value)) return undefined;
  const status = value.status;
  if (
    value.schemaVersion !== 1
    || value.recordType !== "companion_release_receipt"
    || !releaseStatus(status)
    || !record(value.checks)
    || !record(value.checks.slack)
  ) return undefined;
  const version = stringValue(value.version, 80);
  const commitUrl = safeUrl(value.commitUrl);
  const deployRunUrl = safeUrl(value.deployRunUrl);
  if (!version || !commitUrl || !deployRunUrl) return undefined;
  return {
    changedFileCount: boundedNumber(value.changedFileCount),
    checks: {
      slack: { status: stringValue(value.checks.slack.status, 30) ?? "pending" },
    },
    commitSubject: stringValue(value.commitSubject, 200),
    commitUrl,
    components: stringArray(value.components, 12, 80),
    deployMode: value.deployMode === "pulumi" ? "pulumi" : "ecs",
    deployRunUrl,
    failedChecks: stringArray(value.failedChecks, 12, 80),
    notificationClaims: numberRecord(value.notificationClaims),
    notifications: stringRecord(value.notifications),
    previousVersion: stringValue(value.previousVersion, 80),
    pullRequestUrl: safeUrl(value.pullRequestUrl),
    runningVersion: stringValue(value.runningVersion, 80),
    status,
    statusDetail: stringValue(value.statusDetail, MAX_TEXT_LENGTH) ?? "",
    threadTsByChannel: stringRecord(value.threadTsByChannel),
    version,
  };
}

function releasePartition(tenantId: string): string {
  return `tenant#${cleanKey(tenantId, 80)}${RELEASE_PARTITION_SUFFIX}`;
}

function releaseLinks(receipt: ReleaseReceipt): string {
  return [
    slackLink(receipt.deployRunUrl, "Deploy run"),
    slackLink(receipt.commitUrl, "Commit"),
    slackLink(receipt.pullRequestUrl, "Pull request"),
  ].filter(Boolean).join(" · ");
}

function slackLink(value: string | undefined, label: string): string | undefined {
  const url = safeUrl(value);
  return url ? `<${url}|${label}>` : undefined;
}

function safeUrl(value: unknown): string | undefined {
  const normalized = stringValue(value, MAX_LINK_LENGTH);
  if (!normalized) return undefined;
  try {
    const parsed = new URL(normalized);
    if (parsed.protocol !== "https:" || parsed.hostname !== "github.com") return undefined;
    return parsed.toString();
  } catch {
    return undefined;
  }
}

function safeText(value: unknown, maximum: number): string | undefined {
  return stringValue(value, maximum)
    ?.replace(/&/gu, "&amp;")
    .replace(/</gu, "&lt;")
    .replace(/>/gu, "&gt;");
}

function stringValue(value: unknown, maximum: number): string | undefined {
  if (typeof value !== "string") return undefined;
  const normalized = value
    .replace(/[\u0000-\u001f\u007f]+/gu, " ")
    .replace(/\s+/gu, " ")
    .trim();
  return normalized ? normalized.slice(0, maximum).trimEnd() : undefined;
}

function stringArray(
  value: unknown,
  maximumItems: number,
  maximumLength: number,
): string[] {
  if (!Array.isArray(value)) return [];
  return value.slice(0, maximumItems)
    .map((item) => stringValue(item, maximumLength))
    .filter((item): item is string => Boolean(item));
}

function stringRecord(value: unknown): Record<string, string> {
  if (!record(value)) return {};
  return Object.fromEntries(Object.entries(value).slice(0, 300).flatMap(
    ([key, item]) => {
      const clean = stringValue(item, 120);
      return clean ? [[cleanKey(key, 120), clean]] : [];
    },
  ));
}

function numberRecord(value: unknown): Record<string, number> {
  if (!record(value)) return {};
  return Object.fromEntries(Object.entries(value).slice(0, 300).flatMap(
    ([key, item]) => Number.isFinite(item) ? [[cleanKey(key, 120), Number(item)]] : [],
  ));
}

function boundedNumber(value: unknown): number {
  return typeof value === "number" && Number.isSafeInteger(value) && value >= 0
    ? Math.min(value, 1_000_000)
    : 0;
}

function cleanKey(value: string, maximum: number): string {
  return value.replace(/[^A-Za-z0-9_.:-]+/gu, "_").slice(0, maximum);
}

function noticeKey(channelId: string, state: string): string {
  return `${cleanKey(channelId, 60)}:${cleanKey(state, 50)}`;
}

function releaseStatus(value: unknown): value is ReleaseStatus {
  return value === "deploying"
    || value === "failed"
    || value === "rolled_back"
    || value === "superseded"
    || value === "verified";
}

function record(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function isConditionalCheckFailure(error: unknown): boolean {
  return record(error) && error.name === "ConditionalCheckFailedException";
}
