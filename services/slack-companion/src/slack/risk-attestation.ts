import { createHash } from "node:crypto";
import { DynamoDBClient } from "@aws-sdk/client-dynamodb";
import { DynamoDBDocumentClient, GetCommand, PutCommand } from "@aws-sdk/lib-dynamodb";
import type { App as SlackApp, types as SlackTypes } from "@slack/bolt";
import { z } from "zod";
import type { AppConfig } from "../config/index.js";
import { logger } from "../logger.js";
import { redactSecurityText } from "../security/redaction.js";
import { hashTelemetryId, recordMetric, telemetryEvent } from "../telemetry.js";
import { encodeAction } from "./action-codec.js";
import { actionIds } from "./blocks/action-ids.js";

const retentionDays = 90;
const responseDueMs = 72 * 60 * 60 * 1_000;

export type RiskAttestationAnswer = "yes" | "no" | "unsure";
export type RiskAttestationStatus =
  | "sending"
  | "pending"
  | "subject_said_yes"
  | "subject_said_no"
  | "subject_unsure"
  | "delivery_failed";

export interface RiskAttestationRecord {
  schemaVersion: 1;
  id: string;
  riskRef: string;
  sourceChannelId: string;
  sourceThreadTs: string;
  requestedByUserId?: string;
  targetUserId: string;
  targetDisplayName: string;
  activitySummary: string;
  sourceName?: string;
  observedAt?: string;
  identityBasis: string;
  evidenceRefs: string[];
  status: RiskAttestationStatus;
  createdAt: string;
  updatedAt: string;
  responseDueAt: string;
  deliveredAt?: string;
  respondedAt?: string;
  dmChannelId?: string;
  dmMessageTs?: string;
  originNotificationTs?: string;
  answer?: RiskAttestationAnswer;
}

export interface RiskAttestationView {
  request_id: string;
  risk_ref: string;
  target_user_id: string;
  target_display_name: string;
  status: RiskAttestationStatus;
  answer?: RiskAttestationAnswer;
  response_due_at: string;
  response_overdue: boolean;
  duplicate: boolean;
  legitimacy: "unverified";
  evidentiary_weight: "self_attestation";
  can_disposition_risk: false;
  required_next_step: string;
  origin_notified: boolean;
}

type SlackWebClient = SlackApp["client"];
type SlackBlocks = Array<SlackTypes.Block | SlackTypes.KnownBlock>;
type SlackClient = {
  users: Pick<SlackWebClient["users"], "info">;
  conversations: Pick<SlackWebClient["conversations"], "open">;
  chat: Pick<SlackWebClient["chat"], "postMessage" | "update">;
};

export interface RiskAttestationServiceOptions {
  dynamo?: { send(command: unknown): Promise<unknown> };
  now?: () => Date;
  slackClient?: SlackClient;
}

const answerSchema = z.enum(["yes", "no", "unsure"]);
const statusSchema = z.enum(["sending", "pending", "subject_said_yes", "subject_said_no", "subject_unsure", "delivery_failed"]);
const requestSchema = z.object({
  riskRef: z.string().trim().min(1).max(240),
  sourceChannelId: z.string().trim().min(1).max(160),
  sourceThreadTs: z.string().trim().min(1).max(80),
  requestedByUserId: z.string().trim().min(1).max(160).optional(),
  targetUserId: z.string().trim().min(1).max(160),
  activitySummary: z.string().trim().min(8).max(700),
  sourceName: z.string().trim().min(1).max(120).optional(),
  observedAt: z.string().trim().min(1).max(120).optional(),
  identityBasis: z.string().trim().min(8).max(500),
  evidenceRefs: z.array(z.string().trim().min(1).max(240)).min(1).max(8),
});
const recordSchema = z.object({
  schemaVersion: z.literal(1),
  id: z.string().regex(/^risk-attestation-[a-f0-9]{24}$/),
  riskRef: z.string().min(1).max(240),
  sourceChannelId: z.string().min(1).max(160),
  sourceThreadTs: z.string().min(1).max(80),
  requestedByUserId: z.string().min(1).max(160).optional(),
  targetUserId: z.string().min(1).max(160),
  targetDisplayName: z.string().min(1).max(160),
  activitySummary: z.string().min(1).max(700),
  sourceName: z.string().min(1).max(120).optional(),
  observedAt: z.string().min(1).max(120).optional(),
  identityBasis: z.string().min(1).max(500),
  evidenceRefs: z.array(z.string().min(1).max(240)).min(1).max(8),
  status: statusSchema,
  createdAt: z.string().datetime(),
  updatedAt: z.string().datetime(),
  responseDueAt: z.string().datetime(),
  deliveredAt: z.string().datetime().optional(),
  respondedAt: z.string().datetime().optional(),
  dmChannelId: z.string().min(1).max(160).optional(),
  dmMessageTs: z.string().min(1).max(80).optional(),
  originNotificationTs: z.string().min(1).max(80).optional(),
  answer: answerSchema.optional(),
});
const slackUserSchema = z.object({
  id: z.string().min(1),
  deleted: z.boolean().optional(),
  is_bot: z.boolean().optional(),
  is_app_user: z.boolean().optional(),
  name: z.string().optional(),
  profile: z.object({
    display_name: z.string().optional(),
    real_name: z.string().optional(),
  }).optional(),
});
const openedConversationSchema = z.object({ channel: z.object({ id: z.string().min(1) }) });
const postedMessageSchema = z.object({ channel: z.string().optional(), ts: z.string().min(1) });

export class RiskAttestationService {
  private readonly dynamo?: { send(command: unknown): Promise<unknown> };
  private readonly tableName?: string;
  private readonly now: () => Date;
  private readonly memory = new Map<string, RiskAttestationRecord>();
  private slackClient?: SlackClient;

  constructor(private readonly config: AppConfig, options: RiskAttestationServiceOptions = {}) {
    this.tableName = config.learning.tableName;
    this.now = options.now ?? (() => new Date());
    this.slackClient = options.slackClient;
    if (options.dynamo) this.dynamo = options.dynamo;
    else if (config.learning.enabled && this.tableName) {
      this.dynamo = DynamoDBDocumentClient.from(new DynamoDBClient({}), { marshallOptions: { removeUndefinedValues: true } });
    }
  }

  setSlackClient(client: SlackClient): void {
    this.slackClient = client;
  }

  async request(input: {
    riskRef: string;
    sourceChannelId: string;
    sourceThreadTs: string;
    requestedByUserId?: string;
    targetUserId: string;
    activitySummary: string;
    sourceName?: string;
    observedAt?: string;
    identityBasis: string;
    evidenceRefs: string[];
  }): Promise<RiskAttestationView> {
    const sourceChannelId = cleanId(input.sourceChannelId, 160);
    this.requireSecurityChannel(sourceChannelId);
    const parsed = requestSchema.parse({
      ...input,
      sourceChannelId,
      sourceThreadTs: cleanId(input.sourceThreadTs, 80),
      requestedByUserId: optionalId(input.requestedByUserId, 160),
      targetUserId: cleanId(input.targetUserId, 160),
      riskRef: cleanText(input.riskRef, 240),
      activitySummary: cleanText(input.activitySummary, 700),
      sourceName: optionalText(input.sourceName, 120),
      observedAt: optionalText(input.observedAt, 120),
      identityBasis: cleanText(input.identityBasis, 500),
      evidenceRefs: uniqueText(input.evidenceRefs, 8, 240),
    });
    const id = attestationId(this.config.cerebro.tenantId, parsed);
    const existing = await this.getRecord(id);
    if (existing && existing.status !== "delivery_failed") return attestationView(existing, this.now(), true);
    const client = this.requireSlackClient();
    const target = await this.resolveTarget(client, parsed.targetUserId);
    const now = this.now();
    const sending: RiskAttestationRecord = recordSchema.parse({
      schemaVersion: 1,
      id,
      riskRef: parsed.riskRef,
      sourceChannelId: parsed.sourceChannelId,
      sourceThreadTs: parsed.sourceThreadTs,
      requestedByUserId: parsed.requestedByUserId,
      targetUserId: target.id,
      targetDisplayName: target.displayName,
      activitySummary: parsed.activitySummary,
      sourceName: parsed.sourceName,
      observedAt: parsed.observedAt,
      identityBasis: parsed.identityBasis,
      evidenceRefs: parsed.evidenceRefs,
      status: "sending",
      createdAt: existing?.createdAt ?? now.toISOString(),
      updatedAt: now.toISOString(),
      responseDueAt: existing?.responseDueAt ?? new Date(now.getTime() + responseDueMs).toISOString(),
    });
    const claimed = await this.putRecord(sending, existing ? "delivery_failed" : undefined, !existing);
    if (!claimed) {
      const current = await this.getRecord(id);
      if (!current) throw new Error("The security check could not acquire its delivery record.");
      return attestationView(current, this.now(), true);
    }
    try {
      const opened = openedConversationSchema.parse(await this.slackCall("open_dm", () => client.conversations.open({ users: sending.targetUserId })));
      const message = riskAttestationMessage(sending);
      const posted = postedMessageSchema.parse(await this.slackCall("post_dm", () => client.chat.postMessage({
        channel: opened.channel.id,
        text: message.text,
        blocks: message.blocks as SlackBlocks,
        unfurl_links: false,
        unfurl_media: false,
      })));
      const deliveredAt = this.now().toISOString();
      const pending = recordSchema.parse({
        ...sending,
        status: "pending",
        updatedAt: deliveredAt,
        deliveredAt,
        dmChannelId: posted.channel ?? opened.channel.id,
        dmMessageTs: posted.ts,
      });
      await this.putRecord(pending, "sending");
      this.recordEvent("sent", pending);
      return attestationView(pending, this.now(), false);
    } catch (error) {
      const failedAt = this.now().toISOString();
      await this.putRecord(recordSchema.parse({ ...sending, status: "delivery_failed", updatedAt: failedAt }), "sending").catch(() => undefined);
      logger.warn("risk attestation delivery failed", {
        event: "slack.risk_attestation.delivery_failed",
        requestIdHash: hashTelemetryId(id),
        error: errorKind(error),
      });
      throw new Error("Slack could not deliver the security check to that person.");
    }
  }

  async status(id: string, sourceChannelId: string): Promise<RiskAttestationView | undefined> {
    const channelId = cleanId(sourceChannelId, 160);
    this.requireSecurityChannel(channelId);
    const record = await this.getRecord(cleanAttestationId(id));
    if (!record || record.sourceChannelId !== channelId) return undefined;
    return attestationView(record, this.now(), false);
  }

  async respond(input: { id: string; responderUserId: string; answer: RiskAttestationAnswer }): Promise<{ record: RiskAttestationRecord; changed: boolean }> {
    const id = cleanAttestationId(input.id);
    const answer = answerSchema.parse(input.answer);
    const record = await this.getRecord(id);
    if (!record) throw new Error("This security check is no longer available.");
    const responderUserId = cleanId(input.responderUserId, 160);
    if (record.targetUserId !== responderUserId) throw new Error("Only the person who received this security check can answer it.");
    let changed = false;
    let resolved = record;
    if (record.status === "pending") {
      const respondedAt = this.now().toISOString();
      const candidate = recordSchema.parse({
        ...record,
        status: statusForAnswer(answer),
        answer,
        respondedAt,
        updatedAt: respondedAt,
      });
      changed = await this.putRecord(candidate, "pending");
      resolved = changed ? candidate : (await this.getRecord(id) ?? candidate);
    } else if (!isFinalStatus(record.status)) {
      throw new Error("This security check has not been delivered.");
    }
    if (changed) {
      await this.deliverResponse(resolved);
      this.recordEvent("answered", resolved);
    }
    return { record: resolved, changed };
  }

  private requireSecurityChannel(channelId: string): void {
    if (!channelId || !this.config.slack.riskAttestationChannelIds.has(channelId)) {
      throw new Error("Risk confirmation is available only in configured security channels.");
    }
  }

  private requireSlackClient(): SlackClient {
    if (!this.slackClient) throw new Error("Slack risk confirmation is not connected.");
    return this.slackClient;
  }

  private async resolveTarget(client: SlackClient, targetUserId: string): Promise<{ id: string; displayName: string }> {
    const response = await this.slackCall("resolve_user", () => client.users.info({ user: targetUserId }));
    const user = slackUserSchema.parse((response as { user?: unknown })?.user);
    if (user.id !== targetUserId || user.deleted || user.is_bot || user.is_app_user) {
      throw new Error("Risk confirmation requires an active human Slack user.");
    }
    const displayName = cleanText(user.profile?.display_name || user.profile?.real_name || user.name || user.id, 160);
    return { id: cleanId(user.id, 160), displayName };
  }

  private async deliverResponse(record: RiskAttestationRecord): Promise<void> {
    const client = this.requireSlackClient();
    let current = record;
    const dmChannelId = record.dmChannelId;
    const dmMessageTs = record.dmMessageTs;
    if (dmChannelId && dmMessageTs) {
      const message = riskAttestationMessage(record);
      await this.slackCall("record_dm_answer", () => client.chat.update({
        channel: dmChannelId,
        ts: dmMessageTs,
        text: message.text,
        blocks: message.blocks as SlackBlocks,
      })).catch((error) => logger.warn("risk attestation DM refresh failed", {
        event: "slack.risk_attestation.dm_refresh_failed",
        requestIdHash: hashTelemetryId(record.id),
        error: errorKind(error),
      }));
    }
    if (!record.originNotificationTs && record.answer) {
      try {
        const posted = postedMessageSchema.parse(await this.slackCall("notify_security_thread", () => client.chat.postMessage({
          channel: record.sourceChannelId,
          thread_ts: record.sourceThreadTs,
          text: originResponseText(record),
          unfurl_links: false,
          unfurl_media: false,
        })));
        current = recordSchema.parse({ ...record, originNotificationTs: posted.ts, updatedAt: this.now().toISOString() });
        await this.putRecord(current);
      } catch (error) {
        logger.warn("risk attestation origin notification failed", {
          event: "slack.risk_attestation.origin_notification_failed",
          requestIdHash: hashTelemetryId(record.id),
          error: errorKind(error),
        });
      }
    }
  }

  private async slackCall<T>(operation: string, work: () => Promise<T>): Promise<T> {
    let timer: NodeJS.Timeout | undefined;
    const timeout = new Promise<never>((_resolve, reject) => {
      timer = setTimeout(() => reject(new Error(`Slack ${operation} timed out`)), this.config.slack.riskAttestationTimeoutMs);
      timer.unref?.();
    });
    try {
      return await Promise.race([work(), timeout]);
    } finally {
      if (timer) clearTimeout(timer);
    }
  }

  private async getRecord(id: string): Promise<RiskAttestationRecord | undefined> {
    if (this.dynamo && this.tableName) {
      const response = await this.dynamo.send(new GetCommand({
        TableName: this.tableName,
        Key: storageKey(this.config, id),
      })) as { Item?: unknown };
      const parsed = recordSchema.safeParse(response.Item);
      return parsed.success && !recordExpired(parsed.data, this.now()) ? parsed.data : undefined;
    }
    const record = this.memory.get(id);
    return record && !recordExpired(record, this.now()) ? structuredClone(record) : undefined;
  }

  private async putRecord(record: RiskAttestationRecord, expectedStatus?: RiskAttestationStatus, createOnly = false): Promise<boolean> {
    if (this.dynamo && this.tableName) {
      try {
        await this.dynamo.send(new PutCommand({
          TableName: this.tableName,
          Item: {
            ...storageKey(this.config, record.id),
            recordType: "risk_attestation",
            expires_at: Math.floor(Date.parse(record.createdAt) / 1_000) + retentionDays * 86_400,
            ...record,
          },
          ...(createOnly ? { ConditionExpression: "attribute_not_exists(pk) AND attribute_not_exists(sk)" } : {}),
          ...(expectedStatus ? {
            ConditionExpression: "#status = :expected_status",
            ExpressionAttributeNames: { "#status": "status" },
            ExpressionAttributeValues: { ":expected_status": expectedStatus },
          } : {}),
        }));
        return true;
      } catch (error) {
        if (isConditionalCheckFailure(error)) return false;
        throw error;
      }
    }
    const current = this.memory.get(record.id);
    if (createOnly && current) return false;
    if (expectedStatus && current?.status !== expectedStatus) return false;
    this.memory.set(record.id, structuredClone(record));
    return true;
  }

  private recordEvent(event: "sent" | "answered", record: RiskAttestationRecord): void {
    telemetryEvent(`slack.risk_attestation.${event}`, {
      component: "risk-attestation",
      operation: event,
      "risk_attestation.request_id_hash": hashTelemetryId(record.id),
      "risk_attestation.status": record.status,
      "risk_attestation.evidence_ref_count": record.evidenceRefs.length,
      "risk_attestation.origin_notified": Boolean(record.originNotificationTs),
    });
    recordMetric("cerebro_slack_companion_risk_attestations_total", { event, status: record.status }, 1);
  }
}

export function riskAttestationMessage(record: RiskAttestationRecord): { text: string; blocks: object[] } {
  const activity = escapeSlackText(record.activitySummary);
  const details = [
    `*Activity*\n${activity}`,
    ...(record.sourceName ? [`*System*\n${escapeSlackText(record.sourceName)}`] : []),
    ...(record.observedAt ? [`*Observed*\n${escapeSlackText(record.observedAt)}`] : []),
  ].join("\n\n");
  if (record.answer) {
    const answer = answerLabel(record.answer);
    return {
      text: `Security check recorded: ${answer}`,
      blocks: [
        { type: "header", text: { type: "plain_text", text: "Security check recorded" } },
        { type: "section", text: { type: "mrkdwn", text: details } },
        { type: "section", text: { type: "mrkdwn", text: `*Your answer*\n${answer}` } },
        { type: "context", elements: [{ type: "mrkdwn", text: "Security will verify the activity before changing the risk." }] },
      ],
    };
  }
  return {
    text: "Security is checking activity associated with your account.",
    blocks: [
      { type: "header", text: { type: "plain_text", text: "Security check" } },
      { type: "section", text: { type: "mrkdwn", text: "Security is checking activity associated with your account." } },
      { type: "section", text: { type: "mrkdwn", text: details } },
      { type: "section", text: { type: "mrkdwn", text: "*Did you perform or approve this activity?*" } },
      {
        type: "actions",
        elements: [
          responseButton("Yes, this was me", "yes", record.id),
          responseButton("No, this wasn't me", "no", record.id, "danger"),
          responseButton("I'm not sure", "unsure", record.id),
        ],
      },
      { type: "context", elements: [{ type: "mrkdwn", text: "Your answer helps Security triage this risk. It does not close the risk by itself." }] },
    ],
  };
}

function responseButton(label: string, answer: RiskAttestationAnswer, id: string, style?: "danger"): object {
  return {
    type: "button",
    action_id: actionIds.riskAttestationResponse,
    text: { type: "plain_text", text: label },
    value: encodeAction({ kind: "risk_attestation_response", confirmationId: id, confirmationResponse: answer }),
    ...(style ? { style } : {}),
  };
}

function originResponseText(record: RiskAttestationRecord): string {
  const answer = record.answer ? answerLabel(record.answer) : "No answer recorded";
  return [
    "*Security check response*",
    `${escapeSlackText(record.targetDisplayName)} answered *${escapeSlackText(answer)}* for \`${inlineCode(escapeSlackText(record.riskRef))}\`.`,
    "This answer is self-reported. Verify the activity before changing the risk.",
  ].join("\n");
}

function attestationView(record: RiskAttestationRecord, now: Date, duplicate: boolean): RiskAttestationView {
  return {
    request_id: record.id,
    risk_ref: record.riskRef,
    target_user_id: record.targetUserId,
    target_display_name: record.targetDisplayName,
    status: record.status,
    answer: record.answer,
    response_due_at: record.responseDueAt,
    response_overdue: !record.answer && Date.parse(record.responseDueAt) < now.getTime(),
    duplicate,
    legitimacy: "unverified",
    evidentiary_weight: "self_attestation",
    can_disposition_risk: false,
    required_next_step: nextStep(record),
    origin_notified: Boolean(record.originNotificationTs),
  };
}

function nextStep(record: RiskAttestationRecord): string {
  if (record.status === "subject_said_no") return "Escalate the risk and independently verify or contain the activity.";
  if (record.status === "subject_said_yes") return "Corroborate the self-attestation with current source evidence before changing the risk.";
  if (record.status === "subject_unsure") return "Continue the investigation with current source evidence.";
  if (record.status === "delivery_failed") return "Resolve the Slack identity or delivery problem before relying on person confirmation.";
  return "Wait for the person's answer while continuing independent source verification.";
}

function statusForAnswer(answer: RiskAttestationAnswer): RiskAttestationStatus {
  if (answer === "yes") return "subject_said_yes";
  if (answer === "no") return "subject_said_no";
  return "subject_unsure";
}

function isFinalStatus(status: RiskAttestationStatus): boolean {
  return status === "subject_said_yes" || status === "subject_said_no" || status === "subject_unsure";
}

function answerLabel(answer: RiskAttestationAnswer): string {
  if (answer === "yes") return "Yes, this was me.";
  if (answer === "no") return "No, this wasn't me.";
  return "I'm not sure.";
}

function attestationId(tenantId: string, input: z.infer<typeof requestSchema>): string {
  const digest = createHash("sha256")
    .update(JSON.stringify([tenantId, input.sourceChannelId, input.sourceThreadTs, input.targetUserId, input.riskRef]))
    .digest("hex")
    .slice(0, 24);
  return `risk-attestation-${digest}`;
}

function storageKey(config: AppConfig, id: string): { pk: string; sk: string } {
  return { pk: `tenant#${cleanId(config.cerebro.tenantId, 160)}#risk-attestations`, sk: id };
}

function cleanAttestationId(value: string): string {
  const cleaned = cleanId(value, 80);
  if (!/^risk-attestation-[a-f0-9]{24}$/.test(cleaned)) throw new Error("Risk confirmation id is invalid.");
  return cleaned;
}

function cleanId(value: string, max: number): string {
  return redactSecurityText(value).replace(/[^A-Za-z0-9_.:#-]/g, "").slice(0, max);
}

function optionalId(value: string | undefined, max: number): string | undefined {
  const cleaned = value ? cleanId(value, max) : "";
  return cleaned || undefined;
}

function cleanText(value: string, max: number): string {
  return redactSecurityText(value).replace(/\s+/g, " ").trim().slice(0, max);
}

function optionalText(value: string | undefined, max: number): string | undefined {
  const cleaned = value ? cleanText(value, max) : "";
  return cleaned || undefined;
}

function uniqueText(values: string[], limit: number, max: number): string[] {
  return [...new Set(values.map((value) => cleanText(value, max)).filter(Boolean))].slice(0, limit);
}

function escapeSlackText(value: string): string {
  return value.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");
}

function inlineCode(value: string): string {
  return value.replace(/`/g, "'");
}

function recordExpired(record: RiskAttestationRecord, now: Date): boolean {
  return Date.parse(record.createdAt) + retentionDays * 86_400_000 <= now.getTime();
}

function isConditionalCheckFailure(error: unknown): boolean {
  return Boolean(error && typeof error === "object" && "name" in error
    && (error as { name?: unknown }).name === "ConditionalCheckFailedException");
}

function errorKind(error: unknown): string {
  if (error instanceof z.ZodError) return "validation_error";
  if (error && typeof error === "object" && "name" in error && typeof error.name === "string") return error.name.slice(0, 80);
  return "unknown_error";
}
