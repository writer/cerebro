import type {
  SlackMultipartAcceptanceV1,
  SlackMultipartPartProjectionV1,
  SlackMultipartProjectionV1,
} from "./multipart.js";
import {
  contentBoundSlackIdentifier,
  MAX_SLACK_SECTION_LENGTH,
  normalizeSlackText,
  projectSlackBlocks,
  requireSlackKey,
  sha256,
  type SlackBlockV1,
} from "./blocks.js";

export const MAX_SLACK_MESSAGE_PART_LENGTH = 2_800;
export const MAX_SLACK_MESSAGE_PARTS = 40;
export const MAX_SLACK_MESSAGE_SOURCE_LENGTH =
  MAX_SLACK_MESSAGE_PART_LENGTH * MAX_SLACK_MESSAGE_PARTS;

export interface SlackMessagePayloadV1 {
  readonly blocks: readonly SlackBlockV1[];
  readonly link_names: false;
  readonly mrkdwn: false;
  readonly text: string;
  /** These false flags disable destination-side link previews; this projector performs no I/O. */
  readonly unfurl_links: false;
  readonly unfurl_media: false;
}

export interface SlackMessagePartPlanV1 {
  readonly payload: SlackMessagePayloadV1;
  readonly payload_digest: `sha256:${string}`;
  readonly sequence: number;
}

export interface SlackMessagePlanV1 {
  readonly message_key: string;
  readonly part_count: number;
  readonly parts: readonly SlackMessagePartPlanV1[];
  readonly schema_version: "slack-message-plan/v1";
  readonly source_digest: `sha256:${string}`;
}

export interface SlackMessagePartProjectionV1 {
  readonly acceptance?: SlackMultipartAcceptanceV1;
  readonly client_message_id: string;
  readonly part_id: string;
  readonly payload: SlackMessagePayloadV1;
  readonly payload_digest: `sha256:${string}`;
  readonly payload_ref: string;
  readonly schema_version: "slack-message-part-projection/v1";
  readonly sequence: number;
  readonly state: SlackMultipartPartProjectionV1["state"];
}

export interface SlackMessageProjectionV1 {
  readonly delivery_id: string;
  readonly destination_ref: string;
  readonly part_count: number;
  readonly parts: readonly SlackMessagePartProjectionV1[];
  readonly projection_id: string;
  readonly run_id: string;
  readonly schema_version: "slack-message-projection/v1";
  readonly state: SlackMultipartProjectionV1["state"];
}

export class SlackMessageProjectionError extends Error {}

/** Builds the payload bytes that must be stored before a durable delivery plan. */
export function planSlackMessage(
  messageKey: string,
  sourceText: string,
): SlackMessagePlanV1 {
  const key = requireSlackKey(messageKey, "message key");
  const normalized = normalizeSlackText(
    sourceText,
    "message source text",
    MAX_SLACK_MESSAGE_SOURCE_LENGTH,
  );
  const chunks = splitSlackMessageText(normalized);
  if (chunks.length > MAX_SLACK_MESSAGE_PARTS) {
    throw new SlackMessageProjectionError(
      `Slack message cannot exceed ${MAX_SLACK_MESSAGE_PARTS} parts.`,
    );
  }
  const parts = chunks.map((text, index) => {
    const sequence = index + 1;
    const payload = buildPayload(key, sequence, text);
    return Object.freeze({
      payload,
      payload_digest: `sha256:${sha256(JSON.stringify(payload))}` as const,
      sequence,
    });
  });
  return Object.freeze({
    message_key: key,
    part_count: parts.length,
    parts: Object.freeze(parts),
    schema_version: "slack-message-plan/v1",
    source_digest: `sha256:${sha256(normalized)}`,
  });
}

/** Joins stored payload truth to durable receipt identities and resume state. */
export function projectSlackMessages(
  delivery: SlackMultipartProjectionV1,
  plan: SlackMessagePlanV1,
): SlackMessageProjectionV1 {
  if (delivery.schema_version !== "slack-multipart-projection/v1") {
    throw new SlackMessageProjectionError(
      "Slack multipart projection version is unsupported.",
    );
  }
  if (plan.schema_version !== "slack-message-plan/v1") {
    throw new SlackMessageProjectionError(
      "Slack message plan version is unsupported.",
    );
  }
  const messageKey = requireSlackKey(plan.message_key, "message key");
  if (
    !Array.isArray(plan.parts)
    || plan.part_count !== plan.parts.length
    || delivery.part_count !== delivery.parts.length
    || plan.part_count !== delivery.part_count
    || plan.part_count < 1
    || plan.part_count > MAX_SLACK_MESSAGE_PARTS
  ) {
    throw new SlackMessageProjectionError(
      "Slack message plan and durable delivery part counts must match.",
    );
  }
  const sourceDigest = requireSha256(
    plan.source_digest,
    "message source_digest",
  );
  const reconstructedSource = plan.parts
    .map((part) => part.payload.text)
    .join("");
  const normalizedSource = normalizeSlackText(
    reconstructedSource,
    "message source text",
    MAX_SLACK_MESSAGE_SOURCE_LENGTH,
  );
  if (sourceDigest !== `sha256:${sha256(normalizedSource)}`) {
    throw new SlackMessageProjectionError(
      "Slack message source digest does not match its parts.",
    );
  }
  const parts = plan.parts.map((planned, index) => {
    const durable = delivery.parts[index];
    const expectedSequence = index + 1;
    if (
      durable === undefined
      || planned.sequence !== expectedSequence
      || durable.sequence !== expectedSequence
    ) {
      throw new SlackMessageProjectionError(
        "Slack message part sequences must be contiguous.",
      );
    }
    const payloadDigest = requireSha256(
      planned.payload_digest,
      "message payload_digest",
    );
    const actualDigest = `sha256:${sha256(JSON.stringify(planned.payload))}`;
    if (payloadDigest !== actualDigest || durable.payload_digest !== payloadDigest) {
      throw new SlackMessageProjectionError(
        "Slack message payload digest does not match durable delivery truth.",
      );
    }
    validatePayload(planned.payload, messageKey, expectedSequence);
    return Object.freeze({
      ...(durable.acceptance === undefined
        ? {}
        : { acceptance: durable.acceptance }),
      client_message_id: requireSlackKey(
        durable.client_message_id,
        "message client_message_id",
      ),
      part_id: requireSlackKey(durable.part_id, "message part_id"),
      payload: planned.payload,
      payload_digest: payloadDigest,
      payload_ref: durable.payload_ref,
      schema_version: "slack-message-part-projection/v1" as const,
      sequence: expectedSequence,
      state: durable.state,
    });
  });
  const frozenParts = Object.freeze(parts);
  const truth = {
    delivery_id: delivery.delivery_id,
    destination_ref: delivery.destination_ref,
    part_count: frozenParts.length,
    parts: frozenParts,
    run_id: delivery.run_id,
    schema_version: "slack-message-projection/v1" as const,
    state: delivery.state,
  };
  return Object.freeze({
    ...truth,
    projection_id: contentBoundSlackIdentifier(
      "message",
      delivery.delivery_id,
      truth,
    ),
  });
}

function splitSlackMessageText(text: string): string[] {
  const codePoints = Array.from(text);
  const chunks: string[] = [];
  let offset = 0;
  while (offset < codePoints.length) {
    let end = Math.min(offset + MAX_SLACK_MESSAGE_PART_LENGTH, codePoints.length);
    if (end < codePoints.length) {
      const earliestBreak = offset + Math.floor(MAX_SLACK_MESSAGE_PART_LENGTH / 2);
      for (let index = end - 1; index >= earliestBreak; index -= 1) {
        if (codePoints[index] === "\n" || codePoints[index] === " ") {
          end = index + 1;
          break;
        }
      }
    }
    chunks.push(codePoints.slice(offset, end).join(""));
    offset = end;
  }
  return chunks;
}

function buildPayload(
  messageKey: string,
  sequence: number,
  text: string,
): SlackMessagePayloadV1 {
  const blockProjection = projectSlackBlocks({
    projection_key: `${messageKey}:part:${sequence}`,
    sections: [text],
  });
  return Object.freeze({
    blocks: blockProjection.blocks,
    link_names: false as const,
    mrkdwn: false as const,
    text,
    unfurl_links: false as const,
    unfurl_media: false as const,
  });
}

function validatePayload(
  payload: SlackMessagePayloadV1,
  messageKey: string,
  sequence: number,
): void {
  const normalized = normalizeSlackText(
    payload.text,
    "message payload text",
    MAX_SLACK_MESSAGE_PART_LENGTH,
  );
  const expected = buildPayload(messageKey, sequence, normalized);
  if (
    normalized !== payload.text
    || Array.from(payload.text).length > MAX_SLACK_SECTION_LENGTH
    || JSON.stringify(payload) !== JSON.stringify(expected)
  ) {
    throw new SlackMessageProjectionError(
      "Slack message payload is not the supported safe shape.",
    );
  }
}

function requireSha256(value: string, field: string): `sha256:${string}` {
  if (!/^sha256:[0-9a-f]{64}$/.test(value)) {
    throw new SlackMessageProjectionError(`${field} is invalid.`);
  }
  return value as `sha256:${string}`;
}
