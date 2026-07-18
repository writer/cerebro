import { createHash } from "node:crypto";

export const MAX_SLACK_BLOCKS = 50;
export const MAX_SLACK_ACTIONS = 5;
export const MAX_SLACK_SECTION_LENGTH = 3_000;

export interface SlackPlainTextObjectV1 {
  readonly emoji: false;
  readonly text: string;
  readonly type: "plain_text";
}

export interface SlackHeaderBlockV1 {
  readonly block_id: string;
  readonly text: SlackPlainTextObjectV1;
  readonly type: "header";
}

export interface SlackSectionBlockV1 {
  readonly block_id: string;
  readonly text: SlackPlainTextObjectV1;
  readonly type: "section";
}

export interface SlackButtonElementV1 {
  readonly action_id: string;
  readonly style?: "danger" | "primary";
  readonly text: SlackPlainTextObjectV1;
  readonly type: "button";
  readonly value: string;
}

export interface SlackActionsBlockV1 {
  readonly block_id: string;
  readonly elements: readonly SlackButtonElementV1[];
  readonly type: "actions";
}

export type SlackBlockV1 =
  | SlackActionsBlockV1
  | SlackHeaderBlockV1
  | SlackSectionBlockV1;

export interface SlackActionInputV1 {
  readonly action_key: string;
  readonly label: string;
  readonly style?: SlackButtonElementV1["style"];
  readonly value: string;
}

export interface SlackBlocksInputV1 {
  readonly actions?: readonly SlackActionInputV1[];
  readonly projection_key: string;
  readonly sections: readonly string[];
  readonly title?: string;
}

export interface SlackBlocksProjectionV1 {
  readonly blocks: readonly SlackBlockV1[];
  readonly projection_id: string;
  readonly schema_version: "slack-blocks-projection/v1";
}

export class SlackBlockProjectionError extends Error {}

/**
 * Produces a bounded Block Kit subset. Display values are always plain_text,
 * so caller-provided text cannot create mentions, links, or formatting tokens.
 */
export function projectSlackBlocks(
  input: SlackBlocksInputV1,
): SlackBlocksProjectionV1 {
  const projectionKey = requireSlackKey(
    input.projection_key,
    "block projection key",
  );
  if (!Array.isArray(input.sections)) {
    throw new SlackBlockProjectionError(
      "Slack block sections must be an array.",
    );
  }
  if (input.actions !== undefined && !Array.isArray(input.actions)) {
    throw new SlackBlockProjectionError(
      "Slack block actions must be an array.",
    );
  }
  if (
    input.actions !== undefined
    && input.actions.length > MAX_SLACK_ACTIONS
  ) {
    throw new SlackBlockProjectionError(
      `Slack block actions cannot exceed ${MAX_SLACK_ACTIONS}.`,
    );
  }
  const actions = input.actions === undefined ? [] : [...input.actions];
  const blockCount = input.sections.length
    + (input.title === undefined ? 0 : 1)
    + (actions.length === 0 ? 0 : 1);
  if (blockCount === 0 || blockCount > MAX_SLACK_BLOCKS) {
    throw new SlackBlockProjectionError(
      `Slack block output must contain between 1 and ${MAX_SLACK_BLOCKS} blocks.`,
    );
  }

  const blocks: SlackBlockV1[] = [];
  if (input.title !== undefined) {
    const text = slackPlainText(input.title, "block title", 150);
    blocks.push(
      Object.freeze({
        block_id: stableSlackIdentifier("header", [
          projectionKey,
          JSON.stringify(text),
        ]),
        text,
        type: "header" as const,
      }),
    );
  }
  for (const [index, section] of input.sections.entries()) {
    const text = slackPlainText(
      section,
      `block section ${index + 1}`,
      MAX_SLACK_SECTION_LENGTH,
    );
    blocks.push(
      Object.freeze({
        block_id: stableSlackIdentifier("section", [
          projectionKey,
          String(index + 1),
          JSON.stringify(text),
        ]),
        text,
        type: "section" as const,
      }),
    );
  }
  if (actions.length > 0) {
    const actionKeys = new Set<string>();
    const elements = actions.map((action) => {
      const actionKey = requireSlackActionKey(action.action_key);
      if (actionKeys.has(actionKey)) {
        throw new SlackBlockProjectionError(
          "Slack block action keys must be unique.",
        );
      }
      actionKeys.add(actionKey);
      const style = action.style;
      if (style !== undefined && style !== "danger" && style !== "primary") {
        throw new SlackBlockProjectionError(
          "Slack block action style is unsupported.",
        );
      }
      return Object.freeze({
        action_id: stableSlackIdentifier("action", [projectionKey, actionKey]),
        ...(style === undefined ? {} : { style }),
        text: slackPlainText(action.label, "block action label", 75),
        type: "button" as const,
        value: normalizeSlackText(
          action.value,
          "block action value",
          2_000,
        ),
      });
    });
    blocks.push(
      Object.freeze({
        block_id: stableSlackIdentifier("actions", [
          projectionKey,
          JSON.stringify(elements),
        ]),
        elements: Object.freeze(elements),
        type: "actions" as const,
      }),
    );
  }

  const frozenBlocks = Object.freeze(blocks);
  const truth = {
    blocks: frozenBlocks,
    schema_version: "slack-blocks-projection/v1" as const,
  };
  return Object.freeze({
    ...truth,
    projection_id: contentBoundSlackIdentifier(
      "blocks",
      projectionKey,
      truth,
    ),
  });
}

export function slackPlainText(
  value: string,
  field: string,
  maximum: number,
): SlackPlainTextObjectV1 {
  return Object.freeze({
    emoji: false,
    text: normalizeSlackText(value, field, maximum),
    type: "plain_text" as const,
  });
}

export function normalizeSlackText(
  value: string,
  field: string,
  maximum: number,
): string {
  if (typeof value !== "string" || !Number.isInteger(maximum) || maximum < 1) {
    throw new SlackBlockProjectionError(`${field} is invalid.`);
  }
  if (value.length > maximum * 2) {
    throw new SlackBlockProjectionError(`${field} is invalid.`);
  }
  const normalized = value.replace(/\r\n?/g, "\n").normalize("NFC");
  if (
    normalized.trim().length === 0
    || Array.from(normalized).length > maximum
    || /[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f]/.test(normalized)
  ) {
    throw new SlackBlockProjectionError(`${field} is invalid.`);
  }
  return normalized;
}

export function requireSlackKey(value: string, field: string): string {
  const normalized = normalizeSlackText(value, field, 512);
  if (/\s/.test(normalized)) {
    throw new SlackBlockProjectionError(`${field} must not contain whitespace.`);
  }
  return normalized;
}

export function requireSlackOpaqueRef(value: string, field: string): string {
  const normalized = normalizeSlackText(value, field, 2_000);
  if (!/^[a-z][a-z0-9+.-]*:\/\/\S+$/.test(normalized)) {
    throw new SlackBlockProjectionError(`${field} must be an opaque reference.`);
  }
  return normalized;
}

export function stableSlackIdentifier(
  namespace: string,
  fields: readonly string[],
): string {
  if (!/^[a-z][a-z0-9_-]{0,31}$/.test(namespace)) {
    throw new SlackBlockProjectionError("Slack identifier namespace is invalid.");
  }
  const digest = sha256(JSON.stringify(fields));
  return `cerebro.${namespace}.${digest.slice(0, 32)}`;
}

export function contentBoundSlackIdentifier(
  namespace: string,
  logicalKey: string,
  truth: object,
): string {
  return `${stableSlackIdentifier(namespace, [logicalKey])}:sha256:${sha256(
    JSON.stringify(truth),
  )}`;
}

export function sha256(value: string): string {
  return createHash("sha256").update(value).digest("hex");
}

function requireSlackActionKey(value: string): string {
  const normalized = requireSlackKey(value, "block action key");
  if (!/^[a-z][a-z0-9_-]{0,63}$/.test(normalized)) {
    throw new SlackBlockProjectionError(
      "Slack block action key must be a lowercase stable key.",
    );
  }
  return normalized;
}
