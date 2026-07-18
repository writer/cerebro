import {
  contentBoundSlackIdentifier,
  normalizeSlackText,
  projectSlackBlocks,
  requireSlackKey,
  requireSlackOpaqueRef,
  slackPlainText,
  stableSlackIdentifier,
  type SlackActionInputV1,
  type SlackBlockV1,
  type SlackPlainTextObjectV1,
} from "./blocks.js";

export interface SlackModalInputV1 {
  readonly actions?: readonly SlackActionInputV1[];
  readonly close_label?: string;
  readonly context_ref?: string;
  readonly projection_key: string;
  readonly sections: readonly string[];
  readonly submit_label?: string;
  readonly title: string;
}

export interface SlackModalViewV1 {
  readonly blocks: readonly SlackBlockV1[];
  readonly callback_id: string;
  readonly close?: SlackPlainTextObjectV1;
  readonly private_metadata?: string;
  readonly submit?: SlackPlainTextObjectV1;
  readonly title: SlackPlainTextObjectV1;
  readonly type: "modal";
}

export interface SlackModalProjectionV1 {
  readonly projection_id: string;
  readonly schema_version: "slack-modal-projection/v1";
  readonly view: SlackModalViewV1;
}

export function projectSlackModal(
  input: SlackModalInputV1,
): SlackModalProjectionV1 {
  const projectionKey = requireSlackKey(
    input.projection_key,
    "modal projection key",
  );
  const blockProjection = projectSlackBlocks({
    ...(input.actions === undefined ? {} : { actions: input.actions }),
    projection_key: `${projectionKey}:modal`,
    sections: input.sections,
  });
  const contextRef = input.context_ref === undefined
    ? undefined
    : requireSlackOpaqueRef(input.context_ref, "modal context_ref");
  const view = Object.freeze({
    blocks: blockProjection.blocks,
    callback_id: stableSlackIdentifier("modal", [projectionKey]),
    ...(input.close_label === undefined
      ? {}
      : { close: slackPlainText(input.close_label, "modal close label", 24) }),
    ...(contextRef === undefined ? {} : { private_metadata: contextRef }),
    ...(input.submit_label === undefined
      ? {}
      : {
          submit: slackPlainText(
            input.submit_label,
            "modal submit label",
            24,
          ),
        }),
    title: slackPlainText(
      normalizeSlackText(input.title, "modal title", 24),
      "modal title",
      24,
    ),
    type: "modal" as const,
  });
  const truth = {
    schema_version: "slack-modal-projection/v1" as const,
    view,
  };
  return Object.freeze({
    ...truth,
    projection_id: contentBoundSlackIdentifier("modal", projectionKey, truth),
  });
}
