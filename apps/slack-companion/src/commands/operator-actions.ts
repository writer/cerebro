import { encodeSlackActionEnvelope } from "./codec.js";
import {
  createSlackActionRegistry,
  type SlackActionCatalogV1,
} from "./contracts.js";
import {
  requireSlackKey,
  requireSlackOpaqueRef,
  sha256,
  type SlackActionInputV1,
} from "../projections/blocks.js";

export type SlackAnswerFeedbackActionIdV1 =
  | "answer.feedback.helpful"
  | "answer.feedback.missed_source"
  | "answer.feedback.wrong_owner"
  | "answer.feedback.needs_followup";

export interface SlackAnswerFeedbackActionsInputV1 {
  readonly feedback_key: string;
  readonly issued_at: string;
  readonly subject_ref: string;
}

const FEEDBACK_COMMAND = "answer_feedback";
const FEEDBACK_CAPABILITY = Object.freeze({
  capability_id: "assistant.feedback",
  level: "required" as const,
  version: "v1",
});

const FEEDBACK_ACTIONS: readonly {
  readonly action_id: SlackAnswerFeedbackActionIdV1;
  readonly action_key: string;
  readonly label: string;
  readonly style?: SlackActionInputV1["style"];
}[] = Object.freeze([
  Object.freeze({
    action_id: "answer.feedback.helpful",
    action_key: "feedback_helpful",
    label: "Helpful",
    style: "primary" as const,
  }),
  Object.freeze({
    action_id: "answer.feedback.missed_source",
    action_key: "feedback_missed_source",
    label: "Missed source",
  }),
  Object.freeze({
    action_id: "answer.feedback.wrong_owner",
    action_key: "feedback_wrong_owner",
    label: "Wrong owner",
  }),
  Object.freeze({
    action_id: "answer.feedback.needs_followup",
    action_key: "feedback_needs_followup",
    label: "Needs follow-up",
  }),
]);

export const SLACK_OPERATOR_ACTION_CATALOG_V1: SlackActionCatalogV1 = Object.freeze({
  actions: Object.freeze(
    FEEDBACK_ACTIONS.map((action) =>
      Object.freeze({
        action_id: action.action_id,
        command: FEEDBACK_COMMAND,
        parameters: Object.freeze([]),
        required_capabilities: Object.freeze([FEEDBACK_CAPABILITY]),
        retry_policy: "idempotent" as const,
        schema_version: "slack-action-contract/v1" as const,
        subject_requirement: "required" as const,
      }),
    ),
  ),
  catalog_id: "cerebro.slack.operator_actions",
  revision: 1,
  schema_version: "slack-action-catalog/v1",
});

export const SLACK_OPERATOR_ACTION_REGISTRY = createSlackActionRegistry(
  SLACK_OPERATOR_ACTION_CATALOG_V1,
);

export function projectSlackAnswerFeedbackActions(
  input: SlackAnswerFeedbackActionsInputV1,
): readonly SlackActionInputV1[] {
  const feedbackKey = requireSlackKey(input.feedback_key, "feedback key");
  const subjectRef = requireSlackOpaqueRef(input.subject_ref, "feedback subject_ref");
  return Object.freeze(
    FEEDBACK_ACTIONS.map((action) =>
      Object.freeze({
        action_key: action.action_key,
        label: action.label,
        ...(action.style === undefined ? {} : { style: action.style }),
        value: encodeSlackActionEnvelope({
          action: action.action_id,
          command: FEEDBACK_COMMAND,
          idempotency_key: feedbackIdempotencyKey(
            feedbackKey,
            subjectRef,
            action.action_id,
          ),
          issued_at: input.issued_at,
          schema_version: "slack-action-envelope/v1",
          subject_ref: subjectRef,
        }),
      }),
    ),
  );
}

function feedbackIdempotencyKey(
  feedbackKey: string,
  subjectRef: string,
  actionId: SlackAnswerFeedbackActionIdV1,
): string {
  return `feedback:${sha256(JSON.stringify([feedbackKey, subjectRef, actionId]))}`;
}
