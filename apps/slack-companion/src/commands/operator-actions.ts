import { encodeSlackActionEnvelope } from "./codec.js";
import {
  createSlackActionRegistry,
  type SlackActionCatalogV1,
} from "./contracts.js";
import {
  requireSlackKey,
  requireSlackOpaqueRef,
  sha256,
  SlackBlockProjectionError,
  type SlackActionInputV1,
} from "../projections/blocks.js";

export type SlackAnswerFeedbackActionIdV1 =
  | "answer.feedback.helpful"
  | "answer.feedback.missed_source"
  | "answer.feedback.wrong_owner"
  | "answer.feedback.needs_followup";

export type SlackNextStepActionIdV1 =
  | "answer.watch.start"
  | "evidence.recheck.request"
  | "triage.open"
  | "watch.stop";

export type SlackNextStepActionKindV1 =
  | "open_triage"
  | "recheck_evidence"
  | "stop_watch"
  | "watch_answer";

export interface SlackAnswerFeedbackActionsInputV1 {
  readonly feedback_key: string;
  readonly issued_at: string;
  readonly subject_ref: string;
}

export interface SlackNextStepActionCandidateV1 {
  readonly kind: SlackNextStepActionKindV1;
  readonly subject_ref: string;
}

export interface SlackNextStepActionsInputV1 {
  readonly issued_at: string;
  readonly next_step_key: string;
  readonly steps: readonly SlackNextStepActionCandidateV1[];
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

const NEXT_STEP_DEFINITIONS: readonly {
  readonly action_id: SlackNextStepActionIdV1;
  readonly action_key: string;
  readonly capability_id: string;
  readonly command: string;
  readonly kind: SlackNextStepActionKindV1;
  readonly label: string;
  readonly style?: SlackActionInputV1["style"];
}[] = Object.freeze([
  Object.freeze({
    action_id: "answer.watch.start",
    action_key: "watch_answer",
    capability_id: "assistant.watch",
    command: "answer_watch",
    kind: "watch_answer",
    label: "Watch answer",
  }),
  Object.freeze({
    action_id: "evidence.recheck.request",
    action_key: "recheck_evidence",
    capability_id: "evidence.recheck",
    command: "evidence_recheck",
    kind: "recheck_evidence",
    label: "Recheck evidence",
  }),
  Object.freeze({
    action_id: "triage.open",
    action_key: "open_triage",
    capability_id: "triage.open",
    command: "triage_open",
    kind: "open_triage",
    label: "Open triage",
    style: "primary" as const,
  }),
  Object.freeze({
    action_id: "watch.stop",
    action_key: "stop_watch",
    capability_id: "assistant.watch",
    command: "watch_stop",
    kind: "stop_watch",
    label: "Stop watch",
    style: "danger" as const,
  }),
]);

export const SLACK_OPERATOR_ACTION_CATALOG_V1: SlackActionCatalogV1 = Object.freeze({
  actions: Object.freeze(
    [
      ...FEEDBACK_ACTIONS.map((action) =>
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
      ...NEXT_STEP_DEFINITIONS.map((action) =>
        Object.freeze({
          action_id: action.action_id,
          command: action.command,
          parameters: Object.freeze([]),
          required_capabilities: Object.freeze([{
            capability_id: action.capability_id,
            level: "required" as const,
            version: "v1",
          }]),
          retry_policy: "idempotent" as const,
          schema_version: "slack-action-contract/v1" as const,
          subject_requirement: "required" as const,
        }),
      ),
    ],
  ),
  catalog_id: "cerebro.slack.operator_actions",
  revision: 2,
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

export function projectSlackNextStepActions(
  input: SlackNextStepActionsInputV1,
): readonly SlackActionInputV1[] {
  requireExactRecord(
    input,
    ["issued_at", "next_step_key", "steps"],
    "Slack next-step actions input",
  );
  const nextStepKey = requireSlackKey(input.next_step_key, "next-step key");
  requirePlainArray(input.steps, 0, 4, "Slack next-step actions");
  const seen = new Set<SlackNextStepActionKindV1>();
  return Object.freeze(input.steps.map((rawStep, index) => {
    requireExactRecord(
      rawStep,
      ["kind", "subject_ref"],
      `Slack next-step action ${index + 1}`,
    );
    const step = {
      kind: rawStep.kind,
      subject_ref: rawStep.subject_ref,
    };
    if (
      !isNextStepActionKind(step.kind) ||
      typeof step.subject_ref !== "string"
    ) {
      throw new SlackBlockProjectionError("Slack next-step actions are invalid.");
    }
    const definition = NEXT_STEP_DEFINITIONS.find((candidate) =>
      candidate.kind === step.kind
    );
    if (definition === undefined) {
      throw new SlackBlockProjectionError("Unsupported Slack next-step action kind.");
    }
    if (seen.has(step.kind)) {
      throw new SlackBlockProjectionError("Slack next-step action kinds must be unique.");
    }
    seen.add(step.kind);
    const subjectRef = requireSlackOpaqueRef(step.subject_ref, "next-step subject_ref");
    return Object.freeze({
      action_key: definition.action_key,
      label: definition.label,
      ...(definition.style === undefined ? {} : { style: definition.style }),
      value: encodeSlackActionEnvelope({
        action: definition.action_id,
        command: definition.command,
        idempotency_key: nextStepIdempotencyKey(nextStepKey, step.kind, subjectRef),
        issued_at: input.issued_at,
        schema_version: "slack-action-envelope/v1",
        subject_ref: subjectRef,
      }),
    });
  }));
}

function isNextStepActionKind(value: unknown): value is SlackNextStepActionKindV1 {
  return NEXT_STEP_DEFINITIONS.some((definition) => definition.kind === value);
}

function feedbackIdempotencyKey(
  feedbackKey: string,
  subjectRef: string,
  actionId: SlackAnswerFeedbackActionIdV1,
): string {
  return `feedback:${sha256(JSON.stringify([feedbackKey, subjectRef, actionId]))}`;
}

function nextStepIdempotencyKey(
  nextStepKey: string,
  kind: SlackNextStepActionKindV1,
  subjectRef: string,
): string {
  return `next:${sha256(JSON.stringify([nextStepKey, kind, subjectRef]))}`;
}

function requirePlainArray(
  value: unknown,
  minimum: number,
  maximum: number,
  field: string,
): asserts value is readonly Record<string, unknown>[] {
  if (
    !Array.isArray(value) ||
    value.length < minimum ||
    value.length > maximum ||
    Object.getPrototypeOf(value) !== Array.prototype ||
    Object.prototype.hasOwnProperty.call(value, "toJSON")
  ) {
    throw new SlackBlockProjectionError(`${field} must be a bounded plain array.`);
  }
  for (let index = 0; index < value.length; index += 1) {
    if (!Object.prototype.hasOwnProperty.call(value, index)) {
      throw new SlackBlockProjectionError(`${field} must not be sparse.`);
    }
  }
}

function requireExactRecord(
  value: unknown,
  requiredKeys: readonly string[],
  field: string,
): asserts value is Record<string, unknown> {
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    throw new SlackBlockProjectionError(`${field} is invalid.`);
  }
  const prototype = Object.getPrototypeOf(value);
  if (
    (prototype !== Object.prototype && prototype !== null) ||
    Object.prototype.hasOwnProperty.call(value, "toJSON")
  ) {
    throw new SlackBlockProjectionError(`${field} must be a plain record.`);
  }
  let ownKeyCount = 0;
  for (const key in value) {
    if (!Object.prototype.hasOwnProperty.call(value, key)) continue;
    ownKeyCount += 1;
    if (ownKeyCount > requiredKeys.length || !requiredKeys.includes(key)) {
      throw new SlackBlockProjectionError(`${field} contains unsupported fields.`);
    }
  }
  if (
    ownKeyCount !== requiredKeys.length ||
    requiredKeys.some((key) => {
      const descriptor = Object.getOwnPropertyDescriptor(value, key);
      return descriptor === undefined ||
        !("value" in descriptor) ||
        descriptor.enumerable !== true;
    })
  ) {
    throw new SlackBlockProjectionError(`${field} is incomplete.`);
  }
}
