import assert from "node:assert/strict";
import { describe, test } from "node:test";
import {
  QUESTION_WORK_DISPATCH_INITIAL_STATE,
  QuestionWorkDispatchPolicyError,
  decideQuestionWorkDispatch,
  type QuestionWorkDispatchBackoffPolicyV1,
  type QuestionWorkDispatchBackoffStateV1,
} from "../src/question-work/dispatch-policy.js";

const POLICY: QuestionWorkDispatchBackoffPolicyV1 = {
  initial_delay_ms: 100,
  max_delay_ms: 1_000,
  schema_version: "question-work-dispatch-backoff-policy/v1",
};

describe("question-work dispatch backoff", () => {
  test("applies capped exponential delay while retaining durable queued work", () => {
    let state = QUESTION_WORK_DISPATCH_INITIAL_STATE;
    const delays: number[] = [];

    for (let attempt = 0; attempt < 7; attempt += 1) {
      const result = decideQuestionWorkDispatch(POLICY, state, "publication_failed");
      assert.equal(result.queued_work_disposition, "retain");
      delays.push(result.delay_ms);
      state = result.next_state;
    }

    assert.deepEqual(delays, [100, 200, 400, 800, 1_000, 1_000, 1_000]);
    assert.equal(state.consecutive_failures, 7);
  });

  test("returns the same decision for the same failure state", () => {
    const state: QuestionWorkDispatchBackoffStateV1 = {
      consecutive_failures: 3,
      schema_version: "question-work-dispatch-backoff-state/v1",
    };

    const first = decideQuestionWorkDispatch(POLICY, state, "publication_failed");
    const second = decideQuestionWorkDispatch(POLICY, state, "publication_failed");

    assert.deepEqual(first, second);
    assert.deepEqual(state, {
      consecutive_failures: 3,
      schema_version: "question-work-dispatch-backoff-state/v1",
    });
  });

  test("resets failure state after publication succeeds", () => {
    const failed = decideQuestionWorkDispatch(
      POLICY,
      QUESTION_WORK_DISPATCH_INITIAL_STATE,
      "publication_failed",
    );
    const published = decideQuestionWorkDispatch(POLICY, failed.next_state, "published");

    assert.deepEqual(published, {
      delay_ms: 0,
      next_state: QUESTION_WORK_DISPATCH_INITIAL_STATE,
      queued_work_disposition: "retain",
      schema_version: "question-work-dispatch-decision/v1",
    });
    const nextFailure = decideQuestionWorkDispatch(
      POLICY,
      published.next_state,
      "publication_failed",
    );
    assert.equal(nextFailure.delay_ms, POLICY.initial_delay_ms);
    assert.equal(nextFailure.next_state.consecutive_failures, 1);
  });

  test("rejects invalid policy, state, and outcome inputs", () => {
    assert.throws(
      () =>
        decideQuestionWorkDispatch(
          { ...POLICY, initial_delay_ms: 0 },
          QUESTION_WORK_DISPATCH_INITIAL_STATE,
          "publication_failed",
        ),
      QuestionWorkDispatchPolicyError,
    );
    assert.throws(
      () =>
        decideQuestionWorkDispatch(
          { ...POLICY, max_delay_ms: 99 },
          QUESTION_WORK_DISPATCH_INITIAL_STATE,
          "publication_failed",
        ),
      /max_delay_ms cannot be less/,
    );
    assert.throws(
      () =>
        decideQuestionWorkDispatch(
          POLICY,
          {
            consecutive_failures: -1,
            schema_version: "question-work-dispatch-backoff-state/v1",
          },
          "publication_failed",
        ),
      /non-negative safe integer/,
    );
    assert.throws(
      () =>
        decideQuestionWorkDispatch(
          POLICY,
          QUESTION_WORK_DISPATCH_INITIAL_STATE,
          "unknown" as never,
        ),
      /outcome is unsupported/,
    );
  });
});
