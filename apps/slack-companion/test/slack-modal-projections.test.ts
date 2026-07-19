import assert from "node:assert/strict";
import test from "node:test";
import {
  MAX_SLACK_BLOCKS,
  projectSlackModal,
} from "../src/index.js";

test("modal projections produce bounded retry-stable views", () => {
  const input = {
    actions: [
      {
        action_key: "show_evidence",
        label: "Show <@U123>",
        value: "evidence://packet/one",
      },
    ],
    close_label: "Cancel",
    context_ref: "context://run/one",
    projection_key: "run-one:decision",
    sections: ["Approve the proposed action for <@U123>."],
    submit_label: "Approve",
    title: "Review action",
  };

  const first = projectSlackModal(input);
  const retry = projectSlackModal({ ...input });

  assert.deepEqual(retry, first);
  assert.equal(first.view.type, "modal");
  assert.match(first.view.callback_id, /^cerebro\.modal\.[0-9a-f]{32}$/);
  assert.equal(first.view.private_metadata, "context://run/one");
  assert.deepEqual(first.view.submit, {
    emoji: false,
    text: "Approve",
    type: "plain_text",
  });
  assert.equal(JSON.stringify(first).includes('"type":"mrkdwn"'), false);

  const changed = projectSlackModal({
    ...input,
    sections: ["Approve the updated action."],
  });
  assert.notEqual(changed.projection_id, first.projection_id);
});

test("modal projections reject unsafe metadata and Slack size violations", () => {
  assert.throws(
    () =>
      projectSlackModal({
        context_ref: "raw metadata",
        projection_key: "run-one:decision",
        sections: ["Review the action."],
        title: "Review action",
      }),
    /must be an opaque reference/,
  );
  assert.throws(
    () =>
      projectSlackModal({
        projection_key: "run-one:decision",
        sections: ["Review the action."],
        title: "x".repeat(25),
      }),
    /modal title is invalid/,
  );
  assert.throws(
    () =>
      projectSlackModal({
        projection_key: "run-one:decision",
        sections: Array.from({ length: MAX_SLACK_BLOCKS + 1 }, () => "Review"),
        title: "Review action",
      }),
    /between 1 and 50 blocks/,
  );
  assert.throws(
    () =>
      projectSlackModal({
        projection_key: "run-one:decision",
        sections: ["Review\u0007the action."],
        title: "Review action",
      }),
    /block section 1 is invalid/,
  );
});
