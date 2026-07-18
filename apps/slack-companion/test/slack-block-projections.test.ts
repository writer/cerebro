import assert from "node:assert/strict";
import test from "node:test";
import {
  MAX_SLACK_ACTIONS,
  MAX_SLACK_BLOCKS,
  projectSlackBlocks,
  SlackBlockProjectionError,
} from "../src/index.js";

test("block projections keep untrusted display text inert and action ids stable", () => {
  const input = {
    actions: [
      {
        action_key: "open_result",
        label: "Open <@U123>",
        style: "primary" as const,
        value: "result://run/one",
      },
    ],
    projection_key: "run-one:result",
    sections: ["Result from <@U123> with *untrusted formatting*"],
    title: "Run result",
  };

  const first = projectSlackBlocks(input);
  const retry = projectSlackBlocks({ ...input });
  const actionBlock = first.blocks[2];

  assert.deepEqual(retry, first);
  assert.equal(actionBlock?.type, "actions");
  if (actionBlock?.type !== "actions") {
    assert.fail("expected an actions block");
  }
  assert.match(
    actionBlock.elements[0]?.action_id ?? "",
    /^cerebro\.action\.[0-9a-f]{32}$/,
  );
  assert.deepEqual(actionBlock.elements[0]?.text, {
    emoji: false,
    text: "Open <@U123>",
    type: "plain_text",
  });
  assert.equal(first.blocks[1]?.type, "section");
  assert.equal(JSON.stringify(first).includes('"type":"mrkdwn"'), false);
  assert.equal(Object.isFrozen(first), true);
  assert.equal(Object.isFrozen(first.blocks), true);

  const otherLogicalProjection = projectSlackBlocks({
    ...input,
    projection_key: "run-two:result",
  });
  assert.notEqual(otherLogicalProjection.projection_id, first.projection_id);
  assert.notEqual(
    (otherLogicalProjection.blocks[2] as typeof actionBlock).elements[0]?.action_id,
    actionBlock.elements[0]?.action_id,
  );
});

test("block projections reject malformed, duplicate, and oversized input", () => {
  assert.throws(
    () =>
      projectSlackBlocks({
        actions: [
          { action_key: "retry", label: "Retry", value: "one" },
          { action_key: "retry", label: "Retry", value: "two" },
        ],
        projection_key: "run-one",
        sections: ["Work failed."],
      }),
    /action keys must be unique/,
  );
  assert.throws(
    () =>
      projectSlackBlocks({
        actions: Array.from({ length: MAX_SLACK_ACTIONS + 1 }, (_, index) => ({
          action_key: `action_${index}`,
          label: `Action ${index}`,
          value: String(index),
        })),
        projection_key: "run-one",
        sections: ["Choose an action."],
      }),
    /actions cannot exceed/,
  );
  assert.throws(
    () =>
      projectSlackBlocks({
        projection_key: "run-one",
        sections: Array.from({ length: MAX_SLACK_BLOCKS + 1 }, () => "Status"),
      }),
    /between 1 and 50 blocks/,
  );
  assert.throws(
    () =>
      projectSlackBlocks({
        projection_key: "run-one",
        sections: ["unsafe\u0000text"],
      }),
    SlackBlockProjectionError,
  );
  assert.throws(
    () => projectSlackBlocks({ projection_key: "run one", sections: ["Status"] }),
    /must not contain whitespace/,
  );
});
