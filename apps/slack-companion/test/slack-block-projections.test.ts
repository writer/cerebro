import assert from "node:assert/strict";
import test from "node:test";
import {
  MAX_SLACK_ACTIONS,
  MAX_SLACK_BLOCKS,
  projectSlackBlocks,
  projectSlackEphemeralResponse,
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

  const changedContent = projectSlackBlocks({
    ...input,
    sections: ["A revised result"],
  });
  assert.notEqual(
    changedContent.blocks[1]?.block_id,
    first.blocks[1]?.block_id,
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
        actions: new Array(MAX_SLACK_ACTIONS + 1),
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

test("ephemeral command responses are deterministic bounded projections", () => {
  const input = {
    actions: [{
      action_key: "open_result",
      label: "Open result",
      value: "result://run/one",
    }],
    fallback_text: "The command completed.",
    response_key: "command-one:result",
    sections: ["The command completed for <@U_SAMPLE>."],
    title: "Command result",
  };

  const first = projectSlackEphemeralResponse(input);
  const repeat = projectSlackEphemeralResponse({ ...input });

  assert.deepEqual(repeat, first);
  assert.deepEqual(first.payload, {
    blocks: first.payload.blocks,
    response_type: "ephemeral",
    text: "The command completed.",
  });
  assert.equal(JSON.stringify(first.payload).includes('"type":"mrkdwn"'), false);
  assert.match(
    first.projection_id,
    /^cerebro\.ephemeral_response\.[0-9a-f]{32}:sha256:[0-9a-f]{64}$/,
  );
  assert.equal(Object.isFrozen(first), true);
  assert.equal(Object.isFrozen(first.payload), true);
  assert.equal(Object.isFrozen(first.payload.blocks), true);
});

test("ephemeral command responses snapshot input and reject unsafe shapes", () => {
  const sections = ["Original result"];
  const projection = projectSlackEphemeralResponse({
    fallback_text: "Original result",
    response_key: "command-two:result",
    sections,
  });
  sections[0] = "Changed after projection";

  assert.equal(projection.payload.text, "Original result");
  assert.equal(projection.payload.blocks[0]?.type, "section");
  assert.equal(
    projection.payload.blocks[0]?.type === "section"
      ? projection.payload.blocks[0].text.text
      : undefined,
    "Original result",
  );
  assert.throws(
    () => projectSlackEphemeralResponse({
      fallback_text: "Unsafe\u0000fallback",
      response_key: "command-two:unsafe",
      sections: ["Result"],
    }),
    SlackBlockProjectionError,
  );
  assert.throws(
    () => projectSlackEphemeralResponse({
      fallback_text: "x".repeat(3_001),
      response_key: "command-two:oversized",
      sections: ["Result"],
    }),
    /response fallback text is invalid/,
  );
  assert.throws(
    () => projectSlackEphemeralResponse({
      fallback_text: "Result",
      response_key: "command-two:unexpected",
      sections: ["Result"],
      unexpected: true,
    } as never),
    /unsupported fields/,
  );
});
