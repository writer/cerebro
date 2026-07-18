import assert from "node:assert/strict";
import { describe, test } from "node:test";

import {
  slackLearningCandidateRejection,
  type SlackLearningCandidateMessage,
} from "../src/history/message-policy.js";

const acceptedMessage: SlackLearningCandidateMessage = {
  text: "A portable learning candidate",
  ts: "1712345678.000100",
  user: "U_SAMPLE",
};

describe("Slack learning candidate policy", () => {
  test("preserves the ordered rejection reasons", () => {
    const cases: Array<{
      expected: ReturnType<typeof slackLearningCandidateRejection>;
      message: SlackLearningCandidateMessage;
    }> = [
      {
        expected: "machine",
        message: { app_id: "A_SAMPLE", bot_id: "B_SAMPLE", subtype: "message_changed" },
      },
      {
        expected: "machine",
        message: { app_id: "A_SAMPLE", subtype: "message_changed" },
      },
      {
        expected: "subtype",
        message: { subtype: "message_changed" },
      },
      {
        expected: "missing_user",
        message: { text: acceptedMessage.text, ts: acceptedMessage.ts, user: "   " },
      },
      {
        expected: "missing_timestamp",
        message: { text: acceptedMessage.text, ts: " ", user: acceptedMessage.user },
      },
      {
        expected: "empty",
        message: { text: "\n\t", ts: acceptedMessage.ts, user: acceptedMessage.user },
      },
    ];

    for (const value of cases) {
      assert.equal(slackLearningCandidateRejection(value.message, "U_CEREBRO"), value.expected);
    }
  });

  test("rejects messages that mention the configured bot user", () => {
    assert.equal(slackLearningCandidateRejection({
      ...acceptedMessage,
      text: "Please ask <@U_CEREBRO> about this.",
    }, "U_CEREBRO"), "cerebro_mention");
  });

  test("does not treat an empty or different bot identity as a mention", () => {
    const message = {
      ...acceptedMessage,
      text: "Please ask <@U_CEREBRO> about this.",
    };

    assert.equal(slackLearningCandidateRejection(message, ""), undefined);
    assert.equal(slackLearningCandidateRejection(message, "   "), undefined);
    assert.equal(slackLearningCandidateRejection(message, "U_OTHER"), undefined);
  });

  test("accepts a human-authored message with the required fields", () => {
    assert.equal(slackLearningCandidateRejection(acceptedMessage, "U_CEREBRO"), undefined);
  });
});
