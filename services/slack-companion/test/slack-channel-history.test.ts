import assert from "node:assert/strict";
import test from "node:test";
import { SlackChannelHistoryClient, slackLearningCandidateRejection } from "../src/slack/channel-history.js";
import { testConfig } from "./fixtures.js";

test("historical Slack filtering ignores machine traffic and only excludes Cerebro mentions", () => {
  assert.equal(slackLearningCandidateRejection({ ts: "1", user: "U1", bot_id: "B1", text: "digest" }, "UCEREBRO"), "machine");
  assert.equal(slackLearningCandidateRejection({ ts: "1", user: "U1", app_id: "A1", text: "digest" }, "UCEREBRO"), "machine");
  assert.equal(slackLearningCandidateRejection({ ts: "1", user: "U1", subtype: "message_changed", text: "edit" }, "UCEREBRO"), "subtype");
  assert.equal(slackLearningCandidateRejection({ ts: "1", user: "U1", text: "<@UCEREBRO> answer" }, "UCEREBRO"), "cerebro_mention");
  assert.equal(slackLearningCandidateRejection({ ts: "1", user: "U1", text: "<@UOWNER> owns this" }, "UCEREBRO"), undefined);
});

test("Slack history client retries rate limits and lists only joined active channels", async () => {
  let calls = 0;
  const waits: number[] = [];
  const fetchFn = (async () => {
    calls += 1;
    if (calls === 1) return new Response("{}", { status: 429, headers: { "retry-after": "0.001" } });
    if (calls === 2) return response({ ok: true, user_id: "UCEREBRO" });
    return response({
      ok: true,
      channels: [
        { id: "CJOINED", name: "joined", is_member: true, is_private: true },
        { id: "COTHER", name: "other", is_member: false },
        { id: "CARCHIVED", name: "archived", is_member: true, is_archived: true },
      ],
      response_metadata: { next_cursor: "" },
    });
  }) as typeof fetch;
  const client = new SlackChannelHistoryClient(testConfig(), { fetch: fetchFn, sleep: async (milliseconds) => { waits.push(milliseconds); } });

  assert.equal(await client.botUserId(), "UCEREBRO");
  assert.deepEqual(await client.joinedChannels(10), [{ id: "CJOINED", name: "joined", isPrivate: true }]);
  assert.deepEqual(waits, [1]);
});

function response(body: Record<string, unknown>): Response {
  return new Response(JSON.stringify(body), { status: 200, headers: { "content-type": "application/json" } });
}
