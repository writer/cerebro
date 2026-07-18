import assert from "node:assert/strict";
import test from "node:test";
import {
  projectSlackHome,
  projectSlackVisibleStatus,
  SlackHomeProjectionError,
  type SlackStatusProjectionV1,
} from "../src/index.js";

test("Home projections sort durable statuses and preserve exact retries", () => {
  const queued = status("queued", "2026-07-18T10:00:00.000Z");
  const degraded = status("degraded", "2026-07-18T10:00:01.000Z");
  const input = {
    actions: [
      { action_key: "open_queue", label: "Open queue", value: "queue://active" },
    ],
    projection_key: "home:operator",
    statuses: [degraded, queued],
    summary: "Current work for <@U123>",
    title: "Cerebro work",
  };

  const first = projectSlackHome(input);
  const retryWithOtherInputOrder = projectSlackHome({
    ...input,
    statuses: [queued, degraded],
  });

  assert.deepEqual(retryWithOtherInputOrder, first);
  assert.equal(first.view.type, "home");
  assert.match(first.view.external_id, /^cerebro\.home\.[0-9a-f]{32}$/);
  assert.deepEqual(first.status_projection_ids, [
    queued.projection_id,
    degraded.projection_id,
  ]);
  assert.equal(first.view.blocks[1]?.type, "section");
  assert.equal(JSON.stringify(first).includes('"type":"mrkdwn"'), false);
  assert.equal(Object.isFrozen(first.view), true);
});

test("Home projections reject malformed and unbounded status sets", () => {
  const queued = status("queued", "2026-07-18T10:00:00.000Z");
  assert.throws(
    () =>
      projectSlackHome({
        projection_key: "home:operator",
        statuses: [queued, queued],
        summary: "Current work",
        title: "Cerebro work",
      }),
    /projection ids must be unique/,
  );
  assert.throws(
    () =>
      projectSlackHome({
        projection_key: "home:operator",
        statuses: Array.from({ length: 21 }, () => queued),
        summary: "Current work",
        title: "Cerebro work",
      }),
    /more than 20 statuses/,
  );
  assert.throws(
    () =>
      projectSlackHome({
        projection_key: "home:operator",
        statuses: [
          { ...queued, schema_version: "slack-status-projection/v2" },
        ] as unknown as SlackStatusProjectionV1[],
        summary: "Current work",
        title: "Cerebro work",
      }),
    SlackHomeProjectionError,
  );
  assert.throws(
    () =>
      projectSlackHome({
        projection_key: "home:operator",
        statuses: [
          { ...queued, observed_at: "2026-07-18T10:00:00Z" },
        ],
        summary: "Current work",
        title: "Cerebro work",
      }),
    /canonical ISO-8601 timestamp/,
  );
});

function status(
  code: "degraded" | "queued",
  observedAt: string,
): SlackStatusProjectionV1 {
  return projectSlackVisibleStatus({
    code,
    expires_at: "2026-07-18T10:05:00.000Z",
    idempotency_key: `run-one:${code}:1`,
    message: code === "queued"
      ? "Cerebro saved this request. It is queued for execution."
      : "Cerebro is processing this request with reduced service capacity.",
    observed_at: observedAt,
    run_id: "run-one",
  });
}
