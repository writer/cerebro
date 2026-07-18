import assert from "node:assert/strict";
import test from "node:test";
import { loadImprovementWorkerConfig } from "../src/config/improvement-worker.js";

const baseEnv = {
  CEREBRO_IMPROVEMENT_TABLE_NAME: "improvement-runs",
  CEREBRO_IMPROVEMENT_ARTIFACT_BUCKET: "improvement-artifacts",
  CEREBRO_IMPROVEMENT_QUEUE_URL: "https://sqs.us-east-1.amazonaws.com/123/improvement",
};

test("author workcell requires the scoped GitHub App but not verifier keys", () => {
  const config = loadImprovementWorkerConfig({
    ...baseEnv,
    CEREBRO_IMPROVEMENT_WORKER_LANE: "author",
    CEREBRO_CODE_GITHUB_APP_ID: "app",
    CEREBRO_CODE_GITHUB_INSTALLATION_ID: "installation",
    CEREBRO_CODE_GITHUB_PRIVATE_KEY_BASE64: "private-key",
    CEREBRO_IMPROVEMENT_DELEGATION_KEY_ID: "alias/delegation",
  });
  assert.equal(config.lane, "author");
  assert.equal(config.code.enabled, true);
  assert.equal(config.code.githubApp?.appId, "app");
  assert.equal(config.promotionKeyId, undefined);
  assert.equal(config.delegationKeyId, "alias/delegation");
});

test("verifier workcell has verification keys and no GitHub or model authority", () => {
  const config = loadImprovementWorkerConfig({
    ...baseEnv,
    CEREBRO_IMPROVEMENT_WORKER_LANE: "verifier",
    CEREBRO_IMPROVEMENT_PROMOTION_KEY_ID: "alias/promotion",
    CEREBRO_IMPROVEMENT_EVIDENCE_KEY_ID: "alias/evidence",
  });
  assert.equal(config.lane, "verifier");
  assert.equal(config.code.enabled, false);
  assert.equal(config.code.githubApp, undefined);
  assert.equal(config.promotionKeyId, "alias/promotion");
  assert.equal(config.evidenceKeyId, "alias/evidence");
});

test("workcell configuration fails closed when a lane authority is missing", () => {
  assert.throws(() => loadImprovementWorkerConfig({
    ...baseEnv,
    CEREBRO_IMPROVEMENT_WORKER_LANE: "author",
  }), /Author workers require the scoped GitHub App credential/);
  assert.throws(() => loadImprovementWorkerConfig({
    ...baseEnv,
    CEREBRO_IMPROVEMENT_WORKER_LANE: "verifier",
  }), /Verifier workers require the promotion verification key/);
  assert.throws(() => loadImprovementWorkerConfig({
    ...baseEnv,
    CEREBRO_IMPROVEMENT_WORKER_LANE: "author",
    CEREBRO_CODE_GITHUB_APP_ID: "app",
    CEREBRO_CODE_GITHUB_INSTALLATION_ID: "installation",
    CEREBRO_CODE_GITHUB_PRIVATE_KEY_BASE64: "private-key",
  }), /Author workers require the delegation verification key/);
});
