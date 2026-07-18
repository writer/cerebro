import assert from "node:assert/strict";
import test from "node:test";
import { verifyProductReleaseRuntime } from "../src/product-release.js";

const validModule = {
  handleEventsApiRequest() {},
  handleSocketModeRequest() {},
  MissionLedger: class MissionLedger {},
  SlackAdmissionController: class SlackAdmissionController {},
};

test("product release validation stays disabled for local and legacy images", async () => {
  let loaded = false;
  const receipt = await verifyProductReleaseRuntime({}, async () => {
    loaded = true;
    return validModule;
  });

  assert.equal(loaded, false);
  assert.deepEqual(receipt, {
    required: false,
    status: "disabled",
    package: "@writer/cerebro-slack-companion",
  });
});

test("product release validation verifies immutable identity and portable exports", async () => {
  const receipt = await verifyProductReleaseRuntime({
    CEREBRO_PRODUCT_RELEASE_REQUIRED: "true",
    CEREBRO_PRODUCT_RELEASE_VERSION: "v2.2.0",
    CEREBRO_PRODUCT_RELEASE_COMMIT: "A".repeat(40),
  }, async () => validModule);

  assert.equal(receipt.status, "verified");
  assert.equal(receipt.version, "v2.2.0");
  assert.equal(receipt.commit, "a".repeat(40));
  assert.deepEqual(receipt.exports, [
    "handleEventsApiRequest",
    "handleSocketModeRequest",
    "MissionLedger",
    "SlackAdmissionController",
  ]);
});

test("product release validation fails closed on missing identity or exports", async () => {
  await assert.rejects(
    verifyProductReleaseRuntime({ CEREBRO_PRODUCT_RELEASE_REQUIRED: "true" }, async () => validModule),
    /version is missing or invalid/,
  );
  await assert.rejects(
    verifyProductReleaseRuntime({
      CEREBRO_PRODUCT_RELEASE_REQUIRED: "true",
      CEREBRO_PRODUCT_RELEASE_VERSION: "v2.2.0",
      CEREBRO_PRODUCT_RELEASE_COMMIT: "b".repeat(40),
    }, async () => ({ handleEventsApiRequest() {} })),
    /missing required exports/,
  );
});
