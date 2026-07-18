import assert from "node:assert/strict";
import test from "node:test";
import { levelFiveOperatingStandard } from "../src/agent/level-five.js";

test("level five standard requires cause, safe action, and evidence", () => {
  const assistant = levelFiveOperatingStandard("assistant").join("\n");
  assert.match(assistant, /level 5 help/i);
  assert.match(assistant, /likely cause/i);
  assert.match(assistant, /safe actions/i);
  assert.match(assistant, /Do not claim something is fixed/i);
  assert.match(assistant, /durable learning loop/i);
  assert.match(assistant, /Batch independent read-only checks/i);
});

test("triage level five standard keeps noisy alerts evidence-backed", () => {
  const triage = levelFiveOperatingStandard("triage").join("\n");
  assert.match(triage, /first-line triage/i);
  assert.match(triage, /likely cause/i);
  assert.match(triage, /specific normal pattern/i);
});
