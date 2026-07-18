import assert from "node:assert/strict";
import test from "node:test";
import { autonomyCapabilities, autonomyCapability, inferAutonomyCapability, validateAutonomyCapabilities } from "../src/autonomy/capabilities.js";

test("autonomy capabilities declare owners, actions, blast radius, and approval rules", () => {
  const capabilities = autonomyCapabilities();
  assert.equal(capabilities.length >= 5, true);
  assert.ok(capabilities.every((capability) => capability.owner.startsWith("@writer/")));
  assert.ok(capabilities.every((capability) => capability.allowedActions.length > 0));

  const executor = autonomyCapability("executor");
  assert.equal(executor.requiresApproval, true);
  assert.equal(executor.blastRadius, "tenant");
  assert.match(executor.escalationPath, /^slack:/);
  const remediation = autonomyCapability("remediation");
  assert.equal(remediation.requiresApproval, false);
  assert.equal(remediation.blastRadius, "single-user");
  assert.ok(remediation.allowedActions.includes("write:github.pr"));
});

test("autonomy capability inference routes GitOps and execution goals", () => {
  assert.equal(inferAutonomyCapability("handle this GitHub security alert and verify the vulnerability is fixed"), "remediation");
  assert.equal(inferAutonomyCapability("fix the flaky Cerebro PR checks"), "self_repair");
  assert.equal(inferAutonomyCapability("execute approved remediation for finding-1"), "executor");
  assert.equal(inferAutonomyCapability("investigate Okta blast radius"), "investigation");
  assert.equal(inferAutonomyCapability("triage this alert"), "triage");
  assert.equal(inferAutonomyCapability("make a plan for login posture"), "planner");
});

test("autonomy capability validation rejects unsafe approval declarations", () => {
  const invalid = autonomyCapabilities();
  invalid[0] = { ...invalid[0]!, id: "bad" as any, blastRadius: "read-only", requiresApproval: true };

  assert.throws(() => validateAutonomyCapabilities(invalid), /require approval only/);
});
