import assert from "node:assert/strict";
import test from "node:test";
import { fleetIdentityOperatingStandard } from "../src/agent/fleet-identity.js";
import { systemPrompt as assistantSystemPrompt } from "../src/agent/security-assistant-prompts.js";
import { systemPrompt as triageSystemPrompt } from "../src/triage/alert-triage-prompts.js";
import { testConfig } from "./fixtures.js";

test("assistant and triage prompts give a fleet role a real operating emphasis", () => {
  const config = testConfig({
    coordination: { version: "sha-candidate" },
    a2a: {
      instanceId: "analyst-task-1",
      label: "response-canary",
      role: "analyst",
      capabilities: ["security", "research", "goals"],
    },
  });

  const identity = fleetIdentityOperatingStandard(config).join("\n");
  assert.match(identity, /response-canary \(analyst-task-1\), role analyst, commit sha-candidate/);
  assert.match(identity, /work focus, not as extra authority/);
  assert.match(identity, /operating emphasis/);
  assert.match(identity, /Do not impersonate another fleet instance/);

  for (const prompt of [assistantSystemPrompt(config), triageSystemPrompt(config)]) {
    assert.match(prompt, /Fleet identity: this process is response-canary/);
    assert.match(prompt, /Fleet capabilities: security, research, goals/);
    assert.match(prompt, /Apply the analyst role as an operating emphasis/);
  }
});
