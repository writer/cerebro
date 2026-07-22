import assert from "node:assert/strict";
import test from "node:test";
import {
  assessAssistantTurnOutcome,
  assistantTurnBudget,
  buildAssistantTurnEvidenceFallback,
  preflightAssistantTurnInvocation,
  projectAssistantTurnProgress,
  projectSlackMultipartDelivery,
} from "@writer/cerebro-slack-companion";
import type { PortableAssistantTurnContract } from "../src/index.js";

const exactPublicContract: PortableAssistantTurnContract = {
  assessAssistantTurnOutcome,
  assistantTurnBudget,
  buildAssistantTurnEvidenceFallback,
  preflightAssistantTurnInvocation,
  projectAssistantTurnProgress,
  projectSlackMultipartDelivery,
};

test("private assistant-turn boundary accepts the exact pinned public functions", () => {
  assert.equal(exactPublicContract.assistantTurnBudget("lookup").max_tool_calls, 3);
});
