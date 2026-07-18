import assert from "node:assert/strict";
import test from "node:test";
import { parseSecurityAssistantOutput } from "../src/agent/security-assistant-output.js";
import { evaluateAssistantReplayTurn } from "../src/learning/assistant-replay-eval.js";

test("assistant output normalizes private teammate continuity state", () => {
  const answer = parseSecurityAssistantOutput(JSON.stringify({
    execution_lane: "act",
    answer: "I merged the fix and verified the main branch. The right next move is to watch the next deployment.",
    messages: ["I merged the fix and verified the main branch. The right next move is to watch the next deployment."],
    evidence: ["PR 112 reports merged."],
    actions_taken: ["Merged PR 112."],
    next_actions: ["Watch the next deployment."],
    teammate: {
      objective: "Land the fix.",
      desired_outcome: "The fix is merged to main and verified.",
      resolved_scope: ["repo:WriterInternal/cerebro-slack-companion", "pr:112"],
      scope_assumptions: [],
      commitments: [{
        id: "land-pr-112",
        summary: "Land PR 112 and verify main.",
        status: "completed",
        artifact_refs: ["pr:112"],
      }],
      open_loops: [{
        id: "watch-deploy-112",
        summary: "Verify the next deployment uses the merged commit.",
        owner: "cerebro",
        next_action: "Check the deployment receipt.",
      }],
    },
    research: ["github_pr: checked"],
    memory_updates: [],
  }));

  assert.equal(answer?.teammate?.objective, "Land the fix.");
  assert.equal(answer?.teammate?.commitments[0]?.status, "completed");
  assert.equal(answer?.teammate?.openLoops[0]?.owner, "cerebro");
  assert.equal(answer?.teammate?.userDecision?.required, false);
});

test("human replay accepts owned work and rejects burden shifting", () => {
  const owned = evaluateAssistantReplayTurn({
    question: "Study the failures, fix them, and get it landed.",
    answer: {
      executionLane: "act",
      answer: "I fixed the failing path and opened PR 112. My recommendation is to merge after the deployment check passes.",
      messages: ["I fixed the failing path and opened PR 112. My recommendation is to merge after the deployment check passes."],
      keyPoints: [],
      evidence: ["test run 44 passed"],
      actionsTaken: ["Opened PR 112."],
      nextActions: ["Verify the deployment check, then merge PR 112."],
      research: ["github_pr: checked"],
      memoryUpdates: [],
      source: "flue",
      teammate: {
        objective: "Fix the failures and land the change.",
        desiredOutcome: "The fix is merged to main with passing checks.",
        resolvedScope: ["repo:companion", "failing-check:deployment"],
        scopeAssumptions: [],
        commitments: [{
          id: "land-pr-112",
          summary: "Land PR 112 after its checks pass.",
          status: "in_progress",
          nextAction: "Verify the deployment check and merge.",
          artifactRefs: ["pr:112"],
        }],
        openLoops: [],
        userDecision: { required: false },
      },
    },
    toolCount: 4,
    claimCoverage: 1,
    threadStateUsed: true,
  });
  assert.equal(owned.passed, true);
  assert.equal(owned.teammateOwnership, 1);

  const burdenShifted = evaluateAssistantReplayTurn({
    question: "Can you fix this?",
    answer: {
      executionLane: "act",
      answer: "Which repository and ticket scope should I use?",
      messages: ["Which repository and ticket scope should I use?"],
      keyPoints: [], evidence: [], actionsTaken: [], nextActions: [], research: [], memoryUpdates: [], source: "flue",
    },
    toolCount: 0,
  });
  assert.equal(burdenShifted.passed, false);
  assert.ok(burdenShifted.blockers.includes("human_burden_shifted"));
  assert.ok(burdenShifted.blockers.includes("human_goal_not_captured"));
});

test("human replay rejects protocol-shaped customer-service copy", () => {
  const receipt = evaluateAssistantReplayTurn({
    question: "What happened?",
    answer: {
      executionLane: "continue",
      answer: "Evidence: the deployment failed. Let me know if you need more details.",
      messages: ["Evidence: the deployment failed. Let me know if you need more details."],
      keyPoints: [], evidence: [], actionsTaken: [], nextActions: [], research: [], memoryUpdates: [], source: "flue",
    },
    toolCount: 0,
    threadStateUsed: true,
  });
  assert.equal(receipt.passed, false);
  assert.ok(receipt.blockers.includes("protocol_shaped_reply"));
});

test("human replay rejects a next-action list with no owner or resumable commitment", () => {
  const receipt = evaluateAssistantReplayTurn({
    question: "Investigate this and get the fix landed.",
    answer: {
      executionLane: "act",
      answer: "The deployment check still fails. The next step is to fix it.",
      messages: ["The deployment check still fails. The next step is to fix it."],
      keyPoints: [], evidence: ["deploy:44 failed"], actionsTaken: [], nextActions: ["Fix the deployment check."], research: ["deploy_status"], memoryUpdates: [], source: "flue",
      teammate: {
        objective: "Fix the deployment check and land the change.",
        desiredOutcome: "The fix is merged with a passing deployment check.",
        resolvedScope: ["deploy:44"],
        scopeAssumptions: [],
        commitments: [],
        openLoops: [],
        userDecision: { required: false },
      },
    },
    toolCount: 1,
    claimCoverage: 1,
    threadStateUsed: true,
  });
  assert.equal(receipt.passed, false);
  assert.ok(receipt.blockers.includes("work_left_unowned"));
});

test("human replay requires a result-first opening and a verifiable completed action", () => {
  const receipt = evaluateAssistantReplayTurn({
    question: "Fix and merge it.",
    answer: {
      executionLane: "act",
      answer: "Jonathan asked me to fix and merge it. I merged the change.",
      messages: ["Jonathan asked me to fix and merge it. I merged the change."],
      keyPoints: [], evidence: [], actionsTaken: ["Merged the change."], nextActions: [], research: [], memoryUpdates: [], source: "flue",
      teammate: {
        objective: "Fix and merge the change.",
        desiredOutcome: "The change is merged and verified.",
        resolvedScope: ["repo:companion"],
        scopeAssumptions: [],
        commitments: [{ id: "merge", summary: "Merge the change.", status: "completed", artifactRefs: [] }],
        openLoops: [],
        userDecision: { required: false },
      },
    },
    toolCount: 0,
  });

  assert.equal(receipt.passed, false);
  assert.ok(receipt.blockers.includes("request_restated_before_result"));
  assert.ok(receipt.blockers.includes("action_result_unverified"));
});

test("human replay distinguishes a standalone subject from a contextual follow-up", () => {
  const standalone = evaluateAssistantReplayTurn({
    question: "I'm worried about 127.0.0.1. What can you tell me about this IP address?",
    answer: {
      executionLane: "lookup",
      answer: "127.0.0.1 is the IPv4 loopback address.",
      messages: ["127.0.0.1 is the IPv4 loopback address."],
      keyPoints: [], evidence: ["The address was present in the question."], actionsTaken: [], nextActions: [], research: ["question input"], memoryUpdates: [], source: "flue",
    },
    toolCount: 0,
    claimCoverage: 1,
  });
  assert.equal(standalone.blockers.includes("follow_up_context_missed"), false);

  const followUp = evaluateAssistantReplayTurn({
    question: "Can you check it again?",
    answer: {
      executionLane: "lookup",
      answer: "I cannot identify the subject.",
      messages: ["I cannot identify the subject."],
      keyPoints: [], evidence: ["No thread was provided."], actionsTaken: [], nextActions: [], research: ["question input"], memoryUpdates: [], source: "flue",
    },
    toolCount: 0,
    claimCoverage: 1,
  });
  assert.ok(followUp.blockers.includes("follow_up_context_missed"));
});
