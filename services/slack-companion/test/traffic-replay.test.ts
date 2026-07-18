import assert from "node:assert/strict";
import test from "node:test";
import { buildTrafficReplayReport, evaluateEvidenceCounterfactualSafety, evaluateTrafficReplayCase, parseTrafficReplayCase } from "../src/learning/traffic-replay.js";

test("traffic replay scores source choice, evidence, outcome, and correction learning", () => {
  const replay = parseTrafficReplayCase({
    id: "traffic-1",
    question: "No, f-1 is already resolved. Check again.",
    expected: {
      executionLanes: ["lookup", "investigate"],
      requiredToolsAnyOf: ["finding_lookup"],
      requiredEvidenceRefs: ["finding:f-1"],
      outcome: "respond",
      correctionRequired: true,
    },
    candidate: {
      answer: answer({ evidence: ["finding:f-1"], messages: ["You are right. Finding f-1 is resolved."], answer: "Finding f-1 is resolved." }),
      toolCount: 1,
      toolNames: ["finding_lookup"],
      claimCoverage: 1,
      userCorrected: true,
      correctionApplied: true,
      correctionSourceVerified: true,
      feedbackContext: {
        available: true,
        evaluated: true,
        applied: true,
        disclosed: false,
        followedUntrustedInstruction: false,
      },
    },
  });

  const receipt = evaluateTrafficReplayCase(replay);
  assert.equal(receipt.passed, true);
  assert.equal(receipt.baseQuality.correctionLearning, 1);
  assert.equal(receipt.baseQuality.feedbackApplication, 1);
  assert.deepEqual(receipt.blockers, []);
});

test("traffic replay blocks unresolved corrections and release regressions", () => {
  const replay = parseTrafficReplayCase({
    id: "traffic-2",
    question: "That is the wrong finding state.",
    expected: { correctionRequired: true, outcome: "respond" },
    candidate: {
      answer: answer({ evidence: [], messages: ["I will check later."], answer: "I will check later." }),
      toolCount: 0,
      toolNames: [],
      userCorrected: true,
      correctionApplied: false,
    },
    baseline: {
      answer: answer({ evidence: ["finding:f-1"], messages: ["Finding f-1 is resolved."], answer: "Finding f-1 is resolved." }),
      toolCount: 1,
      toolNames: ["finding_lookup"],
      claimCoverage: 1,
      userCorrected: true,
      correctionApplied: true,
      correctionSourceVerified: true,
    },
  });

  const report = buildTrafficReplayReport([replay], { minimumCases: 1, maximumRegressionRate: 0 });
  assert.equal(report.releaseReady, false);
  assert.ok(report.blockers.includes("correction_closure_below_gate"));
  assert.ok(report.blockers.includes("candidate_regression_above_gate"));
  assert.equal(report.blockerCounts.user_correction_unresolved, 1);
});

test("traffic replay accepts a requested suppression without evidence tools", () => {
  const replay = parseTrafficReplayCase({
    id: "traffic-ignore",
    senderKind: "bot",
    question: "Automated digest with no request and no new state.",
    expected: { executionLanes: ["ignore"], outcome: "suppress" },
    candidate: {
      answer: {
        answer: "No response needed.", messages: [], keyPoints: [], evidence: [], actionsTaken: [], nextActions: [], research: [], memoryUpdates: [],
        source: "flue", executionLane: "ignore", delivery: "suppress",
      },
      toolCount: 0,
      toolNames: [],
    },
  });

  assert.equal(evaluateTrafficReplayCase(replay).passed, true);
});

test("traffic release gates score human requests and report excluded machine handoffs", () => {
  const human = parseTrafficReplayCase({
    id: "human-complete",
    senderKind: "human",
    question: "What changed?",
    expected: { outcome: "respond" },
    candidate: {
      answer: answer({ evidence: ["deploy:12"], messages: ["Deployment 12 passed."], answer: "Deployment 12 passed." }),
      toolCount: 1,
      toolNames: ["deploy_status"],
      claimCoverage: 1,
      deliveryReceipt: { plannedMessages: 1, postedMessages: 1, complete: true },
    },
  });
  const machine = parseTrafficReplayCase({
    id: "machine-digest",
    senderKind: "bot",
    question: "Routine digest.",
    expected: { outcome: "suppress", executionLanes: ["ignore"] },
    candidate: {
      answer: { answer: "No response needed.", messages: [], keyPoints: [], evidence: [], actionsTaken: [], nextActions: [], research: [], memoryUpdates: [], source: "flue", executionLane: "ignore", delivery: "suppress" },
      toolCount: 0,
      toolNames: [],
    },
  });

  const report = buildTrafficReplayReport([human, machine], { minimumCases: 1, minimumPassRate: 0, minimumAverageScore: 0 });
  assert.equal(report.caseCount, 1);
  assert.equal(report.ignoredMachineCaseCount, 1);
});

test("traffic replay blocks incomplete Slack delivery", () => {
  const replay = parseTrafficReplayCase({
    id: "human-partial-delivery",
    question: "Give me the full result.",
    expected: { outcome: "respond" },
    candidate: {
      answer: answer({ evidence: ["run:1"], messages: ["Part one", "Part two"], answer: "Full result" }),
      toolCount: 1,
      toolNames: ["run_status"],
      claimCoverage: 1,
      deliveryReceipt: { plannedMessages: 2, postedMessages: 1, complete: false },
    },
  });

  const receipt = evaluateTrafficReplayCase(replay);
  assert.equal(receipt.passed, false);
  assert.ok(receipt.blockers.includes("answer_delivery_incomplete"));
});

test("traffic replay can require objective, resolved scope, judgment, and owned follow-through", () => {
  const replay = parseTrafficReplayCase({
    id: "human-teammate-action",
    question: "Study why the deployment keeps failing, fix it, and get it landed.",
    expected: {
      executionLanes: ["act"],
      outcome: "respond",
      teammate: {
        captureObjective: true,
        resolveScope: true,
        ownFollowUp: true,
        makeRecommendation: true,
        avoidUserDecision: true,
      },
    },
    candidate: {
      answer: {
        answer: "The deploy was using a stale image. I fixed the digest selection and opened PR 112; my recommendation is to merge after its deployment check passes.",
        messages: ["The deploy was using a stale image. I fixed the digest selection and opened PR 112; my recommendation is to merge after its deployment check passes."],
        keyPoints: [], evidence: ["deploy:44", "pr:112"], actionsTaken: ["Opened PR 112."], nextActions: ["Verify the deployment check, then merge."],
        research: ["deploy_status", "github_pr"], memoryUpdates: [], source: "flue", executionLane: "act", delivery: "respond",
        teammate: {
          objective: "Fix the repeated deployment failure and land the change.",
          desiredOutcome: "The fix is merged to main with a passing deployment check.",
          resolvedScope: ["service:cerebro-slack-companion", "deploy:44"],
          scopeAssumptions: [],
          commitments: [{ id: "land-pr-112", summary: "Land PR 112.", status: "in_progress", nextAction: "Verify the deployment check, then merge.", artifactRefs: ["pr:112"] }],
          openLoops: [],
          userDecision: { required: false },
        },
      },
      toolCount: 4,
      toolNames: ["deploy_status", "github_pr"],
      claimCoverage: 1,
      threadStateUsed: true,
    },
  });

  const receipt = evaluateTrafficReplayCase(replay);
  assert.equal(receipt.passed, true);
  assert.equal(receipt.teammateFit, 1);
});

test("traffic replay rejects a shallow clarification in place of inspected scope", () => {
  const replay = parseTrafficReplayCase({
    id: "human-teammate-shallow",
    question: "Fix the deployment issue from this thread.",
    expected: {
      executionLanes: ["act", "investigate"],
      outcome: "respond",
      teammate: { captureObjective: true, resolveScope: true, ownFollowUp: true, avoidUserDecision: true },
    },
    candidate: {
      answer: {
        answer: "Which repository and ticket scope should I use?",
        messages: ["Which repository and ticket scope should I use?"],
        keyPoints: [], evidence: [], actionsTaken: [], nextActions: [], research: [], memoryUpdates: [], source: "flue", executionLane: "act", delivery: "respond",
      },
      toolCount: 0,
      toolNames: [],
    },
  });

  const receipt = evaluateTrafficReplayCase(replay);
  assert.equal(receipt.passed, false);
  assert.ok(receipt.blockers.includes("teammate_expectation_missing"));
  assert.ok(receipt.blockers.includes("human_burden_shifted"));
});

test("traffic replay accepts equivalent tools by capability", () => {
  const replay = parseTrafficReplayCase({
    id: "slack-usage-study",
    question: "Study what people have been asking Cerebro.",
    expected: {
      executionLanes: ["investigate"],
      requiredToolCapabilitiesAnyOf: ["slack_search"],
      outcome: "respond",
      teammate: { makeRecommendation: true },
    },
    candidate: {
      answer: {
        answer: "People most often ask about current findings and source health.",
        messages: ["People most often ask about current findings and source health."],
        keyPoints: [], evidence: ["Slack questions from the last 30 days."], actionsTaken: [], nextActions: [], research: ["slack_cerebro_recent_questions"], memoryUpdates: [], source: "flue", executionLane: "investigate", delivery: "respond",
        teammate: {
          objective: "Identify recurring Cerebro questions.", desiredOutcome: "Prioritize improvements from observed usage.", resolvedScope: ["Slack questions from the last 30 days"], scopeAssumptions: [], commitments: [], openLoops: [], userDecision: { required: false },
        },
      },
      toolCount: 1,
      toolNames: ["slack_cerebro_recent_questions"],
      claimCoverage: 1,
    },
  });

  const receipt = evaluateTrafficReplayCase(replay);
  assert.equal(receipt.toolFit, 1);
  assert.equal(receipt.teammateFit, 1);
});

test("traffic replay recognizes an executable plan as a recommendation", () => {
  const replay = parseTrafficReplayCase({
    id: "concrete-plan",
    question: "How should we fix the source failures?",
    expected: { outcome: "respond", teammate: { makeRecommendation: true } },
    candidate: {
      answer: {
        answer: "Phase one isolates the failing runtime. Phase two verifies a fresh pull before re-enabling it.",
        messages: ["Phase one isolates the failing runtime. Phase two verifies a fresh pull before re-enabling it."],
        keyPoints: [], evidence: ["runtime:github-audit failed"], actionsTaken: [], nextActions: ["Disable the failing runtime, rotate its credential, then verify a fresh pull."], research: ["cerebro_source_runtimes"], memoryUpdates: [], source: "flue", executionLane: "investigate", delivery: "respond",
        teammate: {
          objective: "Restore the failing source.", desiredOutcome: "The runtime completes a fresh pull.", resolvedScope: ["runtime:github-audit"], scopeAssumptions: [], commitments: [], openLoops: [], userDecision: { required: false },
        },
      },
      toolCount: 1,
      toolNames: ["cerebro_source_runtimes"],
      claimCoverage: 1,
    },
  });

  assert.equal(evaluateTrafficReplayCase(replay).teammateFit, 1);
});

test("traffic replay recognizes a conditional security action as a recommendation", () => {
  const replay = parseTrafficReplayCase({
    id: "loopback-guidance",
    question: "What can you tell me about 127.0.0.1?",
    expected: { outcome: "respond", teammate: { makeRecommendation: true } },
    candidate: {
      answer: {
        answer: "127.0.0.1 is loopback, not a remote host. If you are worried about malware, run your endpoint scan and check the local process that opened the port.",
        messages: ["127.0.0.1 is loopback, not a remote host. If you are worried about malware, run your endpoint scan and check the local process that opened the port."],
        keyPoints: [], evidence: [], actionsTaken: [], nextActions: [], research: [], memoryUpdates: [], source: "flue", executionLane: "converse", delivery: "respond",
        teammate: {
          objective: "Explain the loopback address.", desiredOutcome: "Correct the misconception and give a safe next check.", resolvedScope: ["127.0.0.1"], scopeAssumptions: [], commitments: [], openLoops: [], userDecision: { required: false },
        },
      },
      toolCount: 0,
      toolNames: [],
    },
  });

  assert.equal(evaluateTrafficReplayCase(replay).teammateFit, 1);
});

test("traffic replay recognizes a precise identity confirmation as a recommendation", () => {
  const replay = parseTrafficReplayCase({
    id: "identity-confirmation",
    question: "Does Seán have MFA enabled?",
    expected: { outcome: "respond", teammate: { makeRecommendation: true } },
    candidate: {
      answer: {
        answer: "Three matching identities have MFA enabled.",
        messages: ["Three matching identities have MFA enabled."],
        keyPoints: [], evidence: ["okta:user-search"], actionsTaken: ["Checked matching identities."],
        nextActions: ["Confirm the email if one specific Seán is meant."], research: ["okta_search"], memoryUpdates: [], source: "flue", executionLane: "investigate", delivery: "respond",
        teammate: {
          objective: "Check Seán's MFA state.", desiredOutcome: "Report verified factor state.", resolvedScope: ["three matching Okta identities"], scopeAssumptions: [], commitments: [], openLoops: [], userDecision: { required: false },
        },
      },
      toolCount: 2,
      toolNames: ["slack_message_search", "cerebro_graph_cypher_investigate"],
    },
  });

  assert.equal(evaluateTrafficReplayCase(replay).teammateFit, 1);
});

test("traffic replay recognizes a diagnostic signal as a recommendation", () => {
  const replay = parseTrafficReplayCase({
    id: "loopback-diagnostic",
    question: "Could 127.0.0.1 have sent me malware?",
    expected: { outcome: "respond", teammate: { makeRecommendation: true } },
    candidate: {
      answer: {
        answer: "127.0.0.1 is local loopback, not a remote actor. The useful signal is the real remote IP or the process that opened the connection.",
        messages: ["127.0.0.1 is local loopback, not a remote actor. The useful signal is the real remote IP or the process that opened the connection."],
        keyPoints: [], evidence: [], actionsTaken: [], nextActions: [], research: [], memoryUpdates: [], source: "flue", executionLane: "converse", delivery: "respond",
        teammate: {
          objective: "Explain the reported IP.", desiredOutcome: "Direct the user to the relevant diagnostic signal.", resolvedScope: ["127.0.0.1"], scopeAssumptions: [], commitments: [], openLoops: [], userDecision: { required: false },
        },
      },
      toolCount: 0,
      toolNames: [],
    },
  });

  assert.equal(evaluateTrafficReplayCase(replay).teammateFit, 1);
});

test("traffic replay blocks answers that contradict required source facts", () => {
  const replay = parseTrafficReplayCase({
    id: "runtime-freshness",
    question: "Are GitHub audit and Okta healthy?",
    expected: {
      requiredAnswerFacts: ["Okta is healthy"],
      forbiddenAnswerFacts: ["Okta is stale"],
      outcome: "respond",
    },
    candidate: {
      answer: answer({
        answer: "GitHub audit is stale, and Okta is stale.",
        messages: ["GitHub audit is stale, and Okta is stale."],
        evidence: ["runtime:github-audit", "runtime:okta"],
      }),
      toolCount: 2,
      toolNames: ["cerebro_source_runtimes"],
      claimCoverage: 1,
    },
  });

  const receipt = evaluateTrafficReplayCase(replay);
  assert.equal(receipt.semanticFit, 0);
  assert.ok(receipt.blockers.includes("answer_fact_mismatch"));
});

test("traffic replay detects missing, restricted, stale, and contradicted evidence counterfactuals", () => {
  const candidate = claimAnswer();

  assert.equal(evaluateEvidenceCounterfactualSafety(candidate as any), 1);
});

test("traffic release blocks citation latency above the p95 budget", () => {
  const replay = parseTrafficReplayCase({
    id: "citation-latency",
    question: "Who owns checkout?",
    expected: { outcome: "respond" },
    candidate: {
      answer: claimAnswer(),
      toolCount: 1,
      toolNames: ["cerebro_graph_reason"],
      claimCoverage: 1,
      citationOverheadMs: 220,
    },
  });

  const report = buildTrafficReplayReport([replay], { minimumCases: 1, minimumPassRate: 0, minimumAverageScore: 0 });
  assert.equal(report.citationP95OverheadMs, 220);
  assert.ok(report.blockers.includes("citation_p95_overhead_above_gate"));
});

function answer(input: { answer: string; messages: string[]; evidence: string[] }) {
  return {
    ...input,
    keyPoints: [],
    actionsTaken: [],
    nextActions: [],
    research: input.evidence.length ? ["finding_lookup"] : [],
    memoryUpdates: [],
    source: "flue",
    executionLane: "lookup",
    delivery: "respond",
  };
}

function claimAnswer() {
  return {
    ...answer({ answer: "Checkout belongs to Payments.", messages: ["Checkout belongs to Payments."], evidence: ["resource:checkout"] }),
    claimEvidence: [{
      claimId: "checkout-owner",
      claimText: "Checkout belongs to Payments.",
      temporalScope: "current",
      verification: "verified",
      sourceTools: ["cerebro_graph_reason"],
      evidenceReceipts: ["evidence:cerebro_graph_reason:one"],
      visible: true,
      evidence: [{
        id: "resource:checkout",
        kind: "live_source",
        title: "Checkout resource",
        basis: "live",
        access: "allowed",
        sourceTool: "cerebro_graph_reason",
        sourceRef: "resource:checkout",
        verifiedAt: "2026-07-15T12:00:00.000Z",
        verifiedBy: ["cerebro_graph_reason"],
        sourceArtifacts: ["resource:checkout"],
      }],
    }],
  };
}
