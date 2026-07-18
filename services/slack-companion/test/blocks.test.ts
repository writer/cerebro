import assert from "node:assert/strict";
import test from "node:test";
import { buildCompliancePacket } from "../src/compliance/work-packets.js";
import { compliancePacketReviewBlocks, findingBlocks, proactiveSuggestionBlocks, proactiveSuggestionText, runtimeHealthBlocks, securityAnswerBlocks, securityAnswerMessages, triageBlocks, triageResponseBlocks, triageResponseText } from "../src/slack/blocks/index.js";
import { testConfig } from "./fixtures.js";

const config = testConfig({ slack: { triageChannelIds: new Set<string>(["C123"]) } });

test("runtimeHealthBlocks includes runtime operations", () => {
  const blocks = runtimeHealthBlocks([{ runtime_id: "writer-okta", source_id: "okta", sync_status: "healthy" }]);
  const encoded = JSON.stringify(blocks);
  assert.match(encoded, /Sync/);
  assert.match(encoded, /Ingest/);
  assert.match(encoded, /Evaluate/);
});

test("findingBlocks includes evidence and lifecycle actions", () => {
  const blocks = findingBlocks("writer-okta", [{ id: "finding-1", title: "Privileged account active", status: "open" }], config);
  const encoded = JSON.stringify(blocks);
  assert.match(encoded, /Evidence/);
  assert.match(encoded, /Resolve/);
  assert.match(encoded, /Suppress/);
});

test("compliancePacketReviewBlocks shows readiness, gaps, and review actions", () => {
  const packet = buildCompliancePacket({
    packet_type: "control_evidence",
    control_id: "CC-6.1",
    framework: "SOC 2",
    period: "2026-Q2",
    owner: "security",
    policy_refs: ["policy:access"],
    system_refs: ["system:okta"],
    finding_refs: ["finding-1"],
  }) as any;
  const blocks = compliancePacketReviewBlocks(packet);
  const encoded = JSON.stringify(blocks);

  assert.match(encoded, /Compliance packet/);
  assert.match(encoded, /needs_evidence/);
  assert.match(encoded, /evidence_refs/);
  assert.match(encoded, /finding_disposition/);
  assert.doesNotMatch(encoded, /should-not-leak/);
});

test("triageBlocks includes classification and next actions", () => {
  const blocks = triageBlocks({
    classification: "likely_security_issue",
    severity: "high",
    confidence: 0.82,
    shouldRespond: true,
    responseReason: "The open finding changes whether the alert can be closed.",
    summary: "Okta sign-in matched an open privileged access finding.",
    evidence: ["writer-okta finding finding-1 is open."],
    actionsTaken: ["Checked open Okta findings for the actor."],
    recommendedActions: ["Review finding finding-1 before closing the alert."],
    research: ["cerebro_open_findings: checked"],
    source: "pi",
  });
  const encoded = JSON.stringify(blocks);
  assert.match(encoded, /likely security issue/);
  assert.match(encoded, /confidence 82%/);
  assert.match(encoded, /Review finding/);
});

test("triageResponseText returns a compact companion reply", () => {
  const message = triageResponseText({
    classification: "likely_security_issue",
    severity: "high",
    confidence: 0.82,
    shouldRespond: true,
    responseReason: "The open finding changes whether the alert can be closed.",
    summary: "Okta sign-in matched an open privileged access finding.",
    evidence: ["writer-okta finding finding-1 is open."],
    actionsTaken: ["Checked open Okta findings for the actor."],
    recommendedActions: ["Review finding finding-1 before closing the alert."],
    research: ["cerebro_open_findings: checked"],
    source: "pi",
  });

  assert.match(message, /^Okta sign-in matched/);
  assert.doesNotMatch(message, /Observation:|Why it matters:|Suggested action:/);
  assert.doesNotMatch(message, /changes whether the alert can be closed/);
  assert.match(message, /Next: Review finding/);
  assert.ok(message.length <= 900);
});

test("triageResponseBlocks adds monitor suggestion controls", () => {
  const blocks = triageResponseBlocks({
    classification: "needs_context",
    severity: "low",
    confidence: 0.84,
    shouldRespond: true,
    responseReason: "The release state changes the next step.",
    summary: "PR #1488 is merged and the release still needs a rollout check.",
    evidence: ["GitHub PR #1488 is merged."],
    actionsTaken: ["Checked GitHub PR status."],
    recommendedActions: ["Watch the rollout until sec-dev reports the new image."],
    research: ["cerebro_code_github_pr_status: checked"],
    source: "pi",
  }, {
    id: "sugg-1",
    title: "Watch PR #1488 rollout",
    description: "Create a short-lived scheduled check.",
    scheduleText: "Every 30 minutes check PR #1488.",
    dedupKey: "ci:C123:1.1:PR #1488",
    sourceTs: "1.1",
    status: "pending",
    createdAt: "2026-06-29T12:00:00.000Z",
  }, "C123", "1.1");

  const encoded = JSON.stringify(blocks);
  assert.match(encoded, /Start check/);
  assert.match(encoded, /Dismiss/);
  assert.match(encoded, /cerebro_monitor_suggestion_accept/);
  assert.match(encoded, /Watch PR #1488 rollout/);
});

test("proactiveSuggestionBlocks adds goal creation controls", () => {
  const result = {
    classification: "needs_context" as const,
    severity: "low" as const,
    confidence: 0.84,
    shouldRespond: false,
    responseReason: "The release state needs a concrete owner action.",
    summary: "PR #1488 is merged and the release still needs follow-up.",
    evidence: ["GitHub PR #1488 is merged."],
    actionsTaken: ["Checked GitHub PR status."],
    recommendedActions: ["Confirm sec-dev is running the merged image."],
    research: ["cerebro_code_github_pr_status: checked"],
    source: "pi" as const,
  };
  const suggestion = {
    id: "suggestion-1",
    title: "Close the loop on PR #1488",
    description: "Confirm sec-dev is running the merged image.",
    goalText: "Close the loop on PR #1488.",
    dedupKey: "release:C123:1.1:pr #1488:confirm",
    sourceTs: "1.1",
    status: "pending" as const,
    createdAt: "2026-06-29T12:00:00.000Z",
  };
  const blocks = proactiveSuggestionBlocks(result, suggestion, "C123", "1.1");
  const text = proactiveSuggestionText(result, suggestion);
  const encoded = JSON.stringify(blocks);

  assert.match(text, /Suggested action: Close the loop on PR #1488/);
  assert.match(encoded, /Create goal/);
  assert.match(encoded, /Dismiss/);
  assert.match(encoded, /cerebro_proactive_suggestion_accept/);
  assert.doesNotMatch(encoded, /goalText|Suggested action: Confirm/);
});

test("securityAnswerBlocks includes research and next actions", () => {
  const blocks = securityAnswerBlocks("what is login security looking like", {
    answer: "Login posture is mostly healthy, with one Okta finding that needs review.",
    messages: [],
    reaction: "white_check_mark",
    keyPoints: ["Okta runtime is healthy."],
    evidence: ["writer-okta-user returned one open finding."],
    actionsTaken: ["Checked Okta runtime health and open findings."],
    nextActions: ["Review the Okta finding owner."],
    research: ["security_memory_search: checked", "cerebro_runtime_health: checked"],
    memoryUpdates: [],
    source: "pi",
  });
  const encoded = JSON.stringify(blocks);
  assert.match(encoded, /Login posture/);
  assert.match(encoded, /Okta runtime/);
  assert.match(encoded, /security_memory_search/);
});

test("securityAnswerBlocks labels Flue-sourced answers", () => {
  const blocks = securityAnswerBlocks("which instance are you running?", {
    answer: "Cerebro is running the configured Flue path.",
    messages: [],
    reaction: "mag",
    keyPoints: ["Flue runtime selected."],
    evidence: ["Self-context checked."],
    actionsTaken: ["Checked companion self context."],
    nextActions: ["Run a live smoke test."],
    research: ["cerebro_companion_self_context: checked"],
    memoryUpdates: [],
    source: "flue",
  });

  assert.match(JSON.stringify(blocks), /Flue agent with Cerebro tools and memory/);
});

test("securityAnswerMessages returns short thread replies", () => {
  const messages = securityAnswerMessages("please break down what you checked", {
    answer: "Login posture is mostly healthy, with one Okta finding that needs review.",
    messages: [],
    reaction: "white_check_mark",
    keyPoints: ["Okta runtime is healthy.", "GitHub identity linkage has one open finding."],
    evidence: ["writer-okta-user returned healthy."],
    actionsTaken: ["Checked security memory.", "Built a login posture packet."],
    nextActions: ["Review the GitHub identity owner."],
    research: ["security_memory_search: checked", "cerebro_security_posture: checked"],
    memoryUpdates: [],
    source: "pi",
  });

  assert.equal(messages.length, 1);
  assert.match(messages[0] ?? "", /Login posture/);
  assert.doesNotMatch(messages[0] ?? "", /I built a login posture packet/);
  assert.doesNotMatch(messages[0] ?? "", /Next, review the GitHub identity owner/);
  assert.doesNotMatch(messages[0] ?? "", /Checked:|Next:|Tool trail:/);
  assert.ok(messages.every((message) => message.length <= 1400));
});

test("securityAnswerMessages strips report lines from visible replies", () => {
  const messages = securityAnswerMessages("how are you? what version are you?", {
    answer: [
      "I'm running and answering Slack. Version sha-7ac4fbd, node v22.23.1, tenant writer, runtime writer-slack-companion.",
      "Checked: Read self-context for identity/version/env.",
      "Evidence: deployment_environment=production, tenant_id=writer.",
      "Tool trail: cerebro_companion_self_context.",
    ].join("\n"),
    messages: [
      "I'm running and answering Slack. Version sha-7ac4fbd, node v22.23.1, tenant writer, runtime writer-slack-companion.",
      "Checked: Read self-context for identity/version/env.",
    ],
    reaction: "wave",
    keyPoints: ["Version sha-7ac4fbd."],
    evidence: ["Self-context returned version sha-7ac4fbd."],
    actionsTaken: ["Checked companion self context."],
    nextActions: ["No action needed."],
    research: ["cerebro_companion_self_context: checked", "cerebro_runtime_health: checked"],
    memoryUpdates: [],
    source: "pi",
  });

  assert.equal(messages.length, 1);
  assert.equal(messages[0], "I'm running and answering Slack. Version sha-7ac4fbd, node v22.23.1, tenant writer, runtime writer-slack-companion.");
  assert.doesNotMatch(messages[0] ?? "", /Checked:|Evidence:|Tool trail:/);
});

test("securityAnswerMessages keeps investigation fallbacks conversational", () => {
  const messages = securityAnswerMessages("what are you seeing in this Okta alert?", {
    answer: "The Okta alert maps to one open finding.",
    messages: [],
    reaction: "mag",
    keyPoints: ["One Okta finding is open."],
    evidence: ["writer-okta-user returned finding f-1."],
    actionsTaken: ["Checked Okta findings."],
    nextActions: ["Review finding f-1."],
    research: ["cerebro_open_findings: checked"],
    memoryUpdates: [],
    source: "pi",
  });

  assert.equal(messages[0], "The Okta alert maps to one open finding.");
  assert.doesNotMatch(messages[0] ?? "", /I checked Okta findings/);
  assert.doesNotMatch(messages[0] ?? "", /Next, review finding f-1/);
  assert.doesNotMatch(messages[0] ?? "", /Checked:|Next:|Tool trail:/);
});

test("securityAnswerMessages does not turn structured fields into a default next-step reply", () => {
  const messages = securityAnswerMessages("what does the ISO gap need?", {
    answer: "Writer's catalog requires an AI-system inventory entry and a pre-launch AI risk review for material AI systems.",
    messages: [],
    reaction: "mag",
    keyPoints: ["The control is required before launch."],
    evidence: ["ISO 42001 control catalog context was checked."],
    actionsTaken: ["Grounded Cosmo's ISO 42001 gap list against Writer's control catalog."],
    nextActions: ["Open an AI-system inventory entry for Palmyra X6 and run the pre-launch AI risk review before production."],
    research: ["cerebro_compliance_context: checked"],
    memoryUpdates: [],
    source: "pi",
  });

  assert.deepEqual(messages, ["Writer's catalog requires an AI-system inventory entry and a pre-launch AI risk review for material AI systems."]);
  assert.doesNotMatch(messages.join("\n"), /Grounded Cosmo|Next, open/i);
});

test("securityAnswerMessages drops leaked protocol text and posts one composed reply", () => {
  const messages = securityAnswerMessages("can Albert help Cerebro?", {
    answer: "No blocker.</parameter><parameter name=\"messages\">[\"bad\"]",
    messages: ["<parameter name=\"answer\">bad</parameter>", "Ask Albert for the specific runtime or finding to inspect."],
    reaction: "mag",
    keyPoints: ["Albert was asked to help, but no concrete check was named."],
    evidence: ["Slack thread context was checked."],
    actionsTaken: ["Checked thread context."],
    nextActions: ["Ask for the specific runtime or finding."],
    research: ["slack_thread_context: checked"],
    memoryUpdates: [],
    source: "flue",
  });

  assert.equal(messages.length, 1);
  assert.equal(messages[0], "Ask Albert for the specific runtime or finding to inspect.");
  assert.doesNotMatch(messages[0] ?? "", /parameter name|<\/parameter>/i);
});
