import assert from "node:assert/strict";
import test from "node:test";
import { SecurityMemoryStore } from "../src/learning/security-memory/index.js";
import { AlertTriageService, parseTriageAgentOutput, redactAlertText, shouldPostTriageResponse, shouldTriageSlackMessage } from "../src/triage/alert-triage.js";
import { channelPolicyFor } from "../src/triage/channel-policy.js";
import { testConfig } from "./fixtures.js";

const config = testConfig();

test("shouldTriageSlackMessage only accepts normal messages in configured channels", () => {
  assert.equal(shouldTriageSlackMessage(config, { channel: "CSEC", user: "U1", ts: "1.1", text: "alert" }), true);
  assert.equal(shouldTriageSlackMessage(config, { channel: "CSEC", user: "U1", ts: "1.1", text: "<@U0BOT> what is login security looking like?" }), false);
  assert.equal(shouldTriageSlackMessage(config, { channel: "COTHER", user: "U1", ts: "1.1", text: "alert" }), false);
  assert.equal(shouldTriageSlackMessage(config, { channel: "CSEC", user: "UBOT", ts: "1.1", text: "Critical Okta alert for admin token use", bot_id: "B1", subtype: "bot_message" }), true);
  assert.equal(shouldTriageSlackMessage(config, { channel: "CSEC", user: "UCEREBRO", ts: "1.1", text: "Critical Okta alert for admin token use", bot_id: "B1", subtype: "bot_message" }, { botUserId: "UCEREBRO" }), false);
  assert.equal(shouldTriageSlackMessage(config, { channel: "CSEC", user: "UBOT", ts: "1.2", thread_ts: "1.1", text: "Critical Okta alert for admin token use", bot_id: "B1", subtype: "bot_message" }), false);
  assert.equal(shouldTriageSlackMessage(config, { channel: "CSEC", user: "UBOT", ts: "1.1", text: "Daily report finished", bot_id: "B1", subtype: "bot_message" }), false);
  assert.equal(shouldTriageSlackMessage(config, { channel: "CSEC", user: "U1", ts: "1.1", text: "alert", subtype: "message_changed" }), false);
  assert.equal(shouldTriageSlackMessage(config, { channel: "CSEC", user: "U1", ts: "1.1", text: "Cool, shipped the docs update." }), false);
  assert.equal(shouldTriageSlackMessage(config, { channel: "CSEC", user: "U1", ts: "1.1", text: "Fixed token rotation for the Okta connector." }), true);
  assert.equal(shouldTriageSlackMessage(config, { channel: "CSEC", user: "U1", ts: "1.2", thread_ts: "1.1", text: "Fixed" }), true);
  assert.equal(shouldTriageSlackMessage(config, { channel: "CSEC", user: "U1", ts: "1.3", thread_ts: "1.1", text: "Thanks" }), false);
  assert.equal(shouldTriageSlackMessage(config, { channel: "CSEC", user: "U1", ts: "1.4", text: "Fixed" }), false);
});

test("shouldTriageSlackMessage honors proactive channel policies", () => {
  const quiet = testConfig({
    slack: {
      triageChannelIds: new Set(["CQUIET", "CEAGER", "CSTRICT", "CWATCH"]),
      triageChannelPolicies: new Map([["CQUIET", "quiet"], ["CEAGER", "eager"], ["CSTRICT", "strict"]]),
    },
  });

  assert.equal(shouldTriageSlackMessage(quiet, { channel: "CQUIET", user: "U1", ts: "1.1", text: "Long general product note that is not security related but has enough words to look substantive." }), false);
  assert.equal(shouldTriageSlackMessage(quiet, { channel: "CEAGER", user: "U1", ts: "1.1", text: "Long general product note that is not security related but has enough words to look substantive." }), true);
  assert.equal(shouldTriageSlackMessage(quiet, { channel: "CSTRICT", user: "U1", ts: "1.1", text: "Deploy is rolling out but no security signal yet." }), false);
  assert.equal(shouldTriageSlackMessage(quiet, { channel: "CSTRICT", user: "U1", ts: "1.2", text: "Critical Okta admin token alert needs review." }), true);
  assert.equal(channelPolicyFor(quiet, "CQUIET"), "quiet");
  assert.equal(channelPolicyFor(quiet, "CWATCH"), "watch");
  assert.equal(channelPolicyFor(quiet, "COTHER"), "strict");
});

test("parseTriageAgentOutput accepts fenced JSON, normalizes arrays, and reads response gate", () => {
  const result = parseTriageAgentOutput(`\`\`\`json
{"classification":"needs_context","severity":"medium","confidence":0.61,"should_respond":true,"response_reason":"This can prevent the team from closing a privileged-access alert before checking ownership.","summary":"Need cloud trail context.","evidence":"Alert mentions an admin role.","actions_taken":["Checked the actor against open findings"],"recommended_actions":["Check role owner"],"research":[]}
\`\`\``, ["cerebro_graph_reason: checked"]);
  assert.equal(result?.classification, "needs_context");
  assert.equal(result?.confidence, 0.61);
  assert.equal(result?.shouldRespond, true);
  assert.match(result?.responseReason ?? "", /privileged-access/);
  assert.deepEqual(result?.evidence, ["Alert mentions an admin role."]);
  assert.deepEqual(result?.actionsTaken, ["Checked the actor against open findings"]);
  assert.deepEqual(result?.research, ["cerebro_graph_reason: checked"]);
});

test("parseTriageAgentOutput accepts proactive topic metadata", () => {
  const result = parseTriageAgentOutput(`{"topic":"assistant_follow_up","classification":"needs_context","severity":"info","confidence":0.86,"should_respond":true,"summary":"That wording was about Slack workspace role, not seniority.","evidence":["Thread context shows Cerebro said not admin/owner and the user said it seemed shady."],"actions_taken":["Read the visible Slack thread."],"recommended_actions":["Use Slack workspace admin when naming that role."],"research":["slack_thread_context: checked"]}`);

  assert.equal(result?.topic, "assistant_follow_up");
  assert.equal(result?.shouldRespond, true);
});

test("redactAlertText removes common secret forms", () => {
  const redacted = redactAlertText("token=xoxb-123-abc password=hunter2 AKIAABCDEFGHIJKLMNOP");
  assert.doesNotMatch(redacted, /xoxb-123/);
  assert.doesNotMatch(redacted, /hunter2/);
  assert.doesNotMatch(redacted, /AKIAABCDEFGHIJKLMNOP/);
});

test("triage returns canary fallback when Pi and graph reasoning are unavailable", async () => {
  const service = new AlertTriageService(
    { ...config, triage: { ...config.triage, pi: { ...config.triage.pi, enabled: false } } },
    {
      buildEvidencePacket: async () => {
        throw new Error("evidence unavailable");
      },
      reasonGraph: async () => {
        throw new Error("graph unavailable");
      },
    } as any,
    new SecurityMemoryStore(config),
  );
  const result = await service.triage({
    channelId: "CSEC",
    userId: "U1",
    ts: "1.1",
    text: "canary alert for Cerebro triage. No action needed.",
  });
  assert.equal(result.classification, "likely_noise");
  assert.equal(result.source, "cerebro_fallback");
  assert.equal(result.shouldRespond, false);
  assert.match(result.summary, /canary/);
});

test("shouldPostTriageResponse keeps likely noise quiet by default", () => {
  assert.equal(shouldPostTriageResponse(config, {
    classification: "likely_noise",
    severity: "info",
    confidence: 1,
    shouldRespond: false,
    responseReason: "Routine status update.",
    summary: "This looks like normal chatter.",
    evidence: ["No concrete security signal."],
    actionsTaken: [],
    recommendedActions: ["No response action is needed."],
    research: [],
    source: "pi",
  }), false);
});

test("shouldPostTriageResponse allows concrete security value", () => {
  assert.equal(shouldPostTriageResponse(config, {
    classification: "likely_security_issue",
    severity: "high",
    confidence: 0.82,
    shouldRespond: true,
    responseReason: "The permission grant affects an admin role and should change the review path.",
    summary: "A new Okta admin permission grant lines up with an open privileged-access finding.",
    evidence: ["writer-okta finding finding-1 is open for the same actor."],
    actionsTaken: ["Checked open Okta findings for the actor."],
    recommendedActions: ["Check the owner and expiration before accepting the grant."],
    research: ["cerebro_open_findings: checked"],
    source: "pi",
  }), true);
});

test("shouldPostTriageResponse suppresses deploy status replies without source-specific evidence", () => {
  assert.equal(shouldPostTriageResponse(config, {
    classification: "needs_context",
    severity: "low",
    confidence: 0.78,
    shouldRespond: true,
    responseReason: "The author flagged a deploy gap and leftover artifacts.",
    summary: "PR #1488 is validated, and sec-dev still needs v2.1.586 rolled onto the running services.",
    evidence: [
      "Message says sec-dev services still run v2.1.584.",
      "Recalled prior context about writer-github-audit NATS failures.",
    ],
    actionsTaken: [
      "Checked live writer-github-audit runtime health.",
      "Recalled prior session context.",
      "Recorded a runbook note.",
    ],
    recommendedActions: ["Roll v2.1.586 onto sec-dev services."],
    research: [
      "cerebro_runtime_health: checked",
      "security_session_recall: checked",
      "security_learning_docs_write: checked",
    ],
    source: "pi",
  }), false);
});

test("shouldPostTriageResponse allows deploy status replies with artifact evidence", () => {
  assert.equal(shouldPostTriageResponse(config, {
    classification: "needs_context",
    severity: "low",
    confidence: 0.78,
    shouldRespond: true,
    responseReason: "The PR status changes the release path.",
    summary: "PR #1488 is merged, and the current branch checks are green.",
    evidence: ["GitHub PR #1488 is merged and check runs passed."],
    actionsTaken: ["Checked GitHub PR status for writer/cerebro#1488."],
    recommendedActions: ["Deploy the verified image through the sec-dev release path."],
    research: ["cerebro_code_github_pr_status: checked"],
    source: "pi",
  }), true);
});

test("shouldPostTriageResponse allows clear assistant follow-up corrections from thread context", () => {
  assert.equal(shouldPostTriageResponse(config, {
    topic: "assistant_follow_up",
    classification: "needs_context",
    severity: "info",
    confidence: 0.84,
    shouldRespond: true,
    responseReason: "A short clarification prevents the team from reading a Slack role flag as a comment on someone's title.",
    summary: "Clarification: not admin/owner means Slack workspace role, not security title or seniority.",
    evidence: ["Thread context shows Cerebro called Josh not admin/owner, then Jonathan said the wording seemed shady."],
    actionsTaken: ["Read the Slack thread context."],
    recommendedActions: ["Use Slack workspace admin when naming that role."],
    research: ["slack_thread_context: checked"],
    source: "pi",
  }), true);
});

test("shouldPostTriageResponse applies stricter channel thresholds", () => {
  const result = {
    classification: "needs_context" as const,
    severity: "medium" as const,
    confidence: 0.8,
    shouldRespond: true,
    responseReason: "The deploy state changes the release path.",
    summary: "PR #1488 is merged and ready for the next release step.",
    evidence: ["GitHub PR #1488 is merged and check runs passed."],
    actionsTaken: ["Checked GitHub PR status."],
    recommendedActions: ["Deploy through the sec-dev release path."],
    research: ["cerebro_code_github_pr_status: checked"],
    source: "pi" as const,
  };
  assert.equal(shouldPostTriageResponse(config, result, { channelPolicy: "watch" }), true);
  assert.equal(shouldPostTriageResponse(config, result, { channelPolicy: "quiet" }), true);
  assert.equal(shouldPostTriageResponse(config, result, { channelPolicy: "strict" }), false);
  assert.equal(shouldPostTriageResponse(config, { ...result, confidence: 0.65 }, { channelPolicy: "quiet" }), false);
});

test("shouldPostTriageResponse suppresses assistant follow-up without thread basis", () => {
  assert.equal(shouldPostTriageResponse(config, {
    topic: "assistant_follow_up",
    classification: "needs_context",
    severity: "info",
    confidence: 0.84,
    shouldRespond: true,
    responseReason: "The bot wants to clarify.",
    summary: "Clarification: not admin/owner means Slack workspace role.",
    evidence: ["The current message sounded like feedback."],
    actionsTaken: [],
    recommendedActions: ["Use Slack workspace admin when naming that role."],
    research: ["security_session_recall: checked"],
    source: "pi",
  }), false);
});
