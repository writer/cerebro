import assert from "node:assert/strict";
import test from "node:test";
import { parseSecurityAssistantOutput, parseSlackPresentationOutput, SecurityAssistantService } from "../src/agent/security-assistant.js";
import { assistantResultTelemetry, validateSecurityAssistantAnswerContract } from "../src/agent/security-assistant-output.js";
import { userPromptWithPreflightCompaction } from "../src/agent/security-assistant-prompt-preflight.js";
import { presentSlackAnswerWithLlm } from "../src/agent/security-assistant-presentation.js";
import { prepareDeliverableAnswer, recoverIncompleteResearch, recoverQualifiedUncertainty } from "../src/agent/security-assistant-recovery.js";
import { SecurityResearchState } from "../src/agent/research-state.js";
import { slackPresentationSystemPrompt, slackPresentationUserPrompt, systemPrompt } from "../src/agent/security-assistant-prompts.js";
import { testConfig } from "./fixtures.js";

test("system prompt explains graph investigation use cases and limits", () => {
  const prompt = systemPrompt(testConfig({ cerebro: { assistantHelpMention: "<@UHELP>" } }));

  assert.match(prompt, /Graph checks can reveal exposed resources with open findings/);
  assert.match(prompt, /public-to-privileged cloud paths/);
  assert.match(prompt, /identities linked across Okta, GitHub, cloud, and SaaS sources/);
  assert.match(prompt, /successful current-state Cerebro graph check reveals a concrete multi-hop risk path/);
  assert.match(prompt, /rehydrates every node, edge, relation, and declared risk attribute/);
  assert.match(prompt, /After creation returns a grounding receipt/);
  assert.match(prompt, /rejects covered paths, and returns coverage-gap plus proof receipts/);
  assert.match(prompt, /Never create a candidate from Slack text, memory, inferred topology, or an empty graph result/);
  assert.match(prompt, /use cerebro_policy_candidate_prove/);
  assert.match(prompt, /Only then use cerebro_policy_candidate_shadow/);
  assert.match(prompt, /Graph is not the raw event log/);
  assert.match(prompt, /source-event audit rows/);
  assert.match(prompt, /use Cerebro connector\/source tools first/);
  assert.match(prompt, /operator_goal_create/);
  assert.match(prompt, /operator_memory_record/);
  assert.match(prompt, /facts, claims, decisions, risks, blockers, handoffs, or source-health notes/);
  assert.match(prompt, /operator_research_plan/);
  assert.match(prompt, /operator_claim_ledger/);
  assert.match(prompt, /Bot-authored handoffs are allowed to produce no reply/);
  assert.match(prompt, /only restate it, repeat its owner assignments, or report missing repo, ticket, project, or source scope/);
  assert.match(prompt, /named person without a unique id/);
  assert.match(prompt, /Slack AI search or message search/);
  assert.match(prompt, /slack_risk_attestation_request only when current source evidence identifies a real risk/);
  assert.match(prompt, /host-issued evidence receipt that covers those exact returned facts in this answer/);
  assert.match(prompt, /A yes does not prove legitimacy, and a no does not prove compromise/);
  assert.match(prompt, /never resolve, suppress, downgrade, or otherwise change a risk from that answer alone/);
  assert.match(prompt, /call cerebro_source_runtimes separately with runtime_id/);
  assert.match(prompt, /Never copy freshness, status, failure, ownership, or counts/);
  assert.match(prompt, /one user-owned open loop instead of a Cerebro commitment or goal/);
  assert.match(prompt, /negative conclusions with the checked source, population, and time window/);
  assert.match(prompt, /decide whether every decision-relevant source covers the requested window before drafting the first sentence/);
  assert.match(prompt, /start with a named quiet fact or a count of completed checks and pair it with the exact uncovered source interval/);
  assert.match(prompt, /The words 'nothing urgent' must not appear anywhere in that answer, even with a qualifier/);
  assert.match(prompt, /records returned through a time proves only that coverage boundary/);
  assert.match(prompt, /If the source supplies no record contents, omit every positive or negative content claim about those records/);
  assert.match(prompt, /do not mention goal registration, automatic follow-up, or ask the user to ping Cerebro/);
  assert.match(prompt, /say 'I'm not sure' about that exact source state/);
  assert.match(prompt, /Citation rendering, formatting, exact claim-to-sentence matching, and private specialist work are presentation details, not domain evidence/);
  assert.match(prompt, /partial result with non-empty facts or records is bounded evidence/);
  assert.match(prompt, /Never describe the whole source as unavailable or say no context returned/);
  assert.match(prompt, /Do not tag the helper for uncertainty, incomplete evidence, unavailable sources/);
  assert.match(prompt, /recover the underlying request from the thread/);
  assert.match(prompt, /Never ask a frustrated human to choose an angle/);
  assert.match(prompt, /repeat an identity already supplied by Slack/);
  assert.match(prompt, /default to their Slack profile, durable collaboration context, connected access, and findings in that order/);
  assert.match(prompt, /describe the missing outcome rather than private runtime wiring/);
  assert.match(prompt, /state the exact retry you will run without handing the job back/);
  assert.match(prompt, /Do not close with 'want me', 'tell me', 'say the word', 'ping me'/);
  assert.match(prompt, /Treat capability, usefulness, and improvement-opinion questions as evidence-backed diagnoses/);
  assert.match(prompt, /lead with its measured failure rates or counts/);
  assert.match(prompt, /name the sample and coverage boundary/);
  assert.match(prompt, /distinguish what the packet directly measured from your inference about the cause/);
  assert.match(prompt, /make the first recommendation address the largest measured gap/);
  assert.match(prompt, /add one claim_evidence entry/);
  assert.match(prompt, /copy the exact visible claim text from answer or messages/);
  assert.match(prompt, /Do not place citation markers in prose/);
  assert.match(prompt, /inspect the actual repository at one immutable commit SHA/);
  assert.match(prompt, /focused regression test together/);
  assert.match(prompt, /update the same branch and PR when checks require a repair/);
  assert.match(prompt, /Never merge or deploy the PR/);
});

test("Slack presentation preserves bounded urgency coverage", () => {
  const prompt = slackPresentationSystemPrompt();

  assert.match(prompt, /inspect the supplied evidence coverage before writing the first sentence/);
  assert.match(prompt, /start with a named quiet fact or a count of completed checks/);
  assert.match(prompt, /do not use the words 'nothing urgent' anywhere, even with a qualifier/);
  assert.match(prompt, /Remove 'all clear' and every other overall quiet verdict/);
  assert.match(prompt, /Do not turn a coverage fact such as 'records returned through 14:00Z' into a content claim/);
  assert.match(prompt, /If the supplied source has no record contents, omit every claim about what did or did not appear/);
  assert.match(prompt, /Keep goal registration, scheduling mechanics, automatic-follow-up commentary, and requests to ping Cerebro out/);
});

test("parseSecurityAssistantOutput accepts fenced JSON, claim evidence, and memory updates", () => {
  const result = parseSecurityAssistantOutput(`\`\`\`json
{"answer":"Login posture is healthy but one finding needs review.","messages":["Mostly healthy. One identity finding needs review.","I checked Okta health and open identity findings."],"reaction":"white_check_mark","key_points":["Okta runtime is healthy"],"evidence":["Finding f-1 is open"],"actions_taken":["Checked Okta runtime health"],"next_actions":["Review f-1"],"research":[],"claim_evidence":[{"claim_id":"identity-finding","claim_text":"Mostly healthy. One identity finding needs review.","temporal_scope":"current","evidence_ids":["memory-1"]}],"memory_updates":[{"kind":"investigation_note","topic":"Okta posture","summary":"One open Okta finding needs review","tags":["okta"],"promotion_state":"candidate","staleness_policy":"until_reverified","source_artifacts":["finding:f-1"],"verified_by":["cerebro_open_findings"]}]}
\`\`\``, ["security_memory_search: checked"]);
  assert.equal(result?.answer, "Login posture is healthy but one finding needs review.");
  assert.deepEqual(result?.messages, ["Mostly healthy. One identity finding needs review.", "I checked Okta health and open identity findings."]);
  assert.equal(result?.reaction, "white_check_mark");
  assert.deepEqual(result?.actionsTaken, ["Checked Okta runtime health"]);
  assert.deepEqual(result?.research, ["security_memory_search: checked"]);
  assert.equal(result?.memoryUpdates[0]?.topic, "Okta posture");
  assert.equal(result?.memoryUpdates[0]?.promotionState, "candidate");
  assert.equal(result?.memoryUpdates[0]?.stalenessPolicy, "until_reverified");
  assert.deepEqual(result?.memoryUpdates[0]?.sourceArtifacts, ["finding:f-1"]);
  assert.deepEqual(result?.memoryUpdates[0]?.verifiedBy, ["cerebro_open_findings"]);
  assert.deepEqual(result?.claimEvidenceBindings, [{
    claimId: "identity-finding",
    claimText: "Mostly healthy. One identity finding needs review.",
    temporalScope: "current",
    evidenceIds: ["memory-1"],
  }]);
});

test("parseSecurityAssistantOutput preserves final runtime tool outcomes over model research names", () => {
  const result = parseSecurityAssistantOutput(JSON.stringify({
    answer: "The identity bridge is clean, but graph reasoning still needs a retry.",
    messages: ["The identity bridge is clean, but graph reasoning still needs a retry."],
    key_points: [],
    evidence: ["The current identity finding query returned no open findings."],
    actions_taken: ["Checked the identity bridge and graph path."],
    next_actions: ["Retry graph reasoning after the timeout."],
    research: ["cerebro_open_findings: failed", "cerebro_graph_reason: checked", "operator_claim_ledger"],
    memory_updates: [],
  }), [
    "cerebro_open_findings: failed",
    "cerebro_open_findings: checked",
    "cerebro_graph_reason: failed",
  ]);

  assert.deepEqual(result?.research, [
    "cerebro_graph_reason: failed",
    "cerebro_open_findings: checked",
    "operator_claim_ledger",
  ]);
});

test("parseSecurityAssistantOutput drops generic Slack filler messages", () => {
  const result = parseSecurityAssistantOutput(`{"answer":"I found one current GitHub identity risk.","messages":["I found one current GitHub identity risk.","Please let me know if you need more details or assistance with this issue."],"reaction":"mag","key_points":[],"evidence":[],"actions_taken":[],"next_actions":[],"research":[],"memory_updates":[]}`);

  assert.deepEqual(result?.messages, ["I found one current GitHub identity risk."]);
});

test("parseSecurityAssistantOutput preserves long Slack messages for transport splitting", () => {
  const longAnswer = `${"Detailed control evidence and owner notes should survive parser cleanup. ".repeat(500)}Final owner note.`;
  const rawMessages = [longAnswer, ...Array.from({ length: 11 }, (_, index) => `Additional message ${index + 1}.`)];
  const result = parseSecurityAssistantOutput(JSON.stringify({
    answer: longAnswer,
    messages: rawMessages,
    reaction: "mag",
    key_points: ["Control evidence was checked."],
    evidence: ["Compliance context was available."],
    actions_taken: ["Checked compliance source context."],
    next_actions: [],
    research: [],
    memory_updates: [],
  }), ["cerebro_compliance_context: checked"]);

  assert.equal(result?.answer, longAnswer.trim());
  assert.deepEqual(result?.messages, rawMessages);
  assert.ok((result?.answer.length ?? 0) > 24_000);
  assert.match(result?.answer ?? "", /Final owner note\.$/);
});

test("parseSlackPresentationOutput preserves every generated message", () => {
  const messages = Array.from({ length: 12 }, (_, index) => `Slack message ${index + 1}.`);
  assert.deepEqual(parseSlackPresentationOutput(JSON.stringify({ messages })), messages);
});

test("Slack presentation input preserves the complete staged answer", () => {
  const longAnswer = `${"Current evidence remains relevant. ".repeat(900)}Final staged detail.`;
  const prompt = slackPresentationUserPrompt({
    input: { channelId: "CSEC", ts: "1782489502.000003", question: "Give me the complete answer." },
    answer: {
      answer: longAnswer,
      messages: [longAnswer],
      keyPoints: [],
      evidence: ["Current evidence was checked."],
      actionsTaken: [],
      nextActions: [],
      research: ["current_evidence: checked"],
      memoryUpdates: [],
      source: "pi",
    },
  });

  assert.match(prompt, /Final staged detail\./);
  assert.ok(prompt.length > 48_000, "expected the full answer and message to reach the editor");
});

test("parseSlackPresentationOutput accepts LLM Slack presentation JSON", () => {
  const messages = parseSlackPresentationOutput(`\`\`\`json
{"messages":["Short answer first.","Evidence: finding f-1 in writer-okta-user was still open."],"reply_messages":[]}
\`\`\``);

  assert.deepEqual(messages, [
    "Short answer first.",
    "Evidence: finding f-1 in writer-okta-user was still open.",
  ]);
});

test("prompt preflight compacts oversized Slack thread context before blocking", () => {
  const researchTrail: string[] = [];
  const result = userPromptWithPreflightCompaction({
    config: testConfig({ triage: { promptMaxChars: 12_000, promptCompactionTargetChars: 8_000 } }),
    systemText: "system prompt".repeat(200),
    threadContext: Array.from({ length: 100 }, (_value, index) => `user${index}: ${"older thread context ".repeat(20)}`).join("\n"),
    buildUserText: (threadContext) => [
      "question: check this",
      threadContext ? `Visible Slack thread context:\n${threadContext}` : "",
    ].filter(Boolean).join("\n"),
    researchTrail,
  });

  assert.equal(result.compacted, true);
  assert.equal(result.preflight.ok, true);
  assert.match(result.userText, /Older Slack thread context omitted/);
  assert.match(researchTrail.join("\n"), /prompt_preflight: compacted thread context/);
});

test("answer contract rejects completed answers without evidence or research", () => {
  const contract = validateSecurityAssistantAnswerContract({
    answer: "Looks fine.",
    messages: ["Looks fine."],
    reaction: "mag",
    keyPoints: [],
    evidence: [],
    actionsTaken: [],
    nextActions: [],
    research: [],
    memoryUpdates: [],
    source: "pi",
  }, []);

  assert.equal(contract.ok, false);
  assert.equal(contract.reason, "missing_grounding");
});

test("answer contract rejects current claims that only have historical evidence", () => {
  const contract = validateSecurityAssistantAnswerContract({
    answer: "Checkout belongs to Payments.",
    messages: ["Checkout belongs to Payments."],
    keyPoints: [],
    evidence: ["Memory named Payments."],
    actionsTaken: ["Checked memory."],
    nextActions: [],
    research: ["security_memory_intelligence: checked"],
    memoryUpdates: [],
    claimEvidence: [{
      claimId: "owner",
      claimText: "Checkout belongs to Payments.",
      temporalScope: "current",
      verification: "historical_only",
      sourceTools: ["security_memory_intelligence"],
      evidenceReceipts: ["evidence:security_memory_intelligence:one"],
      visible: true,
      evidence: [{
        id: "memory-1",
        kind: "memory",
        title: "Checkout service owner",
        basis: "historical",
        access: "allowed",
        verifiedBy: [],
        sourceArtifacts: [],
      }],
    }],
    source: "pi",
  }, []);

  assert.deepEqual(contract, { ok: false, reason: "current_claim_not_live_verified" });
});

test("assistant preserves grounded research and says it is not sure when certainty is incomplete", () => {
  const recovered = recoverQualifiedUncertainty({
    answer: "Finding F-701 is critical and internet reachable.",
    messages: ["Finding F-701 is critical and internet reachable."],
    keyPoints: ["F-701 is the current priority."],
    evidence: ["The findings source returned F-701."],
    actionsTaken: ["Checked current findings."],
    nextActions: ["Restrict the exposed path for F-701."],
    research: ["cerebro_recent_scary_findings: checked"],
    memoryUpdates: [],
    claimEvidence: [{
      claimId: "finding-f-701",
      claimText: "Finding F-701 is critical and internet reachable.",
      temporalScope: "current",
      verification: "unverified",
      sourceTools: ["cerebro_recent_scary_findings"],
      evidenceReceipts: ["evidence:findings:701"],
      visible: true,
      evidence: [{
        id: "live:finding:F-701",
        kind: "live_source",
        title: "F-701",
        basis: "live",
        access: "allowed",
        sourceTool: "cerebro_recent_scary_findings",
        sourceRef: "F-701",
        subjectId: "F-701",
        verifiedBy: ["cerebro_recent_scary_findings"],
        sourceArtifacts: ["https://cerebro.writer.com/findings/F-701"],
      }],
    }],
    source: "flue",
  }, "flue");

  assert.equal(recovered.source, "flue");
  assert.equal(recovered.contractRecovery, "qualified_uncertainty");
  assert.match(recovered.messages.at(-1) ?? "", /I'm not sure every current detail/i);
  assert.doesNotMatch(recovered.messages.join(" "), /claim ledger|Flue assistant|current_claim_not_live_verified|contract/);
  assert.deepEqual(validateSecurityAssistantAnswerContract(recovered, recovered.research), { ok: true });
});

test("assistant treats Slack presentation wording changes as advisory citation state", () => {
  const answer = recoverQualifiedUncertainty({
    answer: "This release keeps completed source results when another check is incomplete.",
    messages: ["The release keeps useful source results even when one check is incomplete."],
    keyPoints: ["Completed source results are preserved."],
    evidence: ["Release status and learning changes were checked."],
    actionsTaken: ["Checked the current release."],
    nextActions: [],
    research: ["cerebro_code_status: checked", "security_learning_docs_read: checked"],
    memoryUpdates: [],
    claimEvidence: [{
      claimId: "release-update",
      claimText: "This release keeps completed source results when another check is incomplete.",
      temporalScope: "current",
      verification: "verified",
      sourceTools: ["cerebro_code_status"],
      evidenceReceipts: ["evidence:cerebro_code_status:release"],
      visible: false,
      evidence: [{
        id: "live:release:225d41c",
        kind: "live_source",
        title: "Companion release 225d41c",
        basis: "live",
        access: "allowed",
        sourceTool: "cerebro_code_status",
        sourceRef: "225d41c",
        verifiedBy: ["cerebro_code_status"],
        sourceArtifacts: [],
      }],
    }],
    source: "flue",
  }, "flue");

  assert.equal(answer.contractRecovery, undefined);
  assert.doesNotMatch(answer.messages.join(" "), /I'm not sure|LLM error|model request failed|citation_claim_not_visible|Albert/);
  assert.deepEqual(validateSecurityAssistantAnswerContract(answer, answer.research), { ok: true });
  assert.equal(assistantResultTelemetry(answer)["assistant.answer.citation_blocker_count"], 0);
  assert.equal(assistantResultTelemetry(answer)["assistant.answer.citation_advisory_count"], 1);
});

test("assistant keeps one specific source uncertainty instead of appending a generic hedge", () => {
  const answer = recoverQualifiedUncertainty({
    answer: "Release 44ac901 changed answer recovery. The deployment source returned partial coverage, so I couldn't confirm every running task is on 44ac901.",
    messages: ["Release 44ac901 changed answer recovery. The deployment source returned partial coverage, so I couldn't confirm every running task is on 44ac901."],
    keyPoints: ["Release 44ac901 changed answer recovery."],
    evidence: ["The release source returned commit 44ac901."],
    actionsTaken: ["Checked release notes and deployment state."],
    nextActions: ["Re-check deployment state for rollout confirmation."],
    research: ["release_notes: checked", "deployment_state: partial"],
    memoryUpdates: [],
    source: "flue",
    claimEvidence: [
      {
        claimId: "release",
        claimText: "Release 44ac901 changed answer recovery.",
        temporalScope: "current",
        verification: "verified",
        sourceTools: ["release_notes"],
        evidenceReceipts: ["release-44ac901"],
        visible: true,
        evidence: [{
          id: "commit:44ac901",
          kind: "live_source",
          title: "44ac901",
          basis: "live",
          access: "allowed",
          sourceTool: "release_notes",
          sourceRef: "commit:44ac901",
          verifiedBy: ["release_notes"],
          sourceArtifacts: [],
        }],
      },
      {
        claimId: "deployment",
        claimText: "The deployment source returned partial coverage, so I couldn't confirm every running task is on 44ac901.",
        temporalScope: "current",
        verification: "blocked",
        sourceTools: [],
        evidenceReceipts: [],
        visible: true,
        evidence: [],
      },
    ],
  }, "flue");

  assert.equal(answer.contractRecovery, "qualified_uncertainty");
  assert.doesNotMatch(answer.messages.join(" "), /I'm not sure this is complete/i);
  assert.equal(answer.messages.length, 1);
  assert.deepEqual(validateSecurityAssistantAnswerContract(answer, answer.research), { ok: true });
});

test("assistant does not call missing coverage a source disagreement", () => {
  const answer = recoverQualifiedUncertainty({
    answer: "This isn't a source disagreement; GitHub coverage does not exist in cerebro-dev, so the canary stopped without changing provider state.",
    messages: ["This isn't a source disagreement; GitHub coverage does not exist in cerebro-dev, so the canary stopped without changing provider state."],
    keyPoints: ["GitHub coverage is missing."],
    evidence: ["The current runtime query returned no GitHub runtime."],
    actionsTaken: ["Checked current Okta, AWS, and GitHub runtime coverage."],
    nextActions: ["Register and sync the GitHub audit runtime."],
    research: ["cerebro_source_runtimes: checked"],
    memoryUpdates: [],
    source: "flue",
    claimEvidence: [{
      claimId: "github-coverage",
      claimText: "GitHub coverage does not exist in cerebro-dev.",
      temporalScope: "current",
      verification: "contradicted",
      sourceTools: ["cerebro_source_runtimes"],
      evidenceReceipts: ["receipt-github-coverage"],
      visible: true,
      evidence: [{
        id: "github-runtime-check",
        kind: "live_source",
        title: "GitHub runtime coverage check",
        basis: "live",
        access: "allowed",
        sourceTool: "cerebro_source_runtimes",
        sourceRef: "runtime:writer-github-audit",
        verifiedBy: ["cerebro_source_runtimes"],
        sourceArtifacts: [],
      }],
    }],
  }, "flue");

  assert.equal(answer.contractRecovery, undefined);
  assert.doesNotMatch(answer.messages.join(" "), /checked sources disagree|which record is current/i);
  assert.deepEqual(validateSecurityAssistantAnswerContract(answer, answer.research), { ok: true });
});

test("assistant recognizes natural bounded uncertainty without appending a blanket disclaimer", () => {
  const answer = recoverQualifiedUncertainty({
    answer: "The graph returned the host link, but I can't yet confirm the user lookup because it timed out.",
    messages: ["The graph returned the host link, but I can't yet confirm the user lookup because it timed out."],
    keyPoints: ["The host link returned."],
    evidence: ["The graph returned partial evidence."],
    actionsTaken: ["Checked the graph."],
    nextActions: ["Retry the user lookup."],
    research: ["cerebro_graph_reason: partial"],
    memoryUpdates: [],
    source: "flue",
    claimEvidence: [{
      claimId: "user-link",
      claimText: "The user is linked to the host.",
      temporalScope: "current",
      verification: "unverified",
      sourceTools: ["cerebro_graph_reason"],
      evidenceReceipts: ["evidence:cerebro_graph_reason:partial"],
      visible: true,
      evidence: [{
        id: "live:host:build-runner-14",
        kind: "live_source",
        title: "build-runner-14",
        basis: "live",
        access: "allowed",
        sourceTool: "cerebro_graph_reason",
        sourceRef: "host:build-runner-14",
        verifiedBy: ["cerebro_graph_reason"],
        sourceArtifacts: [],
      }],
    }],
  }, "flue");

  assert.equal(answer.messages.length, 1);
  assert.doesNotMatch(answer.messages.join(" "), /I'm not sure every current detail/i);
  assert.equal(answer.contractRecovery, "qualified_uncertainty");
});

test("assistant does not qualify away a restricted evidence boundary", () => {
  const answer = {
    answer: "The private incident record names an owner.",
    messages: ["The private incident record names an owner."],
    keyPoints: [], evidence: ["Private incident record."], actionsTaken: [], nextActions: [], research: ["security_memory_read: checked"], memoryUpdates: [], source: "flue" as const,
    claimEvidence: [{
      claimId: "private-owner",
      claimText: "The private incident record names an owner.",
      temporalScope: "historical" as const,
      verification: "verified" as const,
      sourceTools: ["security_memory_read"],
      evidenceReceipts: ["private-receipt"],
      visible: true,
      evidence: [{ id: "memory-private", kind: "memory" as const, title: "Private incident", basis: "historical" as const, access: "restricted" as const, verifiedBy: [], sourceArtifacts: [] }],
    }],
  };

  const recovered = recoverQualifiedUncertainty(answer, "flue");
  assert.equal(recovered.contractRecovery, undefined);
  assert.deepEqual(validateSecurityAssistantAnswerContract(recovered, recovered.research), { ok: false, reason: "citation_source_not_accessible" });
});

test("assistant removes restricted claims and still gives the human a safe next action", () => {
  const answer = prepareDeliverableAnswer({
    answer: "The private incident record names an owner.",
    messages: ["The private incident record names an owner."],
    keyPoints: ["A private owner was found."],
    evidence: ["Private incident record."],
    actionsTaken: [],
    nextActions: [],
    research: ["security_memory_read: checked"],
    memoryUpdates: [],
    source: "flue",
    claimEvidenceBindings: [{ claimId: "private-owner", claimText: "The private incident record names an owner.", temporalScope: "historical", evidenceIds: ["memory-private"] }],
    claimEvidence: [{
      claimId: "private-owner",
      claimText: "The private incident record names an owner.",
      temporalScope: "historical",
      verification: "verified",
      sourceTools: ["security_memory_read"],
      evidenceReceipts: ["private-receipt"],
      visible: true,
      evidence: [{ id: "memory-private", kind: "memory", title: "Private incident", basis: "historical", access: "restricted", verifiedBy: [], sourceArtifacts: [] }],
    }],
  }, ["security_memory_read: checked"], "flue");

  assert.equal(answer.source, "flue");
  assert.doesNotMatch(answer.messages.join(" "), /names an owner|private owner/i);
  assert.match(answer.messages.join(" "), /source available here|authorized channel/i);
  assert.deepEqual(answer.claimEvidence, []);
  assert.deepEqual(validateSecurityAssistantAnswerContract(answer, answer.research), { ok: true });
});

test("assistant delivers an uncertain draft when grounding quality is incomplete", () => {
  const answer = prepareDeliverableAnswer({
    answer: "The deployment probably finished.",
    messages: ["The deployment probably finished."],
    keyPoints: [], evidence: [], actionsTaken: [], nextActions: [], research: [], memoryUpdates: [], source: "flue", executionLane: "lookup",
  }, [], "flue");

  assert.equal(answer.source, "flue");
  assert.match(answer.messages.join(" "), /deployment probably finished/i);
  assert.match(answer.messages.join(" "), /I'm not sure/i);
  assert.deepEqual(validateSecurityAssistantAnswerContract(answer, []), { ok: true });
});

test("assistant recovery preserves completed claims and qualifies an unrelated current claim", () => {
  const state = new SecurityResearchState();
  state.setAvailableTools(["cerebro_findings", "security_memory_search"]);
  state.establishPlan({
    decision: "Check two claims.",
    claims: [
      { id: "verified", claim: "F-701 is open.", source_candidates: ["cerebro_findings"] },
      { id: "missing", claim: "The owner is current.", source_candidates: ["security_memory_search"] },
    ],
  });
  const liveEvidence = {
    id: "live:finding:F-701",
    kind: "live_source" as const,
    title: "F-701",
    basis: "live" as const,
    access: "allowed" as const,
    sourceTool: "cerebro_findings",
    sourceRef: "F-701",
    subjectId: "F-701",
    verifiedBy: ["cerebro_findings"],
    sourceArtifacts: [],
  };
  const answer = {
    answer: "F-701 is open. The owner is Security.",
    messages: ["F-701 is open. The owner is Security."],
    keyPoints: [], evidence: [], actionsTaken: [], nextActions: [], research: [], memoryUpdates: [], source: "flue" as const,
    claimEvidence: [
      { claimId: "verified", claimText: "F-701 is open.", temporalScope: "current" as const, verification: "verified" as const, sourceTools: ["cerebro_findings"], evidenceReceipts: ["findings-1"], visible: true, evidence: [liveEvidence] },
      { claimId: "missing", claimText: "The owner is Security.", temporalScope: "current" as const, verification: "unverified" as const, sourceTools: ["security_memory_search"], evidenceReceipts: ["memory-1"], visible: true, evidence: [liveEvidence] },
    ],
  };

  const incomplete = recoverIncompleteResearch(answer, state, "flue");
  assert.equal(incomplete.claimEvidence?.[0]?.verification, "verified");
  const recovered = recoverQualifiedUncertainty(incomplete, "flue");
  assert.equal(recovered.contractRecovery, "qualified_uncertainty");
  assert.match(recovered.messages.at(-1) ?? "", /I'm not sure every current detail/i);
});

test("assistant applies the Flue converse lane before grounding validation", async () => {
  const service = new SecurityAssistantService(
    testConfig({ triage: { assistantRuntime: "flue" } }),
    {} as any,
    { workingMemoryPromptBlock: () => "", remember: async () => undefined } as any,
    {
      flueComplete: async () => ({
        data: {
          answer: "127.0.0.1 is your own computer's loopback address.",
          messages: ["127.0.0.1 is your own computer's loopback address. Check the local process that opened the connection."],
          reply_messages: [],
          key_points: [],
          keyPoints: [],
          evidence: [],
          actions_taken: [],
          actionsTaken: [],
          next_actions: ["Check the local process that opened the connection."],
          nextActions: [],
          research: [],
          memory_updates: [],
          memoryUpdates: [],
          specialist_work: [],
          presentation_ready: true,
          teammate: {
            objective: "Explain the reported IP.",
            desired_outcome: "The user understands the local scope and the next check.",
            resolved_scope: ["127.0.0.1"],
            scope_assumptions: [],
            commitments: [],
            open_loops: [],
            user_decision: { required: false },
          },
        },
        execution: { lane: "converse", availableToolCount: 0, selectedToolCount: 0, stageCount: 1, specialistRoles: [], specialistCount: 0, specialistCompletedCount: 0, specialistBlockedCount: 0, specialistIncompleteCount: 0, specialistCoverage: 1 },
      }),
    },
  );

  const result = await service.answer({
    channelId: "CSEC",
    userId: "UUSER",
    ts: "1782489503.000002",
    question: "I'm pretty sure I got a virus from 127.0.0.1, what can you tell me about this IP?",
  });

  assert.equal(result.source, "flue");
  assert.equal(result.executionLane, "converse");
  assert.match(result.answer, /loopback/);
});

test("parseSecurityAssistantOutput removes protocol leakage from user-facing fields", () => {
  const result = parseSecurityAssistantOutput(JSON.stringify({
    answer: "No blocker.</parameter>\n<parameter name=\"messages\">[\"raw draft\"]",
    messages: ["<parameter name=\"answer\">raw draft</parameter>"],
    reaction: "mag",
    key_points: ["Albert was asked to help Cerebro with no concrete check named."],
    evidence: ["Slack thread context was available to the assistant."],
    actions_taken: ["Checked the thread context."],
    next_actions: ["Ask for the specific runtime, finding, or source check Albert should help with."],
    research: [],
    memory_updates: [],
  }), ["slack_thread_context: checked"]);

  assert.doesNotMatch(result?.answer ?? "", /parameter name|<\/parameter>/i);
  assert.deepEqual(result?.messages, []);
  assert.match(result?.answer ?? "", /Albert was asked/);
  assert.match(result?.answer ?? "", /slack thread context was available/i);
  assert.doesNotMatch(result?.answer ?? "", /I checked the thread context/);
  assert.doesNotMatch(result?.answer ?? "", /Next, ask for the specific runtime/);
  assert.match(result?.nextActions[0] ?? "", /Ask for the specific runtime/);
  assert.doesNotMatch(result?.answer ?? "", /Checked:|Evidence:|Next:/);
});

test("assistant repairs malformed final answer JSON with an LLM normalizer", async () => {
  const repairCalls: any[] = [];
  const service = new SecurityAssistantService(
    testConfig(),
    {} as any,
    {} as any,
    {
      repairComplete: async (input) => {
        repairCalls.push(input);
        return JSON.stringify({
          answer: "One high-risk finding landed today: okta-critical in writer-okta-user.",
          messages: ["One high-risk finding landed today: okta-critical in writer-okta-user."],
          reaction: "mag",
          key_points: ["okta-critical is open and high risk."],
          evidence: ["cerebro_recent_scary_findings returned okta-critical."],
          actions_taken: ["Checked recent scary findings."],
          next_actions: ["Review okta-critical in Cerebro."],
          research: [],
          memory_updates: [],
        });
      },
    },
  );

  const repaired = await (service as any).repairAssistantOutput({
    input: {
      channelId: "CSEC",
      userId: "UUSER",
      ts: "1782489502.000000",
      question: "any neat findings land today?",
    },
    rawOutput: "Looks like okta-critical landed today, but I forgot the JSON wrapper.",
    researchTrail: ["cerebro_recent_scary_findings: checked"],
    messages: [{
      role: "toolResult",
      toolName: "cerebro_recent_scary_findings",
      content: [{
        type: "text",
        text: JSON.stringify({
          findings: [{
            finding_id: "okta-critical",
            runtime_id: "writer-okta-user",
            severity: "critical",
            risk_score: 92,
          }],
        }),
      }],
    }],
  });

  assert.equal(repaired?.source, "pi");
  assert.match(repaired?.messages[0] ?? "", /okta-critical/);
  assert.deepEqual(repaired?.research, ["cerebro_recent_scary_findings: checked"]);
  assert.equal(repairCalls.length, 1);
  assert.match(repairCalls[0].systemPrompt, /stable voice across turns/);
  assert.match(repairCalls[0].systemPrompt, /natural thread replies/);
  assert.match(repairCalls[0].userPrompt, /any neat findings land today/);
  assert.match(repairCalls[0].transcript, /cerebro_recent_scary_findings/);
  assert.match(repairCalls[0].transcript, /okta-critical/);
});

test("assistant presents completed answers through the LLM Slack editor", async () => {
  const presentationCalls: any[] = [];
  const result = await presentSlackAnswerWithLlm({
    config: testConfig(),
    question: {
      channelId: "CSEC",
      userId: "UUSER",
      ts: "1782489502.000001",
      question: "Can you make this a useful launch-review answer?",
    },
    answer: {
      answer: "Writer's catalog defines an AI system risk review control that needs an inventory entry.",
      messages: ["Raw control finding with lots of internal structure."],
      reaction: "mag",
      keyPoints: ["AI system inventory entry is required."],
      evidence: ["writer/cerebro control catalog names ISO 42001 6.1.2 + A.2.2."],
      actionsTaken: ["Checked compliance source context."],
      nextActions: ["Open a Palmyra X6 AI-system inventory entry."],
      research: ["cerebro_compliance_context: checked"],
      memoryUpdates: [],
      source: "pi",
    },
    options: {
      presentationComplete: async (input) => {
        presentationCalls.push(input);
        return JSON.stringify({
          messages: [
            "Palmyra X6 needs an inventory entry before launch.",
            "Use the supplied control evidence to capture owner, purpose, data classes, model provider, risk tier, and pre-launch review state.",
          ],
        });
      },
    },
  });

  assert.equal(presentationCalls.length, 1);
  assert.match(presentationCalls[0].systemPrompt, /Slack reply editor/);
  assert.match(presentationCalls[0].systemPrompt, /Decide the response shape from the user's wording/);
  assert.match(presentationCalls[0].userPrompt, /Can you make this a useful launch-review answer/);
  assert.match(presentationCalls[0].userPrompt, /ISO 42001 6.1.2/);
  assert.deepEqual(result.messages, [
    "Palmyra X6 needs an inventory entry before launch.",
    "Use the supplied control evidence to capture owner, purpose, data classes, model provider, risk tier, and pre-launch review state.",
  ]);
  assert.equal(result.answer, "Writer's catalog defines an AI system risk review control that needs an inventory entry.");
});

test("assistant skips the editor model when the staged answer is presentation-ready", async () => {
  let editorCalls = 0;
  const answer = {
    executionLane: "lookup" as const,
    presentationReady: true,
    answer: "Finding f-1 is still open.",
    messages: ["Finding f-1 is still open."],
    keyPoints: ["f-1 is open."],
    evidence: ["finding_lookup returned f-1 with status open."],
    actionsTaken: ["Checked finding f-1."],
    nextActions: ["Review the current owner."],
    research: ["finding_lookup: checked"],
    memoryUpdates: [],
    source: "flue" as const,
  };
  const result = await presentSlackAnswerWithLlm({
    config: testConfig(),
    question: { channelId: "CSEC", ts: "1782489502.000002", question: "Is f-1 open?" },
    answer,
    options: { presentationComplete: async () => { editorCalls += 1; return "{}"; } },
  });

  assert.equal(editorCalls, 0);
  assert.equal(result, answer);
});

test("assistant repairs a presentation-ready ignore before replying to a human", async () => {
  let editorCalls = 0;
  const result = await presentSlackAnswerWithLlm({
    config: testConfig(),
    question: { channelId: "CSEC", userId: "UUSER", senderKind: "human", ts: "1782489502.000003", threadTs: "1782489502.000001", question: "yawn. Something cooler pls" },
    threadContext: "Human: Show me the latest findings.\nCerebro: One routine item was open.",
    answer: {
      executionLane: "continue",
      presentationReady: true,
      answer: "[IGNORE]\n\nI'm not sure this is complete because I could not verify every part against an available source.",
      messages: ["[IGNORE]", "I'm not sure this is complete because I could not verify every part against an available source."],
      keyPoints: [], evidence: [], actionsTaken: [], nextActions: [], research: [], memoryUpdates: [], source: "flue",
      contractRecovery: "qualified_uncertainty",
    },
    options: {
      presentationComplete: async (input) => {
        editorCalls += 1;
        assert.match(input.systemPrompt, /Never return \[IGNORE\] to a human/);
        assert.match(input.userPrompt, /Show me the latest findings/);
        return JSON.stringify({ messages: ["Fair. The routine item was weak; I'll look for a materially different current risk instead."] });
      },
    },
  });

  assert.equal(editorCalls, 1);
  assert.doesNotMatch(result.answer, /IGNORE/);
  assert.match(result.answer, /materially different current risk/i);
  assert.equal(result.delivery, "respond");
});

test("assistant never returns ignore when the human non-answer repair repeats it", async () => {
  const result = await presentSlackAnswerWithLlm({
    config: testConfig(),
    question: { channelId: "CSEC", userId: "UUSER", senderKind: "human", ts: "1782489502.000004", question: "Tell the team what changed." },
    answer: {
      executionLane: "converse",
      presentationReady: true,
      answer: "[IGNORE]",
      messages: ["[IGNORE]"],
      keyPoints: [], evidence: [], actionsTaken: [], nextActions: [], research: [], memoryUpdates: [], source: "flue",
    },
    options: { presentationComplete: async () => JSON.stringify({ messages: ["[IGNORE]"] }) },
  });

  assert.equal(result.source, "blocked");
  assert.doesNotMatch(result.answer, /IGNORE/);
  assert.match(result.answer, /retry it with fresh source checks/i);
  assert.equal(result.delivery, "respond");
});

test("assistant returns a concrete response when human non-answer repair fails", async () => {
  const result = await presentSlackAnswerWithLlm({
    config: testConfig(),
    question: { channelId: "CSEC", userId: "UUSER", senderKind: "human", ts: "1782489502.000005", question: "What changed?" },
    answer: {
      executionLane: "converse",
      presentationReady: true,
      answer: "[IGNORE]",
      messages: ["[IGNORE]"],
      keyPoints: [], evidence: [], actionsTaken: [], nextActions: [], research: [], memoryUpdates: [], source: "flue",
    },
    options: { presentationComplete: async () => { throw new Error("presentation unavailable"); } },
  });

  assert.equal(result.source, "blocked");
  assert.doesNotMatch(result.answer, /IGNORE/);
  assert.match(result.answer, /still have the request/i);
  assert.equal(result.delivery, "respond");
});

test("agent path blocks cleanly when Pi is unavailable without substitute routes", async () => {
  const previousFetch = globalThis.fetch;
  const fetchCalls: string[] = [];
  globalThis.fetch = (async (input: string | URL | Request) => {
    fetchCalls.push(String(input));
    return new Response(JSON.stringify({ ok: false, error: "unexpected_method" }));
  }) as typeof fetch;

  const calls = {
    graph: 0,
    findings: 0,
    runtimeHealth: 0,
    recall: 0,
    search: 0,
    remember: 0,
  };

  try {
    const service = new SecurityAssistantService(
      testConfig({
        triage: { pi: { enabled: false } },
        cerebro: { defaultRuntimeIds: ["writer-okta", "writer-github-audit"] },
      }),
      {
        listFindings: async () => {
          calls.findings += 1;
          return [{ id: "okta-critical", title: "Privileged Okta account active", severity: "critical", status: "open" }];
        },
        listRuntimeHealth: async () => {
          calls.runtimeHealth += 1;
          return [{ runtime_id: "writer-okta", sync_status: "healthy", graph_status: "healthy", finding_status: "healthy" }];
        },
        buildEvidencePacket: async () => {
          calls.graph += 1;
          return {};
        },
        reasonGraph: async () => {
          calls.graph += 1;
          return { answer: "graph should not run" };
        },
      } as any,
      {
        recall: async () => {
          calls.recall += 1;
          return [{
            id: "m1",
            kind: "normal_pattern",
            topic: "Slack context: Sean",
            summary: "Sean often jokes in Slack.",
            tags: ["slack-remember", "team-context"],
            channelId: "CSEC",
            sourceTs: "1782501562.693279",
            classification: "user_provided_context",
            confidence: 1,
            createdAt: new Date().toISOString(),
          }];
        },
        search: async () => {
          calls.search += 1;
          return [];
        },
        remember: async () => {
          calls.remember += 1;
          return undefined;
        },
      } as any,
    );

    const questions = [
      "waht tools do you have access to?",
      "can you tell if Seán has MFA enabled? Or what his additional factors might be?",
      "I'm pretty sure I got a virus from 127.0.0.1, what can you tell me about this IP?",
      "can you search slack for the message from JR from this morning?",
      "what do you remember about Sean?",
      "welcome to teh party",
      "any findings of value today?",
      "debug yourself",
    ];

    for (const [index, question] of questions.entries()) {
      const result = await service.answer({
        channelId: "CSEC",
        userId: "UUSER",
        ts: `17824894${index}0.000000`,
        threadTs: "1782489400.000000",
        question,
      });

      assert.equal(result.source, "blocked", question);
      assert.match(result.messages[0] ?? "", /could not start the source check/i, question);
      assert.match(result.messages[0] ?? "", /no substitute result was posted/i, question);
      assert.doesNotMatch(result.messages[0] ?? "", /LLM|Pi|model|provider/i, question);
      assert.match(result.research.join("\n"), /llm_error: disabled/i, question);
      assert.doesNotMatch(result.answer, /assistant tools|I found this|I remember this|I found relevant memory|Slack context: Sean|okta-critical|graph should not run/i, question);
    }

    assert.deepEqual(calls, {
      graph: 0,
      findings: 0,
      runtimeHealth: 0,
      recall: 0,
      search: 0,
      remember: 0,
    });
    assert.equal(fetchCalls.length, 0);
  } finally {
    globalThis.fetch = previousFetch;
  }
});

test("blocked answer keeps unavailable model details out of Slack", async () => {
  const service = new SecurityAssistantService(
    testConfig({ triage: { pi: { provider: "missing-provider", model: "missing-model" } } }),
    {} as any,
    {} as any,
  );

  const result = await service.answer({
    channelId: "CSEC",
    userId: "UUSER",
    ts: "1782489500.000000",
    question: "what are the newest scariest findings today?",
  });

  assert.equal(result.source, "blocked");
  assert.match(result.answer, /could not start the source check/i);
  assert.doesNotMatch(result.answer, /missing-provider|missing-model|LLM/i);
  assert.match(result.research.join("\n"), /llm_error: model_unavailable/i);
  assert.match(result.actionsTaken[0] ?? "", /configured model could not be loaded/i);
});

test("blocked answer keeps invalid response internals out of Slack", async () => {
  const service = new SecurityAssistantService(
    testConfig(),
    {} as any,
    {} as any,
  );
  (service as any).runPiAgent = async () => {
    throw new Error("Pi security assistant did not return valid answer JSON");
  };

  const result = await service.answer({
    channelId: "CSEC",
    userId: "UUSER",
    ts: "1782489501.000000",
    question: "what are the newest scariest findings today?",
  });

  assert.equal(result.source, "blocked");
  assert.match(result.answer, /I'm not sure yet/i);
  assert.doesNotMatch(result.answer, /JSON|schema|LLM|model/i);
  assert.match(result.research.join("\n"), /llm_error: invalid_response/i);
  assert.match(result.actionsTaken[0] ?? "", /required answer schema/i);
});

test("assistant can answer through the Flue runtime with typed output", async () => {
  const remembered: any[] = [];
  const completeCalls: any[] = [];
  const service = new SecurityAssistantService(
    testConfig({
      triage: {
        assistantRuntime: "flue",
        pi: {
          provider: "missing-provider",
          model: "missing-model",
          executionModel: "fast-model",
          executionThinkingLevel: "low",
        },
      },
      cerebro: {
        assistantHelpMention: "<@U0AR7EF2FSP>",
      },
    }),
    {} as any,
    {
      workingMemoryPromptBlock: () => "Known context: prefer concrete Slack replies.",
      remember: async (record: unknown) => {
        remembered.push(record);
      },
    } as any,
    {
      flueComplete: async (input) => {
        completeCalls.push(input);
        assert.equal(input.model, "missing-provider/missing-model");
        assert.equal(input.thinkingLevel, "medium");
        assert.equal(input.executionModel, "missing-provider/fast-model");
        assert.equal(input.executionThinkingLevel, "low");
        assert.match(input.systemPrompt, /Known context/);
        assert.match(input.systemPrompt, /<@U0AR7EF2FSP>/);
        assert.match(input.systemPrompt, /stable voice across turns/);
        assert.match(input.systemPrompt, /what is running, what is missing or broken/);
        assert.match(input.userPrompt, /which instance are you running/);
        await input.onResearchPlan?.({
          user_intent: "Identify the running companion instance.",
          execution_lane: "lookup",
          claims: [{
            id: "claim-1",
            claim: "The configured runtime path is identified.",
            required: true,
            source_candidates: ["cerebro_companion_self_context"],
          }],
          research_plan: ["Verify the configured runtime path."],
          user_visible_work: ["Check companion runtime context"],
          required_sources: ["cerebro_companion_self_context"],
          missing_context_questions: [],
        });
        const selfContextTool = input.tools.find((tool) => tool.name === "cerebro_companion_self_context");
        assert.ok(selfContextTool);
        const selfContext = await selfContextTool.run({
          input: { include_tools: false, include_commands: false, include_debug_plan: false },
          emitData: () => undefined,
          signal: new AbortController().signal,
        });
        const claimLedgerTool = input.tools.find((tool) => tool.name === "operator_claim_ledger");
        assert.ok(claimLedgerTool);
        await claimLedgerTool.run({
          input: {
            claims: [{
              id: "claim-1",
              status: "supported",
              source_tools: ["cerebro_companion_self_context"],
              evidence_receipts: [(selfContext as any).details.evidence_receipt],
            }],
            answer_ready: true,
          },
          emitData: () => undefined,
          signal: new AbortController().signal,
        });
        return {
          data: {
            execution_lane: "lookup",
            answer: "Cerebro is running from the configured Flue runtime path.",
            messages: ["Cerebro is running from the configured Flue runtime path."],
            reply_messages: [],
            reaction: "mag",
            key_points: ["Flue runtime was selected for this answer."],
            keyPoints: [],
            evidence: ["cerebro_companion_self_context returned service context."],
            actions_taken: ["Checked companion self context."],
            actionsTaken: [],
            next_actions: ["Use the same runtime path for the live smoke test."],
            nextActions: [],
            research: [],
            memory_updates: [],
            memoryUpdates: [],
            specialist_work: [],
            teammate: {
              objective: "Identify the running companion instance.",
              desired_outcome: "The user knows which configured runtime is serving this answer.",
              resolved_scope: ["current companion process"],
              scope_assumptions: [],
              commitments: [],
              open_loops: [],
              user_decision: { required: false },
            },
          },
          model: { provider: "missing-provider", id: "missing-model" },
        };
      },
    },
  );

  const result = await service.answer({
    channelId: "CSEC",
    userId: "UUSER",
    ts: "1782489503.000000",
    question: "which instance are you running?",
  });

  assert.equal(result.source, "flue");
  assert.match(result.answer, /configured Flue runtime path/);
  assert.deepEqual(result.research, ["cerebro_companion_self_context: checked"]);
  assert.equal(completeCalls.length, 1);
  assert.equal(remembered.length, 0);
});

test("assistant preserves a useful answer when private claim binding is incomplete", async () => {
  const service = new SecurityAssistantService(
    testConfig({ triage: { assistantRuntime: "flue" } }),
    {} as any,
    {
      workingMemoryPromptBlock: () => "",
      remember: async () => undefined,
    } as any,
    {
      flueComplete: async (input) => {
        await input.onResearchPlan?.({
          user_intent: "Check the running instance.",
          claims: [{
            id: "runtime-current",
            claim: "The running instance is identified.",
            required: true,
            source_candidates: ["cerebro_companion_self_context"],
          }],
          research_plan: ["Check companion runtime context."],
          user_visible_work: ["Check companion runtime context"],
          required_sources: ["cerebro_companion_self_context"],
          missing_context_questions: [],
        });
        const sourceTool = input.tools.find((tool) => tool.name === "cerebro_companion_self_context");
        assert.ok(sourceTool);
        await sourceTool.run({
          input: { include_tools: false },
          emitData: () => undefined,
          signal: new AbortController().signal,
        });
        return {
          data: {
            answer: "The instance is running.",
            messages: ["The instance is running."],
            reply_messages: [],
            key_points: [],
            keyPoints: [],
            evidence: ["Companion context was checked."],
            actions_taken: [],
            actionsTaken: [],
            next_actions: [],
            nextActions: [],
            research: [],
            memory_updates: [],
            memoryUpdates: [],
            specialist_work: [],
          },
        };
      },
    },
  );

  const result = await service.answer({
    channelId: "CSEC",
    userId: "UUSER",
    ts: "1782489503.000001",
    question: "which instance are you running?",
  });

  assert.equal(result.source, "flue");
  assert.match(result.answer, /completed source checks did not verify one planned detail/i);
  assert.match(result.messages.join("\n"), /I'm not sure about every detail above/);
  assert.doesNotMatch(result.messages.join("\n"), /research contract|claim ledger|binding/i);
  assert.doesNotMatch(result.answer, /claim ledger|specialist|LLM|model/i);
});

test("assistant suppresses a low-value bot handoff without storing an answer", async () => {
  const remembered: unknown[] = [];
  const service = new SecurityAssistantService(
    testConfig({ triage: { assistantRuntime: "flue" } }),
    {} as any,
    {
      workingMemoryPromptBlock: () => "",
      remember: async (record: unknown) => { remembered.push(record); },
    } as any,
    {
      flueComplete: async (input) => {
        assert.equal(input.allowIgnore, true);
        return {
          data: {
            response_disposition: "ignore",
            disposition_reason: "Routine digest had no explicit request and only repeated an unavailable ticket scope.",
            answer: "Automated handoff ignored.",
            messages: [],
            reply_messages: [],
            key_points: [],
            keyPoints: [],
            evidence: [],
            actions_taken: [],
            actionsTaken: [],
            next_actions: [],
            nextActions: [],
            research: [],
            memory_updates: [],
            memoryUpdates: [],
            specialist_work: [],
          },
        };
      },
    },
  );

  const result = await service.answer({
    channelId: "CSEC",
    userId: "UBOT",
    senderKind: "bot",
    ts: "1783700000.000000",
    question: "Routine board digest with existing owners and no request.",
  });

  assert.equal(result.delivery, "suppress");
  assert.deepEqual(result.messages, []);
  assert.match(result.dispositionReason ?? "", /no explicit request/);
  assert.deepEqual(remembered, []);
});

test("assistant never suppresses a human question", async () => {
  let editorCalls = 0;
  const service = new SecurityAssistantService(
    testConfig({ triage: { assistantRuntime: "flue" } }),
    {} as any,
    { workingMemoryPromptBlock: () => "", remember: async () => undefined } as any,
    {
      flueComplete: async (input) => {
        assert.equal(input.allowIgnore, false);
        return {
          data: {
            response_disposition: "ignore",
            disposition_reason: "This value must not suppress a human response.",
            execution_lane: "continue",
            presentation_ready: true,
            answer: "[IGNORE]",
            messages: ["[IGNORE]"],
            reply_messages: [],
            key_points: [],
            keyPoints: [],
            evidence: [],
            actions_taken: [],
            actionsTaken: [],
            next_actions: [],
            nextActions: [],
            research: [],
            memory_updates: [],
            memoryUpdates: [],
            specialist_work: [],
          },
        };
      },
      presentationComplete: async () => {
        editorCalls += 1;
        return JSON.stringify({ messages: ["I won't ignore this. I'll take another pass at the human request."] });
      },
    },
  );

  const result = await service.answer({
    channelId: "CSEC",
    userId: "UHUMAN",
    senderKind: "human",
    ts: "1783700001.000000",
    question: "Can you check this?",
  });

  assert.notEqual(result.delivery, "suppress");
  assert.equal(editorCalls, 1);
  assert.doesNotMatch(result.answer, /IGNORE/);
  assert.match(result.messages.join(" "), /take another pass/i);
});

test("blocked assistant answer does not page a helper or expose runtime internals", async () => {
  const service = new SecurityAssistantService(
    testConfig({
      cerebro: { assistantHelpMention: "<@U0AR7EF2FSP>" },
      triage: { pi: { enabled: false } },
    }),
    {} as any,
    {} as any,
  );

  const result = await service.answer({
    channelId: "CSEC",
    userId: "UUSER",
    ts: "1782489505.000000",
    question: "debug yourself",
  });

  assert.equal(result.source, "blocked");
  assert.doesNotMatch(result.messages[0] ?? "", /<@U0AR7EF2FSP>|LLM|Pi|model/i);
  assert.doesNotMatch(result.nextActions[0] ?? "", /<@U0AR7EF2FSP>/);
});

test("assistant prompt preflight blocks oversized requests before model execution", async () => {
  const service = new SecurityAssistantService(
    testConfig({ triage: { promptMaxChars: 100 } }),
    {} as any,
    {
      workingMemoryPromptBlock: () => "",
      remember: async () => undefined,
    } as any,
  );

  const result = await service.answer({
    channelId: "CSEC",
    userId: "UUSER",
    ts: "1782489506.000000",
    question: "check runtime health",
  });

  assert.equal(result.source, "blocked");
  assert.match(result.answer, /stopped before calling the model/);
  assert.match(result.research.join("\n"), /prompt_preflight: blocked/);
});

test("Flue runtime failures block without falling back to Pi", async () => {
  const service = new SecurityAssistantService(
    testConfig({ triage: { assistantRuntime: "flue" } }),
    {} as any,
    {
      workingMemoryPromptBlock: () => "",
      remember: async () => {
        throw new Error("memory should not store blocked answers");
      },
    } as any,
    {
      flueComplete: async () => {
        throw new Error("Flue typed result was unavailable");
      },
    },
  );

  const result = await service.answer({
    channelId: "CSEC",
    userId: "UUSER",
    ts: "1782489504.000000",
    question: "any neat findings land today?",
  });

  assert.equal(result.source, "blocked");
  assert.match(result.answer, /I'm not sure yet/i);
  assert.doesNotMatch(result.answer, /LLM|Flue|model|typed result/i);
  assert.match(result.keyPoints[0] ?? "", /source check did not complete/i);
  assert.match(result.research.join("\n"), /flue_agent: blocked/);
  assert.doesNotMatch(result.research.join("\n"), /pi_agent: blocked/);
});

test("compromised Okta transcript no longer falls back to remembered Slack noise", async () => {
  const service = new SecurityAssistantService(
    testConfig({ triage: { pi: { enabled: false } } }),
    {
      buildEvidencePacket: async () => {
        throw new Error("graph should not run");
      },
      reasonGraph: async () => {
        throw new Error("graph should not run");
      },
    } as any,
    {
      recall: async () => {
        throw new Error("memory should not answer when the agent is blocked");
      },
      search: async () => {
        throw new Error("memory should not answer when the agent is blocked");
      },
      remember: async () => undefined,
    } as any,
  );

  const ipResult = await service.answer({
    channelId: "CSEC",
    userId: "USEAN",
    ts: "1782489420.000000",
    question: "I'm pretty sure I got a virus from 127.0.0.1, what can you tell me about this IP?",
  });

  assert.equal(ipResult.source, "blocked");
  assert.doesNotMatch(ipResult.answer, /I found relevant memory/i);
  assert.doesNotMatch(ipResult.answer, /Infisical|Brandon/i);
  assert.match(ipResult.answer, /no substitute result was posted/i);
});
