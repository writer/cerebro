import assert from "node:assert/strict";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import {
  parseCuratedMemoryRecallDecision,
  parseCuratedMemoryWriteDecision,
} from "../src/learning/security-memory-curator.js";
import { SecurityMemoryStore } from "../src/learning/security-memory/index.js";
import { testConfig } from "./fixtures.js";

test("memory search matches accented names and short handles", async () => {
  const memory = new SecurityMemoryStore(testConfig());

  await memory.remember({
    kind: "team_context",
    topic: "Slack context: Sean",
    summary: "Seán often jokes in Slack; do not treat jokes as security signal without concrete security context.",
    tags: ["slack-remember", "team-context"],
    classification: "user_provided_context",
    confidence: 1,
  });
  await memory.remember({
    kind: "team_context",
    topic: "Slack context: JR",
    summary: "JR is a short Slack handle that should stay searchable.",
    tags: ["slack-remember", "team-context"],
    classification: "user_provided_context",
    confidence: 1,
  });

  const sean = await memory.search("Sean", 2);
  const accentedSean = await memory.search("Seán", 2);
  const jr = await memory.search("JR", 2);

  assert.equal(sean[0]?.topic, "Slack context: Sean");
  assert.equal(accentedSean[0]?.topic, "Slack context: Sean");
  assert.equal(jr[0]?.topic, "Slack context: JR");
});

test("memory search and recall enforce the trusted Slack audience", async () => {
  const memory = new SecurityMemoryStore(testConfig());
  await memory.remember({
    kind: "owner_context",
    topic: "Checkout owner",
    summary: "Payments owns checkout.",
    tags: ["checkout", "owner"],
    channelId: "CSEC",
    sourceTs: "1782501562.693279",
    classification: "user_provided_context",
    confidence: 1,
  });
  await memory.remember({
    kind: "owner_context",
    topic: "Checkout private escalation",
    summary: "Private escalation details for checkout.",
    tags: ["checkout", "owner"],
    channelId: "CPRIVATE",
    sourceTs: "1782501562.693280",
    classification: "user_provided_context",
    confidence: 1,
  });

  const search = await memory.search("checkout owner", 10, "CSEC");
  const recall = await memory.recall({ query: "checkout owner", limit: 10, audienceChannelId: "CSEC" });

  assert.deepEqual(search.map((record) => record.channelId), ["CSEC"]);
  assert.equal(recall.every((record) => !record.channelId || record.channelId === "CSEC"), true);
  assert.equal(recall.some((record) => record.channelId === "CPRIVATE"), false);
});

test("memory search prioritizes explicit team context over noisy matches", async () => {
  const memory = new SecurityMemoryStore(testConfig());

  await memory.remember({
    kind: "normal_pattern",
    topic: "Easy Street, here I come. Thanks, Seán!",
    summary: "Thanks, Seán. No security-relevant action is needed for this message.",
    tags: ["likely-noise"],
    channelId: "CSEC",
    sourceTs: "1782500100.000000",
    classification: "likely_noise",
    confidence: 0.8,
  });
  await memory.remember({
    kind: "team_context",
    topic: "Slack context: Sean",
    summary: "Seán often jokes in Slack; do not treat jokes as security signal without concrete security context.",
    tags: ["slack-remember", "team-context"],
    channelId: "CSEC",
    sourceTs: "1782501562.693279",
    classification: "user_provided_context",
    sourceKind: "slack_remember",
    confidence: 1,
  });

  const results = await memory.search("what do you remember about Sean?", 3);

  assert.equal(results[0]?.topic, "Slack context: Sean");
  assert.notEqual(results[0]?.topic, "Easy Street, here I come. Thanks, Seán!");
  assert.deepEqual(results[0]?.entities?.includes("sean"), true);
});

test("memory search uses entity hints and ignores expired assistant echoes", async () => {
  const memory = new SecurityMemoryStore(testConfig());
  const records = (memory as unknown as { inMemoryRecords: any[] }).inMemoryRecords;

  records.push({
    id: "expired",
    kind: "assistant_answer",
    topic: "what do you remember about rohithn1?",
    summary: "Old answer about rohithn1 that should not be returned.",
    tags: ["slack-question"],
    sourceKind: "assistant_answer",
    entities: ["rohithn1"],
    expiresAt: "2000-01-01T00:00:00.000Z",
    createdAt: new Date(Date.now() + 1000).toISOString(),
  });

  await memory.remember({
    kind: "investigation_note",
    topic: "GitHub identity rohithn1",
    summary: "rohithn1 performed repository activity without a linked Okta identity.",
    tags: ["github", "identity-linkage"],
    entities: ["rohithn1"],
    confidence: 0.9,
  });

  const results = await memory.search("rohithn1", 3);

  assert.equal(results[0]?.topic, "GitHub identity rohithn1");
  assert.equal(results.some((record) => record.id === "expired"), false);
});

test("memory search returns explicit remembered instructions", async () => {
  const memory = new SecurityMemoryStore(testConfig());

  await memory.remember({
    kind: "explicit_memory",
    topic: "Explicit memory: Slack graph layer",
    summary: "Cerebro was explicitly told to remember: Slack messages are not the same thing as graph state.",
    details: "Raw remembered text: Slack messages are not the same thing as graph state.",
    tags: ["slack-remember", "explicit-memory"],
    classification: "user_provided_context",
    sourceKind: "slack_remember",
    confidence: 1,
  });

  const results = await memory.search("what were you told to remember about Slack and graph", 3);

  assert.equal(results[0]?.kind, "explicit_memory");
  assert.match(results[0]?.summary ?? "", /Slack messages/);
});

test("memory remember suppresses exact duplicate content", async () => {
  const memory = new SecurityMemoryStore(testConfig());

  const first = await memory.remember({
    kind: "team_context",
    topic: "Slack context: JR",
    summary: "JR is a short Slack handle that should stay searchable.",
    tags: ["slack-remember", "team-context"],
    channelId: "CSEC",
    sourceTs: "1",
    classification: "user_provided_context",
    sourceKind: "slack_remember",
  });
  const second = await memory.remember({
    kind: "team_context",
    topic: "Slack context: JR",
    summary: "JR is a short Slack handle that should stay searchable.",
    tags: ["slack-remember", "team-context"],
    channelId: "CSEC",
    sourceTs: "2",
    classification: "user_provided_context",
    sourceKind: "slack_remember",
  });

  const results = await memory.search("JR", 10);

  assert.equal(second?.id, first?.id);
  assert.equal(results.filter((record) => record.topic === "Slack context: JR").length, 1);
});

test("memory search looks past recent noisy records", async () => {
  const memory = new SecurityMemoryStore(testConfig());
  const records = (memory as unknown as { inMemoryRecords: any[] }).inMemoryRecords;
  const now = Date.now();

  for (let index = 0; index < 80; index += 1) {
    records.push({
      id: `noise-${index}`,
      kind: "normal_pattern",
      topic: `Routine channel chatter ${index}`,
      summary: "No security-relevant action is needed for this message.",
      tags: ["slack-alert", "likely_noise"],
      channelId: "CSEC",
      classification: "likely_noise",
      createdAt: new Date(now - index * 1000).toISOString(),
    });
  }
  records.push({
    id: "old-sean-context",
    kind: "normal_pattern",
    topic: "Slack context: Sean",
    summary: "Sean says around 90% of what he says on Slack is a joke; do not treat Sean's Slack jokes as security signal unless there is concrete security context.",
    tags: ["slack-remember", "team-context"],
    channelId: "CSEC",
    classification: "user_provided_context",
    confidence: 1,
    createdAt: new Date(now - 120_000).toISOString(),
  });
  records.sort((left, right) => right.createdAt.localeCompare(left.createdAt));

  const results = await memory.search("Sean", 3);

  assert.equal(results[0]?.topic, "Slack context: Sean");
});

test("memory recall does not drag generic graph/NATS history into a specific PR deploy query", async () => {
  const memory = new SecurityMemoryStore(testConfig());
  const records = (memory as unknown as { inMemoryRecords: any[] }).inMemoryRecords;
  const now = Date.now();

  records.push({
    id: "github-audit-nats-runbook",
    kind: "runbook_note",
    topic: "github access status",
    summary: "Cerebro has GitHub PR creation via GitHub App; separately writer-github-audit ingest is healthy but stale and finding-isolated-open-anchor evaluation fails on NATS no-response-from-stream.",
    details: "Checked runtime health for writer-github-audit during a GitHub access question.",
    tags: ["github", "runtime-health", "github-audit", "nats"],
    createdAt: new Date(now).toISOString(),
  });
  records.push({
    id: "graph-qa-nats-story",
    kind: "encounter_story",
    topic: "Slack encounter: can you help me QA your graph?",
    summary: "Cerebro answered a graph QA question and mentioned writer-github-audit NATS failures after graph reasoning returned 503.",
    details: "Question: can you help me QA your graph? Answer: Graph query path was down and writer-github-audit finding evaluation failed on NATS.",
    tags: ["story", "slack-question", "work-loop", "pi"],
    sourceKind: "tool",
    createdAt: new Date(now - 1000).toISOString(),
  });
  records.sort((left, right) => right.createdAt.localeCompare(left.createdAt));

  const pr1488Status = [
    "Graph projection was writing to Neo4j one element at a time under a global lock, making the archetype vulnerability ingest take ~36 minutes.",
    "We replaced the per-element writes with batched UNWIND upserts.",
    "The fix (PR #1488) added batched UNWIND upserts for projected entities and links.",
    "A full re-projection in sec-dev dropped from 2,140,713 ms to 23,247 ms while processing ~20% more data.",
    "sec-dev services still run v2.1.584 and validation was done via a one-off task on image v2.1.586.",
  ].join(" ");

  const unrelated = await memory.recall({ query: pr1488Status, limit: 6 });
  assert.equal(unrelated.some((record) => /nats|github-audit/i.test([record.topic, record.summary, record.details ?? ""].join(" "))), false);

  const nats = await memory.recall({ query: "writer-github-audit NATS no response from stream", limit: 3 });
  assert.equal(nats[0]?.id, "github-audit-nats-runbook");
});

test("memory recall favors source-specific artifact notes over newer encounter stories", async () => {
  const memory = new SecurityMemoryStore(testConfig());
  const records = (memory as unknown as { inMemoryRecords: any[] }).inMemoryRecords;
  const now = Date.now();

  records.push({
    id: "fresh-graph-story",
    kind: "encounter_story",
    topic: "Slack encounter: graph QA",
    summary: "Recent graph QA mentioned ingest, github-audit, and NATS stream failures.",
    tags: ["story", "slack-question"],
    sourceKind: "tool",
    createdAt: new Date(now).toISOString(),
  });
  records.push({
    id: "pr-1488-artifact",
    kind: "investigation_note",
    topic: "PR #1488 Neo4j UNWIND projection validation",
    summary: "PR #1488 batched Neo4j UNWIND graph projection writes and validated sec-dev image v2.1.586 with checkpoint_complete=true.",
    details: "Measured re-projection went from 2,140,713 ms to 23,247 ms for the archetype vulnerability dataset.",
    tags: ["pr-1488", "neo4j", "unwind", "sec-dev"],
    createdAt: new Date(now - 60_000).toISOString(),
  });
  records.sort((left, right) => right.createdAt.localeCompare(left.createdAt));

  const results = await memory.recall({
    query: "PR #1488 Neo4j UNWIND projection v2.1.586 checkpoint_complete sec-dev",
    limit: 3,
  });

  assert.equal(results[0]?.id, "pr-1488-artifact");
  assert.equal(results.some((record) => record.id === "fresh-graph-story"), false);
});

test("memory recall stays selective across a large recent noisy history", async () => {
  const memory = new SecurityMemoryStore(testConfig());
  const records = (memory as unknown as { inMemoryRecords: any[] }).inMemoryRecords;
  const now = Date.now();

  for (let index = 0; index < 260; index += 1) {
    records.push({
      id: `noisy-history-${index}`,
      kind: index % 2 === 0 ? "encounter_story" : "assistant_answer",
      topic: `Slack encounter: graph runtime health ${index}`,
      summary: "Prior answer discussed graph health, writer-github-audit ingest lag, and NATS stream failures.",
      details: "This is broad conversation memory and should not answer a specific Neo4j PR artifact question.",
      tags: ["story", "slack-question", "github-audit", "nats"],
      sourceKind: index % 2 === 0 ? "tool" : "assistant_answer",
      createdAt: new Date(now - index * 1000).toISOString(),
    });
  }
  records.push({
    id: "pr-1488-validation",
    kind: "investigation_note",
    topic: "PR #1488 archetype vulnerability projection validation",
    summary: "Batched Neo4j UNWIND upserts validated sec-dev image v2.1.586 for archetype vulnerability graph projection.",
    details: "checkpoint_complete=true; one-off task validated output before rolling the image.",
    tags: ["pr-1488", "archetype-vulnerability", "neo4j", "unwind"],
    createdAt: new Date(now - 30_000).toISOString(),
  });
  records.sort((left, right) => right.createdAt.localeCompare(left.createdAt));

  const results = await memory.recall({
    query: "archetype vulnerability PR #1488 Neo4j UNWIND v2.1.586 checkpoint_complete projection",
    limit: 6,
  });

  assert.equal(results[0]?.id, "pr-1488-validation");
  assert.equal(results.some((record) => record.id.startsWith("noisy-history-")), false);
});

test("memory recall builds graph and lineage DAG around source-backed memory", async () => {
  const memory = new SecurityMemoryStore(testConfig());
  const records = (memory as unknown as { inMemoryRecords: any[] }).inMemoryRecords;
  const now = Date.now();

  records.push({
    id: "fresh-assistant-echo",
    kind: "assistant_answer",
    topic: "PR #200 sec-dev deploy status",
    summary: "PR #200 is deployed live in sec-dev.",
    tags: ["slack-question"],
    sourceKind: "assistant_answer",
    promotionState: "transient",
    stalenessPolicy: "short_lived",
    entities: ["pr", "200", "sec-dev"],
    createdAt: new Date(now).toISOString(),
  });
  records.push({
    id: "source-verified-rollout-gap",
    kind: "investigation_note",
    topic: "PR #200 sec-dev deploy status",
    summary: "PR #200 is not deployed to sec-dev; ECS still shows the previous task definition.",
    details: "Verified against the ECS service and GitHub checks before answering.",
    tags: ["pr-200", "sec-dev", "ecs", "deploy"],
    sourceKind: "tool",
    sourceArtifacts: ["github-pr#200", "ecs-service/sec-dev/security"],
    verifiedBy: ["cerebro_code_github_checks", "ecs_describe_services"],
    verifiedAt: new Date(now - 60_000).toISOString(),
    promotionState: "promoted",
    stalenessPolicy: "durable",
    entities: ["pr", "200", "sec-dev", "ecs"],
    createdAt: new Date(now - 86_400_000).toISOString(),
  });
  records.sort((left, right) => right.createdAt.localeCompare(left.createdAt));

  const recalled = await memory.recallWithDiagnostics({
    query: "PR #200 sec-dev ECS deploy status",
    limit: 4,
  });
  const sourceResult = recalled.diagnostics.results.find((result) => result.id === "source-verified-rollout-gap");
  const assistantResult = recalled.diagnostics.results.find((result) => result.id === "fresh-assistant-echo");

  assert.equal(recalled.memories[0]?.id, "source-verified-rollout-gap");
  assert.equal(sourceResult?.quality, "source_verified");
  assert.equal(sourceResult?.freshness, "current");
  assert.ok((sourceResult?.trustScore ?? 0) > (assistantResult?.trustScore ?? 0));
  assert.equal(recalled.diagnostics.conflicts.length, 1);
  assert.match(recalled.diagnostics.warnings.join(" "), /conflicting state signals/i);
  assert.ok(recalled.diagnostics.memoryGraph.nodes.some((node) => node.kind === "source_artifact" && /ecs-service/.test(node.label)));
  assert.ok(recalled.diagnostics.memoryGraph.nodes.some((node) => node.kind === "verifier" && node.label === "ecs_describe_services"));
  assert.ok(recalled.diagnostics.lineageDag.edges.some((edge) => edge.relation === "supports_memory"));
  assert.ok(recalled.diagnostics.lineageDag.edges.some((edge) => edge.relation === "verified_memory"));
  assert.ok(recalled.diagnostics.lineageDag.edges.some((edge) => edge.relation === "recalled_for"));
  const dagOrder = new Map(recalled.diagnostics.lineageDag.topologicalOrder.map((id, index) => [id, index]));
  for (const edge of recalled.diagnostics.lineageDag.edges) {
    assert.ok((dagOrder.get(edge.from) ?? -1) <= (dagOrder.get(edge.to) ?? -1), `${edge.from} should precede ${edge.to}`);
  }
});

test("memory recall diagnostics report missing graph entities", async () => {
  const memory = new SecurityMemoryStore(testConfig());
  const records = (memory as unknown as { inMemoryRecords: any[] }).inMemoryRecords;
  const now = Date.now();

  records.push({
    id: "dev-runbook",
    kind: "runbook_note",
    topic: "Deployment runbook writer.dev.api",
    summary: "For writer.dev.api deploy checks, compare the ECS task definition with the GitHub release artifact.",
    tags: ["deploy", "ecs", "runbook"],
    promotionState: "promoted",
    stalenessPolicy: "durable",
    entities: ["writer.dev.api", "ecs"],
    createdAt: new Date(now).toISOString(),
  });

  const recalled = await memory.recallWithDiagnostics({
    query: "deployment runbook writer.prod.api",
    limit: 3,
  });

  assert.equal(recalled.memories[0]?.id, "dev-runbook");
  assert.deepEqual(recalled.diagnostics.coverage.missingEntities, ["writer.prod.api"]);
  assert.match(recalled.diagnostics.warnings.join(" "), /writer\.prod\.api/);
});

test("memory recall favors source-backed Infosec knowledge over generic incident notes", async () => {
  const memory = new SecurityMemoryStore(testConfig());
  const records = (memory as unknown as { inMemoryRecords: any[] }).inMemoryRecords;
  const now = Date.now();

  records.push({
    id: "generic-payments-note",
    kind: "investigation_note",
    topic: "Payments alert triage",
    summary: "A prior payments alert mentioned owner review and service criticality.",
    tags: ["payments", "alert"],
    promotionState: "candidate",
    stalenessPolicy: "until_reverified",
    createdAt: new Date(now).toISOString(),
  });
  records.push({
    id: "payments-asset-context",
    kind: "asset_context",
    topic: "Payments API asset context",
    summary: "payments-api is a Tier 0 production service that handles cardholder data and needs AppSec owner review for high-severity findings.",
    details: "Use this as routing context only; verify current findings and deployment state with live sources before answering.",
    tags: ["payments", "asset-context", "tier-0", "pci"],
    sourceKind: "tool",
    sourceArtifacts: ["service-catalog:payments-api", "data-classification:pci"],
    verifiedBy: ["service_catalog", "data_classification_registry"],
    verifiedAt: new Date(now - 60_000).toISOString(),
    promotionState: "promoted",
    stalenessPolicy: "until_reverified",
    entities: ["payments-api", "appsec", "pci"],
    scope: "service:payments-api",
    createdAt: new Date(now - 86_400_000).toISOString(),
  });
  records.sort((left, right) => right.createdAt.localeCompare(left.createdAt));

  const recalled = await memory.recallWithDiagnostics({
    query: "payments-api PCI Tier 0 AppSec owner context",
    limit: 3,
  });

  assert.equal(recalled.memories[0]?.id, "payments-asset-context");
  assert.equal(recalled.diagnostics.results[0]?.kind, "asset_context");
  assert.equal(recalled.diagnostics.results[0]?.quality, "source_verified");
  assert.equal(recalled.diagnostics.memoryGraph.sourceArtifactCount, 2);
});

test("memory recall diagnostics come from the LLM curator when configured", async () => {
  const curatorCalls: any[] = [];
  const memory = new SecurityMemoryStore(testConfig(), {
    curator: {
      curateWrite: async () => {
        throw new Error("unexpected write curation");
      },
      curateRecall: async (input: any) => {
        curatorCalls.push(input);
        return {
          queryIntent: "deploy validation status",
          selections: [{
            id: "specific-pr-validation",
            relevance: 0.97,
            reason: "This is the only memory tied to PR #1488, v2.1.586, and checkpoint_complete.",
          }],
          rejected: [{
            id: "fresh-encounter",
            reason: "This is broad runtime chatter without the PR artifact.",
          }],
        };
      },
      curateHygiene: async () => {
        throw new Error("unexpected hygiene curation");
      },
    },
  });
  const records = (memory as unknown as { inMemoryRecords: any[] }).inMemoryRecords;
  const now = Date.now();

  records.push({
    id: "fresh-encounter",
    kind: "encounter_story",
    topic: "Slack encounter: graph runtime chatter",
    summary: "A recent thread discussed graph health, runtime health, and NATS failures.",
    tags: ["story", "graph", "runtime-health"],
    sourceKind: "tool",
    promotionState: "transient",
    stalenessPolicy: "short_lived",
    createdAt: new Date(now).toISOString(),
  });
  records.push({
    id: "specific-pr-validation",
    kind: "investigation_note",
    topic: "PR #1488 Neo4j projection validation",
    summary: "PR #1488 validated batched Neo4j UNWIND projection on image v2.1.586 with checkpoint_complete=true.",
    details: "One-off task validated sec-dev before the service rollout.",
    tags: ["pr-1488", "neo4j", "unwind", "sec-dev"],
    sourceArtifacts: ["pr#1488", "v2.1.586", "checkpoint_complete=true"],
    promotionState: "promoted",
    stalenessPolicy: "durable",
    createdAt: new Date(now - 120_000).toISOString(),
  });
  records.sort((left, right) => right.createdAt.localeCompare(left.createdAt));

  const recalled = await memory.recallWithDiagnostics({
    query: "PR #1488 Neo4j UNWIND projection v2.1.586 checkpoint_complete sec-dev",
    limit: 3,
  });

  assert.equal(recalled.memories[0]?.id, "specific-pr-validation");
  assert.equal(recalled.diagnostics.queryIntent, "deploy validation status");
  assert.equal(recalled.diagnostics.returnedCount, 1);
  assert.equal(recalled.diagnostics.suppressedByIntentCount, 1);
  assert.equal(recalled.diagnostics.results[0]?.score, 0.97);
  assert.match(recalled.diagnostics.results[0]?.matchReason ?? "", /only memory tied to PR #1488/);
  assert.equal(recalled.diagnostics.results[0]?.promotionState, "promoted");
  assert.equal(curatorCalls[0]?.candidates.length, 2);
});

test("memory recall falls back to lexical diagnostics when curator output is invalid", async () => {
  const memory = new SecurityMemoryStore(testConfig(), {
    curator: {
      curateWrite: async () => {
        throw new Error("unexpected write curation");
      },
      curateRecall: async () => {
        throw new Error("Pi memory curator did not return valid memory recall decision JSON.");
      },
      curateHygiene: async () => {
        throw new Error("unexpected hygiene curation");
      },
    },
  });
  const records = (memory as unknown as { inMemoryRecords: any[] }).inMemoryRecords;
  records.push({
    id: "tool-gap",
    kind: "runbook_note",
    topic: "EvidenceCAS tool gap",
    summary: "Check EvidenceCAS status before resolving protected refs.",
    tags: ["evidencecas", "tools"],
    promotionState: "promoted",
    stalenessPolicy: "durable",
    createdAt: new Date().toISOString(),
  });

  const recalled = await memory.recallWithDiagnostics({
    query: "EvidenceCAS protected refs",
    limit: 3,
  });

  assert.equal(recalled.memories[0]?.id, "tool-gap");
  assert.match(recalled.diagnostics.warnings[0] ?? "", /using lexical memory recall/i);
  assert.match(recalled.diagnostics.queryIntent, /lexical recall/);
});

test("memory promotion gates learning docs until a record is explicitly promoted", async () => {
  const directory = mkdtempSync(join(tmpdir(), "cerebro-memory-promotion-"));
  try {
    const memory = new SecurityMemoryStore(testConfig({
      learning: {
        tableName: undefined,
        workingMemoryDir: directory,
        learningDocsDir: join(directory, "docs"),
      },
    }));

    const record = await memory.remember({
      kind: "triage_outcome",
      topic: "PR #1488 sec-dev rollout gap",
      summary: "The validation image was built, but sec-dev services still needed the rollout step.",
      details: "Verified in Slack and ECS task metadata.",
      tags: ["pr-1488", "sec-dev", "deploy"],
      classification: "needs_context",
      confidence: 0.92,
      promotionState: "candidate",
      stalenessPolicy: "until_reverified",
      sourceArtifacts: ["pr#1488", "v2.1.586"],
    });

    assert.ok(record);
    assert.equal(memory.readLearningDocs("investigations")[0]?.entries.length, 0);

    const promoted = await memory.promoteToLearningDocs({ id: record.id });
    assert.equal(promoted.promoted, true);
    assert.equal(promoted.learningDoc?.target, "investigations");
    assert.equal(record.promotionState, "promoted");
    assert.equal(record.stalenessPolicy, "durable");
    assert.equal(memory.readLearningDocs("investigations")[0]?.entries[0]?.topic, "PR #1488 sec-dev rollout gap");
  } finally {
    rmSync(directory, { recursive: true, force: true });
  }
});

test("memory remember stores only LLM-curated valuable records when curator is configured", async () => {
  const decisions = [
    {
      shouldStore: false,
      reason: "One-off deploy cheerleading without reusable evidence.",
    },
    {
      shouldStore: true,
      reason: "Reusable deployment verification lesson.",
      kind: "runbook_note",
      topic: "Deploy verification after one-off validation",
      summary: "After validating an image with a one-off task, verify the running ECS service task definition before calling the deploy live.",
      details: "Current-state claims still require source checks.",
      tags: ["deploy", "ecs"],
      confidence: 0.94,
      sourceKind: "tool",
      entities: ["pr#1488", "ecs"],
      sourceArtifacts: ["pr#1488", "sha-5a62156"],
      verifiedBy: ["github_actions", "ecs_describe_services"],
      verifiedAt: "2026-06-27T19:36:22.000Z",
      stalenessPolicy: "durable",
      promotionState: "promoted",
    },
  ] as any[];
  const memory = new SecurityMemoryStore(testConfig(), {
    curator: {
      curateWrite: async () => decisions.shift(),
      curateRecall: async () => {
        throw new Error("unexpected recall curation");
      },
      curateHygiene: async () => {
        throw new Error("unexpected hygiene curation");
      },
    },
  });

  const rejected = await memory.remember({
    kind: "assistant_answer",
    topic: "Great result",
    summary: "Great result on PR #1488.",
    tags: ["slack-question"],
  });
  const stored = await memory.remember({
    kind: "assistant_answer",
    topic: "Great result",
    summary: "Great result on PR #1488.",
    tags: ["slack-question"],
  });

  assert.equal(rejected, undefined);
  assert.equal(stored?.kind, "runbook_note");
  assert.equal(stored?.topic, "Deploy verification after one-off validation");
  assert.equal(stored?.promotionState, "promoted");
  assert.deepEqual(stored?.entities, ["pr#1488", "ecs"]);
  assert.deepEqual(stored?.sourceArtifacts, ["pr#1488", "sha-5a62156"]);
});

test("memory remember rejects incomplete LLM store decisions", async () => {
  const memory = new SecurityMemoryStore(testConfig(), {
    curator: {
      curateWrite: async () => ({
        shouldStore: true,
        reason: "Useful, but missing staleness and promotion fields.",
        kind: "runbook_note",
        topic: "Deploy verification",
        summary: "Verify the running ECS task definition after rollout.",
      }),
      curateRecall: async () => {
        throw new Error("unexpected recall curation");
      },
      curateHygiene: async () => {
        throw new Error("unexpected hygiene curation");
      },
    },
  });

  await assert.rejects(
    () => memory.remember({
      kind: "assistant_answer",
      topic: "Deploy status",
      summary: "Deploy is done.",
    }),
    /incomplete store decision/,
  );
});

test("memory curator parsing fails closed instead of using fallbacks", () => {
  const parsed = parseCuratedMemoryWriteDecision('{"should_store":true,"reason":"source-backed asset context","kind":"asset_context","topic":"Payments API","summary":"payments-api is a Tier 0 production service.","source_artifacts":["service-catalog:payments-api"],"verified_by":["service_catalog"],"staleness_policy":"until_reverified","promotion_state":"promoted"}');
  assert.equal(parsed.kind, "asset_context");
  const connector = parseCuratedMemoryWriteDecision('{"should_store":true,"reason":"source-backed connector context","kind":"connector_context","topic":"Prisma Cloud GitHub connector","summary":"Use the Prisma Cloud GitHub connector source page for setup details.","source_artifacts":["prisma-cloud-docs:docs/en/enterprise-edition/content-collections/application-security/get-started/connect-code-and-build-providers/code-repositories/add-github.adoc"],"verified_by":["prisma_cloud_docs_repo"],"staleness_policy":"until_reverified","promotion_state":"promoted"}');
  assert.equal(connector.kind, "connector_context");
  const operatorDecision = parseCuratedMemoryWriteDecision('{"should_store":true,"reason":"verified operator decision","kind":"operator_decision","topic":"Finding F-12","summary":"Resolve F-12 after deployment verification.","source_artifacts":["finding:F-12","deploy:sha-5a62156"],"verified_by":["operator_decision_ledger"],"staleness_policy":"durable","promotion_state":"candidate"}');
  assert.equal(operatorDecision.kind, "operator_decision");
  const operatorCorrection = parseCuratedMemoryWriteDecision('{"should_store":true,"reason":"verified replacement","kind":"operator_correction","topic":"Finding F-12","summary":"Finding F-12 is resolved.","source_artifacts":["finding:F-12"],"verified_by":["finding_lookup"],"staleness_policy":"until_reverified","promotion_state":"candidate"}');
  assert.equal(operatorCorrection.kind, "operator_correction");

  assert.throws(
    () => parseCuratedMemoryRecallDecision('Here is JSON: {"query_intent":"deploy status","selections":[],"rejected":[]}'),
    /valid memory recall decision JSON/,
  );
  assert.throws(
    () => parseCuratedMemoryRecallDecision('{"selections":[],"rejected":[]}'),
    /query_intent is required/,
  );
  assert.throws(
    () => parseCuratedMemoryRecallDecision('{"query_intent":"deploy status","selections":[{"id":"a","relevance":1.2,"reason":"too high"}],"rejected":[]}'),
    /relevance must be between 0 and 1/,
  );
  assert.throws(
    () => parseCuratedMemoryWriteDecision('{"should_store":true,"reason":"x","kind":"runbook_note","topic":"Deploy","summary":" ","staleness_policy":"durable","promotion_state":"promoted"}'),
    /summary is required/,
  );
});

test("memory hygiene expires records selected by the LLM curator", async () => {
  const memory = new SecurityMemoryStore(testConfig(), {
    curator: {
      curateWrite: async () => {
        throw new Error("unexpected write curation");
      },
      curateRecall: async () => {
        throw new Error("unexpected recall curation");
      },
      curateHygiene: async () => ({
        expire: [{ id: "assistant-echo", reason: "Assistant echo no longer useful." }],
        keep: [{ id: "durable-lesson", reason: "Still useful runbook context." }],
      }),
    },
  });
  const records = (memory as unknown as { inMemoryRecords: any[] }).inMemoryRecords;
  const now = new Date("2026-06-27T19:40:00.000Z");
  records.push({
    id: "assistant-echo",
    kind: "assistant_answer",
    topic: "Old answer",
    summary: "Old answer.",
    tags: ["slack-question"],
    createdAt: "2026-06-01T00:00:00.000Z",
  });
  records.push({
    id: "durable-lesson",
    kind: "runbook_note",
    topic: "Deploy verification",
    summary: "Verify ECS task definition after rollout.",
    tags: ["deploy"],
    createdAt: "2026-06-01T00:00:00.000Z",
  });

  const result = await memory.runHygiene({ dryRun: false, now });

  assert.equal(result.checked, 2);
  assert.equal(result.expired, 1);
  assert.equal(records.find((record) => record.id === "assistant-echo")?.expiresAt, now.toISOString());
  assert.equal(records.find((record) => record.id === "durable-lesson")?.expiresAt, undefined);
});

test("memory hygiene expires stale transient records and duplicate rows", async () => {
  const memory = new SecurityMemoryStore(testConfig());
  const records = (memory as unknown as { inMemoryRecords: any[] }).inMemoryRecords;
  const now = new Date("2026-06-27T18:00:00.000Z");

  records.push({
    id: "duplicate-kept",
    kind: "assistant_answer",
    topic: "Slack question: deployment",
    summary: "Deploy status answer.",
    tags: ["slack-question"],
    contentHash: "hash-1",
    promotionState: "transient",
    stalenessPolicy: "short_lived",
    createdAt: "2026-06-20T18:00:00.000Z",
  });
  records.push({
    id: "duplicate-expired",
    kind: "assistant_answer",
    topic: "Slack question: deployment",
    summary: "Deploy status answer.",
    tags: ["slack-question"],
    contentHash: "hash-1",
    promotionState: "transient",
    stalenessPolicy: "short_lived",
    createdAt: "2026-06-19T18:00:00.000Z",
  });
  records.push({
    id: "stale-transient",
    kind: "assistant_answer",
    topic: "Old assistant answer",
    summary: "Old answer that should age out.",
    tags: ["slack-question"],
    contentHash: "hash-2",
    promotionState: "transient",
    stalenessPolicy: "short_lived",
    createdAt: "2026-05-20T18:00:00.000Z",
  });
  records.push({
    id: "durable-kept",
    kind: "investigation_note",
    topic: "Durable lesson",
    summary: "Durable promoted lesson.",
    tags: ["runbook"],
    contentHash: "hash-3",
    promotionState: "promoted",
    stalenessPolicy: "durable",
    createdAt: "2026-05-01T18:00:00.000Z",
  });

  const dryRun = await memory.runHygiene({ dryRun: true, now });
  assert.equal(dryRun.expired, 2);
  assert.equal(records.some((record) => record.expiresAt), false);

  const result = await memory.runHygiene({ dryRun: false, now });
  assert.equal(result.expired, 2);
  assert.equal(result.duplicateExpired, 1);
  assert.equal(result.staleTransientExpired, 1);
  assert.equal(records.find((record) => record.id === "duplicate-expired")?.expiresAt, now.toISOString());
  assert.equal(records.find((record) => record.id === "stale-transient")?.expiresAt, now.toISOString());
  assert.equal(records.find((record) => record.id === "durable-kept")?.expiresAt, undefined);
});
