import assert from "node:assert/strict";
import test from "node:test";
import {
  CompanyLibraryStore,
  normalizeCompanyLibraryRecord,
} from "../src/learning/company-library.js";
import { CompanyLibraryCompoundingService } from "../src/learning/company-library-compounding.js";
import { CompanyLibraryCurator, parseCompanyLibraryRecords } from "../src/learning/company-library-curator.js";
import type { SecurityMemoryRecord } from "../src/learning/memory-types.js";
import { testConfig } from "./fixtures.js";

test("company librarian accepts only cited input memories and derives source receipts", () => {
  const records = parseCompanyLibraryRecords(JSON.stringify({
    records: [{
      domain_key: "customer-security-intake",
      title: "Customer security intake",
      summary: "Route one question and a full questionnaire through different intake paths.",
      principles: ["Match the intake path to request size."],
      procedures: ["One question -> quick-answer path; multiple questions -> questionnaire workflow."],
      ownership: ["GRC -> questionnaire response"],
      decisions: [],
      exceptions: [],
      contradictions: [],
      open_questions: ["Confirm the current service-desk route."],
      claims: [{
        text: "One-off and bulk requests use different intake paths.",
        basis: "observed",
        source_memory_ids: ["memory-1", "invented-id"],
      }],
      confidence: 0.8,
    }],
  }), "dossier", [{
    id: "memory-1",
    artifacts: ["slack:CSEC:1.1"],
    channelIds: ["CSEC"],
  }]);

  assert.equal(records.length, 1);
  assert.deepEqual(records[0]?.sourceMemoryIds, ["memory-1"]);
  assert.deepEqual(records[0]?.sourceArtifacts, ["slack:CSEC:1.1"]);
  assert.deepEqual(records[0]?.channelIds, ["CSEC"]);
  assert.equal(records[0]?.status, "candidate");
  assert.equal(records[0]?.stalenessPolicy, "until_reverified");
});

test("company librarian rejects an uncited synthesized claim", () => {
  assert.throws(() => parseCompanyLibraryRecords(JSON.stringify({
    records: [{
      domain_key: "ownership",
      title: "Ownership",
      summary: "Uncited ownership claim.",
      claims: [{ text: "A team owns this.", basis: "inferred", source_memory_ids: ["invented"] }],
      confidence: 0.3,
    }],
  }), "dossier", [{ id: "memory-1" }]), /no valid source memory ids/);
});

test("company librarian requires an Opus orchestrator even with an injected completion", async () => {
  const config = testConfig({ triage: { pi: { model: "baseline-model" } } });
  const curator = new CompanyLibraryCurator(config, {
    complete: async () => JSON.stringify({ records: [] }),
  });

  await assert.rejects(curator.synthesizeBatch([memoryRecord("memory-1", "Ownership")]), /requires a configured Opus model/);
});

test("company library stores versioned records, searches operating detail, and leases one writer", async () => {
  const store = new CompanyLibraryStore(testConfig());
  const dossier = libraryRecord("dossier", "release-verification", "Release verification", "Verify the running task definition before reporting completion.");
  const first = await store.put(dossier);
  const second = await store.put({ ...dossier, summary: "Verify the running image and task definition before reporting completion.", updatedAt: "2026-07-15T02:00:00.000Z" });

  assert.equal(first.version, 1);
  assert.equal(second.version, 2);
  assert.equal((await store.search("running image", 2))[0]?.domainKey, "release-verification");
  assert.equal((await store.read("release-verification"))?.version, 2);

  const firstLease = await store.acquireLease("worker-a", new Date("2026-07-15T00:00:00.000Z"), 60_000);
  const blockedLease = await store.acquireLease("worker-b", new Date("2026-07-15T00:00:30.000Z"), 60_000);
  await store.releaseLease("worker-a");
  const nextLease = await store.acquireLease("worker-b", new Date("2026-07-15T00:00:31.000Z"), 60_000);
  assert.equal(firstLease, "worker-a");
  assert.equal(blockedLease, undefined);
  assert.equal(nextLease, "worker-b");
});

test("company library publishes snapshot rows before the active pointer transaction", async () => {
  const commands: any[] = [];
  const store = new CompanyLibraryStore(testConfig({ learning: { tableName: "learning" } }), {
    client: { send: async (command: any) => {
      commands.push(command);
      if (command.constructor.name === "GetCommand") return {};
      if (command.constructor.name === "QueryCommand") return { Items: [] };
      return {};
    } },
  });
  const completedAt = "2026-07-15T02:00:00.000Z";
  const receipt = {
    runId: "generation-1",
    status: "completed" as const,
    startedAt: "2026-07-15T01:00:00.000Z",
    completedAt,
    sourceRecords: 2,
    batchesProcessed: 1,
    batchesReused: 0,
    dossiers: 1,
    theses: 1,
  };

  await store.publishSnapshot("generation-1", [
    libraryRecord("dossier", "procedure", "Procedure", "Use the current procedure."),
    libraryRecord("thesis", "procedure-pattern", "Procedure pattern", "The team verifies the procedure."),
  ], {
    lastSourceCreatedAt: "2026-07-15T01:30:00.000Z",
    lastRunId: "generation-1",
    lastCompletedAt: completedAt,
  }, receipt);

  const snapshotPuts = commands.filter((command) => command.constructor.name === "PutCommand");
  const transactionIndex = commands.findIndex((command) => command.constructor.name === "TransactWriteCommand");
  assert.equal(snapshotPuts.length, 2);
  assert.ok(snapshotPuts.every((command) => command.input.Item.pk === "tenant#writer#company-library#snapshot#generation-1"));
  assert.ok(snapshotPuts.every((command) => command.input.Item.generationId === "generation-1"));
  assert.equal(transactionIndex, commands.length - 1);
  assert.equal(commands[transactionIndex].input.TransactItems[0].Update.ConditionExpression, "leaseOwner = :generationId");
  assert.equal(commands[transactionIndex].input.TransactItems[1].Put.Item.status, "completed");
});

test("company library compounding reuses source batches and produces dossiers plus theses", async () => {
  const config = testConfig();
  const store = new CompanyLibraryStore(config);
  const sources = [memoryRecord("memory-1", "Customer questionnaires"), memoryRecord("memory-2", "Security document disclosure")];
  const curator = {
    synthesizeBatch: async (records: SecurityMemoryRecord[]) => [libraryRecord(
      "dossier",
      "customer-security-requests",
      "Customer security requests",
      "Use bounded intake and disclosure paths.",
      records.map((record) => record.id),
    )],
    mergeDossiers: async (records: ReturnType<typeof libraryRecord>[]) => records,
    synthesizeTheses: async (records: ReturnType<typeof libraryRecord>[]) => [libraryRecord(
      "thesis",
      "evidence-before-assurance",
      "Evidence before assurance",
      "The team routes assurance through controlled evidence artifacts.",
      records.flatMap((record) => record.sourceMemoryIds),
    )],
  };
  const service = new CompanyLibraryCompoundingService(
    config,
    { recordsBySourceKind: async () => sources },
    store,
    curator,
  );

  const first = await service.run({ force: true, minNewRecords: 1 });
  const second = await service.run({ force: true, minNewRecords: 1 });
  const library = await store.list();

  assert.equal(first.status, "completed");
  assert.equal(first.batchesProcessed, 1);
  assert.equal(first.dossiers, 1);
  assert.equal(first.theses, 1);
  assert.equal(second.batchesProcessed, 0);
  assert.equal(second.batchesReused, 1);
  assert.equal(library.length, 2);
  assert.ok(library.every((record) => record.version === 2));
  assert.equal((await store.state()).activeGenerationId, second.runId);
  assert.deepEqual(new Set(library.map((record) => record.kind)), new Set(["dossier", "thesis"]));
  assert.deepEqual(library.find((record) => record.kind === "thesis")?.sourceMemoryIds.sort(), ["memory-1", "memory-2"]);
});

test("company library exposes one active generation and retains prior snapshots", async () => {
  const config = testConfig();
  const store = new CompanyLibraryStore(config);
  let sourcePass = 0;
  let pass = 0;
  const service = new CompanyLibraryCompoundingService(
    config,
    { recordsBySourceKind: async () => {
      sourcePass += 1;
      return [memoryRecord(`memory-${sourcePass}`, "Company procedure")];
    } },
    store,
    {
      synthesizeBatch: async () => {
        pass += 1;
        return [libraryRecord(
          "dossier",
          pass === 1 ? "old-procedure" : "current-procedure",
          pass === 1 ? "Old procedure" : "Current procedure",
          pass === 1 ? "Use the old route." : "Use the current route.",
        )];
      },
      mergeDossiers: async (records) => [records.at(-1)!],
      synthesizeTheses: async (records) => [libraryRecord(
        "thesis",
        `${records[0]!.domainKey}-pattern`,
        "Procedure pattern",
        `The operating pattern follows ${records[0]!.domainKey}.`,
      )],
    },
  );

  const first = await service.run({ force: true, minNewRecords: 1 });
  const second = await service.run({ force: true, minNewRecords: 1 });
  const active = await store.list();
  const prior = await store.listGeneration(first.runId);

  assert.equal((await store.state()).activeGenerationId, second.runId);
  assert.deepEqual(active.map((record) => record.domainKey).sort(), ["current-procedure", "current-procedure-pattern"]);
  assert.equal(await store.read("old-procedure"), undefined);
  assert.deepEqual(prior.map((record) => record.domainKey).sort(), ["old-procedure", "old-procedure-pattern"]);
});

test("company library keeps the active generation when recursive merging loses every dossier", async () => {
  const config = testConfig();
  const store = new CompanyLibraryStore(config);
  let sourcePass = 0;
  const service = new CompanyLibraryCompoundingService(
    config,
    { recordsBySourceKind: async () => {
      sourcePass += 1;
      const count = sourcePass === 1 ? 1 : 11;
      return Array.from({ length: count }, (_value, index) => memoryRecord(`memory-${index + 1}`, `Domain ${index + 1}`));
    } },
    store,
    {
      synthesizeBatch: async (records) => records.map((record) => libraryRecord(
        "dossier",
        `domain-${record.id}`,
        `Domain ${record.id}`,
        `${record.id} operating detail.`,
        [record.id],
      )),
      mergeDossiers: async () => [],
      synthesizeTheses: async () => [],
    },
  );

  const first = await service.run({ force: true, minNewRecords: 1 });
  await assert.rejects(service.run({ force: true, minNewRecords: 1 }), /produced no canonical dossiers/);

  assert.equal((await store.state()).activeGenerationId, first.runId);
  assert.deepEqual((await store.list()).map((record) => record.domainKey), ["domain-memory-1"]);
});

test("company library compounding carries contradictions across source batches", async () => {
  const config = testConfig();
  const store = new CompanyLibraryStore(config);
  const sources = Array.from({ length: 25 }, (_value, index) => memoryRecord(`memory-${index + 1}`, `Ownership statement ${index + 1}`));
  let sourceBatch = 0;
  const service = new CompanyLibraryCompoundingService(
    config,
    { recordsBySourceKind: async () => sources },
    store,
    {
      synthesizeBatch: async (records) => {
        sourceBatch += 1;
        const record = libraryRecord(
          "dossier",
          "service-ownership",
          "Service ownership",
          "Ownership changed across the observed period.",
          records.map((item) => item.id),
        );
        return [{ ...record, contradictions: [`Batch ${sourceBatch} records a different owner.`] }];
      },
      mergeDossiers: async (records) => records,
      synthesizeTheses: async () => [],
    },
  );

  const result = await service.run({ force: true, minNewRecords: 1 });
  const dossier = await store.read("service-ownership");

  assert.equal(result.batchesProcessed, 2);
  assert.deepEqual(dossier?.contradictions, [
    "Batch 1 records a different owner.",
    "Batch 2 records a different owner.",
  ]);
  assert.equal(dossier?.sourceMemoryIds.length, 25);
});

test("company library compounding bounds recursive Opus merges to six dossiers", async () => {
  const config = testConfig();
  const store = new CompanyLibraryStore(config);
  const sources = Array.from({ length: 25 }, (_value, index) => memoryRecord(`memory-${index + 1}`, `Domain ${index + 1}`));
  const mergeSizes: number[] = [];
  const service = new CompanyLibraryCompoundingService(
    config,
    { recordsBySourceKind: async () => sources },
    store,
    {
      synthesizeBatch: async (records) => records.slice(0, 12).map((record) => libraryRecord(
        "dossier",
        `domain-${record.id}`,
        `Domain ${record.id}`,
        `${record.id} operating detail.`,
        [record.id],
      )),
      mergeDossiers: async (records) => {
        mergeSizes.push(records.length);
        const sourceMemoryIds = records.flatMap((record) => record.sourceMemoryIds);
        return [libraryRecord(
          "dossier",
          `merged-${mergeSizes.length}`,
          "Merged operating domain",
          "Related operating details are reconciled.",
          sourceMemoryIds,
        )];
      },
      synthesizeTheses: async () => [],
    },
  );

  const result = await service.run({ force: true, minNewRecords: 1 });

  assert.equal(result.dossiers, 1);
  assert.deepEqual(mergeSizes, [6, 6, 3]);
  assert.ok(mergeSizes.every((size) => size <= 6));
});

test("company library stops recursion after a low-yield merge pass", async () => {
  const config = testConfig();
  const store = new CompanyLibraryStore(config);
  const sources = Array.from({ length: 7 }, (_value, index) => memoryRecord(`memory-${index + 1}`, `Domain ${index + 1}`));
  const mergeSizes: number[] = [];
  const service = new CompanyLibraryCompoundingService(
    config,
    { recordsBySourceKind: async () => sources },
    store,
    {
      synthesizeBatch: async (records) => records.map((record) => libraryRecord(
        "dossier",
        `domain-${record.id}`,
        `Domain ${record.id}`,
        `${record.id} operating detail.`,
        [record.id],
      )),
      mergeDossiers: async (records) => {
        mergeSizes.push(records.length);
        return records.slice(0, 5);
      },
      synthesizeTheses: async () => [],
    },
  );

  const result = await service.run({ force: true, minNewRecords: 1 });

  assert.equal(result.dossiers, 6);
  assert.deepEqual(mergeSizes, [6]);
});

function memoryRecord(id: string, topic: string): SecurityMemoryRecord {
  const numericId = Number(id.replace(/\D/g, "")) || 1;
  return {
    id,
    kind: "runbook_note",
    topic,
    summary: `${topic} operating detail.`,
    tags: ["slack-channel-learning"],
    channelId: "CSEC",
    sourceTs: `1.${numericId}`,
    sourceKind: "slack_channel",
    sourceArtifacts: [`slack:CSEC:1.${numericId}`],
    stalenessPolicy: "until_reverified",
    promotionState: "candidate",
    createdAt: new Date(Date.parse("2026-07-15T00:00:00.000Z") + numericId * 60_000).toISOString(),
  };
}

function libraryRecord(
  kind: "dossier" | "thesis",
  domainKey: string,
  title: string,
  summary: string,
  sourceMemoryIds = ["memory-1"],
) {
  return normalizeCompanyLibraryRecord({
    kind,
    domainKey,
    title,
    summary,
    principles: ["Use source-backed operating context."],
    procedures: ["Request -> inspect source -> act -> verify outcome."],
    ownership: [],
    decisions: [],
    exceptions: [],
    contradictions: [],
    openQuestions: [],
    claims: [{
      text: summary,
      basis: kind === "thesis" ? "inferred" : "observed",
      sourceMemoryIds,
      sourceArtifacts: sourceMemoryIds.map((id) => `slack:CSEC:${id}`),
    }],
    sourceMemoryIds,
    sourceArtifacts: sourceMemoryIds.map((id) => `slack:CSEC:${id}`),
    channelIds: ["CSEC"],
    confidence: 0.8,
  }, new Date("2026-07-15T01:00:00.000Z"));
}
