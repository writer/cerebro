import assert from "node:assert/strict";
import test from "node:test";
import { runtimePullRequestBody } from "../src/code/runtime-code-github-client.js";
import type { RuntimeCodePrInput } from "../src/code/runtime-code-types.js";
import { InMemoryImprovementArtifactStore } from "../src/improvement/artifacts.js";
import { ImprovementControlPlane } from "../src/improvement/control-plane.js";
import { InMemoryImprovementJobQueue } from "../src/improvement/queue.js";
import { CandidateAuthorPolicyError } from "../src/improvement/candidate-author.js";
import { initialImprovementEvent, newImprovementRun, transitionImprovementRun } from "../src/improvement/state-machine.js";
import { InMemoryImprovementRunStore } from "../src/improvement/store.js";
import type { ImprovementArtifact, ImprovementCandidateReceipt, ImprovementCiReceipt, ImprovementEvent, ImprovementJob, ImprovementRun, ImprovementSignal, SignedImprovementDelegation } from "../src/improvement/types.js";
import { ImprovementWorker } from "../src/improvement/worker.js";

test("author and verifier workcells reject jobs outside their authority", async () => {
  const authorConfig = { ...workerConfig(), lane: "author" as const };
  const author = new ImprovementWorker(authorConfig, {
    pullRequests: candidatePullRequests(async () => ({ ok: false })),
    candidateAuthor: { author: async () => { throw new Error("unused"); } },
  });
  await assert.rejects(author.handle({ schemaVersion: 1, kind: "sweep_stale_runs" }), /author workcell cannot execute sweep_stale_runs/);

  const verifierConfig = { ...workerConfig(), lane: "verifier" as const, code: { ...workerConfig().code, enabled: false, githubApp: undefined } };
  const verifier = new ImprovementWorker(verifierConfig);
  await assert.rejects(verifier.handle({
    schemaVersion: 1,
    kind: "author_candidate",
    runId: "improvement-0123456789abcdef01234567",
    generation: 1,
    inputSignalShas: ["a".repeat(64)],
    baseRef: "main",
  }), /verifier workcell cannot execute author_candidate/);
});

test("author workcells reject unsigned jobs and keep shadow delegations side-effect free", async () => {
  const store = new InMemoryImprovementRunStore();
  const artifacts = new InMemoryImprovementArtifactStore();
  const now = new Date("2026-07-14T18:00:00.000Z");
  const signalArtifact = await artifacts.putJson("seed", "signal", signal(), now);
  const observed = newImprovementRun(signal(), signalArtifact, now, 168);
  const queued = transitionImprovementRun(observed, {
    type: "author_requested",
    inputSignalShas: [signalArtifact.sha256],
    repo: "WriterInternal/cerebro-slack-companion",
    baseRef: "main",
  }, { now, actor: "companion" }).run;
  await store.create(queued, { ...initialImprovementEvent(observed), toStatus: "queued", type: "queued" });
  let authorCalls = 0;
  let signatureValid = false;
  const config = { ...workerConfig(), lane: "author" as const };
  const worker = new ImprovementWorker(config, {
    store,
    artifacts,
    kms: { send: async () => ({ SignatureValid: signatureValid }) },
    now: () => now,
    pullRequests: candidatePullRequests(async () => ({ ok: false })),
    candidateAuthor: { author: async () => { authorCalls += 1; throw new Error("must not run"); } },
  });
  const baseJob = {
    schemaVersion: 1 as const,
    kind: "author_candidate" as const,
    runId: queued.id,
    generation: 1,
    inputSignalShas: [signalArtifact.sha256],
    repo: "WriterInternal/cerebro-slack-companion",
    baseRef: "main",
  };

  await assert.rejects(worker.handle(baseJob), /require a signed delegation manifest/);
  await assert.rejects(worker.handle({ ...baseJob, delegation: signedDelegation(queued, signalArtifact.sha256) }), /Delegation signature is invalid/);
  signatureValid = true;
  await worker.handle({ ...baseJob, delegation: signedDelegation(queued, signalArtifact.sha256, "shadow") });

  assert.equal(authorCalls, 0);
  assert.equal((await store.get(queued.id))?.status, "blocked");
  assert.match((await store.get(queued.id))?.blockers[0] ?? "", /delegation_shadow_no_execution/);
});

test("active delegation binds the author to its exact source and draft budget before GitHub write", async () => {
  const store = new InMemoryImprovementRunStore();
  const artifacts = new InMemoryImprovementArtifactStore();
  const now = new Date("2026-07-14T18:00:00.000Z");
  const signalArtifact = await artifacts.putJson("seed", "signal", signal(), now);
  const observed = newImprovementRun(signal(), signalArtifact, now, 168);
  const queued = transitionImprovementRun(observed, {
    type: "author_requested",
    inputSignalShas: [signalArtifact.sha256],
    repo: "WriterInternal/cerebro-slack-companion",
    baseRef: "main",
  }, { now, actor: "companion" }).run;
  await store.create(queued, { ...initialImprovementEvent(observed), toStatus: "queued", type: "queued" });
  const writes: RuntimeCodePrInput[] = [];
  const worker = new ImprovementWorker({ ...workerConfig(), lane: "author" as const }, {
    store,
    artifacts,
    kms: { send: async () => ({ SignatureValid: true }) },
    now: () => now,
    pullRequests: candidatePullRequests(async (input) => {
      writes.push(input);
      return candidatePullRequestResult(input, "a");
    }),
    candidateAuthor: {
      author: async () => authoredCandidate(queued.id, "WriterInternal/cerebro-slack-companion", "main"),
    },
  });

  await worker.handle({
    schemaVersion: 1,
    kind: "author_candidate",
    runId: queued.id,
    generation: 1,
    inputSignalShas: [signalArtifact.sha256],
    repo: "WriterInternal/cerebro-slack-companion",
    baseRef: "main",
    delegation: signedDelegation(queued, signalArtifact.sha256, "active"),
  });

  assert.equal(writes.length, 1);
  assert.equal(writes[0]?.expectedBaseSha, "d".repeat(40));
  assert.equal(writes[0]?.draft, true);
  assert.equal((await store.get(queued.id))?.status, "candidate_ready");
});

test("isolated worker opens a bounded draft candidate and records its durable receipt", async () => {
  const store = new InMemoryImprovementRunStore();
  const artifacts = new InMemoryImprovementArtifactStore();
  const now = new Date("2026-07-14T18:00:00.000Z");
  const signalArtifact = await artifacts.putJson("seed", "signal", signal(), now);
  const observed = newImprovementRun(signal(), signalArtifact, now, 168);
  const queuedResult = transitionImprovementRun(observed, {
    type: "author_requested",
    inputSignalShas: [signalArtifact.sha256],
    repo: "WriterInternal/cerebro-slack-companion",
    baseRef: "main",
  }, { now, actor: "companion" });
  await store.create(queuedResult.run, { ...initialImprovementEvent(observed), toStatus: "queued", type: "queued" });
  const created: unknown[] = [];
  const worker = new ImprovementWorker(workerConfig(), {
    store,
    artifacts,
    pullRequests: {
      sourceList: async () => ({ ok: true, resolved_ref: "a".repeat(40), entries: [] }),
      sourceRead: async () => ({ ok: true, resolved_ref: "a".repeat(40), files: [] }),
      createPullRequest: async (input) => {
        created.push(input);
        return {
          ok: true,
          repo: "WriterInternal/cerebro-slack-companion",
          branch: "cerebro/improvement/run-1",
          pull_request: {
            number: 121,
            url: "https://github.com/WriterInternal/cerebro-slack-companion/pull/121",
            head_sha: "a".repeat(40),
          },
        };
      },
      pullRequestStatus: async () => ({
        ok: true,
        pull_request: { number: 121, head_sha: "a".repeat(40) },
        checks: { summary: { state: "passed", passed: 1, failed: 0, pending: 0 } },
      }),
    },
  });

  await worker.handle({
    schemaVersion: 1,
    kind: "open_candidate_pr",
    runId: queuedResult.run.id,
    generation: 1,
    inputSignalShas: [signalArtifact.sha256],
    pullRequest: {
      repo: "WriterInternal/cerebro-slack-companion",
      title: "Repair action closure",
      files: [{ path: "docs/self-repair/action-closure.md", content: "# Repair\n" }],
      branch: "cerebro/improvement/run-1",
      base: "main",
      expectedBaseSha: "d".repeat(40),
      draft: true,
      draftBoundReuse: true,
    },
  });

  const run = await store.get(queuedResult.run.id);
  assert.equal(created.length, 1);
  assert.equal(run?.status, "candidate_ready");
  assert.equal(run?.candidateVersion, "a".repeat(40));
  assert.equal(run?.candidateGeneration, 1);
  assert.equal(run?.pullRequest?.number, 121);
  assert.equal(run?.artifacts.some((item) => item.kind === "candidate"), true);
});

test("hourly sweep recovers a crash after durable author intent but before SQS confirmation", async () => {
  const store = new InMemoryImprovementRunStore();
  const artifacts = new InMemoryImprovementArtifactStore();
  const queued: Array<{ job: ImprovementJob; delaySeconds: number }> = [];
  let failSend = true;
  const jobs = {
    send: async (job: ImprovementJob, delaySeconds = 0) => {
      if (failSend) throw new Error("simulated crash before SQS confirmation");
      queued.push({ job: structuredClone(job), delaySeconds });
    },
  };
  const now = () => new Date("2026-07-14T18:00:00.000Z");
  const controlPlane = new ImprovementControlPlane({ store, artifacts, queue: jobs, signalThreshold: 1, cooldownHours: 168, now });

  await assert.rejects(controlPlane.observe(signal(), {
    repo: "WriterInternal/cerebro-slack-companion",
    baseRef: "main",
  }), /simulated crash/);
  const pending = [...store.runs.values()][0];
  assert.equal(pending?.status, "queued");
  assert.equal(pending?.authorRequest?.generation, 1);
  assert.equal(pending?.authorDispatch, undefined);

  failSend = false;
  const worker = new ImprovementWorker(workerConfig(), { store, artifacts, jobs, now });
  await worker.handle({ schemaVersion: 1, kind: "sweep_stale_runs" });

  assert.equal(queued.length, 1);
  assert.equal(queued[0]?.job.kind, "author_candidate");
  assert.equal(queued[0]?.delaySeconds, 5);
  assert.equal((await store.get(pending!.id))?.authorDispatch?.generation, 1);
});

test("worker visibility covers the maximum model and bounded GitHub write lease", async () => {
  const commands: any[] = [];
  const config = workerConfig();
  config.author.timeoutMs = 600_000;
  const worker = new ImprovementWorker(config, {
    queueClient: {
      send: async (command) => {
        commands.push(command);
        return {};
      },
    },
  });

  await (worker as unknown as { pollOnce(): Promise<void> }).pollOnce();

  assert.equal(commands[0]?.input?.VisibilityTimeout, 990);
});

test("candidate evaluation records named GitHub CI receipts before held-out replay", async () => {
  const fixture = await candidateFixture();
  const corpusArtifact = await fixture.artifacts.putJson(fixture.run.id, "corpus", { cases: passingReplayCases() }, fixture.now);
  const worker = evaluationWorker(fixture, async () => githubStatus("a".repeat(40), [
    { name: "test", status: "completed", conclusion: "success" },
    { name: "architecture", status: "completed", conclusion: "success" },
  ]));

  await worker.handle(evaluationJob(fixture.run, corpusArtifact));

  const run = await fixture.store.get(fixture.run.id);
  assert.equal(run?.status, "shadowing");
  assert.equal(run?.ciReceipt?.headSha, "a".repeat(40));
  assert.deepEqual(run?.ciReceipt?.checks.map((check) => [check.name, check.conclusion]), [
    ["test", "success"],
    ["architecture", "success"],
  ]);
  const receipt = [...fixture.artifacts.values.values()].find((value) => (value as any)?.source === "github_protected_workflow") as any;
  assert.equal(receipt.pullRequestNumber, 121);
  assert.equal(receipt.headSha, "a".repeat(40));
  assert.equal(receipt.successful, true);
});

test("verifier rejects an invalid candidate receipt signature without GitHub credentials", async () => {
  const fixture = await candidateFixture();
  const corpusArtifact = await fixture.artifacts.putJson(fixture.run.id, "corpus", { cases: passingReplayCases() }, fixture.now);
  const config = { ...workerConfig(), lane: "verifier" as const, code: { ...workerConfig().code, enabled: false, githubApp: undefined } };
  const worker = new ImprovementWorker(config, {
    store: fixture.store,
    artifacts: fixture.artifacts,
    kms: { send: async () => ({ SignatureValid: false }) },
    now: () => fixture.now,
  });

  await assert.rejects(worker.handle(evaluationJob(fixture.run, corpusArtifact)), /Candidate evidence signature is invalid/);
  assert.equal((await fixture.store.get(fixture.run.id))?.status, "candidate_ready");
});

test("pending signed checks fail before mutating candidate evaluation state", async () => {
  const fixture = await candidateFixture();
  const jobs = new InMemoryImprovementJobQueue();
  const corpusArtifact = await fixture.artifacts.putJson(fixture.run.id, "corpus", { cases: passingReplayCases() }, fixture.now);
  const worker = evaluationWorker(fixture, async () => githubStatus("a".repeat(40), [
    { name: "test", status: "in_progress", conclusion: null },
    { name: "architecture", status: "completed", conclusion: "success" },
  ]), jobs);

  await assert.rejects(worker.handle(evaluationJob(fixture.run, corpusArtifact)), /pending checks: test/);

  const run = await fixture.store.get(fixture.run.id);
  assert.equal(run?.status, "candidate_ready");
  assert.equal(run?.ciReceipt, undefined);
  assert.equal(run?.artifacts.some((artifact) => artifact.kind === "ci"), false);
  assert.equal(run?.updatedAt, fixture.run.updatedAt);
  assert.equal(jobs.jobs.length, 0);
});

test("candidate evaluation blocks PR status outside the stored open draft boundary", async (context) => {
  const scenarios: Array<{ name: string; status: Record<string, unknown>; blocker: RegExp }> = [
    {
      name: "closed PR",
      status: githubStatus("a".repeat(40), passingChecks(), { state: "closed", draft: true }),
      blocker: /no longer an open, unmerged draft/,
    },
    {
      name: "non-draft PR",
      status: githubStatus("a".repeat(40), passingChecks(), { draft: false }),
      blocker: /no longer an open, unmerged draft/,
    },
    {
      name: "different head branch",
      status: githubStatus("a".repeat(40), passingChecks(), { head_ref: "cerebro/improvement/other" }),
      blocker: /branch changed/,
    },
    {
      name: "different head repository",
      status: githubStatus("a".repeat(40), passingChecks(), { head_repo: "WriterInternal/other" }),
      blocker: /head repository changed/,
    },
  ];

  for (const scenario of scenarios) {
    await context.test(scenario.name, async () => {
      const fixture = await candidateFixture();
      const corpusArtifact = await fixture.artifacts.putJson(fixture.run.id, "corpus", { cases: passingReplayCases() }, fixture.now);
      const worker = evaluationWorker(fixture, async () => scenario.status);

      await worker.handle(evaluationJob(fixture.run, corpusArtifact));

      const run = await fixture.store.get(fixture.run.id);
      assert.equal(run?.status, "blocked");
      assert.match(run?.blockers[0] ?? "", scenario.blocker);
      assert.equal(run?.ciReceipt, undefined);
    });
  }
});

test("terminal failed or cancelled GitHub checks durably block the candidate", async () => {
  const fixture = await candidateFixture();
  const corpusArtifact = await fixture.artifacts.putJson(fixture.run.id, "corpus", { cases: passingReplayCases() }, fixture.now);
  const worker = evaluationWorker(fixture, async () => githubStatus("a".repeat(40), [
    { name: "test", status: "completed", conclusion: "success" },
    { name: "architecture", status: "completed", conclusion: "cancelled" },
  ]));

  await worker.handle(evaluationJob(fixture.run, corpusArtifact));

  const run = await fixture.store.get(fixture.run.id);
  assert.equal(run?.status, "blocked");
  assert.equal(run?.ciReceipt?.successful, false);
  assert.match(run?.blockers[0] ?? "", /architecture=cancelled/);
  assert.equal(run?.artifacts.some((artifact) => artifact.kind === "ci"), true);
});

test("a moved draft PR head cannot retarget signed candidate evidence", async () => {
  const fixture = await candidateFixture();
  const jobs = new InMemoryImprovementJobQueue();
  const corpusArtifact = await fixture.artifacts.putJson(fixture.run.id, "corpus", { cases: passingReplayCases() }, fixture.now);
  const worker = evaluationWorker(fixture, async () => githubStatus("b".repeat(40), [
    { name: "test", status: "completed", conclusion: "success" },
    { name: "architecture", status: "completed", conclusion: "success" },
  ]), jobs);

  await worker.handle(evaluationJob(fixture.run, corpusArtifact));

  const blocked = await fixture.store.get(fixture.run.id);
  assert.equal(blocked?.status, "blocked");
  assert.match(blocked?.blockers[0] ?? "", /head changed/);
  assert.equal(blocked?.ciReceipt, undefined);
  assert.equal(jobs.jobs.length, 0);
});

test("transient GitHub status failures do not mutate candidate evaluation state", async () => {
  const fixture = await candidateFixture();
  const corpusArtifact = await fixture.artifacts.putJson(fixture.run.id, "corpus", { cases: passingReplayCases() }, fixture.now);
  const worker = evaluationWorker(fixture, async () => {
    throw new Error("GitHub API failed 503");
  });

  await assert.rejects(worker.handle(evaluationJob(fixture.run, corpusArtifact)), /GitHub API failed 503/);

  const run = await fixture.store.get(fixture.run.id);
  assert.equal(run?.status, "candidate_ready");
  assert.equal(run?.ciReceipt, undefined);
  assert.equal(run?.version, fixture.run.version);
});

test("superseded evaluation, shadow, canary, and promotion jobs are consumed without retargeting", async () => {
  const fixture = await candidateFixture();
  const corpusArtifact = await fixture.artifacts.putJson(fixture.run.id, "corpus", { cases: passingReplayCases() }, fixture.now);
  let kmsCalls = 0;
  const worker = new ImprovementWorker(workerConfig(), {
    store: fixture.store,
    artifacts: fixture.artifacts,
    kms: { send: async () => { kmsCalls += 1; return { SignatureValid: true }; } },
    pullRequests: candidatePullRequests(async () => ({ ok: false })),
  });
  const staleEvaluation = { ...evaluationJob(fixture.run, corpusArtifact), candidateVersion: "b".repeat(40) };
  await worker.handle(staleEvaluation);
  assert.equal((await fixture.store.get(fixture.run.id))?.status, "candidate_ready");

  const evaluator = evaluationWorker(fixture, async () => githubStatus("a".repeat(40), passingChecks()));
  await evaluator.handle(evaluationJob(fixture.run, corpusArtifact));
  const shadowArtifact = await fixture.artifacts.putJson(fixture.run.id, "shadow", { success: true }, fixture.now);
  const shadowOutcome = { stage: "shadow" as const, success: true, sampleSize: 25, errorRate: 0, artifact: shadowArtifact };
  await worker.handle({ schemaVersion: 1, kind: "record_shadow", runId: fixture.run.id, candidateVersion: "b".repeat(40), outcome: shadowOutcome });
  assert.equal((await fixture.store.get(fixture.run.id))?.status, "shadowing");
  await worker.handle({ schemaVersion: 1, kind: "record_shadow", runId: fixture.run.id, candidateVersion: "a".repeat(40), outcome: shadowOutcome });

  const canaryArtifact = await fixture.artifacts.putJson(fixture.run.id, "canary", { success: true }, fixture.now);
  const canaryOutcome = { stage: "canary" as const, success: true, sampleSize: 25, errorRate: 0, artifact: canaryArtifact };
  await worker.handle({ schemaVersion: 1, kind: "record_canary", runId: fixture.run.id, candidateVersion: "b".repeat(40), outcome: canaryOutcome });
  assert.equal((await fixture.store.get(fixture.run.id))?.status, "canary");
  await worker.handle({ schemaVersion: 1, kind: "record_canary", runId: fixture.run.id, candidateVersion: "a".repeat(40), outcome: canaryOutcome });

  await worker.handle({
    schemaVersion: 1,
    kind: "promotion_decision",
    payload: {
      runId: fixture.run.id,
      candidateVersion: "b".repeat(40),
      decision: "promote",
      reason: "stale decision",
      reviewedBy: "operator",
      reviewedAt: fixture.now.toISOString(),
      sourceRef: "https://github.com/WriterInternal/cerebro-slack-companion/actions/runs/2",
      candidateReceipt: candidateReceiptFromStatus(githubStatus("b".repeat(40), passingChecks())),
    },
    signature: "a".repeat(80),
  });
  assert.equal(kmsCalls, 0);
  assert.equal((await fixture.store.get(fixture.run.id))?.status, "awaiting_promotion");
});

test("legacy mutating jobs without generation or candidate bindings fail closed", async () => {
  const store = new InMemoryImprovementRunStore();
  const artifacts = new InMemoryImprovementArtifactStore();
  const now = new Date("2026-07-14T18:00:00.000Z");
  const observed = newImprovementRun(signal(), await artifacts.putJson("seed", "signal", signal(), now), now, 168);
  const queued = transitionImprovementRun(observed, { type: "queued" }, { now, actor: "companion" }).run;
  await store.create(queued, { ...initialImprovementEvent(observed), type: "seed_legacy_queued", toStatus: "queued" });
  const worker = new ImprovementWorker(workerConfig(), { store, artifacts });

  await assert.rejects(worker.handle({
    schemaVersion: 1,
    kind: "author_candidate",
    runId: queued.id,
    repo: "WriterInternal/cerebro-slack-companion",
    baseRef: "main",
  }), /missing its persisted author generation/);
  assert.equal((await store.get(queued.id))?.status, "queued");
});

test("isolated worker authors a draft candidate from at most six signal artifacts", async () => {
  const store = new InMemoryImprovementRunStore();
  const artifacts = new InMemoryImprovementArtifactStore();
  const now = new Date("2026-07-14T18:00:00.000Z");
  const receipts = [];
  for (let index = 0; index < 7; index += 1) {
    const item = { ...signal(), occurredAt: new Date(now.getTime() + index * 1_000).toISOString(), question: `private failure ${index}` };
    receipts.push(await artifacts.putJson("seed", "signal", item, new Date(item.occurredAt)));
  }
  const observed = newImprovementRun(signal(), receipts[0]!, now, 168);
  const inputSignalShas = receipts.slice(-6).map((receipt) => receipt.sha256);
  const queuedResult = transitionImprovementRun({ ...observed, artifacts: receipts, signalCount: 7 }, {
    type: "author_requested",
    inputSignalShas,
    repo: "WriterInternal/cerebro-slack-companion",
    baseRef: "main",
  }, { now, actor: "companion" });
  await store.create(queuedResult.run, { ...initialImprovementEvent(observed), toStatus: "queued", type: "queued" });
  const authoredSignals: ImprovementSignal[][] = [];
  const created: unknown[] = [];
  const worker = new ImprovementWorker(workerConfig(), {
    store,
    artifacts,
    candidateAuthor: {
      author: async (input) => {
        authoredSignals.push(input.signals);
        return {
          pullRequest: {
            repo: input.repo,
            title: "Repair action closure",
            files: [
              { path: "src/work/example.ts", content: "export const repaired = true;\n" },
              { path: "test/example.test.ts", content: "// focused regression\n" },
            ],
            branch: `cerebro/improvement/${input.run.id}`,
            base: input.baseRef,
            draft: true,
          },
          resolvedRef: "b".repeat(40),
          sourceCallCount: 8,
          sourceReceipts: [
            { path: "src/work/example.ts", sha: "d".repeat(40), bytes: 30 },
            { path: "test/example.test.ts", sha: "e".repeat(40), bytes: 22 },
          ],
        };
      },
    },
    pullRequests: {
      sourceList: async () => ({ ok: true, resolved_ref: "b".repeat(40), entries: [] }),
      sourceRead: async () => ({ ok: true, resolved_ref: "b".repeat(40), files: [] }),
      createPullRequest: async (input) => {
        created.push(input);
        return {
          ok: true,
          repo: "WriterInternal/cerebro-slack-companion",
          branch: input.branch,
          pull_request: {
            number: 122,
            url: "https://github.com/WriterInternal/cerebro-slack-companion/pull/122",
            head_sha: "c".repeat(40),
          },
        };
      },
      pullRequestStatus: async () => ({ ok: false }),
    },
  });

  await worker.handle({
    schemaVersion: 1,
    kind: "author_candidate",
    runId: queuedResult.run.id,
    generation: 1,
    inputSignalShas,
    repo: "WriterInternal/cerebro-slack-companion",
    baseRef: "main",
  });

  assert.equal(authoredSignals.length, 1);
  assert.equal(authoredSignals[0]?.length, 6);
  assert.equal(authoredSignals[0]?.[0]?.question, "private failure 1");
  assert.equal((created[0] as { draft?: boolean }).draft, true);
  assert.equal((created[0] as { expectedBaseSha?: string }).expectedBaseSha, "b".repeat(40));
  assert.equal((created[0] as { draftBoundReuse?: boolean }).draftBoundReuse, true);
  assert.equal((await store.get(queuedResult.run.id))?.status, "candidate_ready");
  const candidateReceipt = [...artifacts.values.values()].find((value) => (value as Record<string, unknown>)?.authorGeneration) as Record<string, unknown>;
  assert.deepEqual((candidateReceipt.sourceReceipts as Array<{ path: string }>).map((receipt) => receipt.path), [
    "src/work/example.ts",
    "test/example.test.ts",
  ]);
  assert.doesNotMatch(JSON.stringify(candidateReceipt), /private failure|"content"/);
});

test("a human outcome authors from the exact prior head and updates only the same open draft", async () => {
  const store = new InMemoryImprovementRunStore();
  const artifacts = new InMemoryImprovementArtifactStore();
  const jobs = new InMemoryImprovementJobQueue();
  const now = () => new Date("2026-07-14T18:00:00.000Z");
  const controlPlane = new ImprovementControlPlane({ store, artifacts, queue: jobs, signalThreshold: 1, cooldownHours: 168, now });
  const repo = "WriterInternal/cerebro-slack-companion";
  const run = await controlPlane.observe(signal(), { repo, baseRef: "main" }, {
    humanAssistance: { channelId: "CSEC", intendedUserId: "UUSER" },
  });
  const firstJob = jobs.jobs[0]?.job;
  if (!run || !firstJob || firstJob.kind !== "author_candidate") throw new Error("Expected the initial author generation.");

  const authorInputs: Array<{ sourceRef?: string; signals: ImprovementSignal[] }> = [];
  const writes: RuntimeCodePrInput[] = [];
  const branch = `cerebro/improvement/${run.id}`;
  let currentHead = "";
  let statusCalls = 0;
  const worker = new ImprovementWorker(workerConfig(), {
    store,
    artifacts,
    jobs,
    now,
    candidateAuthor: {
      author: async (input) => {
        authorInputs.push({ sourceRef: input.sourceRef, signals: input.signals });
        return {
          ...authoredCandidate(input.run.id, input.repo, input.baseRef),
          resolvedRef: input.sourceRef ?? "d".repeat(40),
        };
      },
    },
    pullRequests: {
      sourceList: async () => ({ ok: true, resolved_ref: currentHead || "d".repeat(40), entries: [] }),
      sourceRead: async () => ({ ok: true, resolved_ref: currentHead || "d".repeat(40), files: [] }),
      createPullRequest: async (input) => {
        writes.push(structuredClone(input));
        currentHead = writes.length === 1 ? "a".repeat(40) : "b".repeat(40);
        return {
          ok: true,
          repo,
          branch: input.branch,
          pull_request: {
            number: 122,
            url: "https://github.com/WriterInternal/cerebro-slack-companion/pull/122",
            head_sha: currentHead,
          },
        };
      },
      pullRequestStatus: async () => {
        statusCalls += 1;
        return {
          ok: true,
          repo,
          pull_request: {
            number: 122,
            head_sha: currentHead,
            state: "open",
            draft: true,
            merged: false,
            head_ref: branch,
            head_repo: repo,
            base_ref: "main",
            base_sha: "d".repeat(40),
          },
        };
      },
    },
  });

  await worker.handle(firstJob);
  const firstCandidate = await store.get(run.id);
  assert.equal(firstCandidate?.candidateGeneration, 1);
  assert.equal(firstCandidate?.candidateVersion, "a".repeat(40));

  const refined = await controlPlane.recordHumanAssistanceOutcome({
    runId: run.id,
    channelId: "CSEC",
    intendedUserId: "UUSER",
    outcome: "prove the retry completes without a duplicate draft",
  });
  const secondJob = jobs.jobs.find((entry) => entry.job.kind === "author_candidate" && entry.job.generation === 2)?.job;
  if (!refined || !secondJob || secondJob.kind !== "author_candidate") throw new Error("Expected the human-outcome author generation.");
  await worker.handle(secondJob);

  const completed = await store.get(run.id);
  assert.equal(statusCalls, 2);
  assert.equal(authorInputs[1]?.sourceRef, "a".repeat(40));
  assert.equal(authorInputs[1]?.signals.at(-1)?.reason, "human-regression-outcome");
  assert.equal(writes[1]?.repo, repo);
  assert.equal(writes[1]?.branch, branch);
  assert.equal(writes[1]?.base, "main");
  assert.equal(writes[1]?.expectedBaseSha, "d".repeat(40));
  assert.equal(writes[1]?.expectedHeadSha, "a".repeat(40));
  assert.equal(writes[1]?.draftBoundReuse, true);
  assert.equal(completed?.candidateGeneration, 2);
  assert.equal(completed?.candidateVersion, "b".repeat(40));
  assert.equal(completed?.pullRequest?.number, 122);
  assert.equal(completed?.pullRequest?.branch, branch);
  assert.equal(completed?.refinementBaseVersion, undefined);
  assert.equal(completed?.ciReceipt, undefined);
  assert.equal(completed?.assistance?.refinementStatus, "completed");
});

test("a reply-like signal supersedes an in-flight model generation and releases its exact lease", async () => {
  const store = new InMemoryImprovementRunStore();
  const artifacts = new InMemoryImprovementArtifactStore();
  const jobs = new InMemoryImprovementJobQueue();
  const now = () => new Date("2026-07-14T18:00:00.000Z");
  const controlPlane = new ImprovementControlPlane({ store, artifacts, queue: jobs, signalThreshold: 1, cooldownHours: 168, now });
  const candidate = { repo: "WriterInternal/cerebro-slack-companion", baseRef: "main" };
  await controlPlane.observe(signal(), candidate);
  const firstJob = jobs.jobs[0]?.job;
  if (!firstJob || firstJob.kind !== "author_candidate") throw new Error("Expected first author generation.");

  let enterModel!: () => void;
  const modelEntered = new Promise<void>((resolve) => { enterModel = resolve; });
  let releaseModel!: () => void;
  const modelRelease = new Promise<void>((resolve) => { releaseModel = resolve; });
  let authorCalls = 0;
  let pullRequestWrites = 0;
  const worker = new ImprovementWorker(workerConfig(), {
    store,
    artifacts,
    jobs,
    now,
    candidateAuthor: {
      author: async (input) => {
        authorCalls += 1;
        if (authorCalls === 1) {
          enterModel();
          await modelRelease;
        }
        return authoredCandidate(input.run.id, input.repo, input.baseRef);
      },
    },
    pullRequests: candidatePullRequests(async (input) => {
      pullRequestWrites += 1;
      return candidatePullRequestResult(input, pullRequestWrites === 1 ? "a" : "b");
    }),
  });

  const staleCompletion = worker.handle(firstJob);
  await modelEntered;
  const claimed = await store.get(firstJob.runId);
  assert.equal(claimed?.authorLease?.generation, 1);
  assert.equal(Date.parse(claimed!.authorLease!.expiresAt) - now().getTime(), 690_000);

  await controlPlane.observe({ ...signal(), occurredAt: "2026-07-14T18:01:00.000Z", question: "the follow-up changed the expected result" }, candidate);
  assert.equal((await store.get(firstJob.runId))?.authorGeneration, 2);
  releaseModel();
  await staleCompletion;

  const superseded = await store.get(firstJob.runId);
  assert.equal(superseded?.status, "queued");
  assert.equal(superseded?.authorLease, undefined);
  assert.equal(pullRequestWrites, 0);
  const immediate = jobs.jobs.find((entry) => entry.job.kind === "author_candidate" && entry.job.generation === 2 && entry.delaySeconds === 0);
  assert.ok(immediate, "releasing the old exact-token lease should wake the superseding generation immediately");
  const secondJob = immediate.job;
  if (!secondJob || secondJob.kind !== "author_candidate") throw new Error("Expected superseding author generation.");
  await worker.handle(secondJob);

  const ready = await store.get(firstJob.runId);
  assert.equal(ready?.status, "candidate_ready");
  assert.equal(ready?.candidateGeneration, 2);
  assert.equal(pullRequestWrites, 1);
});

test("a superseded generation after intent persistence performs no stale GitHub write", async () => {
  let intentCommitted!: () => void;
  const committed = new Promise<void>((resolve) => { intentCommitted = resolve; });
  let releaseIntent!: () => void;
  const intentRelease = new Promise<void>((resolve) => { releaseIntent = resolve; });
  class PausingIntentStore extends InMemoryImprovementRunStore {
    override async commit(previousVersion: number, run: ImprovementRun, event: ImprovementEvent): Promise<void> {
      await super.commit(previousVersion, run, event);
      if (event.type === "author_write_intended") {
        intentCommitted();
        await intentRelease;
      }
    }
  }
  const store = new PausingIntentStore();
  const artifacts = new InMemoryImprovementArtifactStore();
  const jobs = new InMemoryImprovementJobQueue();
  const now = () => new Date("2026-07-14T18:00:00.000Z");
  const controlPlane = new ImprovementControlPlane({ store, artifacts, queue: jobs, signalThreshold: 1, cooldownHours: 168, now });
  const candidate = { repo: "WriterInternal/cerebro-slack-companion", baseRef: "main" };
  await controlPlane.observe(signal(), candidate);
  const firstJob = jobs.jobs[0]?.job;
  if (!firstJob || firstJob.kind !== "author_candidate") throw new Error("Expected first author generation.");
  let writeCalls = 0;
  const worker = new ImprovementWorker(workerConfig(), {
    store,
    artifacts,
    jobs,
    now,
    candidateAuthor: { author: async (input) => authoredCandidate(input.run.id, input.repo, input.baseRef) },
    pullRequests: candidatePullRequests(async (input) => {
      writeCalls += 1;
      return candidatePullRequestResult(input, "a");
    }),
  });

  const staleCompletion = worker.handle(firstJob);
  await committed;
  await controlPlane.observe({ ...signal(), occurredAt: "2026-07-14T18:01:00.000Z", question: "new evidence supersedes the persisted intent" }, candidate);
  releaseIntent();
  await staleCompletion;

  const superseded = await store.get(firstJob.runId);
  assert.equal(writeCalls, 0);
  assert.equal(superseded?.status, "queued");
  assert.equal(superseded?.authorGeneration, 2);
  assert.equal(superseded?.candidateWriteIntent?.generation, 1);
  assert.equal(superseded?.authorLease, undefined);
});

test("a superseded generation during recovery inspection cannot resume the stale GitHub write", async () => {
  const store = new InMemoryImprovementRunStore();
  const artifacts = new InMemoryImprovementArtifactStore();
  const jobs = new InMemoryImprovementJobQueue();
  const now = () => new Date("2026-07-14T18:00:00.000Z");
  const controlPlane = new ImprovementControlPlane({ store, artifacts, queue: jobs, signalThreshold: 1, cooldownHours: 168, now });
  const candidate = { repo: "WriterInternal/cerebro-slack-companion", baseRef: "main" };
  await controlPlane.observe(signal(), candidate);
  const firstJob = jobs.jobs[0]?.job;
  if (!firstJob || firstJob.kind !== "author_candidate") throw new Error("Expected first author generation.");
  let externalState: any;
  let inspectionEntered!: () => void;
  const entered = new Promise<void>((resolve) => { inspectionEntered = resolve; });
  let releaseInspection!: () => void;
  const inspectionRelease = new Promise<void>((resolve) => { releaseInspection = resolve; });
  let completionCalls = 0;
  const worker = new ImprovementWorker(workerConfig(), {
    store,
    artifacts,
    jobs,
    now,
    candidateAuthor: { author: async (input) => authoredCandidate(input.run.id, input.repo, input.baseRef) },
    pullRequests: {
      ...candidatePullRequests(async (input) => {
        externalState = candidateRecoveryState(input) as any;
        externalState.head_sha = input.expectedHeadSha;
        externalState.head_parent_shas = [];
        externalState.head_changed_paths = [];
        externalState.head_changes = [];
        externalState.pull_requests = [];
        externalState.files = [];
        throw new Error("connection closed after branch creation");
      }),
      candidatePullRequestState: async () => {
        inspectionEntered();
        await inspectionRelease;
        return externalState;
      },
      completeCandidatePullRequest: async () => {
        completionCalls += 1;
        return { ok: false };
      },
    },
  });

  await assert.rejects(worker.handle(firstJob), /after branch creation/);
  const staleRecovery = worker.handle(firstJob);
  await entered;
  await controlPlane.observe({ ...signal(), occurredAt: "2026-07-14T18:01:00.000Z", question: "new evidence arrived during recovery" }, candidate);
  releaseInspection();
  await staleRecovery;

  const superseded = await store.get(firstJob.runId);
  assert.equal(completionCalls, 0);
  assert.equal(superseded?.status, "queued");
  assert.equal(superseded?.authorGeneration, 2);
  assert.equal(superseded?.authorLease, undefined);
});

test("a stale GitHub completion records only its branch head and the next generation reuses that exact head", async () => {
  const store = new InMemoryImprovementRunStore();
  const artifacts = new InMemoryImprovementArtifactStore();
  const jobs = new InMemoryImprovementJobQueue();
  let clock = new Date("2026-07-14T18:00:00.000Z");
  const now = () => clock;
  const controlPlane = new ImprovementControlPlane({ store, artifacts, queue: jobs, signalThreshold: 1, cooldownHours: 168, now });
  const candidate = { repo: "WriterInternal/cerebro-slack-companion", baseRef: "main" };
  await controlPlane.observe(signal(), candidate);
  const firstJob = jobs.jobs[0]?.job;
  if (!firstJob || firstJob.kind !== "author_candidate") throw new Error("Expected first author generation.");

  let enterWrite!: () => void;
  const writeEntered = new Promise<void>((resolve) => { enterWrite = resolve; });
  let releaseWrite!: () => void;
  const writeRelease = new Promise<void>((resolve) => { releaseWrite = resolve; });
  const writes: Array<{ expectedHeadSha?: string }> = [];
  const worker = new ImprovementWorker(workerConfig(), {
    store,
    artifacts,
    jobs,
    now,
    candidateAuthor: { author: async (input) => authoredCandidate(input.run.id, input.repo, input.baseRef) },
    pullRequests: candidatePullRequests(async (input) => {
      writes.push({ expectedHeadSha: input.expectedHeadSha });
      if (writes.length === 1) {
        enterWrite();
        await writeRelease;
        return candidatePullRequestResult(input, "a");
      }
      return candidatePullRequestResult(input, "b");
    }),
  });

  const staleCompletion = worker.handle(firstJob);
  await writeEntered;
  clock = new Date("2026-07-14T18:07:00.000Z");
  await worker.handle(firstJob);
  assert.equal(writes.length, 1, "the bounded GitHub write lease must prevent a replacement worker during the remote write budget");
  await controlPlane.observe({ ...signal(), occurredAt: "2026-07-14T18:02:00.000Z", question: "new reply evidence" }, candidate);
  releaseWrite();
  await staleCompletion;

  const stale = await store.get(firstJob.runId);
  assert.equal(stale?.status, "queued");
  assert.equal(stale?.candidateVersion, undefined);
  assert.equal(stale?.candidateBranchWrite?.generation, 1);
  assert.equal(stale?.candidateBranchWrite?.headSha, "a".repeat(40));
  const secondJob = jobs.jobs.find((entry) => entry.job.kind === "author_candidate" && entry.job.generation === 2)?.job;
  if (!secondJob || secondJob.kind !== "author_candidate") throw new Error("Expected superseding author generation.");
  await worker.handle(secondJob);

  assert.deepEqual(writes, [{ expectedHeadSha: "d".repeat(40) }, { expectedHeadSha: "a".repeat(40) }]);
  const ready = await store.get(firstJob.runId);
  assert.equal(ready?.candidateGeneration, 2);
  assert.equal(ready?.candidateVersion, "b".repeat(40));
});

test("author retry recovers an externally successful write from its immutable intent without a duplicate PR", async () => {
  const store = new InMemoryImprovementRunStore();
  const artifacts = new InMemoryImprovementArtifactStore();
  const jobs = new InMemoryImprovementJobQueue();
  const now = () => new Date("2026-07-14T18:00:00.000Z");
  const controlPlane = new ImprovementControlPlane({ store, artifacts, queue: jobs, signalThreshold: 1, cooldownHours: 168, now });
  await controlPlane.observe(signal(), { repo: "WriterInternal/cerebro-slack-companion", baseRef: "main" });
  const job = jobs.jobs[0]?.job;
  if (!job || job.kind !== "author_candidate") throw new Error("Expected author candidate job.");
  let authorCalls = 0;
  let writeCalls = 0;
  let externalState: Record<string, unknown> | undefined;
  const worker = new ImprovementWorker(workerConfig(), {
    store,
    artifacts,
    jobs,
    now,
    candidateAuthor: {
      author: async (input) => {
        authorCalls += 1;
        return authoredCandidate(input.run.id, input.repo, input.baseRef);
      },
    },
    pullRequests: {
      ...candidatePullRequests(async (input) => {
        writeCalls += 1;
        externalState = candidateRecoveryState(input);
        throw new Error("connection closed after GitHub accepted the write");
      }),
      candidatePullRequestState: async () => {
        if (!externalState) throw new Error("candidate state not written");
        return externalState;
      },
    },
  });

  await assert.rejects(worker.handle(job), /connection closed/);
  const pending = await store.get(job.runId);
  assert.equal(pending?.status, "queued");
  assert.equal(pending?.candidateWriteIntent?.generation, 1);
  assert.equal(pending?.candidateWriteIntent?.expectedBaseSha, "d".repeat(40));
  assert.equal(pending?.candidateWriteIntent?.expectedHeadSha, "d".repeat(40));
  assert.equal(pending?.candidateWriteIntent?.artifact.kind, "candidate_intent");

  await worker.handle(job);

  const ready = await store.get(job.runId);
  assert.equal(authorCalls, 1);
  assert.equal(writeCalls, 1);
  assert.equal(ready?.status, "candidate_ready");
  assert.equal(ready?.candidateVersion, "a".repeat(40));
  assert.equal(ready?.candidateBranchWrite?.pullRequestNumber, 122);
  assert.equal(ready?.pullRequest?.number, 122);
});

test("author retry resumes branch-only, commit-only, and outcome-unknown PR completion windows exactly once", async () => {
  const store = new InMemoryImprovementRunStore();
  const artifacts = new InMemoryImprovementArtifactStore();
  const jobs = new InMemoryImprovementJobQueue();
  const now = () => new Date("2026-07-14T18:00:00.000Z");
  const controlPlane = new ImprovementControlPlane({ store, artifacts, queue: jobs, signalThreshold: 1, cooldownHours: 168, now });
  await controlPlane.observe(signal(), { repo: "WriterInternal/cerebro-slack-companion", baseRef: "main" });
  const job = jobs.jobs[0]?.job;
  if (!job || job.kind !== "author_candidate") throw new Error("Expected author candidate job.");
  let authorCalls = 0;
  let fullWriteCalls = 0;
  let completionCalls = 0;
  let externalState: any;
  const worker = new ImprovementWorker(workerConfig(), {
    store,
    artifacts,
    jobs,
    now,
    candidateAuthor: {
      author: async (input) => {
        authorCalls += 1;
        return authoredCandidate(input.run.id, input.repo, input.baseRef);
      },
    },
    pullRequests: {
      ...candidatePullRequests(async (input) => {
        fullWriteCalls += 1;
        externalState = candidateRecoveryState(input) as any;
        externalState.head_sha = input.expectedHeadSha;
        externalState.head_parent_shas = [];
        externalState.head_changed_paths = [];
        externalState.head_changes = [];
        externalState.pull_requests = [];
        externalState.files = [];
        throw new Error("connection closed after branch creation");
      }),
      candidatePullRequestState: async () => externalState,
      completeCandidatePullRequest: async ({ pullRequest }) => {
        completionCalls += 1;
        if (completionCalls === 1) {
          externalState = candidateRecoveryState(pullRequest);
          externalState.pull_requests = [];
          throw new Error("connection closed after createCommitOnBranch");
        }
        externalState = candidateRecoveryState(pullRequest);
        throw new Error("connection closed after draft PR POST");
      },
    },
  });

  await assert.rejects(worker.handle(job), /after branch creation/);
  await assert.rejects(worker.handle(job), /after createCommitOnBranch/);
  await assert.rejects(worker.handle(job), /after draft PR POST/);
  await worker.handle(job);

  const ready = await store.get(job.runId);
  assert.equal(authorCalls, 1);
  assert.equal(fullWriteCalls, 1);
  assert.equal(completionCalls, 2);
  assert.equal(ready?.status, "candidate_ready");
  assert.equal(ready?.candidateVersion, "a".repeat(40));
  assert.equal(ready?.pullRequest?.number, 122);
});

test("author retry fails closed on ambiguous, moved, non-draft, and closed external writes", async (context) => {
  const scenarios: Array<{ name: string; mutate(state: any): void }> = [
    {
      name: "ambiguous PR history",
      mutate: (state) => { state.pull_requests.push({ ...state.pull_requests[0], number: 123, url: "https://github.com/WriterInternal/cerebro-slack-companion/pull/123" }); },
    },
    {
      name: "moved head",
      mutate: (state) => { state.head_parent_shas = ["b".repeat(40)]; },
    },
    {
      name: "non-draft PR",
      mutate: (state) => { state.pull_requests[0].draft = false; },
    },
    {
      name: "closed PR",
      mutate: (state) => { state.pull_requests[0].state = "closed"; },
    },
    {
      name: "different PR title",
      mutate: (state) => { state.pull_requests[0].title = "Unrelated draft"; },
    },
    {
      name: "different PR body",
      mutate: (state) => { state.pull_requests[0].body = "Unrelated body"; },
    },
  ];

  for (const scenario of scenarios) {
    await context.test(scenario.name, async () => {
      const store = new InMemoryImprovementRunStore();
      const artifacts = new InMemoryImprovementArtifactStore();
      const jobs = new InMemoryImprovementJobQueue();
      const now = () => new Date("2026-07-14T18:00:00.000Z");
      const controlPlane = new ImprovementControlPlane({ store, artifacts, queue: jobs, signalThreshold: 1, cooldownHours: 168, now });
      await controlPlane.observe(signal(), { repo: "WriterInternal/cerebro-slack-companion", baseRef: "main" });
      const job = jobs.jobs[0]?.job;
      if (!job || job.kind !== "author_candidate") throw new Error("Expected author candidate job.");
      let externalState: Record<string, unknown> | undefined;
      const worker = new ImprovementWorker(workerConfig(), {
        store,
        artifacts,
        jobs,
        now,
        candidateAuthor: { author: async (input) => authoredCandidate(input.run.id, input.repo, input.baseRef) },
        pullRequests: {
          ...candidatePullRequests(async (input) => {
            externalState = candidateRecoveryState(input);
            scenario.mutate(externalState);
            throw new Error("connection closed after GitHub accepted the write");
          }),
          candidatePullRequestState: async () => externalState ?? { ok: false },
        },
      });

      await assert.rejects(worker.handle(job), /connection closed/);
      await assert.rejects(worker.handle(job), CandidateAuthorPolicyError);
      const blocked = await store.get(job.runId);
      assert.equal(blocked?.status, "blocked");
      assert.match(blocked?.blockers[0] ?? "", /candidate_author_rejected/);
    });
  }
});

test("a later worker waits for the active author lease and claims only after expiry", async () => {
  const store = new InMemoryImprovementRunStore();
  const artifacts = new InMemoryImprovementArtifactStore();
  const jobs = new InMemoryImprovementJobQueue();
  const startedAt = new Date("2026-07-14T18:00:00.000Z");
  const signalArtifact = await artifacts.putJson("seed", "signal", signal(), startedAt);
  const observed = newImprovementRun(signal(), signalArtifact, startedAt, 168);
  const requested = transitionImprovementRun(observed, {
    type: "author_requested",
    inputSignalShas: [signalArtifact.sha256],
    repo: "WriterInternal/cerebro-slack-companion",
    baseRef: "main",
  }, { now: startedAt, actor: "companion" }).run;
  const claimed = transitionImprovementRun(requested, {
    type: "author_claimed",
    generation: 1,
    token: "11111111-1111-4111-8111-111111111111",
    expiresAt: "2026-07-14T18:00:10.000Z",
  }, { now: startedAt, actor: "worker" }).run;
  await store.create(claimed, { ...initialImprovementEvent(observed), type: "seed_claimed", toStatus: "queued" });
  let clock = new Date("2026-07-14T18:00:05.000Z");
  let authorCalls = 0;
  const worker = new ImprovementWorker(workerConfig(), {
    store,
    artifacts,
    jobs,
    now: () => clock,
    candidateAuthor: {
      author: async (input) => {
        authorCalls += 1;
        return authoredCandidate(input.run.id, input.repo, input.baseRef);
      },
    },
    pullRequests: candidatePullRequests(async (input) => candidatePullRequestResult(input, "a")),
  });
  const job: Extract<ImprovementJob, { kind: "author_candidate" }> = {
    schemaVersion: 1,
    kind: "author_candidate",
    runId: claimed.id,
    generation: 1,
    inputSignalShas: [signalArtifact.sha256],
    repo: "WriterInternal/cerebro-slack-companion",
    baseRef: "main",
  };

  await worker.handle(job);
  assert.equal(authorCalls, 0);
  assert.equal(jobs.jobs[0]?.delaySeconds, 5);
  clock = new Date("2026-07-14T18:00:11.000Z");
  await worker.handle(jobs.jobs[0]!.job);

  assert.equal(authorCalls, 1);
  assert.equal((await store.get(claimed.id))?.status, "candidate_ready");
});

test("candidate author policy failures block while transient model failures remain queued for retry", async () => {
  for (const scenario of [
    { error: new CandidateAuthorPolicyError("candidate leaked private signal text"), expectedStatus: "blocked" },
    { error: new Error("Bedrock request timed out"), expectedStatus: "queued" },
  ] as const) {
    const store = new InMemoryImprovementRunStore();
    const artifacts = new InMemoryImprovementArtifactStore();
    const now = new Date("2026-07-14T18:00:00.000Z");
    const signalArtifact = await artifacts.putJson("seed", "signal", signal(), now);
    const observed = newImprovementRun(signal(), signalArtifact, now, 168);
    const queued = transitionImprovementRun(observed, {
      type: "author_requested",
      inputSignalShas: [signalArtifact.sha256],
      repo: "WriterInternal/cerebro-slack-companion",
      baseRef: "main",
    }, { now, actor: "companion" }).run;
    await store.create(queued, { ...initialImprovementEvent(observed), toStatus: "queued", type: "queued" });
    const worker = new ImprovementWorker(workerConfig(), {
      store,
      artifacts,
      candidateAuthor: { author: async () => { throw scenario.error; } },
      pullRequests: {
        sourceList: async () => ({ ok: true, resolved_ref: "a".repeat(40), entries: [] }),
        sourceRead: async () => ({ ok: true, resolved_ref: "a".repeat(40), files: [] }),
        createPullRequest: async () => { throw new Error("pull request creation should not run"); },
        pullRequestStatus: async () => ({ ok: false }),
      },
    });

    await assert.rejects(worker.handle({
      schemaVersion: 1,
      kind: "author_candidate",
      runId: queued.id,
      generation: 1,
      inputSignalShas: [signalArtifact.sha256],
      repo: "WriterInternal/cerebro-slack-companion",
      baseRef: "main",
    }), (error: unknown) => error === scenario.error);
    assert.equal((await store.get(queued.id))?.status, scenario.expectedStatus);
  }
});

test("promotion refuses a candidate changed after held-out evaluation", async () => {
  const store = new InMemoryImprovementRunStore();
  const artifacts = new InMemoryImprovementArtifactStore();
  const now = new Date("2026-07-14T18:00:00.000Z");
  const observed = newImprovementRun(signal(), await artifacts.putJson("seed", "signal", signal(), now), now, 168);
  const queued = transitionImprovementRun(observed, { type: "queued" }, { now, actor: "companion" }).run;
  const candidate = transitionImprovementRun(queued, {
    type: "candidate_ready",
    candidateVersion: "a".repeat(40),
    pullRequest: {
      repo: "WriterInternal/cerebro-slack-companion",
      number: 121,
      url: "https://github.com/WriterInternal/cerebro-slack-companion/pull/121",
      branch: "cerebro/improvement/run-1",
    },
  }, { now, actor: "worker" }).run;
  const evaluating = transitionImprovementRun(candidate, {
    type: "evaluation_started",
    evaluatorVersion: "evaluator-b",
    ciReceipt: ciReceipt(await artifacts.putJson(observed.id, "ci", { state: "passed" }, now)),
  }, { now, actor: "evaluator" }).run;
  const evaluationArtifact = await artifacts.putJson(observed.id, "evaluation", { releaseReady: true }, now);
  if (evaluationArtifact.kind !== "evaluation") throw new Error("test evaluation artifact kind mismatch");
  const evaluationReceipt = { ...evaluationArtifact, kind: "evaluation" as const };
  const shadowing = transitionImprovementRun(evaluating, {
    type: "evaluation_recorded",
    evaluation: {
      corpusPartition: "held_out",
      candidateVersion: "a".repeat(40),
      evaluatorVersion: "evaluator-b",
      releaseReady: true,
      caseCount: 25,
      passRate: 1,
      averageScore: 1,
      correctionClosureRate: 1,
      regressionRate: 0,
      blockers: [],
      artifact: evaluationReceipt,
    },
  }, { now, actor: "evaluator" }).run;
  const shadowArtifact = await artifacts.putJson(observed.id, "shadow", { success: true }, now);
  const canary = transitionImprovementRun(shadowing, {
    type: "shadow_recorded",
    candidateVersion: "a".repeat(40),
    outcome: { stage: "shadow", success: true, sampleSize: 25, errorRate: 0, artifact: shadowArtifact },
  }, { now, actor: "evaluator" }).run;
  const canaryArtifact = await artifacts.putJson(observed.id, "canary", { success: true }, now);
  const awaiting = transitionImprovementRun(canary, {
    type: "canary_recorded",
    candidateVersion: "a".repeat(40),
    outcome: { stage: "canary", success: true, sampleSize: 25, errorRate: 0, artifact: canaryArtifact },
  }, { now, actor: "evaluator" }).run;
  await store.create(awaiting, { ...initialImprovementEvent(observed), type: "seed_awaiting_promotion", toStatus: "awaiting_promotion" });

  const worker = new ImprovementWorker(workerConfig(), {
    store,
    artifacts,
    kms: { send: async () => ({ SignatureValid: true }) },
    now: () => now,
    pullRequests: {
      sourceList: async () => ({ ok: true, resolved_ref: "a".repeat(40), entries: [] }),
      sourceRead: async () => ({ ok: true, resolved_ref: "a".repeat(40), files: [] }),
      createPullRequest: async () => ({ ok: false }),
      pullRequestStatus: async () => ({
        ok: true,
        repo: "WriterInternal/cerebro-slack-companion",
        pull_request: {
          number: 121,
          head_sha: "b".repeat(40),
          state: "open",
          draft: true,
          merged: false,
          head_ref: "cerebro/improvement/run-1",
          head_repo: "WriterInternal/cerebro-slack-companion",
        },
        checks: {
          check_runs: [{ name: "test", status: "completed", conclusion: "success" }],
          statuses: [],
        },
      }),
    },
  });

  await assert.rejects(worker.handle({
    schemaVersion: 1,
    kind: "promotion_decision",
    payload: {
      runId: awaiting.id,
      candidateVersion: "a".repeat(40),
      decision: "promote",
      reason: "All gates passed.",
      reviewedBy: "operator",
      reviewedAt: now.toISOString(),
      sourceRef: "https://github.com/WriterInternal/cerebro-slack-companion/actions/runs/1",
      candidateReceipt: candidateReceiptFromStatus(githubStatus("b".repeat(40), passingChecks())),
    },
    signature: "a".repeat(80),
  }), /changed after held-out evaluation/);
  assert.equal((await store.get(awaiting.id))?.status, "awaiting_promotion");
});

async function candidateFixture(): Promise<{
  now: Date;
  store: InMemoryImprovementRunStore;
  artifacts: InMemoryImprovementArtifactStore;
  run: ImprovementRun;
}> {
  const store = new InMemoryImprovementRunStore();
  const artifacts = new InMemoryImprovementArtifactStore();
  const now = new Date("2026-07-14T18:00:00.000Z");
  const observed = newImprovementRun(signal(), await artifacts.putJson("seed", "signal", signal(), now), now, 168);
  const queued = transitionImprovementRun(observed, { type: "queued" }, { now, actor: "companion" }).run;
  const run = transitionImprovementRun(queued, {
    type: "candidate_ready",
    candidateVersion: "a".repeat(40),
    pullRequest: {
      repo: "WriterInternal/cerebro-slack-companion",
      number: 121,
      url: "https://github.com/WriterInternal/cerebro-slack-companion/pull/121",
      branch: "cerebro/improvement/run-1",
    },
  }, { now, actor: "worker" }).run;
  await store.create(run, { ...initialImprovementEvent(observed), type: "seed_candidate_ready", toStatus: "candidate_ready" });
  return { now, store, artifacts, run };
}

function evaluationWorker(
  fixture: { store: InMemoryImprovementRunStore; artifacts: InMemoryImprovementArtifactStore; now?: Date },
  pullRequestStatus: () => Promise<Record<string, unknown>>,
  jobs?: InMemoryImprovementJobQueue,
): ImprovementWorker {
  const worker = new ImprovementWorker(workerConfig(), {
    store: fixture.store,
    artifacts: fixture.artifacts,
    jobs,
    kms: { send: async () => ({ SignatureValid: true }) },
    now: () => fixture.now ?? new Date("2026-07-14T18:00:00.000Z"),
    pullRequests: {
      sourceList: async () => ({ ok: true, resolved_ref: "a".repeat(40), entries: [] }),
      sourceRead: async () => ({ ok: true, resolved_ref: "a".repeat(40), files: [] }),
      createPullRequest: async () => ({ ok: false }),
      pullRequestStatus,
    },
  });
  const handle = worker.handle.bind(worker);
  worker.handle = async (job) => handle(job.kind === "evaluate_candidate"
    ? { ...job, candidateReceipt: candidateReceiptFromStatus(await pullRequestStatus(), fixture.now) }
    : job);
  return worker;
}

function evaluationJob(
  run: ImprovementRun,
  corpusArtifact: ImprovementArtifact,
): Extract<ImprovementJob, { kind: "evaluate_candidate" }> {
  if (corpusArtifact.kind !== "corpus") throw new Error("Expected a corpus artifact.");
  return {
    schemaVersion: 1,
    kind: "evaluate_candidate",
    runId: run.id,
    candidateVersion: run.candidateVersion ?? "",
    evaluatorVersion: "evaluator-b",
    requiredChecks: ["test", "architecture"],
    corpusArtifact: { ...corpusArtifact, kind: "corpus" },
    candidateReceipt: candidateReceiptFromStatus(githubStatus(run.candidateVersion ?? "", passingChecks())),
    receiptSignature: "a".repeat(80),
  };
}

function candidateReceiptFromStatus(raw: Record<string, unknown>, observedAt = new Date("2026-07-14T18:00:00.000Z")): ImprovementCandidateReceipt {
  const status = raw as any;
  const pull = status.pull_request;
  return {
    schemaVersion: 1,
    repo: status.repo,
    pullRequestNumber: pull.number,
    pullRequestUrl: "https://github.com/WriterInternal/cerebro-slack-companion/pull/121",
    state: pull.state,
    draft: pull.draft,
    merged: pull.merged,
    headRepo: pull.head_repo,
    headRef: pull.head_ref,
    headSha: pull.head_sha,
    baseRef: "main",
    baseSha: "d".repeat(40),
    requiredChecks: ["test", "architecture"],
    checks: status.checks.check_runs.map((check: any) => ({
      name: check.name,
      source: "check_run" as const,
      status: check.status,
      conclusion: check.conclusion ?? "pending",
    })),
    observedAt: observedAt.toISOString(),
  };
}

function githubStatus(
  headSha: string,
  checkRuns: Array<{ name: string; status: string; conclusion: string | null }>,
  pullRequest: Partial<{
    number: number;
    state: string;
    draft: boolean;
    merged: boolean;
    head_ref: string;
    head_repo: string;
  }> = {},
): Record<string, unknown> {
  return {
    ok: true,
    repo: "WriterInternal/cerebro-slack-companion",
    pull_request: {
      number: 121,
      head_sha: headSha,
      state: "open",
      draft: true,
      merged: false,
      head_ref: "cerebro/improvement/run-1",
      head_repo: "WriterInternal/cerebro-slack-companion",
      ...pullRequest,
    },
    checks: { check_runs: checkRuns, statuses: [] },
  };
}

function passingChecks(): Array<{ name: string; status: string; conclusion: string }> {
  return [
    { name: "test", status: "completed", conclusion: "success" },
    { name: "architecture", status: "completed", conclusion: "success" },
  ];
}

function passingReplayCases(): unknown[] {
  return Array.from({ length: 25 }, (_, index) => ({
    id: `ci-receipt-${index}`,
    question: "No, f-1 is already resolved. Check again.",
    expected: {
      executionLanes: ["lookup"],
      requiredToolsAnyOf: ["finding_lookup"],
      requiredEvidenceRefs: ["finding:f-1"],
      outcome: "respond",
      correctionRequired: true,
    },
    candidate: {
      answer: {
        answer: "Finding f-1 is resolved.",
        messages: ["You are right. Finding f-1 is resolved."],
        keyPoints: [],
        evidence: ["finding:f-1"],
        actionsTaken: [],
        nextActions: [],
        research: ["finding_lookup"],
        memoryUpdates: [],
        source: "flue",
        executionLane: "lookup",
        delivery: "respond",
      },
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
  }));
}

function ciReceipt(artifact: ImprovementArtifact): ImprovementCiReceipt {
  if (artifact.kind !== "ci") throw new Error("Expected a CI artifact.");
  return {
    repo: "WriterInternal/cerebro-slack-companion",
    pullRequestNumber: 121,
    headSha: "a".repeat(40),
    requiredChecks: ["test"],
    checks: [{ name: "test", source: "check_run", status: "completed", conclusion: "success" }],
    successful: true,
    verifiedAt: "2026-07-14T18:00:00.000Z",
    artifact: { ...artifact, kind: "ci" },
  };
}

function authoredCandidate(runId: string, repo: string, baseRef: string) {
  return {
    pullRequest: {
      repo,
      title: "Repair action closure",
      files: [
        { path: "src/work/example.ts", content: "export const repaired = true;\n" },
        { path: "test/example.test.ts", content: "// focused regression\n" },
      ],
      branch: `cerebro/improvement/${runId}`,
      base: baseRef,
      draft: true,
    },
    resolvedRef: "d".repeat(40),
    sourceCallCount: 2,
    sourceReceipts: [
      { path: "src/work/example.ts", sha: "e".repeat(40), bytes: 30 },
      { path: "test/example.test.ts", sha: "f".repeat(40), bytes: 22 },
    ],
  };
}

function candidatePullRequestResult(input: RuntimeCodePrInput, head: string): Record<string, unknown> {
  return {
    ok: true,
    repo: input.repo,
    branch: input.branch,
    pull_request: {
      number: 122,
      url: "https://github.com/WriterInternal/cerebro-slack-companion/pull/122",
      head_sha: head.repeat(40),
    },
  };
}

function candidateRecoveryState(input: RuntimeCodePrInput): Record<string, unknown> {
  return {
    ok: true,
    repo: input.repo,
    branch: input.branch,
    branch_exists: true,
    head_sha: "a".repeat(40),
    head_parent_shas: [input.expectedHeadSha],
    head_changed_paths: input.files.map((file) => file.path),
    head_changes: input.files.map((file) => ({ path: file.path, status: "modified" })),
    head_changed_paths_truncated: false,
    pull_requests: [{
      number: 122,
      url: "https://github.com/WriterInternal/cerebro-slack-companion/pull/122",
      title: input.title,
      body: runtimePullRequestBody(input),
      state: "open",
      draft: true,
      merged: false,
      head_ref: input.branch,
      head_sha: "a".repeat(40),
      head_repo: input.repo,
      base_ref: input.base,
      base_sha: input.expectedBaseSha,
    }],
    pull_requests_truncated: false,
    files: input.files.map((file) => ({ ok: true, path: file.path, content: file.content })),
  };
}

function candidatePullRequests(createPullRequest: (input: RuntimeCodePrInput) => Promise<Record<string, unknown>>) {
  return {
    sourceList: async () => ({ ok: true, resolved_ref: "d".repeat(40), entries: [] }),
    sourceRead: async () => ({ ok: true, resolved_ref: "d".repeat(40), files: [] }),
    createPullRequest,
    pullRequestStatus: async () => githubStatus("a".repeat(40), passingChecks()),
  };
}

function workerConfig() {
  return {
    lane: "all" as const,
    tableName: "improvement",
    artifactBucket: "test-improvement",
    queueUrl: "https://sqs.us-east-1.amazonaws.com/123/improvement",
    promotionKeyId: "alias/promotion",
    evidenceKeyId: "alias/evidence",
    delegationKeyId: "alias/delegation",
    delegationPolicyVersion: "cerebro-improvement-author-v1",
    delegationToolsetVersion: "candidate-author-v1",
    pollIntervalMs: 1_000,
    staleRunHours: 72,
    author: {
      provider: "amazon-bedrock",
      model: "us.anthropic.claude-opus-4-8",
      thinkingLevel: "medium" as const,
      timeoutMs: 300_000,
      maxSourceCalls: 8,
    },
    code: {
      enabled: true,
      workspaceDir: "/tmp/improvement-test",
      defaultRepo: "WriterInternal/cerebro-slack-companion",
      repoPathPrefix: "",
      writeAllowedOrgs: new Set(["WriterInternal"]),
      branchPrefix: "cerebro/improvement",
      maxFileBytes: 120_000,
      maxFiles: 12,
      shellEnabled: false,
      shellTimeoutMs: 1_000,
      shellMaxOutputBytes: 1_000,
      shellMaxCommandBytes: 1_000,
    },
  };
}

function signedDelegation(
  run: ImprovementRun,
  signalSha: string,
  mode: "disabled" | "shadow" | "canary" | "active" = "active",
): SignedImprovementDelegation {
  return {
    manifest: {
      schemaVersion: 1,
      manifestId: `delegation-${"a".repeat(32)}`,
      issuer: "cerebro-improvement-control-plane",
      runId: run.id,
      generation: run.authorGeneration ?? 1,
      jobKind: "author_candidate",
      inputSignalShas: [signalSha],
      repo: "WriterInternal/cerebro-slack-companion",
      baseRef: "main",
      baseSha: "d".repeat(40),
      sourceSha: "d".repeat(40),
      authority: ["repository:read", "pull_request:draft"],
      budgets: {
        maxFiles: 6,
        maxFileBytes: 120_000,
        maxTotalBytes: 200_000,
        maxSourceCalls: 8,
        maxRuntimeMs: 300_000,
      },
      policyVersion: "cerebro-improvement-author-v1",
      toolsetVersion: "candidate-author-v1",
      rollout: { mode, cohortBucket: 5_000, canaryBasisPoints: 1_000 },
      issuedAt: "2026-07-14T18:00:00.000Z",
      notBefore: "2026-07-14T17:59:30.000Z",
      expiresAt: "2026-07-14T18:20:00.000Z",
    },
    signature: "a".repeat(80),
  };
}

function signal(): ImprovementSignal {
  return {
    signature: "self-repair:self-improvement:did-not-act",
    source: "answer_gap",
    issueKind: "did-not-act",
    skillId: "self-improvement",
    occurredAt: "2026-07-14T18:00:00.000Z",
    toolNames: [],
    evidenceCount: 0,
    actionCount: 0,
    commitmentStates: [],
  };
}
