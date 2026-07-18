import assert from "node:assert/strict";
import test from "node:test";
import { InMemoryImprovementArtifactStore } from "../src/improvement/artifacts.js";
import { ImprovementControlPlane } from "../src/improvement/control-plane.js";
import { InMemoryImprovementJobQueue } from "../src/improvement/queue.js";
import {
  initialImprovementEvent,
  newImprovementRun,
  transitionImprovementRun,
} from "../src/improvement/state-machine.js";
import { InMemoryImprovementRunStore } from "../src/improvement/store.js";
import { improvementJobSchema, type ImprovementArtifact, type ImprovementCiReceipt, type ImprovementEvaluation, type ImprovementEvent, type ImprovementOutcome, type ImprovementRun, type ImprovementSignal, type SignedImprovementDelegation } from "../src/improvement/types.js";

test("recursive improvement accumulates redacted signals and queues one private candidate boundary", async () => {
  const store = new InMemoryImprovementRunStore();
  const artifacts = new InMemoryImprovementArtifactStore();
  const queue = new InMemoryImprovementJobQueue();
  const now = () => new Date("2026-07-14T18:00:00.000Z");
  const controlPlane = new ImprovementControlPlane({
    store,
    artifacts,
    queue,
    signalThreshold: 2,
    cooldownHours: 168,
    now,
    delegations: testDelegationIssuer(now),
  });
  const candidate = {
    repo: "WriterInternal/cerebro-slack-companion",
    baseRef: "main",
  };

  const first = await controlPlane.observe(signal("first request with token=abc123"), candidate);
  const second = await controlPlane.observe(signal("second request with token=def456", "2026-07-14T18:01:00.000Z"), candidate);

  assert.equal(first?.status, "observed");
  assert.equal(second?.status, "queued");
  assert.equal(second?.signalCount, 2);
  assert.equal(queue.jobs.length, 1);
  assert.equal(queue.jobs[0]?.job.kind, "author_candidate");
  if (queue.jobs[0]?.job.kind === "author_candidate") {
    assert.equal(queue.jobs[0].job.repo, "WriterInternal/cerebro-slack-companion");
    assert.equal(queue.jobs[0].job.baseRef, "main");
    assert.equal(queue.jobs[0].job.generation, 1);
    assert.equal(queue.jobs[0].job.inputSignalShas?.length, 2);
    assert.ok(queue.jobs[0].job.delegation);
    assert.deepEqual(Object.keys(queue.jobs[0].job).sort(), ["baseRef", "delegation", "generation", "inputSignalShas", "kind", "repo", "runId", "schemaVersion"]);
  }
  assert.equal(second?.authorGeneration, 1);
  assert.equal(second?.authorDispatch?.generation, 1);
  assert.equal(second?.authorRequest?.repo, "WriterInternal/cerebro-slack-companion");
  assert.doesNotMatch(JSON.stringify(queue.jobs), /first request|second request|abc123|def456|"files"/);
  const storedSignals = [...artifacts.values.values()] as ImprovementSignal[];
  assert.equal(storedSignals.length, 2);
  assert.doesNotMatch(storedSignals[0]?.question ?? "", /abc123/);
  assert.equal(storedSignals[0]?.channelHash, "0123456789abcdef");
});

test("queued reply signals supersede the author generation while duplicate observations stay idempotent", async () => {
  const store = new InMemoryImprovementRunStore();
  const artifacts = new InMemoryImprovementArtifactStore();
  const queue = new InMemoryImprovementJobQueue();
  const controlPlane = new ImprovementControlPlane({
    store,
    artifacts,
    queue,
    signalThreshold: 1,
    cooldownHours: 168,
    now: () => new Date("2026-07-14T18:00:00.000Z"),
  });
  const candidate = { repo: "WriterInternal/cerebro-slack-companion", baseRef: "main" };

  const firstSignal = signal("first reply gap");
  const first = await controlPlane.observe(firstSignal, candidate);
  const duplicate = await controlPlane.observe(firstSignal, candidate);
  const second = await controlPlane.observe(signal("follow-up reply changed the expected result", "2026-07-14T18:01:00.000Z"), candidate);

  assert.equal(first?.authorGeneration, 1);
  assert.equal(duplicate?.authorGeneration, 1);
  assert.equal(queue.jobs.length, 2);
  assert.equal(second?.authorGeneration, 2);
  assert.equal(second?.authorRequest?.generation, 2);
  assert.equal(second?.authorRequest?.inputSignalShas.length, 2);
  assert.equal(queue.jobs[1]?.job.kind, "author_candidate");
  if (queue.jobs[1]?.job.kind !== "author_candidate") throw new Error("Expected superseding author job.");
  assert.equal(queue.jobs[1].job.generation, 2);
  assert.deepEqual(queue.jobs[1].job.inputSignalShas, second?.authorInputSignalShas);
});

test("concurrent first observations retain both distinct signals and queue one author generation", async () => {
  const store = new ConcurrentFirstObservationStore();
  const artifacts = new RecordingImprovementArtifactStore();
  const queue = new InMemoryImprovementJobQueue();
  const controlPlane = new ImprovementControlPlane({
    store,
    artifacts,
    queue,
    signalThreshold: 2,
    cooldownHours: 168,
    now: () => new Date("2026-07-14T18:00:00.000Z"),
  });
  const candidate = { repo: "WriterInternal/cerebro-slack-companion", baseRef: "main" };

  const observations = await Promise.all([
    controlPlane.observe(signal("first concurrent observation"), candidate),
    controlPlane.observe(signal("second concurrent observation", "2026-07-14T18:01:00.000Z"), candidate),
  ]);
  const runId = observations[0]?.id ?? observations[1]?.id;
  assert.ok(runId);
  const run = await store.get(runId);
  const expectedSignalShas = artifacts.signalArtifacts.map((artifact) => artifact.sha256).sort();

  assert.equal(run?.status, "queued");
  assert.equal(run?.signalCount, 2);
  assert.equal(run?.authorGeneration, 1);
  assert.deepEqual([...run?.authorInputSignalShas ?? []].sort(), expectedSignalShas);
  assert.equal(store.events.filter((event) => event.type === "author_requested").length, 1);
  assert.equal(queue.jobs.length, 1);
  assert.equal(queue.jobs[0]?.job.kind, "author_candidate");
  if (queue.jobs[0]?.job.kind !== "author_candidate") throw new Error("Expected one author candidate job.");
  assert.equal(queue.jobs[0].job.generation, 1);
  assert.deepEqual([...(queue.jobs[0].job.inputSignalShas ?? [])].sort(), expectedSignalShas);
});

test("concurrent duplicate first observations remain one recorded signal", async () => {
  const store = new ConcurrentFirstObservationStore();
  const artifacts = new InMemoryImprovementArtifactStore();
  const queue = new InMemoryImprovementJobQueue();
  const controlPlane = new ImprovementControlPlane({
    store,
    artifacts,
    queue,
    signalThreshold: 2,
    cooldownHours: 168,
    now: () => new Date("2026-07-14T18:00:00.000Z"),
  });
  const duplicate = signal("same concurrent observation");
  const candidate = { repo: "WriterInternal/cerebro-slack-companion", baseRef: "main" };

  const observations = await Promise.all([
    controlPlane.observe(duplicate, candidate),
    controlPlane.observe(duplicate, candidate),
  ]);
  const runId = observations[0]?.id ?? observations[1]?.id;
  assert.ok(runId);
  const run = await store.get(runId);

  assert.equal(run?.status, "observed");
  assert.equal(run?.signalCount, 1);
  assert.equal(run?.artifacts.filter((artifact) => artifact.kind === "signal").length, 1);
  assert.equal(store.events.filter((event) => event.type === "signal_recorded").length, 0);
  assert.equal(queue.jobs.length, 0);
});

test("a stale two-signal author request cannot overwrite a newer three-signal generation", async () => {
  const store = new StaleAuthorRequestStore();
  const artifacts = new RecordingImprovementArtifactStore();
  const queue = new InMemoryImprovementJobQueue();
  const controlPlane = new ImprovementControlPlane({
    store,
    artifacts,
    queue,
    signalThreshold: 2,
    cooldownHours: 168,
    now: () => new Date("2026-07-14T18:00:00.000Z"),
  });
  const candidate = { repo: "WriterInternal/cerebro-slack-companion", baseRef: "main" };
  await controlPlane.observe(signal("first observation"), candidate);

  const staleObservation = controlPlane.observe(signal("second observation", "2026-07-14T18:01:00.000Z"), candidate);
  await store.waitForStaleRequest();
  await controlPlane.observe(signal("third observation", "2026-07-14T18:02:00.000Z"), candidate);
  store.releaseStaleRequest();
  await staleObservation;

  const run = [...store.runs.values()][0];
  const expectedSignalShas = artifacts.signalArtifacts.map((artifact) => artifact.sha256).sort();
  assert.equal(run?.signalCount, 3);
  assert.equal(run?.authorGeneration, 1);
  assert.deepEqual([...(run?.authorInputSignalShas ?? [])].sort(), expectedSignalShas);
  assert.deepEqual([...(run?.authorRequest?.inputSignalShas ?? [])].sort(), expectedSignalShas);
  assert.equal(queue.jobs.length, 1);
  assert.equal(queue.jobs[0]?.job.kind, "author_candidate");
  if (queue.jobs[0]?.job.kind !== "author_candidate") throw new Error("Expected one author candidate job.");
  assert.equal(queue.jobs[0].job.generation, 1);
  assert.deepEqual([...(queue.jobs[0].job.inputSignalShas ?? [])].sort(), expectedSignalShas);
});

test("promotion requires held-out evaluation, separate evaluator, shadow, canary, and reviewed approval", () => {
  const now = new Date("2026-07-14T18:00:00.000Z");
  const run = newImprovementRun(signal("gap"), artifact("signal", "1"), now, 168);
  assert.equal(initialImprovementEvent(run).toStatus, "observed");
  const queued = transitionImprovementRun(run, { type: "queued" }, { now, actor: "companion" }).run;
  const candidate = transitionImprovementRun(queued, {
    type: "candidate_ready",
    candidateVersion: "a".repeat(40),
    pullRequest: { repo: "WriterInternal/cerebro-slack-companion", number: 120, url: "https://github.com/WriterInternal/cerebro-slack-companion/pull/120", branch: "candidate-a" },
  }, { now, actor: "worker" }).run;

  assert.throws(() => transitionImprovementRun(candidate, {
    type: "evaluation_started",
    evaluatorVersion: "a".repeat(40),
    ciReceipt: ciReceipt(),
  }, { now, actor: "evaluator" }), /must be different/);

  const evaluating = transitionImprovementRun(candidate, {
    type: "evaluation_started",
    evaluatorVersion: "evaluator-b",
    ciReceipt: ciReceipt(),
  }, { now, actor: "evaluator" }).run;
  assert.throws(() => transitionImprovementRun(evaluating, {
    type: "evaluation_recorded",
    evaluation: { ...evaluation(), artifact: artifact("signal", "2") } as ImprovementEvaluation,
  }, { now, actor: "evaluator" }), /evaluation artifact/);
  const shadowing = transitionImprovementRun(evaluating, { type: "evaluation_recorded", evaluation: evaluation() }, { now, actor: "evaluator" }).run;
  assert.throws(() => transitionImprovementRun(shadowing, {
    type: "shadow_recorded",
    candidateVersion: "a".repeat(40),
    outcome: { ...outcome("shadow"), artifact: artifact("canary", "3") },
  }, { now, actor: "evaluator" }), /shadow artifact/);
  const canary = transitionImprovementRun(shadowing, { type: "shadow_recorded", candidateVersion: "a".repeat(40), outcome: outcome("shadow") }, { now, actor: "evaluator" }).run;
  const awaiting = transitionImprovementRun(canary, { type: "canary_recorded", candidateVersion: "a".repeat(40), outcome: outcome("canary") }, { now, actor: "evaluator" }).run;
  const promoted = transitionImprovementRun(awaiting, {
    type: "promoted",
    candidateVersion: "a".repeat(40),
    approval: {
      reviewedBy: "operator",
      reviewedAt: now.toISOString(),
      sourceRef: "https://github.com/WriterInternal/cerebro-slack-companion/actions/runs/1",
      reason: "Held-out, shadow, and canary gates passed.",
      signingKeyId: "alias/promotion",
      signature: "a".repeat(80),
    },
  }, { now, actor: "promotion_controller" }).run;

  assert.equal(shadowing.status, "shadowing");
  assert.equal(canary.status, "canary");
  assert.equal(awaiting.status, "awaiting_promotion");
  assert.equal(promoted.status, "promoted");
});

test("candidate queue jobs reject payloads above the bounded SQS envelope", () => {
  assert.throws(() => improvementJobSchema.parse({
    schemaVersion: 1,
    kind: "open_candidate_pr",
    runId: "improvement-0123456789abcdef01234567",
    pullRequest: {
      title: "Oversized candidate",
      files: [
        { path: "docs/one.md", content: "a".repeat(110_000) },
        { path: "docs/two.md", content: "b".repeat(110_000) },
      ],
    },
  }), /200000-byte queue payload limit/);
});

test("a human outcome preserves the same draft and immutable candidate source while invalidating release evidence", () => {
  const now = new Date("2026-07-14T18:00:00.000Z");
  const observed = newImprovementRun(signal("gap"), artifact("signal", "1"), now, 168);
  const queued = {
    ...transitionImprovementRun(observed, { type: "queued" }, { now, actor: "companion" }).run,
    assistance: {
      channelId: "CSEC",
      intendedUserId: "UUSER",
      expiresAt: "2026-07-17T18:00:00.000Z",
      deliveryStatus: "pending" as const,
    },
  };
  const candidate = transitionImprovementRun(queued, {
    type: "candidate_ready",
    candidateVersion: "a".repeat(40),
    pullRequest: { repo: "WriterInternal/cerebro-slack-companion", number: 120, url: "https://github.com/WriterInternal/cerebro-slack-companion/pull/120", branch: "candidate-a" },
  }, { now, actor: "worker" }).run;
  const evaluating = transitionImprovementRun(candidate, {
    type: "evaluation_started",
    evaluatorVersion: "evaluator-b",
    ciReceipt: ciReceipt(),
  }, { now, actor: "evaluator" }).run;
  const shadowing = transitionImprovementRun(evaluating, { type: "evaluation_recorded", evaluation: evaluation() }, { now, actor: "evaluator" }).run;
  const canary = transitionImprovementRun(shadowing, { type: "shadow_recorded", candidateVersion: "a".repeat(40), outcome: outcome("shadow") }, { now, actor: "evaluator" }).run;
  const awaiting = transitionImprovementRun(canary, { type: "canary_recorded", candidateVersion: "a".repeat(40), outcome: outcome("canary") }, { now, actor: "evaluator" }).run;
  const outcomeArtifact = artifact("signal", "9") as ImprovementArtifact & { kind: "signal" };
  const refined = transitionImprovementRun(awaiting, {
    type: "refinement_requested",
    artifact: outcomeArtifact,
    inputSignalShas: [observed.artifacts[0]!.sha256, outcomeArtifact.sha256],
    repo: "WriterInternal/cerebro-slack-companion",
    baseRef: "main",
  }, { now, actor: "companion" }).run;

  assert.equal(refined.status, "queued");
  assert.equal(refined.pullRequest?.number, 120);
  assert.equal(refined.pullRequest?.branch, "candidate-a");
  assert.equal(refined.authorRequest?.baseRef, "main");
  assert.equal(refined.authorGeneration, 1);
  assert.equal(refined.refinementBaseVersion, "a".repeat(40));
  assert.equal(refined.candidateVersion, undefined);
  assert.equal(refined.ciReceipt, undefined);
  assert.equal(refined.evaluation, undefined);
  assert.equal(refined.shadowOutcome, undefined);
  assert.equal(refined.canaryOutcome, undefined);
  assert.deepEqual(refined.blockers, []);
});

test("interaction ledger joins a redacted human answer to later structured feedback", async () => {
  const artifacts = new InMemoryImprovementArtifactStore();
  const controlPlane = new ImprovementControlPlane({
    store: new InMemoryImprovementRunStore(),
    artifacts,
    queue: new InMemoryImprovementJobQueue(),
    signalThreshold: 2,
    cooldownHours: 168,
  });
  await controlPlane.recordInteraction({
    interactionId: "1111111111111111",
    answerHash: "abcdef0123456789",
    channelHash: "0123456789abcdef",
    threadHash: "2222222222222222",
    occurredAt: "2026-07-14T18:00:00.000Z",
    question: "Check token=xoxb-demo",
    answer: "The token=xoxb-demo check failed.",
    answerSource: "flue",
    toolNames: ["runtime_status"],
    evidenceCount: 1,
    actionCount: 0,
    commitmentStates: ["in_progress"],
    deliveryComplete: true,
  });
  await controlPlane.recordFeedbackOutcome({
    interactionId: "1111111111111111",
    answerHash: "abcdef0123456789",
    occurredAt: "2026-07-14T18:05:00.000Z",
    vote: "down",
    reason: "incorrect",
    providedBy: { slackUserId: "UUSER", displayName: "Jonathan Haas" },
  });
  await controlPlane.recordContextExposure({
    interactionId: "1111111111111111",
    occurredAt: "2026-07-14T17:59:00.000Z",
    requester: { slackUserId: "UUSER" },
    channelHash: "0123456789abcdef",
    threadHash: "2222222222222222",
    selectorVersion: "assistant-feedback-v4",
    treatment: "context",
    candidateClaimIds: ["corr-123456789012"],
    selectedClaims: [{ claimId: "corr-123456789012", kind: "task_correction", scope: "same_thread", relevanceScore: 100 }],
    promptIncluded: true,
    promptCharCount: 240,
  });
  await controlPlane.recordOutcomeEvent({
    interactionId: "1111111111111111",
    answerHash: "abcdef0123456789",
    occurredAt: "2026-07-14T18:01:00.000Z",
    type: "delivery",
    result: "complete",
    confidence: 1,
  });

  const values = [...artifacts.values.values()] as Array<Record<string, unknown>>;
  assert.equal(values.length, 4);
  assert.doesNotMatch(JSON.stringify(values), /xoxb-demo/);
  assert.equal(values.some((value) => value.vote === "down" && value.answerHash === "abcdef0123456789"), true);
  assert.equal(values.some((value) => (value.providedBy as Record<string, unknown> | undefined)?.displayName === "Jonathan Haas"), true);
  assert.equal(values.every((value) => value.interactionId === "1111111111111111"), true);
  assert.equal(values.some((value) => value.selectorVersion === "assistant-feedback-v4"), true);
});

function signal(question: string, occurredAt = "2026-07-14T18:00:00.000Z"): ImprovementSignal {
  return {
    signature: "self-repair:self-improvement:did-not-act",
    source: "feedback_downvote",
    issueKind: "did-not-act",
    skillId: "self-improvement",
    occurredAt,
    channelHash: "0123456789abcdef",
    question,
    toolNames: [],
    evidenceCount: 0,
    actionCount: 0,
    commitmentStates: [],
  };
}

function testDelegationIssuer(now: () => Date) {
  return {
    issue: async (input: { run: ImprovementRun; request: NonNullable<ImprovementRun["authorRequest"]> }): Promise<SignedImprovementDelegation> => ({
      manifest: {
        schemaVersion: 1,
        manifestId: `delegation-${"a".repeat(32)}`,
        issuer: "cerebro-improvement-control-plane",
        runId: input.run.id,
        generation: input.request.generation,
        jobKind: "author_candidate",
        inputSignalShas: input.request.inputSignalShas,
        repo: input.request.repo ?? "WriterInternal/cerebro-slack-companion",
        baseRef: input.request.baseRef,
        baseSha: "d".repeat(40),
        sourceSha: "d".repeat(40),
        authority: ["repository:read", "pull_request:draft"],
        budgets: { maxFiles: 6, maxFileBytes: 120_000, maxTotalBytes: 200_000, maxSourceCalls: 8, maxRuntimeMs: 300_000 },
        policyVersion: "cerebro-improvement-author-v1",
        toolsetVersion: "candidate-author-v1",
        rollout: { mode: "active", cohortBucket: 1, canaryBasisPoints: 1_000 },
        issuedAt: now().toISOString(),
        notBefore: new Date(now().getTime() - 30_000).toISOString(),
        expiresAt: new Date(now().getTime() + 1_200_000).toISOString(),
      },
      signature: "a".repeat(80),
    }),
  };
}

class ConcurrentFirstObservationStore extends InMemoryImprovementRunStore {
  private initialGetCount = 0;
  private releaseInitialGets: (() => void) | undefined;
  private readonly initialGetsReady = new Promise<void>((resolve) => {
    this.releaseInitialGets = resolve;
  });

  override async get(runId: string) {
    if (this.initialGetCount < 2) {
      this.initialGetCount += 1;
      if (this.initialGetCount === 2) this.releaseInitialGets?.();
      await this.initialGetsReady;
      return undefined;
    }
    return super.get(runId);
  }
}

class RecordingImprovementArtifactStore extends InMemoryImprovementArtifactStore {
  readonly signalArtifacts: ImprovementArtifact[] = [];

  override async putJson(runId: string, kind: ImprovementArtifact["kind"], value: unknown, now?: Date): Promise<ImprovementArtifact> {
    const stored = await super.putJson(runId, kind, value, now);
    if (kind === "signal") this.signalArtifacts.push(stored);
    return stored;
  }
}

class StaleAuthorRequestStore extends InMemoryImprovementRunStore {
  private staleRequestEntered!: () => void;
  private readonly staleRequestReady = new Promise<void>((resolve) => { this.staleRequestEntered = resolve; });
  private releaseRequest!: () => void;
  private readonly requestRelease = new Promise<void>((resolve) => { this.releaseRequest = resolve; });
  private paused = false;

  waitForStaleRequest(): Promise<void> {
    return this.staleRequestReady;
  }

  releaseStaleRequest(): void {
    this.releaseRequest();
  }

  override async commit(previousVersion: number, run: ImprovementRun, event: ImprovementEvent): Promise<void> {
    if (!this.paused && event.type === "author_requested" && run.authorInputSignalShas?.length === 2) {
      this.paused = true;
      this.staleRequestEntered();
      await this.requestRelease;
    }
    await super.commit(previousVersion, run, event);
  }
}

function artifact<K extends ImprovementArtifact["kind"]>(kind: K, suffix: string): ImprovementArtifact & { kind: K } {
  return {
    kind,
    uri: `s3://test-improvement/${kind}-${suffix}.json`,
    sha256: suffix.padEnd(64, "0").slice(0, 64),
    createdAt: "2026-07-14T18:00:00.000Z",
  };
}

function evaluation(): ImprovementEvaluation {
  return {
    corpusPartition: "held_out",
    candidateVersion: "a".repeat(40),
    evaluatorVersion: "evaluator-b",
    releaseReady: true,
    caseCount: 25,
    passRate: 1,
    averageScore: 0.95,
    correctionClosureRate: 1,
    regressionRate: 0,
    blockers: [],
    artifact: artifact("evaluation", "2"),
  };
}

function ciReceipt(): ImprovementCiReceipt {
  return {
    repo: "WriterInternal/cerebro-slack-companion",
    pullRequestNumber: 120,
    headSha: "a".repeat(40),
    requiredChecks: ["test"],
    checks: [{ name: "test", source: "check_run", status: "completed", conclusion: "success" }],
    successful: true,
    verifiedAt: "2026-07-14T18:00:00.000Z",
    artifact: artifact("ci", "5"),
  };
}

function outcome(stage: ImprovementOutcome["stage"]): ImprovementOutcome {
  return {
    stage,
    success: true,
    sampleSize: 50,
    helpfulRate: 0.9,
    errorRate: 0,
    artifact: artifact(stage, stage === "shadow" ? "3" : "4"),
  };
}
