import assert from "node:assert/strict";
import test from "node:test";
import { InMemoryImprovementArtifactStore } from "../src/improvement/artifacts.js";
import {
  assertDelegationFresh,
  delegationExecutionDecision,
  deterministicCohortBucket,
  KmsImprovementDelegationIssuer,
} from "../src/improvement/delegation.js";
import { newImprovementRun, transitionImprovementRun } from "../src/improvement/state-machine.js";
import type { ImprovementDelegationManifest, ImprovementSignal } from "../src/improvement/types.js";

test("delegation issuer binds immutable source, authority, budgets, lifetime, and deterministic cohort", async () => {
  const now = new Date("2026-07-14T18:00:00.000Z");
  const artifacts = new InMemoryImprovementArtifactStore();
  const signalArtifact = await artifacts.putJson("seed", "signal", signal(), now);
  const observed = newImprovementRun(signal(), signalArtifact, now, 168);
  const run = transitionImprovementRun(observed, {
    type: "author_requested",
    inputSignalShas: [signalArtifact.sha256],
    repo: "WriterInternal/cerebro-slack-companion",
    baseRef: "main",
  }, { now, actor: "companion" }).run;
  const commands: unknown[] = [];
  const issuer = new KmsImprovementDelegationIssuer({
    keyId: "alias/delegation",
    defaultRepo: "WriterInternal/cerebro-slack-companion",
    rolloutMode: "canary",
    canaryBasisPoints: 2_500,
    ttlSeconds: 1_200,
    policyVersion: "cerebro-improvement-author-v1",
    toolsetVersion: "candidate-author-v1",
    budgets: {
      maxFiles: 6,
      maxFileBytes: 120_000,
      maxTotalBytes: 200_000,
      maxSourceCalls: 8,
      maxRuntimeMs: 300_000,
    },
  }, {
    sourceList: async ({ repo, ref }) => ({ ok: true, repo, requested_ref: ref, resolved_ref: "d".repeat(40), entries: [] }),
    sourceRead: async () => ({ ok: true, files: [] }),
  }, {
    now: () => now,
    kms: { send: async (command) => { commands.push(command); return { Signature: Buffer.alloc(64, 7) }; } },
  });

  const delegation = await issuer.issue({ run, request: run.authorRequest! });

  assert.equal(commands.length, 1);
  assert.equal(delegation.manifest.repo, "WriterInternal/cerebro-slack-companion");
  assert.equal(delegation.manifest.baseSha, "d".repeat(40));
  assert.equal(delegation.manifest.sourceSha, "d".repeat(40));
  assert.deepEqual(delegation.manifest.authority, ["repository:read", "pull_request:draft"]);
  assert.equal(delegation.manifest.rollout.cohortBucket, deterministicCohortBucket(
    `${run.id}:1:WriterInternal/cerebro-slack-companion:${"d".repeat(40)}`,
  ));
  assert.equal(Date.parse(delegation.manifest.expiresAt) - Date.parse(delegation.manifest.issuedAt), 1_200_000);
  assert.ok(delegation.signature.length >= 80);
});

test("rollout decisions are deterministic and expired delegations fail closed", () => {
  const manifest: ImprovementDelegationManifest = {
    schemaVersion: 1 as const,
    manifestId: `delegation-${"a".repeat(32)}`,
    issuer: "cerebro-improvement-control-plane" as const,
    runId: "improvement-0123456789abcdef01234567",
    generation: 1,
    jobKind: "author_candidate" as const,
    inputSignalShas: ["b".repeat(64)],
    repo: "WriterInternal/cerebro-slack-companion",
    baseRef: "main",
    baseSha: "c".repeat(40),
    sourceSha: "c".repeat(40),
    authority: ["repository:read", "pull_request:draft"],
    budgets: { maxFiles: 6, maxFileBytes: 120_000, maxTotalBytes: 200_000, maxSourceCalls: 8, maxRuntimeMs: 300_000 },
    policyVersion: "cerebro-improvement-author-v1",
    toolsetVersion: "candidate-author-v1",
    rollout: { mode: "canary" as const, cohortBucket: 2_500, canaryBasisPoints: 2_500 },
    issuedAt: "2026-07-14T18:00:00.000Z",
    notBefore: "2026-07-14T17:59:30.000Z",
    expiresAt: "2026-07-14T18:20:00.000Z",
  };

  assert.equal(delegationExecutionDecision(manifest), "shadow");
  assert.equal(delegationExecutionDecision({ ...manifest, rollout: { ...manifest.rollout, cohortBucket: 2_499 } }), "execute");
  assert.equal(delegationExecutionDecision({ ...manifest, rollout: { ...manifest.rollout, mode: "active" } }), "execute");
  assert.equal(delegationExecutionDecision({ ...manifest, rollout: { ...manifest.rollout, mode: "disabled" } }), "shadow");
  assert.throws(() => assertDelegationFresh(manifest, new Date("2026-07-14T18:20:00.000Z")), /not active/);
});

function signal(): ImprovementSignal {
  return {
    signature: "self-repair:self-improvement:delegation-test",
    source: "answer_gap",
    issueKind: "delegation-test",
    skillId: "self-improvement",
    occurredAt: "2026-07-14T18:00:00.000Z",
    toolNames: [],
    evidenceCount: 0,
    actionCount: 0,
    commitmentStates: [],
  };
}
