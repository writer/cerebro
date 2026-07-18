import assert from "node:assert/strict";
import test from "node:test";
import type { AgentTool } from "@earendil-works/pi-agent-core";
import { ModelImprovementCandidateAuthor, type ImprovementCandidateSource } from "../src/improvement/candidate-author.js";
import { newImprovementRun } from "../src/improvement/state-machine.js";
import type { ImprovementArtifact, ImprovementSignal } from "../src/improvement/types.js";

const resolvedRef = "a".repeat(40);

test("candidate author binds source reads to one immutable ref and returns a draft source plus test repair", async () => {
  const calls: Array<{ kind: string; ref: string; paths?: string[] }> = [];
  const source = candidateSource(calls);
  const author = new ModelImprovementCandidateAuthor(workerConfig(), {
    source,
    runAgent: async ({ tools, userPrompt }) => {
      assert.doesNotMatch(userPrompt, /U09GFTUDY1Y|C0BJ7JD5L3A|Jonathan Haas|0123456789abcdef|abcdef0123456789|1784183855\.454569/);
      assert.match(userPrompt, /\[slack-reference\]|\[slack-timestamp\]/);
      await sourceRead(tools).execute("read", { paths: ["src/work/example.ts", "test/example.test.ts"] });
      return JSON.stringify(validCandidate());
    },
  });

  const result = await author.author(authorInput());

  assert.equal(result.pullRequest.draft, true);
  assert.match(result.pullRequest.branch ?? "", /^cerebro\/improvement\/did-not-act-[a-f0-9]{12}$/);
  assert.doesNotMatch(JSON.stringify(result.pullRequest), new RegExp(authorInput().run.id));
  assert.equal(result.resolvedRef, resolvedRef);
  assert.equal(result.sourceCallCount, 2);
  assert.deepEqual(result.sourceReceipts.map((receipt) => receipt.path), ["src/work/example.ts", "test/example.test.ts"]);
  assert.deepEqual(calls.map((call) => call.ref), ["main", resolvedRef]);
  assert.deepEqual(result.pullRequest.files.map((file) => file.path), ["src/work/example.ts", "test/example.test.ts"]);
});

test("candidate author enforces the eight-call limit and refuses protected corpus reads", async () => {
  const calls: Array<{ kind: string; ref: string; paths?: string[] }> = [];
  const source = candidateSource(calls);
  const author = new ModelImprovementCandidateAuthor(workerConfig(), {
    source,
    runAgent: async ({ tools }) => {
      const read = sourceRead(tools);
      const protectedResult = await read.execute("protected", { paths: ["evals/assistant-hard-corpus.jsonl"] }) as { details?: Record<string, unknown> };
      assert.equal(protectedResult.details?.error, "protected_source_path");
      for (let index = 0; index < 8; index += 1) {
        const result = await read.execute(`read-${index}`, { paths: ["src/work/example.ts", "test/example.test.ts"] }) as { details?: Record<string, unknown> };
        if (index === 7) assert.equal(result.details?.error, "source_call_limit");
      }
      return JSON.stringify(validCandidate());
    },
  });

  const result = await author.author(authorInput());

  assert.equal(result.sourceCallCount, 8);
  assert.equal(calls.filter((call) => call.kind === "read").length, 7);
  assert.equal(calls.some((call) => call.paths?.includes("evals/assistant-hard-corpus.jsonl")), false);
});

test("candidate author applies per-delegation source and runtime budgets before tool execution", async () => {
  const calls: Array<{ kind: string; ref: string; paths?: string[] }> = [];
  const author = new ModelImprovementCandidateAuthor(workerConfig(), {
    source: candidateSource(calls),
    runAgent: async ({ tools, timeoutMs }) => {
      assert.equal(timeoutMs, 45_000);
      const read = sourceRead(tools);
      await read.execute("read", { paths: ["src/work/example.ts", "test/example.test.ts"] });
      const denied = await read.execute("read-again", { paths: ["src/work/example.ts"] }) as { details?: Record<string, unknown> };
      assert.equal(denied.details?.error, "source_call_limit");
      assert.equal(denied.details?.max_source_calls, 2);
      return JSON.stringify(validCandidate());
    },
  });

  const result = await author.author({ ...authorInput(), maxSourceCalls: 2, maxRuntimeMs: 45_000 });

  assert.equal(result.sourceCallCount, 2);
  assert.equal(calls.filter((call) => call.kind === "read").length, 1);
});

test("candidate author rejects private text, protected output paths, and candidates without a focused test", async () => {
  const variants = [
    {
      name: "private text",
      output: { ...validCandidate(), summary: "the production assistant repeated this exact private request wording" },
      error: /private signal text/,
    },
    {
      name: "protected path",
      output: {
        ...validCandidate(),
        files: [
          { path: "src/improvement/worker.ts", content: "export const bypass = true;\n" },
          validCandidate().files[1],
        ],
      },
      inspected: ["src/improvement/worker.ts", "test/example.test.ts"],
      error: /protected author, evaluator, policy, workflow, or infrastructure path/,
    },
    {
      name: "missing test",
      output: {
        ...validCandidate(),
        files: [
          validCandidate().files[0],
          { path: "src/work/second.ts", content: "export const second = true;\n" },
        ],
      },
      inspected: ["src/work/example.ts", "src/work/second.ts"],
      error: /focused test file/,
    },
    {
      name: "arbitrary extra path",
      output: {
        ...validCandidate(),
        files: [...validCandidate().files, { path: "package.json", content: "{}\n" }],
      },
      inspected: ["src/work/example.ts", "test/example.test.ts", "package.json"],
      error: /only source files and focused test files/,
    },
    {
      name: "unread new source",
      output: {
        ...validCandidate(),
        files: [
          ...validCandidate().files,
          { path: "src/work/new-helper.ts", content: "export const helper = true;\n" },
        ],
      },
      inspected: ["src/work/example.ts", "test/example.test.ts", "src/work/new-helper.ts"],
      missing: ["src/work/new-helper.ts"],
      error: /Every candidate source file must exist and be read/,
    },
  ];

  for (const variant of variants) {
    const source = candidateSource([], new Set(variant.missing ?? []));
    const author = new ModelImprovementCandidateAuthor(workerConfig(), {
      source,
      runAgent: async ({ tools }) => {
        await sourceRead(tools).execute("read", { paths: variant.inspected ?? ["src/work/example.ts", "test/example.test.ts"] });
        return JSON.stringify(variant.output);
      },
    });
    await assert.rejects(author.author(authorInput()), variant.error, variant.name);
  }
});

function candidateSource(
  calls: Array<{ kind: string; ref: string; paths?: string[] }>,
  missingPaths = new Set<string>(),
): ImprovementCandidateSource {
  return {
    sourceList: async (input) => {
      calls.push({ kind: "list", ref: input.ref });
      return {
        ok: true,
        repo: "WriterInternal/cerebro-slack-companion",
        requested_ref: input.ref,
        resolved_ref: resolvedRef,
        entries: [{ path: "src", type: "dir" }, { path: "test", type: "dir" }],
      };
    },
    sourceRead: async (input) => {
      calls.push({ kind: "read", ref: input.ref, paths: input.paths });
      return {
        ok: true,
        repo: "WriterInternal/cerebro-slack-companion",
        requested_ref: input.ref,
        resolved_ref: resolvedRef,
        files: input.paths.map((path: string, index: number) => missingPaths.has(path)
          ? { ok: false, error: "file_not_found", path }
          : {
              ok: true,
              path,
              sha: String(index + 1).repeat(40),
              bytes: Buffer.byteLength(`// current ${path}\n`, "utf8"),
              content: `// current ${path}\n`,
            }),
      };
    },
  };
}

function sourceRead(tools: AgentTool[]): AgentTool {
  const tool = tools.find((candidate) => candidate.name === "candidate_source_read");
  if (!tool) throw new Error("candidate source read tool missing");
  return tool;
}

function validCandidate() {
  return {
    summary: "Keep the work loop open until its result is durably recorded.",
    files: [
      { path: "src/work/example.ts", content: "export const repaired = true;\n" },
      { path: "test/example.test.ts", content: "import assert from \"node:assert/strict\";\nassert.equal(true, true);\n" },
    ],
  };
}

function authorInput() {
  const signal = improvementSignal();
  return {
    run: newImprovementRun(signal, artifact(), new Date(signal.occurredAt), 168),
    signals: [signal],
    repo: "WriterInternal/cerebro-slack-companion",
    baseRef: "main",
  };
}

function improvementSignal(): ImprovementSignal {
  return {
    signature: "self-repair:self-improvement:did-not-act",
    source: "answer_gap",
    issueKind: "did-not-act",
    skillId: "self-improvement",
    occurredAt: "2026-07-14T18:00:00.000Z",
    channelHash: "0123456789abcdef",
    answerHash: "abcdef0123456789",
    question: "the production assistant repeated this exact private request wording from <@U09GFTUDY1Y> in C0BJ7JD5L3A at 1784183855.454569",
    answer: "the private answer must stay out of the candidate pull request",
    providedBy: { slackUserId: "U09GFTUDY1Y", displayName: "Jonathan Haas" },
    toolNames: [],
    evidenceCount: 0,
    actionCount: 0,
    commitmentStates: [],
  };
}

function artifact(): ImprovementArtifact {
  return {
    kind: "signal",
    uri: "s3://test-improvement/runs/improvement/signal.json",
    sha256: "b".repeat(64),
    createdAt: "2026-07-14T18:00:00.000Z",
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
