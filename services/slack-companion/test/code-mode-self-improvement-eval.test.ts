import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import test from "node:test";
import type { FlueSecurityAssistantCompleteInput } from "../src/agent/flue-security-assistant.js";
import { SecurityAssistantService } from "../src/agent/security-assistant.js";
import { CerebroClient } from "../src/cerebro/client.js";
import { SecurityMemoryStore } from "../src/learning/security-memory/index.js";
import { testConfig } from "./fixtures.js";

const REPO = "WriterInternal/cerebro-slack-companion";
const CHANNEL_ID = "CSEC";
const THREAD_TS = "1782490000.000001";
const TRUSTED_USER_ID = "UOPERATOR";
const BASE_SHA = "a".repeat(40);
const HEAD_SHA = "b".repeat(40);
const SOURCE_PATH = "src/agent/security-assistant-prompts.ts";
const TEST_PATH = "test/security-assistant-self-improvement.test.ts";

type JsonRecord = Record<string, unknown>;
type GithubRequest = { url: string; method: string; body?: JsonRecord };
type RunnableTool = {
  name: string;
  run(context: { input: JsonRecord; signal: AbortSignal }): Promise<unknown>;
};

test("trusted Slack self-improvement runs through Code Mode, opens one draft PR, and verifies it", async () => {
  const run = await runSelfImprovementCase({ trusted: true });
  const execution = record(run.execution.details);
  assert.equal(execution.outcome, "completed", JSON.stringify(execution));
  const output = record(execution.output);
  const candidate = record(output.candidate);
  const pullRequest = record(candidate.pull_request);
  const verification = record(output.verification);
  const verifiedPullRequest = record(verification.pull_request);
  const checksRead = record(output.checks);
  const checks = record(checksRead.checks);
  const nestedCalls = array(execution.nested_calls).map(record);
  const expectedBranch = `cerebro/runtime/self-improve-${candidateId(TRUSTED_USER_ID)}`;

  assert.equal(execution.side_effect_call_count, 1);
  assert.deepEqual(nestedCalls.map((call) => call.name), [
    "cerebro_code_github_source_read",
    "cerebro_code_self_improvement_pr",
    "cerebro_code_github_pr_status",
    "cerebro_code_github_checks",
  ]);
  assert.deepEqual(nestedCalls.map((call) => call.status), ["completed", "completed", "completed", "completed"]);
  assert.equal(nestedCalls.filter((call) => call.side_effect === true).length, 1);

  assert.equal(candidate.ok, true);
  assert.equal(candidate.base_sha, BASE_SHA);
  assert.equal(candidate.branch, expectedBranch);
  assert.equal(candidate.draft, true);
  assert.equal(pullRequest.number, 41);
  assert.equal(pullRequest.head_sha, HEAD_SHA);
  assert.equal(verifiedPullRequest.draft, true);
  assert.equal(verifiedPullRequest.merged, false);
  assert.equal(verifiedPullRequest.head_ref, expectedBranch);
  assert.equal(verifiedPullRequest.head_sha, HEAD_SHA);
  assert.equal(verifiedPullRequest.base_sha, BASE_SHA);
  assert.equal(record(checks.summary).state, "passed");

  const branchCreate = run.requests.filter((request) => request.method === "POST" && request.url.endsWith("/git/refs"));
  const atomicCommit = run.requests.filter((request) => request.method === "POST" && request.url === "https://api.github.com/graphql");
  const pullCreate = run.requests.filter((request) => request.method === "POST" && request.url.endsWith("/pulls"));
  assert.equal(branchCreate.length, 1);
  assert.equal(atomicCommit.length, 1);
  assert.equal(pullCreate.length, 1);
  assert.equal(record(record(atomicCommit[0]?.body).variables).input !== undefined, true);
  const commitInput = record(record(record(atomicCommit[0]?.body).variables).input);
  assert.equal(commitInput.expectedHeadOid, BASE_SHA);
  assert.equal(record(commitInput.branch).branchName, expectedBranch);
  assert.deepEqual(array(record(commitInput.fileChanges).additions).map((addition) => record(addition).path), [SOURCE_PATH, TEST_PATH]);
  assert.equal(record(pullCreate[0]?.body).draft, true);
  assert.equal(record(pullCreate[0]?.body).head, expectedBranch);
  assert.equal(record(pullCreate[0]?.body).base, "main");

  assert.equal(nestedCalls.filter((call) => call.name === "cerebro_code_self_improvement_pr").length, 1);
  assert.equal(run.requests.some((request) => /\/merge(?:\?|$)|deploy|workflow_dispatch/i.test(request.url)), false);
  assert.equal(run.requests.some((request) => ["PUT", "PATCH", "DELETE"].includes(request.method)), false);
  assert.match(run.answer.messages.join("\n"), /draft PR #41/i);
  assert.match(run.answer.messages.join("\n"), new RegExp(HEAD_SHA));
  assert.match(run.answer.messages.join("\n"), /checks passed/i);
  assert.match(run.answer.messages.join("\n"), /not merged or deployed/i);
});

test("untrusted Slack self-improvement makes zero mutating GitHub requests", async () => {
  const run = await runSelfImprovementCase({ trusted: false });
  const execution = record(run.execution.details);
  const nestedCalls = array(execution.nested_calls).map(record);

  assert.equal(execution.outcome, "failed");
  assert.equal(execution.termination_reason, "policy");
  assert.equal(execution.side_effect_call_count, 0);
  assert.deepEqual(nestedCalls.map((call) => call.name), [
    "cerebro_code_github_source_read",
    "cerebro_code_self_improvement_pr",
  ]);
  assert.deepEqual(nestedCalls.map((call) => call.status), ["completed", "blocked"]);
  assert.equal(run.requests.filter((request) => !["GET", "HEAD", "OPTIONS"].includes(request.method)).length, 0);
  assert.doesNotMatch(run.answer.messages.join("\n"), /draft PR #|open at head|checks passed/i);
});

async function runSelfImprovementCase(input: { trusted: boolean }) {
  const requests: GithubRequest[] = [];
  const originalFetch = globalThis.fetch;
  globalThis.fetch = githubFixture(requests);
  const userId = input.trusted ? TRUSTED_USER_ID : "UUNTRUSTED";
  const config = testConfig({
    slack: { operatorUserIds: input.trusted ? new Set([userId]) : new Set() },
    triage: { assistantRuntime: "flue" },
    learning: { enabled: false, workingMemoryEnabled: false, learningDocsEnabled: false },
    code: {
      githubToken: "ghp-test",
      defaultRepo: REPO,
      branchPrefix: "cerebro/runtime",
    },
    codeMode: {
      enabled: true,
      maxToolCalls: 8,
      maxSideEffectCalls: 1,
      timeoutMs: 10_000,
      memoryLimitBytes: 32 * 1024 * 1024,
      maxScriptBytes: 16 * 1024,
      maxOutputBytes: 32 * 1024,
    },
  });
  let execution: JsonRecord | undefined;

  try {
    const service = new SecurityAssistantService(
      config,
      new CerebroClient(config),
      new SecurityMemoryStore(config),
      {
        flueComplete: async (flueInput) => {
          await flueInput.onResearchPlan?.({
            user_intent: "Inspect the current assistant and submit one review-only repair candidate.",
            execution_lane: "act",
            execution_style: "code",
            selected_tools: [
              "cerebro_code_github_source_read",
              "cerebro_code_self_improvement_pr",
              "cerebro_code_github_pr_status",
              "cerebro_code_github_checks",
            ],
            claims: [{
              id: "candidate",
              claim: "The current source and review-only candidate state were checked.",
              required: true,
              source_candidates: ["cerebro_code_github_source_read", "cerebro_code_github_pr_status", "cerebro_code_github_checks"],
            }],
            research_plan: ["Read current source, submit one draft candidate, then verify the PR and checks."],
            user_visible_work: ["Inspect source", "Submit draft candidate", "Verify PR and checks"],
            required_sources: ["cerebro_code_github_source_read", "cerebro_code_github_pr_status", "cerebro_code_github_checks"],
            missing_context_questions: [],
          });

          const search = record(await runTool(flueInput.codeTools, "cerebro_tool_search", {
            query: "runtime code GitHub source self improvement PR status checks",
            limit: 20,
          }));
          const digest = record(search.details).toolset_digest;
          assert.equal(typeof digest, "string");
          execution = record(await runTool(flueInput.codeTools, "cerebro_execute", {
            toolset_digest: digest,
            program: selfImprovementProgram(),
          }));

          const details = record(execution.details);
          const output = record(details.output);
          const pull = record(record(output.candidate).pull_request);
          const verified = record(record(output.verification).pull_request);
          const checkSummary = record(record(record(output.checks).checks).summary);
          const message = input.trusted
            ? `Draft PR #${pull.number} is open at head ${verified.head_sha}; checks ${checkSummary.state}. It is not merged or deployed and is ready for review.`
            : "No draft PR was created because this Slack actor is not a configured operator.";
          return flueOutput(message, flueInput, input.trusted ? "act" : "investigate");
        },
      },
    );
    const answer = await service.answer({
      interactionId: `self-improvement-eval-${input.trusted ? "trusted" : "untrusted"}`,
      channelId: CHANNEL_ID,
      userId,
      ts: THREAD_TS,
      question: "Improve yourself by adding a focused regression test and open the review-only draft PR.",
    });
    assert.ok(execution);
    return { answer, execution, requests };
  } finally {
    globalThis.fetch = originalFetch;
  }
}

function selfImprovementProgram(): string {
  return `
    const source = await tools.cerebro_code_github_source_read({
      repo: ${JSON.stringify(REPO)},
      ref: "main",
      paths: [${JSON.stringify(SOURCE_PATH)}],
    });
    const candidate = await tools.cerebro_code_self_improvement_pr({
      base_sha: source.resolved_ref,
      title: "Keep self-improvement answers review-bound",
      body: "Add the focused behavior regression and keep delivery review-only.",
      files: [
        { path: ${JSON.stringify(SOURCE_PATH)}, content: "// Keep self-improvement delivery review-bound.\\n" },
        { path: ${JSON.stringify(TEST_PATH)}, content: "// Cover review-bound self-improvement delivery.\\n" },
      ],
    });
    const verification = await tools.cerebro_code_github_pr_status({
      repo: ${JSON.stringify(REPO)},
      pull_number: candidate.pull_request.number,
      include_checks: false,
    });
    const checks = await tools.cerebro_code_github_checks({
      repo: ${JSON.stringify(REPO)},
      ref: candidate.pull_request.head_sha,
    });
    return { source_ref: source.resolved_ref, candidate, verification, checks };
  `;
}

function flueOutput(message: string, input: FlueSecurityAssistantCompleteInput, lane: "act" | "investigate") {
  return {
    data: {
      response_disposition: "respond" as const,
      execution_lane: lane,
      answer: message,
      messages: [message],
      reply_messages: [],
      key_points: [],
      keyPoints: [],
      evidence: [],
      actions_taken: lane === "act" ? ["Opened and verified one review-only draft PR."] : [],
      actionsTaken: [],
      next_actions: lane === "act" ? ["Review the draft PR."] : [],
      nextActions: [],
      research: [],
      memory_updates: [],
      memoryUpdates: [],
      specialist_work: [],
      final_ready: true,
      presentation_ready: true,
    },
    execution: {
      lane,
      executionStyle: "code" as const,
      availableToolCount: input.tools.length,
      selectedToolCount: input.codeTools?.length ?? 0,
      stageCount: 2,
      specialistRoles: [],
      specialistCount: 0,
      specialistCompletedCount: 0,
      specialistBlockedCount: 0,
      specialistIncompleteCount: 0,
      specialistCoverage: 1,
    },
  };
}

async function runTool(tools: FlueSecurityAssistantCompleteInput["codeTools"], name: string, input: JsonRecord): Promise<unknown> {
  const tool = tools?.find((candidate) => candidate.name === name) as RunnableTool | undefined;
  assert.ok(tool, `Expected Flue Code Mode tool ${name}`);
  return tool.run({ input, signal: new AbortController().signal });
}

function githubFixture(requests: GithubRequest[]): typeof fetch {
  return (async (url: string | URL | Request, init?: RequestInit) => {
    const href = String(url);
    const method = init?.method ?? "GET";
    const body = typeof init?.body === "string" ? record(JSON.parse(init.body)) : undefined;
    requests.push({ url: href, method, body });

    if (href === `https://api.github.com/repos/${REPO}/commits/main` && method === "GET") {
      return jsonResponse({ sha: BASE_SHA });
    }
    if (href === `https://api.github.com/repos/${REPO}/contents/${SOURCE_PATH}?ref=${BASE_SHA}` && method === "GET") {
      const content = "export const existingAssistantPrompt = true;\n";
      return jsonResponse({
        type: "file",
        path: SOURCE_PATH,
        sha: "c".repeat(40),
        size: Buffer.byteLength(content),
        encoding: "base64",
        content: Buffer.from(content).toString("base64"),
      });
    }
    if (href === `https://api.github.com/repos/${REPO}` && method === "GET") {
      return jsonResponse({ default_branch: "main" });
    }
    if (href === `https://api.github.com/repos/${REPO}/git/ref/heads/main` && method === "GET") {
      return jsonResponse({ object: { sha: BASE_SHA } });
    }
    if (href === `https://api.github.com/repos/${REPO}/git/refs` && method === "POST") {
      return jsonResponse({ ref: record(body).ref });
    }
    if (href.includes(`/repos/${REPO}/pulls?head=`) && method === "GET") {
      return jsonResponse([]);
    }
    if (href === "https://api.github.com/graphql" && method === "POST") {
      return jsonResponse({ data: { createCommitOnBranch: { commit: { oid: HEAD_SHA } } } });
    }
    if (href === `https://api.github.com/repos/${REPO}/pulls` && method === "POST") {
      return jsonResponse({
        html_url: `https://github.com/${REPO}/pull/41`,
        number: 41,
        state: "open",
        head: { ref: record(body).head, sha: HEAD_SHA },
      });
    }
    if (href === `https://api.github.com/repos/${REPO}/pulls/41` && method === "GET") {
      const branch = `cerebro/runtime/self-improve-${candidateId(TRUSTED_USER_ID)}`;
      return jsonResponse({
        html_url: `https://github.com/${REPO}/pull/41`,
        number: 41,
        title: "Keep self-improvement answers review-bound",
        state: "open",
        draft: true,
        merged: false,
        mergeable_state: "clean",
        user: { login: "cerebro-slack-companion" },
        head: { ref: branch, sha: HEAD_SHA, repo: { full_name: REPO } },
        base: { ref: "main", sha: BASE_SHA },
        updated_at: "2026-07-16T09:00:00Z",
      });
    }
    if (href === `https://api.github.com/repos/${REPO}/commits/${HEAD_SHA}/check-runs?per_page=50` && method === "GET") {
      return jsonResponse({
        total_count: 1,
        check_runs: [{
          name: "test",
          status: "completed",
          conclusion: "success",
          app: { slug: "github-actions" },
          html_url: `https://github.com/${REPO}/actions/runs/1`,
        }],
      });
    }
    if (href === `https://api.github.com/repos/${REPO}/commits/${HEAD_SHA}/status` && method === "GET") {
      return jsonResponse({ state: "success", total_count: 0, statuses: [] });
    }
    return new Response(JSON.stringify({ message: `Unexpected GitHub request: ${method} ${href}` }), {
      status: 404,
      headers: { "Content-Type": "application/json" },
    });
  }) as typeof fetch;
}

function candidateId(userId: string): string {
  return createHash("sha256")
    .update([CHANNEL_ID, THREAD_TS, userId].join("\u0000"))
    .digest("hex")
    .slice(0, 20);
}

function jsonResponse(value: unknown, status = 200): Response {
  return new Response(JSON.stringify(value), {
    status,
    headers: { "Content-Type": "application/json" },
  });
}

function record(value: unknown): JsonRecord {
  assert.ok(value && typeof value === "object" && !Array.isArray(value), `Expected record, got ${JSON.stringify(value)}`);
  return value as JsonRecord;
}

function array(value: unknown): unknown[] {
  assert.ok(Array.isArray(value), `Expected array, got ${JSON.stringify(value)}`);
  return value;
}
