import assert from "node:assert/strict";
import { mkdtempSync, rmSync } from "node:fs";
import { createServer } from "node:http";
import type { AddressInfo } from "node:net";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { RuntimeCodeGithubClient, runtimePullRequestBody } from "../src/code/runtime-code-github-client.js";
import { RuntimeCodeWorkspace } from "../src/code/runtime-code.js";
import { testConfig } from "./fixtures.js";

test("runtime code workspace writes, reads, and patches bounded files", () => {
  const directory = mkdtempSync(join(tmpdir(), "cerebro-code-"));
  try {
    const config = testConfig({
      code: { workspaceDir: directory },
    });
    const workspace = new RuntimeCodeWorkspace(config);

    const write = workspace.writeFile({ path: "skills/example.ts", content: "export const value = 1;\n" }) as any;
    assert.equal(write.ok, true);
    assert.match(write.diff, /export const value = 1/);

    const patch = workspace.patchFile({ path: "skills/example.ts", oldText: "value = 1", newText: "value = 2" }) as any;
    assert.equal(patch.ok, true);

    const read = workspace.readFile("skills/example.ts") as any;
    assert.equal(read.ok, true);
    assert.match(read.content, /value = 2/);

    const list = workspace.listFiles("skills") as any;
    assert.equal(list.ok, true);
    assert.equal(list.files[0].path, "skills/example.ts");
  } finally {
    rmSync(directory, { recursive: true, force: true });
  }
});

test("runtime code workspace searches and reads multiple files without shell", () => {
  const directory = mkdtempSync(join(tmpdir(), "cerebro-code-"));
  try {
    const config = testConfig({
      code: { workspaceDir: directory },
    });
    const workspace = new RuntimeCodeWorkspace(config);
    workspace.writeFile({ path: "agent/policy.ts", content: "export const policy = 'approval required';\n" });
    workspace.writeFile({ path: "agent/runner.ts", content: "export const runner = 'read first, then patch';\n" });

    const search = workspace.searchFiles({ query: "approval", prefix: "agent", maxResults: 5 }) as any;
    assert.equal(search.ok, true);
    assert.equal(search.match_count, 1);
    assert.equal(search.matches[0].path, "agent/policy.ts");
    assert.equal(search.matches[0].line_number, 1);

    const files = workspace.readMany({ paths: ["agent/policy.ts", "agent/runner.ts", "agent/policy.ts"] }) as any;
    assert.equal(files.ok, true);
    assert.equal(files.files.length, 2);
    assert.match(files.files[0].content, /approval required/);
    assert.match(files.files[1].content, /read first/);
  } finally {
    rmSync(directory, { recursive: true, force: true });
  }
});

test("runtime code workspace refuses secret paths and secret payloads", () => {
  const directory = mkdtempSync(join(tmpdir(), "cerebro-code-"));
  try {
    const config = testConfig({
      code: { workspaceDir: directory },
    });
    const workspace = new RuntimeCodeWorkspace(config);
    assert.equal((workspace.writeFile({ path: ".env", content: "A=B\n" }) as any).error, "secret_path_refused");
    assert.equal((workspace.writeFile({ path: "x.ts", content: "token=xoxb-abc\n" }) as any).error, "secret_like_content_refused");
  } finally {
    rmSync(directory, { recursive: true, force: true });
  }
});

test("runtime code status enables GitHub PRs with GitHub App auth", () => {
  const config = testConfig({
    code: {
      githubApp: {
        appId: "12345",
        installationId: "67890",
        privateKeyBase64: Buffer.from("test-private-key").toString("base64"),
      },
    },
  });
  const workspace = new RuntimeCodeWorkspace(config);
  const status = workspace.status() as any;
  assert.equal(status.github_pr_enabled, true);
  assert.equal(status.github_auth_mode, "app");
  assert.equal(status.github_read_scope, "any_repo");
  assert.deepEqual(status.write_allowed_orgs, ["Writer", "WriterColab", "WriterInternal"]);
});

test("runtime code PR creation reports missing GitHub auth", async () => {
  const config = testConfig();
  const workspace = new RuntimeCodeWorkspace(config);

  const result = await workspace.createGithubPullRequest({
    title: "Test PR",
    files: [{ path: "docs/example.md", content: "example\n" }],
  }) as any;

  assert.equal(result.ok, false);
  assert.equal(result.error, "github_auth_not_configured");
  assert.match(result.message, /GitHub App/);
});

test("runtime code reads GitHub PR and check status for any repo", async () => {
  const originalFetch = globalThis.fetch;
  const calls: string[] = [];
  globalThis.fetch = (async (url: string | URL | Request) => {
    const href = String(url);
    calls.push(href);
    if (href.endsWith("/repos/writer/cerebro/pulls/1567")) {
      return jsonResponse({
        html_url: "https://github.com/writer/cerebro/pull/1567",
        number: 1567,
        title: "Promote catalog sources to runtimes",
        state: "open",
        draft: false,
        merged: false,
        mergeable_state: "clean",
        updated_at: "2026-06-26T20:00:00Z",
        user: { login: "cerebro" },
        head: { ref: "codex/promote-catalog-sources", sha: "abc123", repo: { full_name: "writer/cerebro" } },
        base: { ref: "main", sha: "def456" },
      });
    }
    if (href.endsWith("/commits/abc123/check-runs?per_page=50")) {
      return jsonResponse({
        total_count: 2,
        check_runs: [
          { name: "test", status: "completed", conclusion: "success", html_url: "https://github.com/checks/1", app: { slug: "github-actions" } },
          { name: "lint", status: "in_progress", conclusion: null, html_url: "https://github.com/checks/2", app: { slug: "github-actions" } },
        ],
      });
    }
    if (href.endsWith("/commits/abc123/status")) {
      return jsonResponse({
        state: "pending",
        total_count: 1,
        statuses: [{ context: "legacy", state: "success", description: "ok", target_url: "https://github.com/status/1" }],
      });
    }
    return new Response("not found", { status: 404 });
  }) as typeof fetch;

  try {
    const workspace = new RuntimeCodeWorkspace(testConfig({
      code: { githubToken: "ghp-test" },
    }));
    const result = await workspace.githubPullRequestStatus({ repo: "writer/cerebro", pullNumber: 1567 }) as any;

    assert.equal(result.ok, true);
    assert.equal(result.repo, "writer/cerebro");
    assert.equal(result.pull_request.head_sha, "abc123");
    assert.equal(result.checks.summary.state, "pending");
    assert.equal(result.checks.summary.passed, 2);
    assert.equal(result.checks.summary.pending, 1);
    assert.equal(calls.some((href) => href.endsWith("/repos/writer/cerebro/pulls/1567")), true);
    assert.equal(calls.some((href) => href.endsWith("/commits/abc123/check-runs?per_page=50")), true);
  } finally {
    globalThis.fetch = originalFetch;
  }
});

test("runtime code GitHub check reads accept repo URLs and reject unsafe refs", async () => {
  const originalFetch = globalThis.fetch;
  const calls: string[] = [];
  globalThis.fetch = (async (url: string | URL | Request) => {
    const href = String(url);
    calls.push(href);
    if (href.endsWith("/commits/main/check-runs?per_page=50")) {
      return jsonResponse({ total_count: 0, check_runs: [] });
    }
    if (href.endsWith("/commits/main/status")) {
      return jsonResponse({ state: "success", total_count: 0, statuses: [] });
    }
    return new Response("not found", { status: 404 });
  }) as typeof fetch;
  const workspace = new RuntimeCodeWorkspace(testConfig({
    code: { githubToken: "ghp-test" },
  }));

  try {
    const result = await workspace.githubChecksStatus({ repo: "https://github.com/someone/else/pull/1", ref: "main" }) as any;
    assert.equal(result.ok, true);
    assert.equal(result.repo, "someone/else");
    assert.equal(calls.some((href) => href.endsWith("/repos/someone/else/commits/main/status")), true);
    assert.equal((await workspace.githubChecksStatus({ ref: "feature branch" }) as any).error, "invalid_ref");
  } finally {
    globalThis.fetch = originalFetch;
  }
});

test("runtime code lists and reads the monorepo service at an exact ref", async () => {
  const originalFetch = globalThis.fetch;
  const calls: string[] = [];
  const resolvedRef = "a".repeat(40);
  globalThis.fetch = (async (url: string | URL | Request) => {
    const href = String(url);
    calls.push(href);
    if (href.endsWith("/repos/writer/cerebro/commits/main")) {
      return jsonResponse({ sha: resolvedRef });
    }
    if (href.endsWith(`/repos/writer/cerebro/contents/services/slack-companion/src?ref=${resolvedRef}`)) {
      return jsonResponse([
        { path: "services/slack-companion/src/agent", type: "dir", sha: "dir-sha", size: 0 },
        { path: "services/slack-companion/src/index.ts", type: "file", sha: "file-sha", size: 24 },
      ]);
    }
    if (href.endsWith(`/repos/writer/cerebro/contents/services/slack-companion/src/index.ts?ref=${resolvedRef}`)) {
      const content = "export const ready = true;\n";
      return jsonResponse({
        path: "services/slack-companion/src/index.ts",
        type: "file",
        sha: "file-sha",
        size: Buffer.byteLength(content),
        encoding: "base64",
        content: Buffer.from(content).toString("base64"),
      });
    }
    return new Response("not found", { status: 404 });
  }) as typeof fetch;

  try {
    const workspace = new RuntimeCodeWorkspace(testConfig({ code: {
      githubToken: "ghp-test",
      defaultRepo: "writer/cerebro",
      repoPathPrefix: "services/slack-companion",
    } }));
    const listed = await workspace.githubSourceList({ repo: "writer/cerebro", ref: "main", path: "src" }) as any;
    const read = await workspace.githubSourceRead({ repo: "writer/cerebro", ref: "main", paths: ["src/index.ts"] }) as any;

    assert.equal(listed.ok, true);
    assert.equal(listed.requested_ref, "main");
    assert.equal(listed.resolved_ref, resolvedRef);
    assert.deepEqual(listed.entries.map((entry: any) => entry.path), ["src/agent", "src/index.ts"]);
    assert.equal(read.ok, true);
    assert.equal(read.requested_ref, "main");
    assert.equal(read.resolved_ref, resolvedRef);
    assert.equal(read.files[0].sha, "file-sha");
    assert.equal(read.files[0].content, "export const ready = true;\n");
    assert.equal(calls.filter((href) => href.endsWith("/commits/main")).length, 2);
    assert.equal(calls.filter((href) => href.includes("/contents/")).every((href) => href.endsWith(`?ref=${resolvedRef}`)), true);
  } finally {
    globalThis.fetch = originalFetch;
  }
});

test("runtime code GitHub source reads cap file count and decoded bytes", async () => {
  const originalFetch = globalThis.fetch;
  const calls: string[] = [];
  const resolvedRef = "b".repeat(40);
  globalThis.fetch = (async (url: string | URL | Request) => {
    const href = String(url);
    calls.push(href);
    if (href.endsWith("/repos/writer/cerebro/commits/abc123")) {
      return jsonResponse({ sha: resolvedRef });
    }
    const match = href.match(new RegExp(`/contents/src/file-(\\d+)\\.ts\\?ref=${resolvedRef}$`));
    if (!match) return new Response("not found", { status: 404 });
    const fileNumber = Number(match[1]);
    if (fileNumber === 1) {
      return jsonResponse({ path: "src/file-1.ts", type: "file", sha: "large", size: 120_001 });
    }
    const content = `export const value = ${fileNumber};\n`;
    return jsonResponse({
      path: `src/file-${fileNumber}.ts`,
      type: "file",
      sha: `sha-${fileNumber}`,
      size: Buffer.byteLength(content),
      encoding: "base64",
      content: Buffer.from(content).toString("base64"),
    });
  }) as typeof fetch;

  try {
    const workspace = new RuntimeCodeWorkspace(testConfig({ code: { githubToken: "ghp-test" } }));
    const result = await workspace.githubSourceRead({
      repo: "writer/cerebro",
      ref: "abc123",
      paths: Array.from({ length: 9 }, (_, index) => `src/file-${index + 1}.ts`),
    }) as any;

    assert.equal(result.ok, true);
    assert.equal(result.files.length, 8);
    assert.equal(result.files[0].error, "file_too_large");
    assert.equal(result.files[0].max_file_bytes, 120_000);
    assert.equal(result.truncated, true);
    assert.equal(calls.length, 9);
  } finally {
    globalThis.fetch = originalFetch;
  }
});

test("runtime code GitHub source reads refuse unsafe paths and binary content", async () => {
  const originalFetch = globalThis.fetch;
  const calls: string[] = [];
  const resolvedRef = "c".repeat(40);
  globalThis.fetch = (async (url: string | URL | Request) => {
    const href = String(url);
    calls.push(href);
    if (href.endsWith("/repos/writer/cerebro/commits/abc123")) {
      return jsonResponse({ sha: resolvedRef });
    }
    if (href.endsWith(`/contents/src/image.bin?ref=${resolvedRef}`)) {
      const content = Buffer.from([0xff, 0x00, 0x01]);
      return jsonResponse({
        path: "src/image.bin",
        type: "file",
        sha: "binary-sha",
        size: content.byteLength,
        encoding: "base64",
        content: content.toString("base64"),
      });
    }
    if (href.endsWith(`/contents/src/config.ts?ref=${resolvedRef}`)) {
      const content = Buffer.from(["api", "key=example-value"].join("_"));
      return jsonResponse({
        path: "src/config.ts",
        type: "file",
        sha: "config-sha",
        size: content.byteLength,
        encoding: "base64",
        content: content.toString("base64"),
      });
    }
    return new Response("not found", { status: 404 });
  }) as typeof fetch;

  try {
    const workspace = new RuntimeCodeWorkspace(testConfig({ code: { githubToken: "ghp-test" } }));
    assert.equal((await workspace.githubSourceRead({ repo: "writer/cerebro", ref: "abc123", paths: ["../secret.ts"] }) as any).error, "path_traversal_refused");
    assert.equal((await workspace.githubSourceRead({ repo: "writer/cerebro", ref: "abc123", paths: [".env"] }) as any).error, "secret_path_refused");
    assert.equal(calls.length, 0);

    const binary = await workspace.githubSourceRead({ repo: "writer/cerebro", ref: "abc123", paths: ["src/image.bin"] }) as any;
    assert.equal(binary.files[0].error, "binary_file_refused");
    assert.equal(calls.length, 2);

    const secretLike = await workspace.githubSourceRead({ repo: "writer/cerebro", ref: "abc123", paths: ["src/config.ts"] }) as any;
    assert.equal(secretLike.files[0].error, "secret_like_content_refused");
    assert.equal("content" in secretLike.files[0], false);
    assert.equal(calls.length, 4);
  } finally {
    globalThis.fetch = originalFetch;
  }
});

test("runtime code inspects all-state candidate PR metadata, commit provenance, and exact file content", async () => {
  const originalFetch = globalThis.fetch;
  const calls: string[] = [];
  const headSha = "a".repeat(40);
  const baseSha = "d".repeat(40);
  const branch = "cerebro/runtime/recovery";
  const body = runtimePullRequestBody({ body: "Persist the exact fix." });
  globalThis.fetch = (async (url: string | URL | Request) => {
    const href = String(url);
    calls.push(href);
    if (href.endsWith(`/git/ref/heads/${branch}`)) return jsonResponse({ object: { sha: headSha } });
    if (href.includes("/pulls?head=WriterInternal%3Acerebro%2Fruntime%2Frecovery&state=all&per_page=100")) {
      return jsonResponse([{
        number: 77,
        html_url: "https://github.com/WriterInternal/cerebro-slack-companion/pull/77",
        title: "Recover candidate write",
        body,
        state: "open",
        draft: true,
        merged: false,
        head: { ref: branch, sha: headSha, repo: { full_name: "WriterInternal/cerebro-slack-companion" } },
        base: { ref: "main", sha: baseSha },
      }]);
    }
    if (href.endsWith(`/commits/${headSha}?per_page=100`)) {
      return jsonResponse({
        sha: headSha,
        parents: [{ sha: baseSha }],
        files: [
          { filename: "src/fix.ts", status: "modified" },
          { filename: "test/fix.test.ts", status: "renamed", previous_filename: "test/old.test.ts" },
        ],
      });
    }
    const path = href.includes("/contents/src/fix.ts") ? "src/fix.ts" : "test/fix.test.ts";
    if (href.includes(`/contents/${path}?ref=${headSha}`)) {
      const content = path.startsWith("src/") ? "export const fixed = true;\n" : "// regression\n";
      return jsonResponse({ path, type: "file", sha: "f".repeat(40), size: Buffer.byteLength(content), encoding: "base64", content: Buffer.from(content).toString("base64") });
    }
    return new Response("not found", { status: 404 });
  }) as typeof fetch;

  try {
    const client = new RuntimeCodeGithubClient(testConfig({ code: { githubToken: "ghp-test", branchPrefix: "cerebro/runtime" } }));
    const result = await client.candidatePullRequestState({
      repo: "WriterInternal/cerebro-slack-companion",
      branch,
      paths: ["src/fix.ts", "test/fix.test.ts"],
    }) as any;

    assert.equal(result.ok, true);
    assert.equal(result.head_sha, headSha);
    assert.deepEqual(result.head_parent_shas, [baseSha]);
    assert.deepEqual(result.head_changes, [
      { path: "src/fix.ts", status: "modified" },
      { path: "test/fix.test.ts", status: "renamed", previous_path: "test/old.test.ts" },
    ]);
    assert.equal(result.pull_requests[0].title, "Recover candidate write");
    assert.equal(result.pull_requests[0].body, body);
    assert.equal(result.files[0].content, "export const fixed = true;\n");
    assert.equal(calls.some((href) => href.includes("&state=all&per_page=100")), true);
  } finally {
    globalThis.fetch = originalFetch;
  }
});

test("runtime code resumes branch-only and commit-only candidate writes without duplicating commits", async (context) => {
  for (const phase of ["branch-only", "commit-only"] as const) {
    await context.test(phase, async () => {
      const originalFetch = globalThis.fetch;
      const calls: Array<{ href: string; method: string; body?: any }> = [];
      const baseSha = "d".repeat(40);
      const candidateHeadSha = "a".repeat(40);
      const branch = "cerebro/runtime/recovery";
      let branchReads = 0;
      const pullRequest = {
        repo: "WriterInternal/cerebro-slack-companion",
        title: "Recover candidate write",
        body: "Persist the exact fix.",
        files: [{ path: "src/fix.ts", content: "export const fixed = true;\n" }],
        branch,
        base: "main",
        expectedBaseSha: baseSha,
        expectedHeadSha: baseSha,
        draft: true,
        draftBoundReuse: true,
      };
      globalThis.fetch = (async (url: string | URL | Request, init?: RequestInit) => {
        const href = String(url);
        const method = init?.method ?? "GET";
        const body = typeof init?.body === "string" ? JSON.parse(init.body) : undefined;
        calls.push({ href, method, body });
        if (href.endsWith("/git/ref/heads/main")) return jsonResponse({ object: { sha: baseSha } });
        if (href.endsWith(`/git/ref/heads/${branch}`)) {
          branchReads += 1;
          return jsonResponse({ object: { sha: phase === "branch-only" && branchReads === 1 ? baseSha : candidateHeadSha } });
        }
        if (href.includes("/pulls?head=") && href.includes("&state=all&per_page=100")) return jsonResponse([]);
        if (href === "https://api.github.com/graphql") {
          return jsonResponse({ data: { createCommitOnBranch: { commit: { oid: candidateHeadSha } } } });
        }
        if (href.endsWith("/pulls") && method === "POST") {
          return jsonResponse({
            number: 77,
            html_url: "https://github.com/WriterInternal/cerebro-slack-companion/pull/77",
            title: pullRequest.title,
            body: runtimePullRequestBody(pullRequest),
            state: "open",
            draft: true,
            merged: false,
            head: { ref: branch, sha: candidateHeadSha, repo: { full_name: pullRequest.repo } },
            base: { ref: "main", sha: baseSha },
          });
        }
        return new Response("not found", { status: 404 });
      }) as typeof fetch;

      try {
        const client = new RuntimeCodeGithubClient(testConfig({ code: { githubToken: "ghp-test", branchPrefix: "cerebro/runtime" } }));
        const result = await client.completeCandidatePullRequest({
          pullRequest,
          expectedCandidateHeadSha: phase === "branch-only" ? baseSha : candidateHeadSha,
        }) as any;
        assert.equal(result.ok, true);
        assert.equal(result.pull_request.head_sha, candidateHeadSha);
        assert.equal(calls.filter((call) => call.href === "https://api.github.com/graphql").length, phase === "branch-only" ? 1 : 0);
        assert.equal(calls.filter((call) => call.href.endsWith("/pulls") && call.method === "POST").length, 1);
      } finally {
        globalThis.fetch = originalFetch;
      }
    });
  }
});

test("runtime code candidate completion rejects moved, ambiguous, and metadata-mismatched boundaries", async (context) => {
  const baseSha = "d".repeat(40);
  const candidateHeadSha = "a".repeat(40);
  const branch = "cerebro/runtime/recovery";
  const pullRequest = {
    repo: "WriterInternal/cerebro-slack-companion",
    title: "Recover candidate write",
    body: "Persist the exact fix.",
    files: [{ path: "src/fix.ts", content: "export const fixed = true;\n" }],
    branch,
    base: "main",
    expectedBaseSha: baseSha,
    expectedHeadSha: baseSha,
    draft: true,
    draftBoundReuse: true,
  };
  const scenarios = [
    { name: "moved base", base: "e".repeat(40), head: candidateHeadSha, pulls: [], error: "base_sha_changed" },
    { name: "moved head", base: baseSha, head: "b".repeat(40), pulls: [], error: "self_improvement_candidate_head_changed" },
    { name: "existing PR history", base: baseSha, head: candidateHeadSha, pulls: [{ number: 76 }], error: "self_improvement_candidate_pr_ambiguous" },
    { name: "mismatched response metadata", base: baseSha, head: candidateHeadSha, pulls: [], responseBody: "wrong body", error: "candidate_pr_completion_mismatch" },
  ];
  for (const scenario of scenarios) {
    await context.test(scenario.name, async () => {
      const originalFetch = globalThis.fetch;
      const calls: Array<{ href: string; method: string }> = [];
      globalThis.fetch = (async (url: string | URL | Request, init?: RequestInit) => {
        const href = String(url);
        const method = init?.method ?? "GET";
        calls.push({ href, method });
        if (href.endsWith("/git/ref/heads/main")) return jsonResponse({ object: { sha: scenario.base } });
        if (href.endsWith(`/git/ref/heads/${branch}`)) return jsonResponse({ object: { sha: scenario.head } });
        if (href.includes("/pulls?head=") && href.includes("&state=all&per_page=100")) return jsonResponse(scenario.pulls);
        if (href.endsWith("/pulls") && method === "POST") {
          return jsonResponse({
            number: 77,
            html_url: "https://github.com/WriterInternal/cerebro-slack-companion/pull/77",
            title: pullRequest.title,
            body: scenario.responseBody ?? runtimePullRequestBody(pullRequest),
            state: "open",
            draft: true,
            merged: false,
            head: { ref: branch, sha: candidateHeadSha, repo: { full_name: pullRequest.repo } },
            base: { ref: "main", sha: baseSha },
          });
        }
        return new Response("not found", { status: 404 });
      }) as typeof fetch;
      try {
        const client = new RuntimeCodeGithubClient(testConfig({ code: { githubToken: "ghp-test", branchPrefix: "cerebro/runtime" } }));
        const result = await client.completeCandidatePullRequest({ pullRequest, expectedCandidateHeadSha: candidateHeadSha }) as any;
        assert.equal(result.error, scenario.error);
      } finally {
        globalThis.fetch = originalFetch;
      }
    });
  }
});

test("runtime code updates files before returning an existing runtime pull request", async () => {
  const originalFetch = globalThis.fetch;
  const calls: Array<{ href: string; method: string; body?: any }> = [];
  globalThis.fetch = (async (url: string | URL | Request, init?: RequestInit) => {
    const href = String(url);
    const method = init?.method ?? "GET";
    const body = typeof init?.body === "string" ? JSON.parse(init.body) : undefined;
    calls.push({ href, method, body });
    if (href.endsWith("/git/ref/heads/main") && method === "GET") {
      return jsonResponse({ object: { sha: "base-sha" } });
    }
    if (href.endsWith("/git/refs") && method === "POST") {
      return new Response(JSON.stringify({ message: "Reference already exists" }), { status: 422 });
    }
    if (href.includes("/pulls?head=WriterInternal%3Acerebro%2Fruntime%2Fretry&state=open&per_page=100")) {
      return jsonResponse([{
        number: 41,
        html_url: "https://github.com/WriterInternal/cerebro-slack-companion/pull/41",
        state: "open",
        head: { sha: "old-head" },
      }]);
    }
    if (href.endsWith("/contents/src/fix.ts?ref=cerebro%2Fruntime%2Fretry") && method === "GET") {
      return jsonResponse({ sha: "old-file" });
    }
    if (href.endsWith("/contents/src/fix.ts") && method === "PUT") {
      return jsonResponse({ content: { sha: "new-file" } });
    }
    if (href.endsWith("/git/ref/heads/cerebro/runtime/retry") && method === "GET") {
      return jsonResponse({ object: { sha: "new-head" } });
    }
    return new Response("not found", { status: 404 });
  }) as typeof fetch;

  try {
    const workspace = new RuntimeCodeWorkspace(testConfig({
      code: { githubToken: "ghp-test", branchPrefix: "cerebro/runtime" },
    }));
    const result = await workspace.createGithubPullRequest({
      repo: "WriterInternal/cerebro-slack-companion",
      title: "Retry runtime repair",
      base: "main",
      branch: "cerebro/runtime/retry",
      files: [{ path: "src/fix.ts", content: "export const fixed = true;\n" }],
    }) as any;

    assert.equal(result.ok, true);
    assert.equal(result.reused_pull_request, true);
    assert.equal(result.pull_request.number, 41);
    assert.equal(result.pull_request.head_sha, "new-head");
    const put = calls.find((call) => call.method === "PUT");
    assert.equal(put?.body.sha, "old-file");
    const putIndex = calls.findIndex((call) => call.method === "PUT");
    const refreshedHeadIndex = calls.findIndex((call) => call.href.endsWith("/git/ref/heads/cerebro/runtime/retry") && call.method === "GET");
    assert.equal(putIndex >= 0 && refreshedHeadIndex > putIndex, true);
    assert.equal(calls.some((call) => call.href.endsWith("/pulls") && call.method === "POST"), false);
  } finally {
    globalThis.fetch = originalFetch;
  }
});

test("runtime code GitHub PR creation only writes to configured orgs", async () => {
  const workspace = new RuntimeCodeWorkspace(testConfig({
    code: { githubToken: "ghp-test" },
  }));

  const blocked = await workspace.createGithubPullRequest({
    repo: "someone/else",
    title: "Test PR",
    files: [{ path: "docs/example.md", content: "example\n" }],
  }) as any;

  assert.equal(blocked.ok, false);
  assert.equal(blocked.error, "repo_write_not_allowed");
  assert.deepEqual(blocked.allowed_write_orgs, ["Writer", "WriterColab", "WriterInternal"]);
});

test("runtime code GitHub PR creation refuses branches outside the configured write prefix", async () => {
  const workspace = new RuntimeCodeWorkspace(testConfig({
    code: { githubToken: "ghp-test", branchPrefix: "cerebro/runtime" },
  }));

  const blocked = await workspace.createGithubPullRequest({
    repo: "WriterInternal/cerebro-slack-companion",
    title: "Test PR",
    base: "main",
    branch: "main",
    files: [{ path: "docs/example.md", content: "example\n" }],
  }) as any;

  assert.equal(blocked.ok, false);
  assert.equal(blocked.error, "branch_not_allowed");
  assert.equal(blocked.branch_prefix, "cerebro/runtime");
});

test("self-improvement PRs reject dependency and host-authority paths before GitHub access", async () => {
  const workspace = new RuntimeCodeWorkspace(testConfig({
    code: { githubToken: "ghp-test" },
  }));

  for (const path of [
    "package.json",
    "src/agent/security-assistant.ts",
    "src/agent/tool-packs.ts",
    "src/agent/tools/index.ts",
    "src/agent/tools/operator-tools.ts",
    "src/agent/tool-policy.ts",
    "src/auth.ts",
    "src/slack/actions/index.ts",
    "src/slack/commands/index.ts",
    "src/slack/events/app-mention-route.ts",
    "src/slack/events/message-route.ts",
    "src/work/companion-work-loop.ts",
  ]) {
    const result = await workspace.createSelfImprovementPullRequest({
      candidateId: "repair-prompt",
      baseSha: "a".repeat(40),
      title: "Repair assistant behavior",
      files: [{ path, content: "export const bypass = true;\n" }],
    }) as any;

    assert.equal(result.error, "self_improvement_protected_path", path);
  }
});

test("self-improvement PRs accept bounded assistant and regression-test paths", async () => {
  const workspace = new RuntimeCodeWorkspace(testConfig());

  const result = await workspace.createSelfImprovementPullRequest({
    candidateId: "repair-prompt",
    baseSha: "a".repeat(40),
    title: "Repair assistant behavior",
    files: [
      { path: "src/agent/security-assistant-prompts.ts", content: "export const repaired = true;\n" },
      { path: "test/security-assistant.test.ts", content: "export const covered = true;\n" },
    ],
  }) as any;

  assert.equal(result.error, "github_auth_not_configured");
});

test("self-improvement PRs bind the monorepo service path, content digest, base SHA, branch, and draft state", async () => {
  const originalFetch = globalThis.fetch;
  const requests: Array<{ url: string; method: string; body?: any }> = [];
  const inspectedBaseSha = "d".repeat(40);
  const committedHeadSha = "e".repeat(40);
  globalThis.fetch = (async (url: string | URL | Request, init?: RequestInit) => {
    const href = String(url);
    const method = init?.method ?? "GET";
    const body = typeof init?.body === "string" ? JSON.parse(init.body) : undefined;
    requests.push({ url: href, method, body });
    if (href === "https://api.github.com/repos/WriterInternal/cerebro") {
      return jsonResponse({ default_branch: "main" });
    }
    if (href.endsWith("/git/ref/heads/main")) return jsonResponse({ object: { sha: inspectedBaseSha } });
    if (href.endsWith("/git/refs")) return jsonResponse({ ref: body?.ref });
    if (href.includes("/pulls?head=")) return jsonResponse([]);
    if (href === "https://api.github.com/graphql" && method === "POST") {
      return jsonResponse({ data: { createCommitOnBranch: { commit: { oid: committedHeadSha } } } });
    }
    if (href.endsWith("/pulls") && method === "POST") {
      return jsonResponse({
        html_url: "https://github.com/WriterInternal/cerebro/pull/41",
        number: 41,
        state: "open",
        head: { ref: body?.head, sha: "head-sha-456" },
      });
    }
    return new Response("not found", { status: 404 });
  }) as typeof fetch;

  try {
    const workspace = new RuntimeCodeWorkspace(testConfig({
      code: {
        githubToken: "ghp-test",
        defaultRepo: "WriterInternal/cerebro",
        repoPathPrefix: "services/slack-companion",
        branchPrefix: "cerebro/runtime",
      },
    }));
    const result = await workspace.createSelfImprovementPullRequest({
      candidateId: "turn-123",
      baseSha: inspectedBaseSha,
      title: "Repair assistant behavior",
      body: "Keep the response grounded.",
      files: [{ path: "src/agent/security-assistant-prompts.ts", content: "export const repaired = true;\n" }],
    }) as any;

    assert.equal(result.ok, true);
    assert.equal(result.repo, "WriterInternal/cerebro");
    assert.equal(result.base, "main");
    assert.equal(result.base_sha, inspectedBaseSha);
    assert.equal(result.draft, true);
    assert.match(result.candidate_digest, /^sha256:[a-f0-9]{64}$/);
    assert.equal(result.branch, "cerebro/runtime/self-improve-turn-123");
    const pullRequest = requests.find((request) => request.url.endsWith("/pulls") && request.method === "POST");
    assert.equal(pullRequest?.body?.draft, true);
    assert.equal(pullRequest?.body?.base, "main");
    assert.equal(pullRequest?.body?.head, result.branch);
    const commitRequest = requests.find((request) => request.url === "https://api.github.com/graphql");
    assert.equal(commitRequest?.body?.variables?.input?.expectedHeadOid, inspectedBaseSha);
    assert.equal(commitRequest?.body?.variables?.input?.branch?.branchName, result.branch);
    assert.equal(commitRequest?.body?.variables?.input?.fileChanges?.additions?.[0]?.path, "services/slack-companion/src/agent/security-assistant-prompts.ts");
    assert.equal(result.files[0].path, "src/agent/security-assistant-prompts.ts");
    assert.equal(requests.every((request) => request.url === "https://api.github.com/graphql" || request.url.includes("/repos/WriterInternal/cerebro")), true);
  } finally {
    globalThis.fetch = originalFetch;
  }
});

test("self-improvement PR reuse rejects unsafe candidate state before file writes", async () => {
  const originalFetch = globalThis.fetch;
  const inspectedBaseSha = "d".repeat(40);
  const branch = "cerebro/runtime/self-improve-turn-123";
  const candidateHeadSha = "a".repeat(40);
  const scenarios: Array<{ name: string; pulls: any[]; error: string; expectedHeadSha?: string }> = [
    {
      name: "missing open PR",
      pulls: [],
      error: "self_improvement_candidate_pr_missing",
    },
    {
      name: "ready PR",
      pulls: [{
        number: 41,
        draft: false,
        head: { ref: branch, repo: { full_name: "WriterInternal/cerebro-slack-companion" } },
        base: { ref: "main", sha: inspectedBaseSha },
      }],
      error: "self_improvement_candidate_not_draft",
    },
    {
      name: "retargeted PR",
      pulls: [{
        number: 41,
        draft: true,
        head: { ref: branch, repo: { full_name: "WriterInternal/cerebro-slack-companion" } },
        base: { ref: "release", sha: "e".repeat(40) },
      }],
      error: "self_improvement_candidate_base_changed",
    },
    {
      name: "draft PR without inspected head",
      pulls: [{
        number: 41,
        draft: true,
        head: { ref: branch, sha: candidateHeadSha, repo: { full_name: "WriterInternal/cerebro-slack-companion" } },
        base: { ref: "main", sha: inspectedBaseSha },
      }],
      error: "self_improvement_candidate_head_sha_required",
    },
    {
      name: "draft PR with moved head",
      pulls: [{
        number: 41,
        draft: true,
        head: { ref: branch, sha: candidateHeadSha, repo: { full_name: "WriterInternal/cerebro-slack-companion" } },
        base: { ref: "main", sha: inspectedBaseSha },
      }],
      expectedHeadSha: "b".repeat(40),
      error: "self_improvement_candidate_head_changed",
    },
    {
      name: "multiple open PRs",
      pulls: [
        { number: 41, draft: true },
        { number: 42, draft: false },
      ],
      error: "self_improvement_candidate_pr_ambiguous",
    },
  ];

  try {
    for (const scenario of scenarios) {
      const requests: Array<{ url: string; method: string }> = [];
      globalThis.fetch = (async (url: string | URL | Request, init?: RequestInit) => {
        const href = String(url);
        const method = init?.method ?? "GET";
        requests.push({ url: href, method });
        if (href === "https://api.github.com/repos/WriterInternal/cerebro-slack-companion") {
          return jsonResponse({ default_branch: "main" });
        }
        if (href.endsWith("/git/ref/heads/main")) return jsonResponse({ object: { sha: inspectedBaseSha } });
        if (href.endsWith("/git/refs") && method === "POST") {
          return new Response(JSON.stringify({ message: "Reference already exists" }), { status: 422 });
        }
        if (href.includes("/pulls?head=")) return jsonResponse(scenario.pulls);
        return new Response("unexpected write", { status: 500 });
      }) as typeof fetch;

      const workspace = new RuntimeCodeWorkspace(testConfig({
        code: {
          githubToken: "ghp-test",
          defaultRepo: "WriterInternal/cerebro-slack-companion",
          branchPrefix: "cerebro/runtime",
        },
      }));
      const result = await workspace.createSelfImprovementPullRequest({
        candidateId: "turn-123",
        baseSha: inspectedBaseSha,
        expectedHeadSha: scenario.expectedHeadSha,
        title: "Repair assistant behavior",
        files: [{ path: "src/agent/security-assistant-prompts.ts", content: "export const repaired = true;\n" }],
      }) as any;

      assert.equal(result.error, scenario.error, scenario.name);
      assert.equal("draft" in result, false, scenario.name);
      assert.equal(requests.some((request) => request.method === "PUT"), false, scenario.name);
    }
  } finally {
    globalThis.fetch = originalFetch;
  }
});

test("self-improvement PR reuse updates the expected open draft candidate", async () => {
  const originalFetch = globalThis.fetch;
  const inspectedBaseSha = "d".repeat(40);
  const inspectedHeadSha = "a".repeat(40);
  const committedHeadSha = "b".repeat(40);
  const branch = "cerebro/runtime/self-improve-turn-123";
  const requests: Array<{ url: string; method: string; body?: any }> = [];
  globalThis.fetch = (async (url: string | URL | Request, init?: RequestInit) => {
    const href = String(url);
    const method = init?.method ?? "GET";
    const body = typeof init?.body === "string" ? JSON.parse(init.body) : undefined;
    requests.push({ url: href, method, body });
    if (href === "https://api.github.com/repos/WriterInternal/cerebro-slack-companion") {
      return jsonResponse({ default_branch: "main" });
    }
    if (href.endsWith("/git/ref/heads/main")) return jsonResponse({ object: { sha: inspectedBaseSha } });
    if (href.endsWith("/git/refs") && method === "POST") {
      return new Response(JSON.stringify({ message: "Reference already exists" }), { status: 422 });
    }
    if (href.includes("/pulls?head=")) {
      return jsonResponse([{
        number: 41,
        html_url: "https://github.com/WriterInternal/cerebro-slack-companion/pull/41",
        state: "open",
        draft: true,
        head: { ref: branch, sha: inspectedHeadSha, repo: { full_name: "WriterInternal/cerebro-slack-companion" } },
        base: { ref: "main", sha: inspectedBaseSha },
      }]);
    }
    if (href === "https://api.github.com/graphql" && method === "POST") {
      return jsonResponse({ data: { createCommitOnBranch: { commit: { oid: committedHeadSha } } } });
    }
    return new Response("not found", { status: 404 });
  }) as typeof fetch;

  try {
    const workspace = new RuntimeCodeWorkspace(testConfig({
      code: {
        githubToken: "ghp-test",
        defaultRepo: "WriterInternal/cerebro-slack-companion",
        branchPrefix: "cerebro/runtime",
      },
    }));
    const result = await workspace.createSelfImprovementPullRequest({
      candidateId: "turn-123",
      baseSha: inspectedBaseSha,
      expectedHeadSha: inspectedHeadSha,
      title: "Repair assistant behavior",
      files: [{ path: "src/agent/security-assistant-prompts.ts", content: "export const repaired = true;\n" }],
    }) as any;

    assert.equal(result.ok, true);
    assert.equal(result.reused_pull_request, true);
    assert.equal(result.pull_request.number, 41);
    assert.equal(result.pull_request.head_sha, committedHeadSha);
    const commitRequest = requests.find((request) => request.url === "https://api.github.com/graphql");
    assert.equal(commitRequest?.body?.variables?.input?.expectedHeadOid, inspectedHeadSha);
    assert.equal(requests.some((request) => request.method === "PUT"), false);
    assert.equal(requests.some((request) => request.url.endsWith("/pulls") && request.method === "POST"), false);
  } finally {
    globalThis.fetch = originalFetch;
  }
});

test("self-improvement PR reuse fails when the candidate head moves during the atomic commit", async () => {
  const originalFetch = globalThis.fetch;
  const inspectedBaseSha = "d".repeat(40);
  const inspectedHeadSha = "a".repeat(40);
  const movedHeadSha = "b".repeat(40);
  const branch = "cerebro/runtime/self-improve-turn-123";
  const requests: Array<{ url: string; method: string; body?: any }> = [];
  globalThis.fetch = (async (url: string | URL | Request, init?: RequestInit) => {
    const href = String(url);
    const method = init?.method ?? "GET";
    const body = typeof init?.body === "string" ? JSON.parse(init.body) : undefined;
    requests.push({ url: href, method, body });
    if (href === "https://api.github.com/repos/WriterInternal/cerebro-slack-companion") {
      return jsonResponse({ default_branch: "main" });
    }
    if (href.endsWith("/git/ref/heads/main")) return jsonResponse({ object: { sha: inspectedBaseSha } });
    if (href.endsWith("/git/refs") && method === "POST") {
      return new Response(JSON.stringify({ message: "Reference already exists" }), { status: 422 });
    }
    if (href.includes("/pulls?head=")) {
      return jsonResponse([{
        number: 41,
        draft: true,
        head: { ref: branch, sha: inspectedHeadSha, repo: { full_name: "WriterInternal/cerebro-slack-companion" } },
        base: { ref: "main", sha: inspectedBaseSha },
      }]);
    }
    if (href === "https://api.github.com/graphql" && method === "POST") {
      return jsonResponse({ errors: [{ type: "UNPROCESSABLE", message: "Expected branch head did not match." }] });
    }
    if (href.endsWith(`/git/ref/heads/${branch}`) && method === "GET") {
      return jsonResponse({ object: { sha: movedHeadSha } });
    }
    return new Response("not found", { status: 404 });
  }) as typeof fetch;

  try {
    const workspace = new RuntimeCodeWorkspace(testConfig({
      code: {
        githubToken: "ghp-test",
        defaultRepo: "WriterInternal/cerebro-slack-companion",
        branchPrefix: "cerebro/runtime",
      },
    }));
    const result = await workspace.createSelfImprovementPullRequest({
      candidateId: "turn-123",
      baseSha: inspectedBaseSha,
      expectedHeadSha: inspectedHeadSha,
      title: "Repair assistant behavior",
      files: [{ path: "src/agent/security-assistant-prompts.ts", content: "export const repaired = true;\n" }],
    }) as any;

    assert.equal(result.error, "self_improvement_candidate_head_changed");
    assert.equal(result.side_effect_outcome, "not_started");
    assert.equal(result.expected_head_sha, inspectedHeadSha);
    assert.equal(result.current_head_sha, movedHeadSha);
    assert.equal(requests.find((request) => request.url === "https://api.github.com/graphql")?.body?.variables?.input?.expectedHeadOid, inspectedHeadSha);
    assert.equal(requests.some((request) => request.method === "PUT"), false);
  } finally {
    globalThis.fetch = originalFetch;
  }
});

test("self-improvement PRs refuse a moved base before creating a branch", async () => {
  const originalFetch = globalThis.fetch;
  const requests: Array<{ url: string; method: string }> = [];
  const inspectedBaseSha = "a".repeat(40);
  const currentBaseSha = "b".repeat(40);
  globalThis.fetch = (async (url: string | URL | Request, init?: RequestInit) => {
    const href = String(url);
    const method = init?.method ?? "GET";
    requests.push({ url: href, method });
    if (href === "https://api.github.com/repos/WriterInternal/cerebro-slack-companion") {
      return jsonResponse({ default_branch: "main" });
    }
    if (href.endsWith("/git/ref/heads/main")) return jsonResponse({ object: { sha: currentBaseSha } });
    return new Response("unexpected write", { status: 500 });
  }) as typeof fetch;

  try {
    const workspace = new RuntimeCodeWorkspace(testConfig({
      code: {
        githubToken: "ghp-test",
        defaultRepo: "WriterInternal/cerebro-slack-companion",
        branchPrefix: "cerebro/runtime",
      },
    }));
    const result = await workspace.createSelfImprovementPullRequest({
      candidateId: "turn-123",
      baseSha: inspectedBaseSha,
      title: "Repair assistant behavior",
      files: [{ path: "src/agent/security-assistant-prompts.ts", content: "export const repaired = true;\n" }],
    }) as any;

    assert.equal(result.error, "base_sha_changed");
    assert.equal(result.side_effect_outcome, "not_started");
    assert.equal(result.expected_base_sha, inspectedBaseSha);
    assert.equal(result.current_base_sha, currentBaseSha);
    assert.equal(requests.some((request) => request.url.endsWith("/git/refs") && request.method === "POST"), false);
  } finally {
    globalThis.fetch = originalFetch;
  }
});

test("runtime shell fails closed before computed filesystem or network commands execute", async () => {
  const directory = mkdtempSync(join(tmpdir(), "cerebro-code-"));
  let requests = 0;
  const server = createServer((_request, response) => {
    requests += 1;
    response.end("unexpected");
  });
  try {
    await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
    const port = (server.address() as AddressInfo).port;
    const config = testConfig({ code: { workspaceDir: directory, shellEnabled: true } });
    const workspace = new RuntimeCodeWorkspace(config);

    const filesystem = await workspace.runShell({
      command: "node -e \"require('fs').readFileSync(String.fromCharCode(47)+'etc'+String.fromCharCode(47)+'hosts')\"",
    }) as any;
    const network = await workspace.runShell({
      command: `node -e "require('http').get({host:'127.0.0.1',port:${port}})"`,
    }) as any;

    assert.equal(filesystem.error, "runtime_shell_requires_os_sandbox");
    assert.equal(network.error, "runtime_shell_requires_os_sandbox");
    await new Promise((resolve) => setImmediate(resolve));
    assert.equal(requests, 0);
  } finally {
    server.close();
    rmSync(directory, { recursive: true, force: true });
  }
});

function jsonResponse(value: unknown): Response {
  return new Response(JSON.stringify(value), {
    status: 200,
    headers: { "content-type": "application/json" },
  });
}
