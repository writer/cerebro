import assert from "node:assert/strict";
import test from "node:test";
import type { AgentTool, AgentToolResult } from "@earendil-works/pi-agent-core";
import { Type } from "@earendil-works/pi-ai";
import { createCodeModeTools } from "../src/agent/code-mode/index.js";
import { toolResult } from "../src/agent/tools/tool-result.js";

const memoryLimitBytes = 32 * 1024 * 1024;

test("Code Mode searches typed tools and composes a read without ambient host capabilities", async () => {
  const calls: string[] = [];
  const hooks: string[] = [];
  const baseTools = [readTool(async (value) => {
    calls.push(value);
    return { value: value.toUpperCase() };
  })];
  const tools = createHarness(baseTools, {
    beforeToolCall: (name) => { hooks.push(`before:${name}`); },
    afterToolCall: (name, failed) => { hooks.push(`after:${name}:${failed}`); },
  });
  const digest = await searchDigest(tools);
  const result = await execute(tools, {
    program: `
      const read = await tools.cerebro_code_status({ value: "alpha" });
      return {
        read,
        ambient: {
          process: typeof process,
          require: typeof require,
          fetch: typeof fetch,
          WebAssembly: typeof WebAssembly,
          eval: typeof eval,
        },
      };
    `,
    toolset_digest: digest,
  });

  const details = resultDetails(result);
  assert.equal(details.outcome, "completed", JSON.stringify(details));
  assert.deepEqual((details.output as any).read, { value: "ALPHA" });
  assert.deepEqual((details.output as any).ambient, {
    process: "undefined",
    require: "undefined",
    fetch: "undefined",
    WebAssembly: "undefined",
    eval: "undefined",
  });
  assert.deepEqual(calls, ["alpha"]);
  assert.deepEqual(hooks, ["before:cerebro_code_status", "after:cerebro_code_status:false"]);
});

test("Code Mode permits parallel reads while applying hooks to every nested call", async () => {
  let active = 0;
  let maxActive = 0;
  const tools = createHarness([readTool(async (value) => {
    active += 1;
    maxActive = Math.max(maxActive, active);
    await new Promise((resolve) => setTimeout(resolve, 40));
    active -= 1;
    return { value };
  })]);
  const digest = await searchDigest(tools);
  const result = await execute(tools, {
    program: `
      const rows = await Promise.all([
        tools.cerebro_code_status({ value: "one" }),
        tools.cerebro_code_status({ value: "two" }),
      ]);
      return rows.map((row) => row.value).sort();
    `,
    toolset_digest: digest,
  });

  const details = resultDetails(result);
  assert.equal(details.outcome, "completed", JSON.stringify(details));
  assert.deepEqual(details.output, ["one", "two"]);
  assert.equal(details.tool_call_count, 2);
  assert.equal(maxActive, 2);
});

test("Code Mode returns partial read facts instead of collapsing them into a nested failure", async () => {
  const parameters = Type.Object({});
  const partialTool: AgentTool<typeof parameters> = {
    name: "cerebro_code_status",
    label: "Partial graph read",
    description: "Return bounded partial evidence.",
    parameters,
    execute: async () => toolResult({
      success: false,
      status: "partial",
      facts: ["build-runner-14 is linked to the rotated CI secret and INC-0417."],
      records: [{ id: "host:build-runner-14" }],
      error: "The j.reyes lookup timed out.",
      evidence_receipt: "evidence:cerebro_code_status:partial",
    }),
  };
  const hooks: string[] = [];
  const tools = createHarness([partialTool], {
    afterToolCall: (name, failed) => { hooks.push(`${name}:${failed}`); },
  });
  const digest = await searchDigest(tools);
  const result = await execute(tools, {
    program: `
      const partial = await tools.cerebro_code_status({});
      return partial;
    `,
    toolset_digest: digest,
  });

  const details = resultDetails(result);
  assert.equal(details.outcome, "completed", JSON.stringify(details));
  assert.deepEqual((details.output as any).facts, ["build-runner-14 is linked to the rotated CI secret and INC-0417."]);
  assert.equal((details.output as any).error, "The j.reyes lookup timed out.");
  assert.deepEqual(hooks, ["cerebro_code_status:false"]);
  assert.deepEqual(details.nested_calls, [{
    name: "cerebro_code_status",
    status: "completed",
    side_effect: false,
    evidence_receipt: "evidence:cerebro_code_status:partial",
  }]);
});

test("Code Mode executes one trusted write and blocks a second side effect", async () => {
  let writes = 0;
  const writeParameters = Type.Object({ value: Type.String() });
  const writeTool: AgentTool<typeof writeParameters> = {
    name: "cerebro_compliance_packet_store",
    label: "Test persistent compliance write",
    description: "Store one test packet through the normal host boundary.",
    parameters: writeParameters,
    execute: async (_id, params) => {
      writes += 1;
      return toolResult({ stored: true, value: params.value });
    },
  };
  const tools = createHarness([writeTool]);
  const digest = await searchDigest(tools);
  const result = await execute(tools, {
    program: `
      await tools.cerebro_compliance_packet_store({ value: "one" });
      try { await tools.cerebro_compliance_packet_store({ value: "two" }); } catch {}
      return { finished: true };
    `,
    toolset_digest: digest,
  });

  const details = resultDetails(result);
  assert.equal(details.outcome, "blocked", JSON.stringify(details));
  assert.equal(details.side_effect_call_count, 1);
  assert.equal(details.retry_allowed, false);
  assert.equal(writes, 1);
  assert.deepEqual((details.nested_calls as any[]).map((call) => call.status), ["completed", "blocked"]);
});

test("Code Mode composes self-improvement reads and opens one draft PR", async () => {
  const readValues: string[] = [];
  const pullRequests: Array<{ repository: string; title: string; draft: boolean }> = [];
  const prParameters = Type.Object({
    repository: Type.String(),
    title: Type.String(),
    draft: Type.Boolean(),
  });
  const prTool: AgentTool<typeof prParameters> = {
    name: "cerebro_code_self_improvement_pr",
    label: "Open draft self-improvement PR",
    description: "Open one reviewable draft PR through the host GitHub boundary.",
    parameters: prParameters,
    execute: async (_id, params) => {
      pullRequests.push(params);
      return toolResult({ success: true, draft: params.draft, pull_request_number: 41 });
    },
  };
  const tools = createHarness([
    readTool(async (value) => {
      readValues.push(value);
      return { value };
    }),
    prTool,
  ]);
  const digest = await searchDigest(tools);
  const result = await execute(tools, {
    program: `
      const context = await Promise.all([
        tools.cerebro_code_status({ value: "runtime-status" }),
        tools.cerebro_code_status({ value: "self-improvement-skill" }),
      ]);
      const pr = await tools.cerebro_code_self_improvement_pr({
        repository: "WriterInternal/cerebro-slack-companion",
        title: "Repair the assistant behavior",
        draft: true,
      });
      try {
        await tools.cerebro_code_self_improvement_pr({
          repository: "WriterInternal/cerebro-slack-companion",
          title: "Second write",
          draft: true,
        });
      } catch {}
      return { context, pr };
    `,
    toolset_digest: digest,
  });

  const details = resultDetails(result);
  assert.equal(details.outcome, "blocked", JSON.stringify(details));
  assert.deepEqual(readValues.sort(), ["runtime-status", "self-improvement-skill"]);
  assert.deepEqual(pullRequests, [{
    repository: "WriterInternal/cerebro-slack-companion",
    title: "Repair the assistant behavior",
    draft: true,
  }]);
  assert.equal(details.side_effect_call_count, 1);
  assert.equal(details.retry_allowed, false);
});

test("Code Mode treats a guest failure after a completed side effect as unknown", async () => {
  let writes = 0;
  const writeParameters = Type.Object({ value: Type.String() });
  const writeTool: AgentTool<typeof writeParameters> = {
    name: "security_memory_write",
    label: "Test completed write",
    description: "Complete one write before the guest fails.",
    parameters: writeParameters,
    execute: async () => {
      writes += 1;
      return toolResult({ stored: true });
    },
  };
  const tools = createHarness([writeTool]);
  const digest = await searchDigest(tools);
  const result = await execute(tools, {
    program: `
      await tools.security_memory_write({ value: "one" });
      throw new Error("guest failed after write");
    `,
    toolset_digest: digest,
  });

  const details = resultDetails(result);
  assert.equal(details.outcome, "outcome_unknown", JSON.stringify(details));
  assert.equal(details.verification_required, true);
  assert.equal(details.retry_allowed, false);
  assert.equal(result.terminate, true);
  assert.equal(writes, 1);
});

test("Code Mode treats a failed side-effect result as unknown even when the guest catches it", async () => {
  let partialWrites = 0;
  const prParameters = Type.Object({ draft: Type.Boolean() });
  const prTool: AgentTool<typeof prParameters> = {
    name: "cerebro_code_github_pr",
    label: "Partially failing PR",
    description: "Simulate a PR operation that mutates before reporting failure.",
    parameters: prParameters,
    execute: async () => {
      partialWrites += 1;
      return toolResult({ ok: false, error: "PR creation failed after branch creation." });
    },
  };
  const tools = createHarness([prTool]);
  const digest = await searchDigest(tools);
  const result = await execute(tools, {
    program: `
      try { await tools.cerebro_code_github_pr({ draft: true }); } catch {}
      return { recovered: true };
    `,
    toolset_digest: digest,
  });

  const details = resultDetails(result);
  assert.equal(details.outcome, "outcome_unknown", JSON.stringify(details));
  assert.equal(details.verification_required, true);
  assert.equal(details.retry_allowed, false);
  assert.equal(result.terminate, true);
  assert.equal(partialWrites, 1);
});

test("Code Mode reports a host-classified no-write refusal without requiring verification", async () => {
  const prParameters = Type.Object({ draft: Type.Boolean() });
  const prTool: AgentTool<typeof prParameters> = {
    name: "cerebro_code_self_improvement_pr",
    label: "Stale self-improvement candidate",
    description: "Refuse a stale candidate before starting a GitHub write.",
    parameters: prParameters,
    execute: async () => toolResult({
      ok: false,
      error: "self_improvement_candidate_head_changed",
      side_effect_outcome: "not_started",
    }),
  };
  const tools = createHarness([prTool]);
  const digest = await searchDigest(tools);
  const result = await execute(tools, {
    program: `
      try { await tools.cerebro_code_self_improvement_pr({ draft: true }); } catch {}
      return { refreshed: false };
    `,
    toolset_digest: digest,
  });

  const details = resultDetails(result);
  assert.equal(details.outcome, "failed", JSON.stringify(details));
  assert.equal(details.verification_required, false);
  assert.equal(details.retry_allowed, true);
  assert.equal(result.terminate, undefined);
  assert.deepEqual((details.nested_calls as any[])[0], {
    name: "cerebro_code_self_improvement_pr",
    status: "failed",
    side_effect: true,
    side_effect_outcome: "not_started",
    error_code: "self_improvement_candidate_head_changed",
  });
});

test("Code Mode treats a fire-and-forget write as unknown", async () => {
  let writes = 0;
  const writeParameters = Type.Object({ value: Type.String() });
  const writeTool: AgentTool<typeof writeParameters> = {
    name: "security_memory_write",
    label: "Fire-and-forget test write",
    description: "Complete one write that the guest does not await.",
    parameters: writeParameters,
    execute: async () => {
      writes += 1;
      return toolResult({ stored: true });
    },
  };
  const tools = createHarness([writeTool]);
  const digest = await searchDigest(tools);
  const result = await execute(tools, {
    program: `
      tools.security_memory_write({ value: "one" });
      return { returned_early: true };
    `,
    toolset_digest: digest,
  });

  const details = resultDetails(result);
  assert.equal(details.outcome, "outcome_unknown", JSON.stringify(details));
  assert.equal(details.verification_required, true);
  assert.equal(details.retry_allowed, false);
  assert.equal(result.terminate, true);
  assert.equal(writes, 1);
});

test("Code Mode treats post-write hook failure as unknown", async () => {
  const writeParameters = Type.Object({ value: Type.String() });
  const writeTool: AgentTool<typeof writeParameters> = {
    name: "security_memory_write",
    label: "Post-write hook test",
    description: "Complete one write before result finalization fails.",
    parameters: writeParameters,
    execute: async () => toolResult({ stored: true }),
  };
  const tools = createHarness([writeTool], {
    afterToolCall: () => { throw new Error("finalization failed"); },
  });
  const digest = await searchDigest(tools);
  const result = await execute(tools, {
    program: `return await tools.security_memory_write({ value: "one" });`,
    toolset_digest: digest,
  });

  const details = resultDetails(result);
  assert.equal(details.outcome, "outcome_unknown", JSON.stringify(details));
  assert.equal(details.verification_required, true);
  assert.equal(details.retry_allowed, false);
});

test("Code Mode blocks every tool without explicit authority metadata", async () => {
  let writes = 0;
  const parameters = Type.Object({ value: Type.String() });
  const unclassifiedTool: AgentTool<typeof parameters> = {
    name: "cerebro_deploy",
    label: "Unclassified future deploy",
    description: "A side-effecting tool whose name is not an authority boundary.",
    parameters,
    execute: async () => {
      writes += 1;
      return toolResult({ ok: true });
    },
  };
  const tools = createHarness([unclassifiedTool]);
  const digest = await searchDigest(tools);
  const result = await execute(tools, {
    program: `
      try { await tools.cerebro_deploy({ value: "one" }); } catch {}
      return { finished: true };
    `,
    toolset_digest: digest,
  });

  const details = resultDetails(result);
  assert.equal(details.outcome, "blocked", JSON.stringify(details));
  assert.equal(details.termination_reason, "policy");
  assert.equal(writes, 0);
});

test("Code Mode permits an explicitly injected read-only evaluation tool", async () => {
  const parameters = Type.Object({ value: Type.String() });
  const toolName = "offline_source_01_current_findings";
  const evaluationTool: AgentTool<typeof parameters> = {
    name: toolName,
    label: "Offline current findings",
    description: "Read one bounded offline evaluation fixture.",
    parameters,
    execute: async (_id, params) => toolResult({ value: params.value.toUpperCase() }),
  };
  const tools = createHarness([evaluationTool], {
    additionalReadOnlyToolNames: new Set([toolName]),
  });
  const digest = await searchDigest(tools);
  const result = await execute(tools, {
    program: `return await tools.offline_source_01_current_findings({ value: "evidence" });`,
    toolset_digest: digest,
  });

  const details = resultDetails(result);
  assert.equal(details.outcome, "completed", JSON.stringify(details));
  assert.deepEqual(details.output, { value: "EVIDENCE" });
  assert.equal(details.side_effect_call_count, 0);
});

test("Code Mode reports an unknown outcome and forbids retry when a write is interrupted", async () => {
  let notifyStarted!: () => void;
  const started = new Promise<void>((resolve) => { notifyStarted = resolve; });
  let writes = 0;
  const writeParameters = Type.Object({ value: Type.String() });
  const writeTool: AgentTool<typeof writeParameters> = {
    name: "security_memory_write",
    label: "Test interruptible write",
    description: "Start one test write and wait for cancellation.",
    parameters: writeParameters,
    execute: async (_id, _params, signal) => {
      writes += 1;
      notifyStarted();
      await new Promise<void>((_resolve, reject) => signal?.addEventListener("abort", () => reject(new Error("aborted")), { once: true }));
      return toolResult({ stored: true });
    },
  };
  const tools = createHarness([writeTool]);
  const digest = await searchDigest(tools);
  const controller = new AbortController();
  const pending = execute(tools, {
    program: `return await tools.security_memory_write({ value: "one" });`,
    toolset_digest: digest,
  }, controller.signal);
  await started;
  controller.abort();
  const result = await pending;

  const details = resultDetails(result);
  assert.equal(details.outcome, "outcome_unknown");
  assert.equal(details.verification_required, true);
  assert.equal(details.retry_allowed, false);
  assert.equal(result.terminate, true);
  assert.equal(writes, 1);
});

test("a guest approval field cannot bypass the host write policy", async () => {
  let writes = 0;
  const hooks: string[] = [];
  const parameters = Type.Object({ value: Type.String(), approved: Type.Optional(Type.Boolean()) });
  const writeTool: AgentTool<typeof parameters> = {
    name: "security_memory_write",
    label: "Policy-bound write",
    description: "Write only after the host policy permits it.",
    parameters,
    execute: async () => {
      writes += 1;
      return toolResult({ stored: true });
    },
  };
  const tools = createHarness([writeTool], {
    beforeToolCall: () => { hooks.push("before"); throw new Error("approval_required"); },
    afterToolCall: () => { hooks.push("after"); },
  });
  const digest = await searchDigest(tools);
  const result = await execute(tools, {
    program: `return await tools.security_memory_write({ value: "one", approved: true });`,
    toolset_digest: digest,
  });

  const details = resultDetails(result);
  assert.equal(details.outcome, "failed");
  assert.equal(details.side_effect_call_count, 0);
  assert.equal(writes, 0);
  assert.deepEqual(hooks, ["before"]);
  assert.equal((details.nested_calls as any[])[0].status, "blocked");
});

test("catalog drift and module imports are blocked before guest execution", async () => {
  const baseTools = [readTool(async (value) => ({ value }))];
  const allowed = new Set(baseTools.map((tool) => tool.name));
  const tools = createHarness(baseTools, { allowedToolNames: () => allowed });
  const digest = await searchDigest(tools);
  allowed.clear();
  const stale = await execute(tools, {
    program: `return { reached: true };`,
    toolset_digest: digest,
  });
  assert.equal(resultDetails(stale).outcome, "blocked");

  allowed.add("cerebro_code_status");
  const currentDigest = await searchDigest(tools);
  const imported = await execute(tools, {
    program: `return await import("node:fs");`,
    toolset_digest: currentDigest,
  });
  assert.equal(resultDetails(imported).outcome, "blocked");
  assert.equal(resultDetails(imported).tool_call_count, 0);
});

test("output and memory limits fail closed and leave the next child healthy", async () => {
  const tools = createHarness([readTool(async (value) => ({ value }))], {
    maxOutputBytes: 1_024,
    memoryLimitBytes: 32 * 1024 * 1024,
  });
  const digest = await searchDigest(tools);
  const oversized = await execute(tools, {
    program: `return "x".repeat(4096);`,
    toolset_digest: digest,
  });
  assert.equal(resultDetails(oversized).outcome, "failed");
  assert.equal(resultDetails(oversized).termination_reason, "output_limit");
  assert.equal(resultDetails(oversized).output_truncated, true);

  const exhausted = await execute(tools, {
    program: `const rows = []; while (true) rows.push("x".repeat(1024 * 1024));`,
    toolset_digest: digest,
  });
  assert.notEqual(resultDetails(exhausted).outcome, "completed");
  assert.ok(["memory_limit", "guest_error"].includes(String(resultDetails(exhausted).termination_reason)));

  const recovered = await execute(tools, {
    program: `return await tools.cerebro_code_status({ value: "healthy" });`,
    toolset_digest: digest,
  });
  assert.equal(resultDetails(recovered).outcome, "completed");
});

test("a timed-out guest is killed and the next execution starts in a fresh child", async () => {
  const tools = createHarness([readTool(async (value) => ({ value }))], { timeoutMs: 1_000 });
  const digest = await searchDigest(tools);
  const timedOut = await execute(tools, {
    program: "while (true) {}",
    toolset_digest: digest,
  });
  assert.equal(resultDetails(timedOut).outcome, "timed_out");

  const recovered = await execute(tools, {
    program: `return await tools.cerebro_code_status({ value: "recovered" });`,
    toolset_digest: digest,
  });
  assert.equal(resultDetails(recovered).outcome, "completed");
  assert.deepEqual(resultDetails(recovered).output, { value: "recovered" });
});

test("Code Mode returns at its deadline when a nested read ignores cancellation", async () => {
  const parameters = Type.Object({});
  const hungRead: AgentTool<typeof parameters> = {
    name: "cerebro_code_status",
    label: "Cancellation-ignoring read",
    description: "Never settle, including after the host aborts the call.",
    parameters,
    execute: async () => await new Promise<AgentToolResult<unknown>>(() => undefined),
  };
  const tools = createHarness([hungRead], { timeoutMs: 1_000 });
  const digest = await searchDigest(tools);
  const startedAt = Date.now();

  const timedOut = await execute(tools, {
    program: "return await tools.cerebro_code_status({});",
    toolset_digest: digest,
  });

  assert.equal(resultDetails(timedOut).outcome, "timed_out");
  assert.equal(resultDetails(timedOut).termination_reason, "deadline");
  assert.ok(Date.now() - startedAt < 2_500);
});

function createHarness(
  baseTools: AgentTool[],
  overrides: Partial<Parameters<typeof createCodeModeTools>[0]> = {},
): AgentTool[] {
  return createCodeModeTools({
    baseTools,
    maxToolCalls: 8,
    maxSideEffectCalls: 1,
    timeoutMs: 15_000,
    memoryLimitBytes,
    maxScriptBytes: 16 * 1024,
    maxOutputBytes: 16 * 1024,
    allowedToolNames: () => new Set(baseTools.map((tool) => tool.name)),
    ...overrides,
  });
}

function readTool(work: (value: string) => Promise<unknown>): AgentTool {
  const parameters = Type.Object({ value: Type.String() });
  const tool: AgentTool<typeof parameters> = {
    name: "cerebro_code_status",
    label: "Test Cerebro read",
    description: "Read one bounded test value.",
    parameters,
    execute: async (_id, params) => toolResult(await work(params.value)),
  };
  return tool;
}

async function searchDigest(tools: AgentTool[]): Promise<string> {
  const search = tools.find((tool) => tool.name === "cerebro_tool_search");
  assert.ok(search);
  const result = await search.execute("search", {} as never);
  const digest = resultDetails(result).toolset_digest;
  assert.equal(typeof digest, "string");
  return digest as string;
}

async function execute(
  tools: AgentTool[],
  params: { program: string; toolset_digest: string },
  signal?: AbortSignal,
): Promise<AgentToolResult<unknown>> {
  const executor = tools.find((tool) => tool.name === "cerebro_execute");
  assert.ok(executor);
  return executor.execute("execute", params as never, signal);
}

function resultDetails(result: AgentToolResult<unknown>): Record<string, unknown> {
  assert.ok(result.details && typeof result.details === "object" && !Array.isArray(result.details));
  return result.details as Record<string, unknown>;
}
