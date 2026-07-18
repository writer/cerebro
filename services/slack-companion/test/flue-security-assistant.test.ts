import assert from "node:assert/strict";
import test from "node:test";
import { Type } from "@earendil-works/pi-ai";
import type { AgentTool } from "@earendil-works/pi-agent-core";
import * as v from "valibot";
import { adaptPiToolsToFlue, flueResearchBudget, flueSecurityAssistantResearchPlanSchema, flueSecurityAssistantResultSchema, flueStageBudgets, resolveFlueModel, settleFlueStage, typeboxToValibotObject } from "../src/agent/flue-security-assistant.js";

test("Flue stage budgets bound planning and synthesis while preserving research time", () => {
  assert.deepEqual(flueStageBudgets(300_000), { plan: 90_000, research: 165_000, synthesis: 45_000 });
  assert.deepEqual(flueStageBudgets(20_000), { plan: 6_000, research: 11_000, synthesis: 3_000 });
});

test("Flue gives unused planning time back to research while reserving synthesis", () => {
  assert.equal(flueResearchBudget(300_000, 30_000), 225_000);
  assert.equal(flueResearchBudget(300_000, 90_000), 165_000);
});

test("Flue stage settlement returns when a provider ignores cancellation", async () => {
  const controller = new AbortController();
  const providerCall = new Promise<string>(() => undefined);
  const settled = settleFlueStage(providerCall, controller.signal);
  controller.abort(new Error("stage budget exhausted"));
  await assert.rejects(settled, /stage budget exhausted/);
});

test("Flue resolves Bedrock inference profiles with foundation model metadata", () => {
  const model = resolveFlueModel("amazon-bedrock/global.amazon.nova-2-lite-v1:0");
  assert.equal(model?.id, "global.amazon.nova-2-lite-v1:0");
  assert.equal(model?.provider, "amazon-bedrock");
  assert.equal(model?.api, "bedrock-converse-stream");
  assert.equal(model?.contextWindow, 128_000);
});

test("typeboxToValibotObject preserves required and optional tool fields", () => {
  const schema = typeboxToValibotObject(Type.Object({
    query: Type.String(),
    limit: Type.Optional(Type.Number()),
    include_archived: Type.Optional(Type.Boolean()),
    tags: Type.Optional(Type.Array(Type.String())),
  }));

  assert.deepEqual(v.parse(schema, { query: "okta mfa" }), { query: "okta mfa" });
  assert.deepEqual(v.parse(schema, {
    query: "okta mfa",
    limit: 5,
    include_archived: false,
    tags: ["identity"],
  }), {
    query: "okta mfa",
    limit: 5,
    include_archived: false,
    tags: ["identity"],
  });
  assert.throws(() => v.parse(schema, { limit: 5 }), /Invalid key: Expected "query"/);
});

test("adaptPiToolsToFlue executes the wrapped Pi tool with typed input", async () => {
  const calls: Array<Record<string, unknown>> = [];
  const tool: AgentTool = {
    name: "security_test_lookup",
    label: "Security test lookup",
    description: "Look up a security test record.",
    parameters: Type.Object({
      query: Type.String(),
    }),
    execute: async (toolCallId, params, signal) => {
      const args = params as { query: string };
      calls.push({ toolCallId, params: args, aborted: signal?.aborted ?? false });
      return {
        content: [{ type: "text", text: `found ${args.query}` }],
        details: { query: args.query, found: true },
      };
    },
  };
  const lifecycle: string[] = [];
  const flueTool = adaptPiToolsToFlue([tool], {
    toolCallId: () => "tool-call-1",
    beforeToolCall: (toolName) => {
      lifecycle.push(`before:${toolName}`);
    },
    afterToolCall: (toolName, isError) => {
      lifecycle.push(`after:${toolName}:${isError ? "error" : "ok"}`);
    },
  })[0];
  assert.ok(flueTool);

  const result = await flueTool.run({
    input: { query: "okta" },
    signal: new AbortController().signal,
    emitData: () => undefined,
  });

  assert.deepEqual(calls, [{
    toolCallId: "tool-call-1",
    params: { query: "okta" },
    aborted: false,
  }]);
  assert.deepEqual(lifecycle, ["before:security_test_lookup", "after:security_test_lookup:ok"]);
  assert.deepEqual(result, {
    content: [{ type: "text", text: "found okta" }],
    details: { query: "okta", found: true },
    terminate: false,
  });
});

test("flueSecurityAssistantResultSchema validates typed assistant output", () => {
  const parsed = v.parse(flueSecurityAssistantResultSchema, {
    answer: "One finding needs review.",
    messages: ["One finding needs review."],
    evidence: ["cerebro_open_findings returned finding-1."],
    actions_taken: ["Checked open findings."],
    next_actions: ["Review finding-1."],
    specialist_work: [{
      role: "qa",
      status: "completed",
      checks: ["Confirmed the required claim has a successful evidence receipt."],
    }],
    teammate: {
      objective: "Decide how to handle the open finding.",
      desired_outcome: "The finding has a verified disposition and owner.",
      resolved_scope: ["finding:finding-1"],
      commitments: [{
        id: "review-finding-1",
        summary: "Review finding-1.",
        status: "in_progress",
        next_action: "Check the finding evidence.",
        artifact_refs: ["finding:finding-1"],
      }],
      open_loops: [],
      user_decision: { required: false },
    },
    memory_updates: [{
      kind: "investigation_note",
      topic: "Okta finding",
      summary: "finding-1 remains open.",
      tags: ["okta"],
      promotion_state: "candidate",
    }],
  });

  assert.equal(parsed.answer, "One finding needs review.");
  assert.deepEqual(parsed.messages, ["One finding needs review."]);
  assert.equal((parsed.memory_updates[0] as { topic?: string } | undefined)?.topic, "Okta finding");
  assert.equal(parsed.teammate?.commitments[0]?.id, "review-finding-1");
  assert.equal(parsed.specialist_work[0]?.role, "qa");
});

test("flueSecurityAssistantResearchPlanSchema validates staged planning output", () => {
  const parsed = v.parse(flueSecurityAssistantResearchPlanSchema, {
    user_intent: "Jonathan wants Albert to help Cerebro with the next concrete check.",
    desired_outcome: "The thread's concrete blocker is identified and assigned.",
    resolved_scope: ["current Slack thread"],
    scope_assumptions: ["The latest unresolved item is the intended target."],
    execution_lane: "lookup",
    domain_lenses: ["self"],
    selected_tools: ["slack_thread_context"],
    claims: [{
      id: "blocker-exists",
      claim: "A concrete blocker exists in the thread.",
      required: true,
      source_candidates: ["slack_thread_context"],
    }],
    research_plan: ["Read the Slack thread context.", "Identify whether a blocker exists."],
    user_visible_work: ["Check thread context", "Identify the unresolved blocker"],
    required_sources: ["Slack thread"],
    missing_context_questions: [],
    specialists: [{
      role: "researcher",
      objective: "Find the current blocker in the thread.",
      deliverables: ["source finding", "evidence receipt"],
      depends_on: [],
    }],
  });

  assert.match(parsed.user_intent, /Albert/);
  assert.equal(parsed.execution_lane, "lookup");
  assert.deepEqual(parsed.domain_lenses, ["self"]);
  assert.deepEqual(parsed.selected_tools, ["slack_thread_context"]);
  assert.equal(parsed.claims[0]?.id, "blocker-exists");
  assert.deepEqual(parsed.user_visible_work, ["Check thread context", "Identify the unresolved blocker"]);
  assert.deepEqual(parsed.resolved_scope, ["current Slack thread"]);
  assert.equal(parsed.specialists[0]?.role, "researcher");
});

test("flue schemas carry a no-send disposition for automated handoffs", () => {
  const plan = v.parse(flueSecurityAssistantResearchPlanSchema, {
    response_disposition: "ignore",
    disposition_reason: "Routine digest had no explicit request or new verified value.",
    user_intent: "Decide whether this automated handoff needs a reply.",
  });
  const result = v.parse(flueSecurityAssistantResultSchema, {
    response_disposition: "ignore",
    disposition_reason: plan.disposition_reason,
    answer: "Automated handoff ignored.",
  });

  assert.equal(plan.response_disposition, "ignore");
  assert.equal(result.response_disposition, "ignore");
});

test("Flue tool adaptation bounds custom Pi tool details", async () => {
  const tool: AgentTool = {
    name: "large_lookup",
    label: "Large lookup",
    description: "Return a large synthetic result.",
    parameters: Type.Object({}),
    execute: async () => ({
      content: [{ type: "text", text: "large result" }],
      details: { rows: Array.from({ length: 500 }, () => "evidence ".repeat(100)) },
    }),
  };
  const flueTool = adaptPiToolsToFlue([tool])[0];
  assert.ok(flueTool);
  const result = await flueTool.run({
    input: {},
    signal: new AbortController().signal,
    emitData: () => undefined,
  }) as any;

  assert.equal(result.details.tool_result_meta.truncated, true);
  assert.ok(JSON.stringify(result.details).length <= 20_000);
});
