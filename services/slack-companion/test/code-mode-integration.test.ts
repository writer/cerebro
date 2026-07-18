import assert from "node:assert/strict";
import test from "node:test";
import { Type } from "@earendil-works/pi-ai";
import * as v from "valibot";
import { flueSecurityAssistantResearchPlanSchema } from "../src/agent/flue-security-assistant.js";
import { SecurityResearchState } from "../src/agent/research-state.js";
import { systemPrompt } from "../src/agent/security-assistant-prompts.js";
import { SecurityAssistantService } from "../src/agent/security-assistant.js";
import { SecurityAssistantToolHooks } from "../src/agent/security-assistant-tool-hooks.js";
import { selectExecutionToolPack } from "../src/agent/tool-packs.js";
import { loadConfig } from "../src/config/index.js";
import { findSecuritySkill } from "../src/skills/security-skills.js";
import { testConfig } from "./fixtures.js";

test("code mode config uses bounded defaults and accepts explicit deployment limits", () => {
  const defaults = loadConfig(minimalEnv()).codeMode;
  assert.deepEqual(defaults, {
    enabled: true,
    maxToolCalls: 8,
    maxSideEffectCalls: 1,
    timeoutMs: 30_000,
    memoryLimitBytes: 64 * 1024 * 1024,
    maxScriptBytes: 24 * 1024,
    maxOutputBytes: 64 * 1024,
  });

  const configured = loadConfig(minimalEnv({
    CEREBRO_CODE_MODE_ENABLED: "false",
    CEREBRO_CODE_MODE_MAX_TOOL_CALLS: "4",
    CEREBRO_CODE_MODE_MAX_SIDE_EFFECT_CALLS: "1",
    CEREBRO_CODE_MODE_TIMEOUT_MS: "12000",
    CEREBRO_CODE_MODE_MEMORY_LIMIT_BYTES: `${32 * 1024 * 1024}`,
    CEREBRO_CODE_MODE_MAX_SCRIPT_BYTES: "8192",
    CEREBRO_CODE_MODE_MAX_OUTPUT_BYTES: "16384",
  })).codeMode;
  assert.deepEqual(configured, {
    enabled: false,
    maxToolCalls: 4,
    maxSideEffectCalls: 1,
    timeoutMs: 12_000,
    memoryLimitBytes: 32 * 1024 * 1024,
    maxScriptBytes: 8 * 1024,
    maxOutputBytes: 16 * 1024,
  });
  assert.throws(() => loadConfig(minimalEnv({ CEREBRO_CODE_MODE_MAX_SIDE_EFFECT_CALLS: "2" })));
});

test("Flue Stage 1 carries the model-selected execution style with a direct default", () => {
  const direct = v.parse(flueSecurityAssistantResearchPlanSchema, {
    user_intent: "Read one current finding.",
  });
  const code = v.parse(flueSecurityAssistantResearchPlanSchema, {
    user_intent: "Compare findings across runtimes.",
    execution_style: "code",
  });

  assert.equal(direct.execution_style, "direct");
  assert.equal(code.execution_style, "code");
});

test("execution tool packs use broker tools only for a model-selected code plan", () => {
  const directTools = [{ name: "operator_research_plan" }, { name: "cerebro_findings" }];
  const codeTools = [{ name: "cerebro_tool_search" }, { name: "cerebro_execute" }];
  const plan = {
    executionLane: "lookup" as const,
    executionStyle: "code" as const,
    domainLenses: ["general" as const],
    selectedTools: ["cerebro_findings"],
    sourceCandidates: ["cerebro_findings"],
  };

  assert.deepEqual(selectExecutionToolPack(directTools, codeTools, plan), {
    executionStyle: "code",
    tools: codeTools,
  });
  assert.deepEqual(selectExecutionToolPack(directTools, [], plan), {
    executionStyle: "direct",
    tools: directTools,
  });
});

test("code broker calls require a plan without consuming evidence budget or receipts", async () => {
  const sourceTool = "cerebro_findings";
  const researchTrail: string[] = [];
  const researchState = new SecurityResearchState();
  researchState.setAvailableTools([sourceTool]);
  const hooks = new SecurityAssistantToolHooks({
    allowedTools: new Set([sourceTool, "cerebro_tool_search", "cerebro_execute"]),
    inferredIntent: "security_answer",
    maxResearchSteps: 2,
    researchState,
    researchTrail,
  });

  const blocked = await hooks.beforePi({ toolCall: { name: "cerebro_tool_search" } });
  assert.match(blocked?.reason ?? "", /operator_research_plan/);
  assert.equal(hooks.count, 0);

  researchState.establishPlan({
    decision: "Read current findings and filter the result.",
    execution_style: "code",
    selected_tools: [sourceTool],
    claims: [{ id: "findings", claim: "Current findings were checked.", source_candidates: [sourceTool] }],
  });

  assert.equal(await hooks.beforePi({ toolCall: { name: "cerebro_execute" } }), undefined);
  await hooks.afterPi({ toolCall: { name: "cerebro_execute" }, isError: false });
  assert.equal(hooks.count, 0);
  assert.deepEqual(researchTrail, []);

  const directCall = await hooks.beforePi({ toolCall: { name: sourceTool } });
  assert.match(directCall?.reason ?? "", /must run through cerebro_execute/);

  hooks.beforeCodeMode(sourceTool);
  researchState.recordToolResult(sourceTool, { details: { findings: [{ id: "finding-1" }] } });
  hooks.afterCodeMode(sourceTool, false);
  assert.equal(hooks.count, 1);
  assert.deepEqual(researchTrail, [`${sourceTool}: checked`]);
  assert.equal((researchState.snapshot() as { tool_runs: unknown[] }).tool_runs.length, 1);
  assert.equal(researchState.adaptivePlan().executionStyle, "code");
});

test("a direct plan blocks Code Mode infrastructure and permits its selected tool directly", async () => {
  const sourceTool = "cerebro_findings";
  const researchState = new SecurityResearchState();
  researchState.setAvailableTools([sourceTool]);
  researchState.establishPlan({
    decision: "Read one current finding.",
    execution_style: "direct",
    selected_tools: [sourceTool],
    claims: [{ id: "findings", claim: "Current findings were checked.", source_candidates: [sourceTool] }],
  });
  const hooks = new SecurityAssistantToolHooks({
    allowedTools: new Set([sourceTool, "cerebro_tool_search", "cerebro_execute"]),
    inferredIntent: "security_answer",
    maxResearchSteps: 2,
    researchState,
    researchTrail: [],
  });

  assert.equal(await hooks.beforePi({ toolCall: { name: sourceTool } }), undefined);
  const brokerCall = await hooks.beforePi({ toolCall: { name: "cerebro_execute" } });
  assert.match(brokerCall?.reason ?? "", /execution_style=code/);
});

test("direct execution rejects a newly registered tool without explicit host authority", async () => {
  const toolName = "cerebro_deploy";
  const researchState = new SecurityResearchState();
  researchState.setAvailableTools([toolName]);
  researchState.establishPlan({
    decision: "Run the requested tool.",
    execution_style: "direct",
    selected_tools: [toolName],
  });
  const hooks = new SecurityAssistantToolHooks({
    allowedTools: new Set([toolName]),
    inferredIntent: "self_improvement",
    maxResearchSteps: 2,
    researchState,
    researchTrail: [],
    trustedOperator: true,
  });

  const blocked = await hooks.beforePi({ toolCall: { name: toolName } });
  assert.match(blocked?.reason ?? "", /authority metadata is registered/);
  assert.equal(hooks.count, 0);
});

test("direct execution permits an explicitly injected read-only evaluation tool", async () => {
  const toolName = "offline_source_01_current_findings";
  const researchState = new SecurityResearchState();
  researchState.setAvailableTools([toolName]);
  researchState.establishPlan({
    decision: "Read the supplied evaluation evidence.",
    execution_style: "direct",
    selected_tools: [toolName],
  });
  const hooks = new SecurityAssistantToolHooks({
    allowedTools: new Set([toolName]),
    additionalReadOnlyToolNames: new Set([toolName]),
    inferredIntent: "security_answer",
    maxResearchSteps: 2,
    researchState,
    researchTrail: [],
  });

  assert.equal(await hooks.beforePi({ toolCall: { name: toolName } }), undefined);
  assert.equal(hooks.count, 1);
});

test("self-improvement keeps nested Code Mode calls inside normal plan, actor, and turn policy", () => {
  const selectedTools = ["cerebro_code_status", "security_skill_view", "cerebro_code_self_improvement_pr"];
  const researchState = new SecurityResearchState();
  researchState.setAvailableTools(selectedTools);
  researchState.establishPlan({
    decision: "Inspect the assistant and open one reviewable repair.",
    execution_style: "code",
    selected_tools: selectedTools,
    claims: [{
      id: "repair",
      claim: "The current behavior and repair target were inspected.",
      source_candidates: ["cerebro_code_status", "security_skill_view"],
    }],
  });
  const researchTrail: string[] = [];
  const hooks = new SecurityAssistantToolHooks({
    allowedTools: new Set([...selectedTools, "cerebro_tool_search", "cerebro_execute"]),
    inferredIntent: "self_improvement",
    maxResearchSteps: 4,
    researchState,
    researchTrail,
    trustedOperator: true,
  });

  assert.doesNotThrow(() => hooks.beforeCodeMode("cerebro_code_status"));
  hooks.afterCodeMode("cerebro_code_status", false);
  assert.doesNotThrow(() => hooks.beforeCodeMode("security_skill_view"));
  hooks.afterCodeMode("security_skill_view", false);
  assert.doesNotThrow(() => hooks.beforeCodeMode("cerebro_code_self_improvement_pr"));
  hooks.afterCodeMode("cerebro_code_self_improvement_pr", false);
  assert.throws(() => hooks.beforeCodeMode("cerebro_code_self_improvement_pr"), /already used its one side effect/);
  assert.equal(hooks.count, 3);
  assert.deepEqual(researchTrail, [
    "cerebro_code_status: checked",
    "security_skill_view: checked",
    "cerebro_code_self_improvement_pr: checked",
  ]);
});

test("self-improvement guidance selects Code Mode by judgment and keeps delivery review-only", () => {
  const prompt = systemPrompt(testConfig());
  const skill = findSecuritySkill("self-improvement");

  assert.ok(skill);
  assert.match(prompt, /self-improvement turn gets one side effect/i);
  assert.match(prompt, /one cerebro_code_self_improvement_pr/);
  assert.match(prompt, /Never merge or deploy the PR/i);
  assert.match(prompt, /Never promote the candidate/i);
  assert.match(prompt, /Do not depend on hardcoded phrase routes/);
  assert.match(skill.prompt, /execution_style=code/);
  assert.match(skill.prompt, /one side effect/);
  assert.match(skill.prompt, /Keep merge, deploy, promotion/);
});

test("self-improvement candidate submission rejects an untrusted Slack actor", () => {
  const toolName = "cerebro_code_self_improvement_pr";
  const researchState = new SecurityResearchState();
  researchState.setAvailableTools([toolName]);
  researchState.establishPlan({
    decision: "Submit a bounded repair candidate.",
    execution_style: "code",
    selected_tools: [toolName],
  });
  const hooks = new SecurityAssistantToolHooks({
    allowedTools: new Set([toolName]),
    inferredIntent: "self_improvement",
    maxResearchSteps: 2,
    researchState,
    researchTrail: [],
    trustedOperator: false,
  });

  assert.throws(() => hooks.beforeCodeMode(toolName), /configured Slack operator/);
  assert.equal(hooks.count, 0);
});

test("the Slack Flue work loop gives Stage 2 broker tools for a code plan", async () => {
  const captured: { direct: string[]; code: string[] }[] = [];
  const service = new SecurityAssistantService(
    testConfig({
      triage: { assistantRuntime: "flue" },
      codeMode: {
        enabled: true,
        maxToolCalls: 4,
        maxSideEffectCalls: 1,
        timeoutMs: 5_000,
        memoryLimitBytes: 32 * 1024 * 1024,
        maxScriptBytes: 8 * 1024,
        maxOutputBytes: 16 * 1024,
      },
    }),
    {} as any,
    { workingMemoryPromptBlock: () => "", remember: async () => undefined } as any,
    {
      toolFactory: () => [{
        name: "security_test_lookup",
        label: "Security test lookup",
        description: "Read a bounded test record.",
        parameters: Type.Object({ query: Type.String() }),
        execute: async () => ({ content: [{ type: "text", text: "ok" }], details: { ok: true } }),
      }],
      flueComplete: async (input) => {
        captured.push({
          direct: input.tools.map((tool) => tool.name),
          code: (input.codeTools ?? []).map((tool) => tool.name),
        });
        await input.onResearchPlan?.({
          user_intent: "Read and reduce the planned test records.",
          execution_lane: "investigate",
          execution_style: "code",
          selected_tools: ["security_test_lookup"],
          claims: [{ id: "test-record", claim: "The test record was checked.", required: true, source_candidates: ["security_test_lookup"] }],
          research_plan: ["Read the planned test records."],
          user_visible_work: ["Check the current test records"],
          required_sources: ["security_test_lookup"],
          missing_context_questions: [],
        });
        return {
          data: {
            execution_lane: "investigate",
            answer: "The code plan is ready.",
            messages: ["The code plan is ready."],
            reply_messages: [],
            key_points: [],
            keyPoints: [],
            evidence: [],
            actions_taken: [],
            actionsTaken: [],
            next_actions: [],
            nextActions: [],
            research: [],
            memory_updates: [],
            memoryUpdates: [],
            specialist_work: [],
            final_ready: true,
            presentation_ready: true,
          },
          execution: {
            lane: "investigate",
            executionStyle: "code",
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
      },
    },
  );

  const answer = await service.answer({
    channelId: "CSEC",
    userId: "UUSER",
    ts: "1782490000.000001",
    question: "Compare the current test records and keep only the relevant rows.",
  });

  assert.deepEqual(captured, [{
    direct: ["security_test_lookup"],
    code: ["cerebro_tool_search", "cerebro_execute"],
  }]);
  assert.equal(answer.source, "flue");
});

function minimalEnv(overrides: NodeJS.ProcessEnv = {}): NodeJS.ProcessEnv {
  return {
    SLACK_BOT_TOKEN: "xoxb-test",
    SLACK_SOCKET_MODE: "true",
    SLACK_APP_TOKEN: "xapp-test",
    CEREBRO_BASE_URL: "https://cerebro.example.com",
    CEREBRO_TENANT_ID: "writer",
    CEREBRO_READ_API_KEY: "read-key",
    ...overrides,
  };
}
