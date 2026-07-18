import { Agent, type ThinkingLevel } from "@earendil-works/pi-agent-core";
import { builtinModels } from "@earendil-works/pi-ai/providers/all";
import { adaptPiToolsToFlue, completeWithFlueSecurityAssistant, type FlueSecurityAssistantCompleteInput, type FlueSecurityAssistantCompleteOutput } from "./flue-security-assistant.js";
import { summarizeLlmError } from "./security-assistant-errors.js";
import { assistantConversationContext, assistantLearningPromptBlock, persistAssistantIntelligence } from "./security-assistant-intelligence.js";
import { assistantResultTelemetry, normalizeSecurityAssistantOutput, parseSecurityAssistantOutput } from "./security-assistant-output.js";
import { buildAssistantUserPrompt } from "./security-assistant-prompt-build.js";
import { blockedSlackMessage, prepareDeliverableAnswer, recoverIncompleteResearch } from "./security-assistant-recovery.js";
import { oversizedPromptAnswer } from "./security-assistant-prompt-preflight.js";
import { presentSlackAnswerWithLlm } from "./security-assistant-presentation.js";
import { specialistTelemetryAttributes } from "./specialist-team.js";
import { SecurityResearchState } from "./research-state.js";
import { SourceHealthRegistry } from "./source-health.js";
import { SecurityAssistantToolHooks } from "./security-assistant-tool-hooks.js";
import { prepareDistributedResearch, withAssistantWorkflowPermit } from "./security-assistant-distributed.js";
import { assistantOutputRepairSystemPrompt, assistantOutputRepairUserPrompt, systemPrompt, toolCatalogPrompt } from "./security-assistant-prompts.js";
import { SlotQueue } from "./slot-queue.js";
import { compactAgentTranscript, latestAssistantText } from "./security-assistant-transcript.js";
import { AssistantThreadStateStore } from "./thread-intelligence-store.js";
import type { SecurityAssistantAnswer, SecurityAssistantInput, SecurityAssistantRepairCompleteInput, SecurityAssistantServiceOptions } from "./security-assistant-types.js";
import { createSecurityAgentTools } from "./tools/index.js";
import type { SecurityToolDeps } from "./tools/types.js";
import { createAssistantCodeModeTools } from "./tool-packs.js";
import { inferSecurityAgentIntent, toolPolicyPrompt } from "./tool-policy.js";
import { reconcileTeammateGoals } from "./teammate-goals.js";
import type { AppConfig } from "../config/index.js";
import type { CerebroClient } from "../cerebro/client.js";
import type { SecurityMemoryStore } from "../learning/security-memory/index.js";
import {
  annotateMainDependency,
  annotateMainPhase,
  annotateSpan,
  captureTelemetryError,
  maxMain,
  slackTelemetryAttributes,
  telemetryErrorKind,
  telemetryEvent,
  withTelemetrySpan,
} from "../telemetry.js";
export { normalizeSecurityAssistantOutput, parseSecurityAssistantOutput, parseSlackPresentationOutput } from "./security-assistant-output.js";
export type { SecurityAssistantAnswer, SecurityAssistantInput, SecurityAssistantRepairCompleteInput, SecurityAssistantServiceOptions } from "./security-assistant-types.js";
export class SecurityAssistantService {
  private readonly models = builtinModels();
  private readonly sourceHealth = new SourceHealthRegistry();
  private readonly slots: SlotQueue;
  private readonly threadState: AssistantThreadStateStore;
  constructor(
    private readonly config: AppConfig,
    private readonly cerebro: CerebroClient,
    private readonly memory: SecurityMemoryStore,
    private readonly options: SecurityAssistantServiceOptions = {},
  ) {
    this.slots = new SlotQueue(() => this.config.triage.maxConcurrent);
    this.threadState = options.threadState ?? new AssistantThreadStateStore(config);
  }
  private toolDeps(input: SecurityAssistantInput, researchState?: SecurityResearchState): SecurityToolDeps {
    return {
      config: this.config,
      cerebro: this.cerebro,
      memory: this.memory,
      autonomyGoals: this.options.goals, riskAttestations: this.options.riskAttestations,
      researchState,
      requestContext: { channelId: input.channelId, userId: input.userId, threadTs: input.threadTs ?? input.ts },
    };
  }
  private createTools(input: SecurityAssistantInput, researchState: SecurityResearchState) {
    return (this.options.toolFactory ?? createSecurityAgentTools)(this.toolDeps(input, researchState));
  }
  async answer(input: SecurityAssistantInput): Promise<SecurityAssistantAnswer> {
    return withTelemetrySpan("assistant.answer", {
      component: "security-assistant",
      operation: "answer",
      "assistant.question.length": input.question.length,
      "assistant.runtime": this.config.triage.assistantRuntime,
      "triage.pi.enabled": this.config.triage.pi.enabled,
      "assistant.code_mode.enabled": this.config.codeMode?.enabled ?? false,
      ...slackTelemetryAttributes(input),
    }, async (span) => {
      const run = async () => {
        if (!this.config.triage.pi.enabled) {
          return this.blockedAnswer("Pi disabled by configuration.");
        }
        const runtime = this.config.triage.assistantRuntime;
        try {
          return runtime === "flue" ? await this.runFlueAgent(input) : await this.runPiAgent(input);
        } catch (error) {
          captureTelemetryError(`assistant.${runtime}.unavailable`, error, { component: "security-assistant", operation: `${runtime}_agent` });
          annotateMainDependency("gen_ai", `${runtime}-agent`, "security_answer", "failed", {
            error_kind: telemetryErrorKind(error),
            "gen_ai.provider.name": this.config.triage.pi.provider,
            "gen_ai.request.model": this.config.triage.pi.model,
          });
          return this.blockedAnswer(error);
        }
      };
      const result = await this.slots.run(() => withAssistantWorkflowPermit(this.config, this.options.rateLimits, run));
      annotateSpan(span, assistantResultTelemetry(result));
      return result;
    }, {
      statusForResult: (result) => result.source === "blocked" ? "failed" : "completed",
      errorEventName: "assistant.answer.error",
    });
  }
  async recordDelivery(
    input: SecurityAssistantInput,
    delivery: { plannedMessages: number; postedMessages: number; complete: boolean; answerTs?: string },
  ): Promise<void> {
    await this.threadState.recordDelivery(input, delivery);
  }
  private async runPiAgent(input: SecurityAssistantInput): Promise<SecurityAssistantAnswer> {
    return withTelemetrySpan("assistant.pi.run", {
      component: "security-assistant",
      operation: "pi_agent",
      "gen_ai.provider.name": this.config.triage.pi.provider,
      "gen_ai.request.model": this.config.triage.pi.model,
      "gen_ai.thinking_level": this.config.triage.pi.thinkingLevel,
      "gen_ai.tool.max_count": this.config.triage.maxResearchSteps,
      "gen_ai.timeout_ms": this.config.triage.timeoutMs,
      ...slackTelemetryAttributes(input),
    }, async (span) => {
    const model = this.models.getModel(this.config.triage.pi.provider, this.config.triage.pi.model);
    if (!model) {
      throw new Error(`Pi model ${this.config.triage.pi.provider}/${this.config.triage.pi.model} is not available`);
    }

    const researchState = new SecurityResearchState(this.sourceHealth, input.channelId);
    const baseTools = this.createTools(input, researchState);
    const allowedTools = new Set(baseTools.map((tool) => tool.name));
    const inferredIntent = inferSecurityAgentIntent({ question: input.question });
    const researchTrail: string[] = [];
    const toolHooks = new SecurityAssistantToolHooks({ allowedTools, inferredIntent, additionalReadOnlyToolNames: this.options.additionalReadOnlyToolNames,
      maxResearchSteps: this.config.triage.maxResearchSteps, researchState, researchTrail,
      trustedOperator: Boolean(input.userId && this.config.slack.operatorUserIds.has(input.userId)) });
    const codeModeTools = createAssistantCodeModeTools(this.config, baseTools, toolHooks, this.options.additionalReadOnlyToolNames);
    codeModeTools.forEach((tool) => allowedTools.add(tool.name));
    const tools = [...baseTools, ...codeModeTools];
    const toolCatalogBlock = toolCatalogPrompt(tools);
    const toolPolicyBlock = toolPolicyPrompt(baseTools);
    const threadContext = await assistantConversationContext({ config: this.config, stateStore: this.threadState, question: input, research: researchTrail, goals: this.options.goals, evidenceGovernance: this.options.evidenceGovernance });
    const learningPromptBlock = await assistantLearningPromptBlock({ memoryPromptBlock: this.memory.workingMemoryPromptBlock(), feedback: this.options.feedback, userId: input.userId, interactionId: input.interactionId, channelId: input.channelId, threadTs: input.threadTs ?? input.ts, question: input.question, research: researchTrail });
    const assistantSystemPrompt = systemPrompt(this.config, learningPromptBlock, toolCatalogBlock, toolPolicyBlock, this.options.evaluationInstructions);
    const promptBuild = buildAssistantUserPrompt({ config: this.config, question: input, systemText: assistantSystemPrompt, threadContext, researchTrail });
    const assistantUserPrompt = promptBuild.userText;
    const preflight = promptBuild.preflight;
    annotateSpan(span, {
      "assistant.prompt.size_chars": preflight.size,
      "assistant.prompt.limit_chars": preflight.limit,
      "assistant.prompt.original_size_chars": promptBuild.originalSize,
      "assistant.prompt.compacted": promptBuild.compacted,
    });
    if (!preflight.ok) {
      return oversizedPromptAnswer(input, preflight, researchTrail);
    }
    const agent = new Agent({
      initialState: {
        systemPrompt: assistantSystemPrompt,
        model,
        thinkingLevel: this.config.triage.pi.thinkingLevel as ThinkingLevel,
        tools,
      },
      streamFn: (requestModel, context, options) => this.models.streamSimple(requestModel, context, options),
      toolExecution: "parallel",
      beforeToolCall: toolHooks.beforePi,
      afterToolCall: toolHooks.afterPi,
    });
    const timeout = setTimeout(() => agent.abort(), this.config.triage.timeoutMs);
    timeout.unref?.();
    try {
      await agent.prompt(assistantUserPrompt);
    } finally {
      clearTimeout(timeout);
    }
    if (agent.state.errorMessage) {
      throw new Error(agent.state.errorMessage);
    }
    const rawAssistantText = latestAssistantText(agent.state.messages);
    let parsed = parseSecurityAssistantOutput(rawAssistantText, researchTrail);
    if (!parsed) {
      parsed = await this.repairAssistantOutput({
        input,
        rawOutput: rawAssistantText,
        messages: agent.state.messages,
        researchTrail,
      });
    }
    if (!parsed) {
      throw new Error("Pi security assistant did not return valid answer JSON");
    }
    parsed = researchState.reconcileClaimEvidence(parsed);
    parsed = recoverIncompleteResearch(parsed, researchState, "pi");
    parsed = prepareDeliverableAnswer(parsed, researchTrail, "pi");
    const adaptivePlan = researchState.adaptivePlan();
    parsed = { ...parsed, executionLane: parsed.executionLane ?? adaptivePlan.executionLane, domainLenses: adaptivePlan.domainLenses };
    parsed = await this.options.ensemble?.refine(input, parsed) ?? parsed;
    const goalResult = await reconcileTeammateGoals({ answer: parsed, question: input, goals: this.options.goals, createdGoalIds: researchState.createdGoals() });
    parsed = goalResult.answer;
    parsed = await presentSlackAnswerWithLlm({ config: this.config, question: input, answer: parsed, options: this.options, threadContext });
    parsed = researchState.reconcileClaimEvidence(parsed);
    parsed = prepareDeliverableAnswer(parsed, researchTrail, "pi");
    annotateSpan(span, {
      "gen_ai.tool.count": toolHooks.count,
      "assistant.research.count": researchTrail.length,
      "assistant.memory_update.count": parsed.memoryUpdates.length,
      "assistant.execution_style": adaptivePlan.executionStyle,
      "assistant.code_mode.selected_count": adaptivePlan.executionStyle === "code" ? 1 : 0,
      ...researchState.telemetryAttributes(),
      ...assistantResultTelemetry(parsed),
      "assistant.goal.linked_count": goalResult.reconciliation.linked,
      "assistant.goal.unbacked_count": goalResult.reconciliation.unbacked,
      "assistant.goal.missing_count": goalResult.reconciliation.missing,
      "assistant.goal.scope_mismatch_count": goalResult.reconciliation.scopeMismatch,
    });
    maxMain("gen_ai.tool.max_observed_count", toolHooks.count);
    annotateMainDependency("gen_ai", "pi-agent", "security_answer", "completed", {
      "gen_ai.provider.name": this.config.triage.pi.provider,
      "gen_ai.request.model": this.config.triage.pi.model,
    });

    await Promise.all(parsed.memoryUpdates.map((update) => this.memory.remember({
      ...update,
      channelId: input.channelId,
      sourceTs: input.ts,
      sourceKind: update.sourceKind ?? "tool",
    }).catch(() => undefined)));
    await persistAssistantIntelligence({ stateStore: this.threadState, memory: this.memory, question: input, answer: parsed, researchState })
      .catch((error) => captureTelemetryError("assistant.intelligence.persist.error", error, { component: "security-assistant", operation: "persist_intelligence" }));
    return parsed;
    }, { errorEventName: "assistant.pi.error" });
  }

  private async runFlueAgent(input: SecurityAssistantInput): Promise<SecurityAssistantAnswer> {
    return withTelemetrySpan("assistant.flue.run", {
      component: "security-assistant",
      operation: "flue_agent",
      "gen_ai.provider.name": this.config.triage.pi.provider,
      "gen_ai.request.model": this.config.triage.pi.model,
      "gen_ai.thinking_level": this.config.triage.pi.thinkingLevel,
      "assistant.flue.execution_model": this.config.triage.pi.executionModel, "assistant.flue.execution_thinking_level": this.config.triage.pi.executionThinkingLevel,
      "gen_ai.tool.max_count": this.config.triage.maxResearchSteps,
      "gen_ai.timeout_ms": this.config.triage.timeoutMs,
      ...slackTelemetryAttributes(input),
    }, async (span) => {
      const researchState = new SecurityResearchState(this.sourceHealth, input.channelId);
      const baseTools = this.createTools(input, researchState);
      const allowedTools = new Set(baseTools.map((tool) => tool.name));
      const inferredIntent = inferSecurityAgentIntent({ question: input.question });
      const researchTrail: string[] = [];
      const toolHooks = new SecurityAssistantToolHooks({ allowedTools, inferredIntent, additionalReadOnlyToolNames: this.options.additionalReadOnlyToolNames,
        maxResearchSteps: this.config.triage.maxResearchSteps, researchState, researchTrail,
        trustedOperator: Boolean(input.userId && this.config.slack.operatorUserIds.has(input.userId)) });
      const codeModeTools = createAssistantCodeModeTools(this.config, baseTools, toolHooks, this.options.additionalReadOnlyToolNames);
      const tools = [...baseTools, ...codeModeTools];
      const toolCatalogBlock = toolCatalogPrompt(tools);
      const toolPolicyBlock = toolPolicyPrompt(baseTools);
      const threadContext = await assistantConversationContext({ config: this.config, stateStore: this.threadState, question: input, research: researchTrail, goals: this.options.goals, evidenceGovernance: this.options.evidenceGovernance });
      const learningPromptBlock = await assistantLearningPromptBlock({ memoryPromptBlock: this.memory.workingMemoryPromptBlock(), feedback: this.options.feedback, userId: input.userId, interactionId: input.interactionId, channelId: input.channelId, threadTs: input.threadTs ?? input.ts, question: input.question, research: researchTrail });
      const assistantSystemPrompt = systemPrompt(this.config, learningPromptBlock, toolCatalogBlock, toolPolicyBlock, this.options.evaluationInstructions);
      const promptBuild = buildAssistantUserPrompt({ config: this.config, question: input, systemText: assistantSystemPrompt, threadContext, researchTrail });
      const assistantUserPrompt = promptBuild.userText;
      const preflight = promptBuild.preflight;
      annotateSpan(span, {
        "assistant.prompt.size_chars": preflight.size,
        "assistant.prompt.limit_chars": preflight.limit,
        "assistant.prompt.original_size_chars": promptBuild.originalSize,
        "assistant.prompt.compacted": promptBuild.compacted,
      });
      if (!preflight.ok) {
        return oversizedPromptAnswer(input, preflight, researchTrail);
      }
      const flueTools = adaptPiToolsToFlue(baseTools, {
        beforeToolCall: toolHooks.beforeFlue,
        afterToolCall: toolHooks.afterFlue,
      });
      const flueCodeModeTools = adaptPiToolsToFlue(codeModeTools);
      const complete = this.options.flueComplete ?? completeWithFlueSecurityAssistant;
      const response = await complete({
        systemPrompt: assistantSystemPrompt,
        userPrompt: assistantUserPrompt,
        model: `${this.config.triage.pi.provider}/${this.config.triage.pi.model}`,
        thinkingLevel: this.config.triage.pi.thinkingLevel as FlueSecurityAssistantCompleteInput["thinkingLevel"],
        executionModel: `${this.config.triage.pi.provider}/${this.config.triage.pi.executionModel}`, executionThinkingLevel: this.config.triage.pi.executionThinkingLevel as FlueSecurityAssistantCompleteInput["executionThinkingLevel"],
        tools: flueTools,
        codeTools: flueCodeModeTools,
        timeoutMs: this.config.triage.timeoutMs,
        allowIgnore: input.senderKind === "bot",
        onResearchPlan: (plan) => prepareDistributedResearch({ question: input, plan, researchState, distributedWork: this.options.distributedWork }),
      });
      if (!researchState.hasPlan() && response.stages?.researchPlan) {
        researchState.seedStagedPlan(response.stages.researchPlan);
      }
      if (input.senderKind === "bot" && response.data.response_disposition === "ignore") {
        const ignored = this.ignoredBotHandoff(response.data.disposition_reason);
        annotateSpan(span, {
          "gen_ai.tool.count": toolHooks.count,
          "assistant.research.count": researchTrail.length,
          "assistant.flue.typed_output": true,
          "assistant.flue.stage.count": response.stages?.researchPlan.response_disposition === "ignore" ? 1 : 2,
          ...researchState.telemetryAttributes(),
          ...assistantResultTelemetry(ignored),
        });
        await persistAssistantIntelligence({ stateStore: this.threadState, memory: this.memory, question: input, answer: ignored, researchState })
          .catch((error) => captureTelemetryError("assistant.intelligence.persist.error", error, { component: "security-assistant", operation: "persist_intelligence" }));
        return ignored;
      }
      let parsed = normalizeSecurityAssistantOutput(response.data, researchTrail, "flue");
      if (!parsed) throw new Error("Flue security assistant did not return valid answer data");
      parsed = researchState.reconcileClaimEvidence(parsed);
      const adaptivePlan = researchState.adaptivePlan();
      parsed = {
        ...parsed,
        executionLane: parsed.executionLane ?? response.execution?.lane ?? adaptivePlan.executionLane,
        domainLenses: adaptivePlan.domainLenses,
      };
      parsed = recoverIncompleteResearch(parsed, researchState, "flue");
      parsed = prepareDeliverableAnswer(parsed, researchTrail, "flue");
      parsed = await this.options.ensemble?.refine(input, parsed) ?? parsed;
      const goalResult = await reconcileTeammateGoals({ answer: parsed, question: input, goals: this.options.goals, createdGoalIds: researchState.createdGoals() });
      parsed = goalResult.answer;
      parsed = await presentSlackAnswerWithLlm({ config: this.config, question: input, answer: parsed, options: this.options, threadContext });
      parsed = researchState.reconcileClaimEvidence(parsed);
      parsed = prepareDeliverableAnswer(parsed, researchTrail, "flue");
      annotateSpan(span, {
        "gen_ai.tool.count": toolHooks.count,
        "assistant.research.count": researchTrail.length,
        "assistant.memory_update.count": parsed.memoryUpdates.length,
        "assistant.flue.typed_output": true,
        "assistant.flue.stage.count": response.execution?.stageCount ?? (response.stages ? 3 : 1),
        "assistant.execution_style": response.execution?.executionStyle ?? adaptivePlan.executionStyle,
        "assistant.code_mode.selected_count": (response.execution?.executionStyle ?? adaptivePlan.executionStyle) === "code" ? 1 : 0,
        "assistant.tool_pack.available_count": response.execution?.availableToolCount ?? tools.length,
        "assistant.tool_pack.selected_count": response.execution?.selectedToolCount ?? tools.length,
        ...specialistTelemetryAttributes(response.execution),
        ...researchState.telemetryAttributes(),
        ...assistantResultTelemetry(parsed),
        "assistant.goal.linked_count": goalResult.reconciliation.linked,
        "assistant.goal.unbacked_count": goalResult.reconciliation.unbacked,
        "assistant.goal.missing_count": goalResult.reconciliation.missing,
        "assistant.goal.scope_mismatch_count": goalResult.reconciliation.scopeMismatch,
      });
      maxMain("gen_ai.tool.max_observed_count", toolHooks.count);
      annotateMainDependency("gen_ai", "flue-agent", "security_answer", "completed", {
        "gen_ai.provider.name": this.config.triage.pi.provider,
        "gen_ai.request.model": this.config.triage.pi.model,
      });
      await Promise.all(parsed.memoryUpdates.map((update) => this.memory.remember({
        ...update,
        channelId: input.channelId,
        sourceTs: input.ts,
        sourceKind: update.sourceKind ?? "tool",
      }).catch(() => undefined)));
      await persistAssistantIntelligence({ stateStore: this.threadState, memory: this.memory, question: input, answer: parsed, researchState })
        .catch((error) => captureTelemetryError("assistant.intelligence.persist.error", error, { component: "security-assistant", operation: "persist_intelligence" }));
      return parsed;
    }, { errorEventName: "assistant.flue.error" });
  }

  private async repairAssistantOutput(input: {
    input: SecurityAssistantInput;
    rawOutput: string;
    messages: unknown[];
    researchTrail: string[];
  }): Promise<SecurityAssistantAnswer | undefined> {
    const transcript = compactAgentTranscript(input.messages);
    const systemPrompt = assistantOutputRepairSystemPrompt();
    const userPrompt = assistantOutputRepairUserPrompt({
      input: input.input,
      rawOutput: input.rawOutput,
      researchTrail: input.researchTrail,
      transcript,
    });
    const raw = await this.completeOutputRepair({
      systemPrompt,
      userPrompt,
      rawOutput: input.rawOutput,
      researchTrail: input.researchTrail,
      transcript,
    });
    const parsed = parseSecurityAssistantOutput(raw, input.researchTrail);
    if (parsed) {
      telemetryEvent("assistant.output_repair.completed", {
        component: "security-assistant",
        operation: "output_repair",
        "assistant.research.count": input.researchTrail.length,
      });
    }
    return parsed;
  }
  private async completeOutputRepair(input: SecurityAssistantRepairCompleteInput): Promise<string> {
    if (this.options.repairComplete) return this.options.repairComplete(input);
    if (!this.config.triage.pi.enabled) {
      throw new Error("Pi assistant output repair is disabled by configuration.");
    }
    const model = this.models.getModel(this.config.triage.pi.provider, this.config.triage.pi.model);
    if (!model) {
      throw new Error(`Pi model ${this.config.triage.pi.provider}/${this.config.triage.pi.model} is not available`);
    }
    const agent = new Agent({
      initialState: {
        systemPrompt: input.systemPrompt,
        model,
        thinkingLevel: this.config.triage.pi.thinkingLevel as ThinkingLevel,
        tools: [],
      },
      streamFn: (requestModel, context, options) => this.models.streamSimple(requestModel, context, options),
    });
    const timeout = setTimeout(() => agent.abort(), this.config.triage.timeoutMs);
    timeout.unref?.();
    try {
      await agent.prompt(input.userPrompt);
    } finally {
      clearTimeout(timeout);
    }
    if (agent.state.errorMessage) {
      throw new Error(agent.state.errorMessage);
    }
    return latestAssistantText(agent.state.messages);
  }
  private blockedAnswer(reason: unknown): SecurityAssistantAnswer {
    const llmError = summarizeLlmError(reason, this.config);
    const runtime = this.config.triage.assistantRuntime;
    telemetryEvent("assistant.blocked", {
      component: "security-assistant",
      operation: "blocked_answer",
      error_kind: telemetryErrorKind(reason),
      "llm.error.category": llmError.category,
      "llm.error.detail_present": Boolean(llmError.detail),
      "gen_ai.provider.name": this.config.triage.pi.provider,
      "gen_ai.request.model": this.config.triage.pi.model,
    });
    const message = blockedSlackMessage(llmError.category);
    return {
      answer: message,
      messages: [message],
      reaction: "warning",
      keyPoints: ["The source check did not complete.", "The failed run is recorded with its internal error category."],
      evidence: [],
      actionsTaken: [llmError.actionTaken],
      nextActions: ["Retrying from this conversation will retain the current mission and source subjects."],
      research: [`llm_error: ${llmError.category} (${llmError.detail})`, `${runtime}_agent: blocked`],
      memoryUpdates: [],
      source: "blocked",
    };
  }
  private ignoredBotHandoff(reason: string | undefined): SecurityAssistantAnswer {
    const dispositionReason = reason?.replace(/\s+/g, " ").trim().slice(0, 500)
      || "Automated handoff had no explicit request or verified new value.";
    telemetryEvent("assistant.delivery.suppressed", {
      component: "security-assistant",
      operation: "delivery_disposition",
      "assistant.delivery": "suppress",
      "assistant.sender.kind": "bot",
    });
    return {
      answer: "Automated handoff ignored.",
      messages: [],
      keyPoints: [dispositionReason],
      evidence: [],
      actionsTaken: [],
      nextActions: [],
      research: ["delivery_disposition: ignored_bot_handoff"],
      memoryUpdates: [],
      source: "flue",
      executionLane: "ignore",
      presentationReady: true,
      delivery: "suppress",
      dispositionReason,
    };
  }
}
