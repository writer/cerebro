import { Agent, type ThinkingLevel } from "@earendil-works/pi-agent-core";
import { builtinModels } from "@earendil-works/pi-ai/providers/all";
import { SlotQueue } from "../agent/slot-queue.js";
import { createSecurityAgentTools } from "../agent/tools/index.js";
import { evaluateSecurityAgentToolCall } from "../agent/tool-policy.js";
import type { AppConfig } from "../config/index.js";
import type { CerebroClient } from "../cerebro/client.js";
import type { SecurityMemoryStore } from "../learning/security-memory/index.js";
import { answerFromGraphReason, trimForSlack } from "../slack/format.js";
import {
  annotateMainDependency,
  annotateMainPhase,
  annotateSpan,
  captureTelemetryError,
  incrementMain,
  maxMain,
  slackTelemetryAttributes,
  telemetryErrorKind,
  telemetryEvent,
  withTelemetrySpan,
} from "../telemetry.js";
import { actionsFromResearch, heuristicTriage, shortError } from "./alert-triage-fallback.js";
import { contextBlockForPrompt, createAlertTriageContextCollector, type AlertTriageContextOptions } from "./alert-triage-context.js";
import { triageMemoryExpiresAt, sourceArtifactsFromTriage, toolsCheckedFromResearch, topicFromAlert } from "./alert-triage-memory.js";
import { parseTriageAgentOutput, redactAlertText } from "./alert-triage-output.js";
import { systemPrompt, userPrompt } from "./alert-triage-prompts.js";
import { shouldPostTriageResponse, shouldTriageSlackMessage } from "./alert-triage-response.js";
import { hasSecuritySignal } from "./alert-triage-signals.js";
import { triageResultTelemetry } from "./alert-triage-telemetry.js";
import { latestAssistantText } from "./alert-triage-transcript.js";
import type { ProactiveSlackContextCollector } from "./proactive-context.js";
import type { AlertTriageInput, AlertTriageResult } from "./alert-triage-types.js";

export { parseTriageAgentOutput, redactAlertText } from "./alert-triage-output.js";
export { shouldPostTriageResponse, shouldTriageSlackMessage } from "./alert-triage-response.js";
export type { AlertTriageInput, AlertTriageResult, SlackMessageForTriage, TriageClassification, TriageSeverity } from "./alert-triage-types.js";

export class AlertTriageService {
  private readonly models = builtinModels();
  private readonly slots: SlotQueue;
  private readonly contextCollector?: ProactiveSlackContextCollector;

  constructor(
	    private readonly config: AppConfig,
	    private readonly cerebro: CerebroClient,
	    private readonly memory: SecurityMemoryStore,
	    options: AlertTriageContextOptions = {},
	  ) {
	    this.slots = new SlotQueue(() => this.config.triage.maxConcurrent);
	    this.contextCollector = createAlertTriageContextCollector(config, memory, options);
	  }

  async triage(input: AlertTriageInput): Promise<AlertTriageResult> {
    return withTelemetrySpan("triage.run", {
      component: "alert-triage",
      operation: "triage",
      "triage.text.length": input.text.length,
      "triage.pi.enabled": this.config.triage.pi.enabled,
      ...slackTelemetryAttributes(input),
    }, async (span) => {
    const result = await this.slots.run(async () => {
      if (!this.config.triage.pi.enabled) {
        return this.fallbackTriage(input, "Pi disabled by configuration.");
      }
      try {
        return await this.runPiAgent(input);
      } catch (error) {
        captureTelemetryError("triage.pi.unavailable", error, { component: "alert-triage", operation: "pi_agent" });
        return this.fallbackTriage(input, error instanceof Error ? error.message : String(error));
      }
    });
    annotateSpan(span, triageResultTelemetry(result));
    await this.rememberTriage(input, result)
      .then(() => annotateMainPhase("triage.memory_remember", "completed"))
      .catch((error) => {
        annotateMainPhase("triage.memory_remember", "failed", { error_kind: telemetryErrorKind(error) });
        captureTelemetryError("triage.memory_remember.error", error, { component: "alert-triage", operation: "remember_triage" });
      });
    return result;
    }, {
      statusForResult: (result) => result.source === "cerebro_fallback" ? "degraded" : "completed",
      errorEventName: "triage.run.error",
    });
  }

  private async runPiAgent(input: AlertTriageInput): Promise<AlertTriageResult> {
    return withTelemetrySpan("triage.pi.run", {
      component: "alert-triage",
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

    const tools = createSecurityAgentTools({ config: this.config, cerebro: this.cerebro, memory: this.memory });
    const allowedTools = new Set(tools.map((tool) => tool.name));
    const researchTrail: string[] = [];
	    const contextBlock = await contextBlockForPrompt(this.config, input, researchTrail, this.contextCollector);
    let toolCallCount = 0;

    const agent = new Agent({
      initialState: {
        systemPrompt: systemPrompt(this.config, this.memory.workingMemoryPromptBlock()),
        model,
        thinkingLevel: this.config.triage.pi.thinkingLevel as ThinkingLevel,
        tools,
      },
      streamFn: (requestModel, context, options) => this.models.streamSimple(requestModel, context, options),
      toolExecution: "parallel",
      beforeToolCall: async ({ toolCall }) => {
        if (!allowedTools.has(toolCall.name)) {
          telemetryEvent("triage.tool.blocked", {
            component: "alert-triage",
            operation: "before_tool_call",
            "tool.name": toolCall.name,
            "tool.block.reason": "not_available",
          });
          return { block: true, reason: `Tool ${toolCall.name} is not available in alert triage.` };
        }
        const policy = evaluateSecurityAgentToolCall(toolCall.name, "security_answer");
        if (!policy.allowed) {
          telemetryEvent("triage.tool.blocked", {
            component: "alert-triage",
            operation: "before_tool_call",
            "tool.name": toolCall.name,
            "tool.block.reason": "policy",
            "tool.policy.tier": policy.policy.tier,
          });
          return { block: true, reason: policy.reason };
        }
        toolCallCount += 1;
        incrementMain("gen_ai.tool.request.count", 1);
        annotateMainPhase(`triage.tool.${toolCall.name}`, "queued", { "tool.last_name": toolCall.name });
        if (toolCallCount > this.config.triage.maxResearchSteps) {
          telemetryEvent("triage.tool.blocked", {
            component: "alert-triage",
            operation: "before_tool_call",
            "tool.name": toolCall.name,
            "tool.block.reason": "max_research_steps",
            "gen_ai.tool.count": toolCallCount,
          });
          return {
            block: true,
            reason: `Research step limit ${this.config.triage.maxResearchSteps} reached. Return the best triage from current evidence.`,
          };
        }
        return undefined;
      },
      afterToolCall: async ({ toolCall, isError }) => {
        researchTrail.push(`${toolCall.name}: ${isError ? "failed" : "checked"}`);
        annotateMainPhase(`triage.tool.${toolCall.name}`, isError ? "failed" : "completed", { "tool.last_name": toolCall.name });
        if (isError) incrementMain("gen_ai.tool.error.count", 1);
        return undefined;
      },
    });

    const timeout = setTimeout(() => agent.abort(), this.config.triage.timeoutMs);
    timeout.unref?.();
    try {
      await agent.prompt(userPrompt(input, this.config, contextBlock));
    } finally {
      clearTimeout(timeout);
    }

    if (agent.state.errorMessage) {
      throw new Error(agent.state.errorMessage);
    }

    const rawAnswer = latestAssistantText(agent.state.messages);
    const parsed = parseTriageAgentOutput(rawAnswer, researchTrail);
    if (!parsed) {
      throw new Error("Pi triage did not return valid triage JSON");
    }
    annotateSpan(span, {
      "gen_ai.tool.count": toolCallCount,
      "triage.research.count": researchTrail.length,
      ...triageResultTelemetry(parsed),
    });
    maxMain("gen_ai.tool.max_observed_count", toolCallCount);
    annotateMainDependency("gen_ai", "pi-agent", "alert_triage", "completed", {
      "gen_ai.provider.name": this.config.triage.pi.provider,
      "gen_ai.request.model": this.config.triage.pi.model,
    });
    return parsed;
    }, { errorEventName: "triage.pi.error" });
  }

  private async fallbackTriage(input: AlertTriageInput, reason: string): Promise<AlertTriageResult> {
    return withTelemetrySpan("triage.fallback", {
      component: "alert-triage",
      operation: "fallback",
      error_kind: telemetryErrorKind(reason),
      ...slackTelemetryAttributes(input),
    }, async (span) => {
    annotateMainDependency("gen_ai", "pi-agent", "alert_triage", "failed", {
      error_kind: telemetryErrorKind(reason),
      "gen_ai.provider.name": this.config.triage.pi.provider,
      "gen_ai.request.model": this.config.triage.pi.model,
    });
    const alertText = redactAlertText(input.text);
    const research = [`Pi fallback: ${reason}`];
	    const contextBlock = await contextBlockForPrompt(this.config, input, research, this.contextCollector);
    const question = [
      "Triage this Slack security alert with Cerebro graph context.",
      `Slack channel: ${input.channelId}`,
      `Slack event ts: ${input.ts}`,
      input.threadTs ? `Slack thread ts: ${input.threadTs}` : "",
      `Alert text: ${alertText}`,
      contextBlock ? `Slack context:\n${contextBlock}` : "",
      "Classify it as likely security issue, likely noise, or needs context. Name concrete evidence and next actions.",
      "If this is a conversational follow-up, answer the actual question from the thread context instead of treating the short text as a standalone alert.",
      "If the follow-up asks what actions an identity performed, answer with observed activity, not remediation steps.",
    ].join("\n");
    await this.cerebro.buildEvidencePacket({
      question,
      capability_ids: ["security-alert-triage", "graph-reasoning"],
      slack_channel_id: input.channelId,
      slack_event_ts: input.ts,
    })
      .then(() => research.push("cerebro_evidence_packet: checked"))
      .catch((error) => research.push(`cerebro_evidence_packet: failed (${shortError(error)})`));
    let graphAnswer: string | undefined;
    await this.cerebro.reasonGraph({ question })
      .then((graph) => {
        graphAnswer = answerFromGraphReason(graph);
        research.push("cerebro_graph_reason: checked");
      })
      .catch((error) => research.push(`cerebro_graph_reason: failed (${shortError(error)})`));
    if (!graphAnswer) {
      const heuristic = heuristicTriage(input, research);
      annotateSpan(span, {
        ...triageResultTelemetry(heuristic),
        "triage.fallback.graph_answer_present": false,
      });
      return heuristic;
    }
    const result: AlertTriageResult = {
      classification: "needs_context",
      severity: "info",
      confidence: 0.45,
      shouldRespond: hasSecuritySignal(alertText),
      responseReason: hasSecuritySignal(alertText)
        ? "Cerebro fallback found graph context for a security-relevant message."
        : "Fallback did not verify enough signal to interrupt the thread.",
      summary: trimForSlack(graphAnswer, 900),
      evidence: ["Cerebro graph reasoning ran after Pi triage was unavailable."],
      actionsTaken: actionsFromResearch(research),
      recommendedActions: [
        "Review the source alert fields and affected resource.",
        "Check related Cerebro findings before resolving or suppressing the alert.",
      ],
      research,
      source: "cerebro_fallback",
    };
    annotateSpan(span, {
      ...triageResultTelemetry(result),
      "triage.fallback.graph_answer_present": true,
    });
    return result;
    }, { errorEventName: "triage.fallback.error" });
  }

	  private async rememberTriage(input: AlertTriageInput, result: AlertTriageResult): Promise<void> {
    const willAutoReply = shouldPostTriageResponse(this.config, result);
    await this.memory.remember({
      kind: result.classification === "likely_noise" ? "normal_pattern" : "triage_outcome",
      topic: topicFromAlert(input.text),
      summary: result.summary,
      details: [
        `classification=${result.classification}`,
        result.severity ? `severity=${result.severity}` : "",
        `auto_reply=${willAutoReply ? "posted" : "suppressed"}`,
        result.actionsTaken.length > 0 ? `actions=${result.actionsTaken.slice(0, 3).join(" | ")}` : "",
        result.research.length > 0 ? `research=${result.research.slice(0, 4).join(" | ")}` : "",
        result.evidence.slice(0, 3).join(" | "),
      ].filter(Boolean).join("; "),
      tags: ["slack-alert", result.classification, result.severity ?? "severity-unknown", willAutoReply ? "auto-reply-posted" : "auto-reply-suppressed"],
      channelId: input.channelId,
      sourceTs: input.ts,
      classification: result.classification,
      confidence: result.confidence,
      expiresAt: triageMemoryExpiresAt(result, willAutoReply),
      scope: input.threadTs ? `slack-thread:${input.channelId}:${input.threadTs}` : `slack-message:${input.channelId}`,
      verifiedBy: toolsCheckedFromResearch(result.research),
      verifiedAt: new Date().toISOString(),
      sourceArtifacts: sourceArtifactsFromTriage(input, result),
      stalenessPolicy: "short_lived",
      promotionState: "transient",
    });
  }
}
