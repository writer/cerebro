import { Agent, type ThinkingLevel } from "@earendil-works/pi-agent-core";
import { builtinModels } from "@earendil-works/pi-ai/providers/all";
import { parseSlackPresentationOutput } from "./security-assistant-output.js";
import { slackPresentationSystemPrompt, slackPresentationUserPrompt } from "./security-assistant-prompts.js";
import { latestAssistantText } from "./security-assistant-transcript.js";
import type { SecurityAssistantAnswer, SecurityAssistantInput, SecurityAssistantPresentationCompleteInput, SecurityAssistantServiceOptions } from "./security-assistant-types.js";
import type { AppConfig } from "../config/index.js";
import { captureTelemetryError, telemetryErrorKind, telemetryEvent } from "../telemetry.js";

const HUMAN_NON_ANSWER_FALLBACK = "I couldn't reconstruct a reliable answer from this attempt. I still have the request and can retry it with fresh source checks.";

export async function presentSlackAnswerWithLlm(input: {
  config: AppConfig;
  question: SecurityAssistantInput;
  answer: SecurityAssistantAnswer;
  options: SecurityAssistantServiceOptions;
  threadContext?: string;
}): Promise<SecurityAssistantAnswer> {
  if (input.answer.source === "blocked") return input.answer;
  const repairHumanNonAnswer = input.question.senderKind !== "bot" && isNonAnswer(input.answer);
  if (input.answer.presentationReady && input.answer.messages.length > 0 && !repairHumanNonAnswer) return input.answer;
  const systemPrompt = slackPresentationSystemPrompt();
  const userPrompt = slackPresentationUserPrompt({ input: input.question, answer: input.answer, threadContext: input.threadContext });
  try {
    const raw = await completeSlackPresentation(input.config, input.options, { systemPrompt, userPrompt, answer: input.answer });
    const messages = parseSlackPresentationOutput(raw);
    if (messages.length === 0) return input.answer;
    if (repairHumanNonAnswer && containsNonAnswer(messages)) {
      throw new Error("Slack presentation returned a human non-answer");
    }
    telemetryEvent("assistant.slack_presentation.completed", {
      component: "security-assistant",
      operation: "slack_presentation",
      "assistant.answer.source": input.answer.source,
      "assistant.answer.message_count": messages.length,
    });
    return {
      ...input.answer,
      answer: repairHumanNonAnswer ? messages.join("\n\n") : input.answer.answer,
      messages,
      delivery: repairHumanNonAnswer ? "respond" : input.answer.delivery,
      dispositionReason: repairHumanNonAnswer ? undefined : input.answer.dispositionReason,
    };
  } catch (error) {
    telemetryEvent("assistant.slack_presentation.failed", {
      component: "security-assistant",
      operation: "slack_presentation",
      error_kind: telemetryErrorKind(error),
      "assistant.answer.source": input.answer.source,
    });
    captureTelemetryError("assistant.slack_presentation.error", error, { component: "security-assistant", operation: "slack_presentation" });
    if (repairHumanNonAnswer) {
      return {
        ...input.answer,
        answer: HUMAN_NON_ANSWER_FALLBACK,
        messages: [HUMAN_NON_ANSWER_FALLBACK],
        source: "blocked",
        presentationReady: true,
        delivery: "respond",
        dispositionReason: undefined,
      };
    }
    return input.answer;
  }
}

function isNonAnswer(answer: SecurityAssistantAnswer): boolean {
  const visible = [answer.answer, ...answer.messages].map((value) => value.trim()).filter(Boolean);
  return visible.length === 0 || containsNonAnswer(visible);
}

function containsNonAnswer(messages: string[]): boolean {
  return messages.some((value) => /^(?:\[?ignore\]?|automated handoff ignored\.?)$/i.test(value.trim()));
}

async function completeSlackPresentation(
  config: AppConfig,
  options: SecurityAssistantServiceOptions,
  input: SecurityAssistantPresentationCompleteInput,
): Promise<string> {
  if (options.presentationComplete) return options.presentationComplete(input);
  if (!config.triage.pi.enabled) {
    throw new Error("Pi assistant Slack presentation is disabled by configuration.");
  }
  const models = builtinModels();
  const model = models.getModel(config.triage.pi.provider, config.triage.pi.model);
  if (!model) {
    throw new Error(`Pi model ${config.triage.pi.provider}/${config.triage.pi.model} is not available`);
  }
  const agent = new Agent({
    initialState: {
      systemPrompt: input.systemPrompt,
      model,
      thinkingLevel: config.triage.pi.thinkingLevel as ThinkingLevel,
      tools: [],
    },
    streamFn: (requestModel, context, requestOptions) => models.streamSimple(requestModel, context, requestOptions),
  });
  const timeout = setTimeout(() => agent.abort(), config.triage.timeoutMs);
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
