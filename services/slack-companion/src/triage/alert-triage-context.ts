import type { AppConfig } from "../config/index.js";
import type { SecurityMemoryStore } from "../learning/security-memory/index.js";
import { SlackResearchClient } from "../slack/research/index.js";
import { shortError } from "./alert-triage-fallback.js";
import type { AlertTriageInput } from "./alert-triage-types.js";
import { ProactiveSlackContextCollector, renderProactiveContextPromptBlock } from "./proactive-context.js";
import type { SlackThreadSessionStateStore } from "./slack-thread-state.js";

export interface AlertTriageContextOptions {
  threadState?: SlackThreadSessionStateStore;
  contextCollector?: ProactiveSlackContextCollector;
}

export function createAlertTriageContextCollector(
  config: AppConfig,
  memory: SecurityMemoryStore,
  options: AlertTriageContextOptions,
): ProactiveSlackContextCollector | undefined {
  return options.contextCollector ?? (options.threadState ? new ProactiveSlackContextCollector(config, memory, options.threadState) : undefined);
}

export async function contextBlockForPrompt(
  config: AppConfig,
  input: AlertTriageInput,
  research: string[],
  contextCollector?: ProactiveSlackContextCollector,
): Promise<string> {
  if (!contextCollector) return threadContextForPrompt(config, input, research);
  return contextCollector.collect(input)
    .then((packet) => {
      research.push("slack_proactive_context: checked");
      if (packet.thread) research.push("slack_thread_context: checked");
      if (packet.message) research.push("slack_message_context: checked");
      if (packet.channel) research.push("slack_channel_context: checked");
      if (packet.memories.length > 0) research.push("security_memory_search: checked");
      return renderProactiveContextPromptBlock(packet);
    })
    .catch((error) => {
      research.push(`slack_proactive_context: failed (${shortError(error)})`);
      return threadContextForPrompt(config, input, research);
    });
}

async function threadContextForPrompt(config: AppConfig, input: AlertTriageInput, research: string[]): Promise<string> {
  if (!input.threadTs) return "";
  const slack = new SlackResearchClient(config);
  return slack.threadContext(input.channelId, input.threadTs, 12)
    .then((thread) => {
      research.push("slack_thread_context: checked");
      return thread.messages
        .map((message) => `${message.user_name ?? message.user_id ?? message.bot_id ?? "unknown"}: ${message.text}`)
        .join("\n");
    })
    .catch((error) => {
      research.push(`slack_thread_context: failed (${shortError(error)})`);
      return "";
    });
}
