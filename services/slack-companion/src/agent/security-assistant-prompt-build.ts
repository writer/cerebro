import type { AppConfig } from "../config/index.js";
import { userPromptWithPreflightCompaction, type AssistantPromptCompactionResult } from "./security-assistant-prompt-preflight.js";
import { userPrompt } from "./security-assistant-prompts.js";
import type { SecurityAssistantInput } from "./security-assistant-types.js";

export function buildAssistantUserPrompt(input: {
  config: AppConfig;
  question: SecurityAssistantInput;
  systemText: string;
  threadContext: string;
  researchTrail: string[];
}): AssistantPromptCompactionResult {
  return userPromptWithPreflightCompaction({
    config: input.config,
    systemText: input.systemText,
    threadContext: input.threadContext,
    buildUserText: (compactedThreadContext) => userPrompt(input.question, input.config, compactedThreadContext),
    researchTrail: input.researchTrail,
  });
}
