import { ArchetypeWorkspaceClient } from "./archetype-client.js";
import { FileAgentApprovalStore } from "./runtime/agent-approval-store.js";
import { FileAgentDeliveryOutbox } from "./runtime/agent-delivery-outbox.js";
import { CerebroAskClient } from "./runtime/cerebro-ask-client.js";
import { loadSlackRuntimeConfig } from "./runtime/config.js";
import { FileOutcomeStore } from "./runtime/outcome-store.js";
import { FileThreadScratchpadStore } from "./runtime/thread-scratchpad-store.js";
import { SlackAnswerAuthorityClient } from "./runtime/slack-answer-authority-client.js";
import {
  AssistantQuestionService,
  createAssistantTurnHost,
  SlackCompanionRuntime,
} from "./runtime/slack-runtime.js";
import { ArchetypeSlackWorkspace } from "./runtime/archetype-workspace.js";

async function main(): Promise<void> {
  const config = loadSlackRuntimeConfig();
  const outcomes = new FileOutcomeStore(config.memoryDirectory);
  const approvals = new FileAgentApprovalStore(config.memoryDirectory);
  const agentDeliveries = new FileAgentDeliveryOutbox(config.memoryDirectory);
  const scratchpads = new FileThreadScratchpadStore(config.memoryDirectory);
  const host = createAssistantTurnHost(outcomes);
  const questions = new AssistantQuestionService(host, new CerebroAskClient({
    ...(config.rustAgentEnabled
      ? { agentRuntimeUrl: config.slackAnswerAuthorityUrl }
      : {}),
    answerAuthority: new SlackAnswerAuthorityClient({
      baseUrl: config.slackAnswerAuthorityUrl,
    }),
    apiKey: config.cerebroReadApiKey,
    baseUrl: config.cerebroBaseUrl,
    tenantId: config.cerebroTenantId,
  }), {
    approvalStore: approvals,
  });
  const archetype = config.archetype
    ? new ArchetypeSlackWorkspace(new ArchetypeWorkspaceClient({
      allowedEmailDomains: config.archetype.allowedEmailDomains,
      archetypeBaseUrl: config.archetype.baseUrl,
      oktaApiToken: config.archetype.oktaApiToken,
      oktaDomain: config.archetype.oktaDomain,
      timeoutMs: config.archetype.timeoutMs,
    }))
    : undefined;
  const runtime = new SlackCompanionRuntime(
    config,
    host,
    questions,
    outcomes,
    scratchpads,
    agentDeliveries,
    archetype,
  );
  await runtime.start();
  process.stdout.write(`${JSON.stringify({
    component: "slack-runtime",
    operation: "start",
    state: "ready",
  })}\n`);

  let stopping = false;
  const stop = async (signal: string): Promise<void> => {
    if (stopping) return;
    stopping = true;
    process.stdout.write(`${JSON.stringify({
      component: "slack-runtime",
      operation: "stop",
      signal,
      state: "started",
    })}\n`);
    await runtime.stop();
  };
  process.once("SIGTERM", () => void stop("SIGTERM"));
  process.once("SIGINT", () => void stop("SIGINT"));
}

main().catch((error: unknown) => {
  process.stderr.write(`${JSON.stringify({
    component: "slack-runtime",
    error_kind: error instanceof Error ? error.name : "unknown",
    operation: "start",
    state: "failed",
  })}\n`);
  process.exitCode = 1;
});
