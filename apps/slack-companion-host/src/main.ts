import { CerebroAskClient } from "./runtime/cerebro-ask-client.js";
import { loadSlackRuntimeConfig } from "./runtime/config.js";
import { FileOutcomeStore } from "./runtime/outcome-store.js";
import {
  AssistantQuestionService,
  createAssistantTurnHost,
  SlackCompanionRuntime,
} from "./runtime/slack-runtime.js";

async function main(): Promise<void> {
  const config = loadSlackRuntimeConfig();
  const outcomes = new FileOutcomeStore(config.memoryDirectory);
  const host = createAssistantTurnHost(outcomes);
  const questions = new AssistantQuestionService(host, new CerebroAskClient({
    apiKey: config.cerebroReadApiKey,
    baseUrl: config.cerebroBaseUrl,
    tenantId: config.cerebroTenantId,
  }));
  const runtime = new SlackCompanionRuntime(config, host, questions, outcomes);
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
