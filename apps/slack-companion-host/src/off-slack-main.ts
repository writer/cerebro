import { createInterface } from "node:readline";
import { FileAgentApprovalStore } from "./runtime/agent-approval-store.js";
import { FileAgentDeliveryOutbox } from "./runtime/agent-delivery-outbox.js";
import { CerebroAskClient } from "./runtime/cerebro-ask-client.js";
import { loadSlackRuntimeConfig } from "./runtime/config.js";
import {
  OffSlackTransportAdapter,
  runOffSlackTransportJsonl,
} from "./runtime/off-slack-transport.js";
import { FileOutcomeStore } from "./runtime/outcome-store.js";
import { SlackAnswerAuthorityClient } from "./runtime/slack-answer-authority-client.js";
import { FileSlackIngressQueue } from "./runtime/slack-ingress-store.js";
import { FileSlackThreadRouteStore } from "./runtime/slack-thread-route-store.js";
import {
  AssistantQuestionService,
  createAssistantTurnHost,
} from "./runtime/slack-runtime.js";
import { FileThreadScratchpadStore } from "./runtime/thread-scratchpad-store.js";

async function main(): Promise<void> {
  const config = loadSlackRuntimeConfig();
  if (!config.rustAgentEnabled) {
    throw new Error("The off-Slack transport requires the Rust agent runtime.");
  }
  const outcomes = new FileOutcomeStore(config.memoryDirectory);
  const host = createAssistantTurnHost(outcomes);
  const agentClient = new CerebroAskClient({
    agentRuntimeUrl: config.slackAnswerAuthorityUrl,
    answerAuthority: new SlackAnswerAuthorityClient({
      baseUrl: config.slackAnswerAuthorityUrl,
    }),
    apiKey: config.cerebroReadApiKey,
    baseUrl: config.cerebroBaseUrl,
    tenantId: config.cerebroTenantId,
  });
  const adapter = new OffSlackTransportAdapter({
    agentDeliveries: new FileAgentDeliveryOutbox(config.memoryDirectory),
    config,
    host,
    ingressQueue: new FileSlackIngressQueue(config.memoryDirectory),
    outcomes,
    questions: new AssistantQuestionService(host, agentClient, {
      approvalStore: new FileAgentApprovalStore(config.memoryDirectory),
    }),
    scratchpads: new FileThreadScratchpadStore(config.memoryDirectory),
    threadRoutes: new FileSlackThreadRouteStore(config.memoryDirectory),
  });
  const lines = createInterface({
    crlfDelay: Infinity,
    input: process.stdin,
    terminal: false,
  });
  await runOffSlackTransportJsonl(lines, adapter, (line) => {
    if (!process.stdout.write(line)) {
      return new Promise<void>((resolve) => process.stdout.once("drain", resolve));
    }
  });
}

main().catch((error: unknown) => {
  process.stderr.write(`${JSON.stringify({
    component: "off-slack-transport",
    error_kind: error instanceof Error ? error.name : "unknown",
    operation: "run",
    state: "failed",
  })}\n`);
  process.exitCode = 1;
});
