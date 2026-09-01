import { FileAgentApprovalStore } from "./agent-approval-store.js";
import { FileAgentDeliveryOutbox } from "./agent-delivery-outbox.js";
import { CerebroAskClient } from "./cerebro-ask-client.js";
import type { SlackRuntimeConfig } from "./config.js";
import { OffSlackTransportAdapter } from "./off-slack-transport.js";
import { FileOutcomeStore } from "./outcome-store.js";
import { SlackAnswerAuthorityClient } from "./slack-answer-authority-client.js";
import { FileSlackIngressQueue } from "./slack-ingress-store.js";
import { FileSlackThreadRouteStore } from "./slack-thread-route-store.js";
import {
  AssistantQuestionService,
  createAssistantTurnHost,
} from "./slack-runtime.js";
import { FileThreadScratchpadStore } from "./thread-scratchpad-store.js";

/**
 * Builds the same assistant-turn host, Rust client, durable stores, and Slack
 * handlers used by the deployed companion. Only the Slack Web API is replaced
 * by the adapter's deterministic in-memory implementation.
 */
export function createProductionOffSlackAdapter(
  config: SlackRuntimeConfig,
): OffSlackTransportAdapter {
  return createProductionOffSlackRuntime(config).adapter;
}

export interface ProductionOffSlackRuntime {
  adapter: OffSlackTransportAdapter;
  agentClient: CerebroAskClient;
  threadRoutes: FileSlackThreadRouteStore;
}

export function createProductionOffSlackRuntime(
  config: SlackRuntimeConfig,
): ProductionOffSlackRuntime {
  if (!config.rustAgentEnabled) {
    throw new Error("The off-Slack transport requires the Rust agent runtime.");
  }
  const outcomes = new FileOutcomeStore(config.memoryDirectory);
  const host = createAssistantTurnHost(outcomes);
  const agentClient = new CerebroAskClient({
    agentRuntimeToken: config.slackAgentRuntimeToken,
    agentRuntimeUrl: config.slackAnswerAuthorityUrl,
    answerAuthority: new SlackAnswerAuthorityClient({
      baseUrl: config.slackAnswerAuthorityUrl,
    }),
    apiKey: config.cerebroReadApiKey,
    baseUrl: config.cerebroBaseUrl,
    tenantId: config.cerebroTenantId,
  });
  const threadRoutes = new FileSlackThreadRouteStore(config.memoryDirectory);
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
    threadRoutes,
  });
  return { adapter, agentClient, threadRoutes };
}
