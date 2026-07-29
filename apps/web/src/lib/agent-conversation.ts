import { createHash } from "node:crypto";

import { OpenAIConversationsSession } from "@openai/agents";
import OpenAI from "openai";

const CONVERSATION_PREFIX = "conv_";
const METADATA_SCHEMA = "cerebro-web-agent-v1";

type ConversationRecord = {
  id: string;
  metadata?: unknown;
};

export type AgentConversationClient = {
  conversations: {
    create(input: { metadata: Record<string, string> }): Promise<ConversationRecord>;
    retrieve(id: string): Promise<ConversationRecord>;
    delete(id: string): Promise<unknown>;
  };
};

export class AgentConversationOwnershipError extends Error {
  constructor() {
    super("Conversation is not available for the current identity and tenant.");
    this.name = "AgentConversationOwnershipError";
  }
}

const ownershipMetadata = (tenantId: string, actorKey: string) => ({
  schema: METADATA_SCHEMA,
  tenant_hash: createHash("sha256").update(tenantId).digest("hex").slice(0, 24),
  actor_key: actorKey,
});

const ownsConversation = (
  conversation: ConversationRecord,
  tenantId: string,
  actorKey: string,
) => {
  const expected = ownershipMetadata(tenantId, actorKey);
  if (
    !conversation.metadata ||
    typeof conversation.metadata !== "object" ||
    Array.isArray(conversation.metadata)
  ) {
    return false;
  }
  const metadata = conversation.metadata as Record<string, unknown>;
  return (
    metadata.schema === expected.schema &&
    metadata.tenant_hash === expected.tenant_hash &&
    metadata.actor_key === expected.actor_key
  );
};

export const openAgentConversation = async ({
  actorKey,
  client,
  conversationId,
  providerClient,
  tenantId,
}: {
  actorKey: string;
  client?: AgentConversationClient;
  conversationId?: string;
  providerClient?: OpenAI;
  tenantId: string;
}) => {
  const openAIClient = providerClient ?? (client ? undefined : new OpenAI());
  if (!openAIClient) {
    throw new TypeError("A providerClient is required when overriding the conversation client.");
  }
  const conversationClient = client ?? openAIClient;
  let conversation: ConversationRecord;
  if (conversationId?.startsWith(CONVERSATION_PREFIX)) {
    conversation = await conversationClient.conversations.retrieve(conversationId);
    if (!ownsConversation(conversation, tenantId, actorKey)) {
      throw new AgentConversationOwnershipError();
    }
  } else {
    conversation = await conversationClient.conversations.create({
      metadata: ownershipMetadata(tenantId, actorKey),
    });
  }
  return {
    conversationId: conversation.id,
    session: new OpenAIConversationsSession({
      conversationId: conversation.id,
      client: openAIClient,
    }),
  };
};

export const removeAgentConversation = async ({
  actorKey,
  client,
  conversationId,
  tenantId,
}: {
  actorKey: string;
  client?: AgentConversationClient;
  conversationId: string;
  tenantId: string;
}) => {
  if (!conversationId.startsWith(CONVERSATION_PREFIX)) return false;
  const conversationClient = client ?? new OpenAI();
  const conversation = await conversationClient.conversations.retrieve(conversationId);
  if (!ownsConversation(conversation, tenantId, actorKey)) {
    throw new AgentConversationOwnershipError();
  }
  await conversationClient.conversations.delete(conversation.id);
  return true;
};
