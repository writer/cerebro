import { createHash } from "node:crypto";

import { OpenAIConversationsSession } from "@openai/agents";
import OpenAI from "openai";

const CONVERSATION_PREFIX = "conv_";
const METADATA_SCHEMA = "cerebro-web-agent-v1";

type ConversationRecord = {
  id: string;
  metadata?: Record<string, unknown> | null;
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
  return (
    conversation.metadata?.schema === expected.schema &&
    conversation.metadata?.tenant_hash === expected.tenant_hash &&
    conversation.metadata?.actor_key === expected.actor_key
  );
};

export const openAgentConversation = async ({
  actorKey,
  client = new OpenAI() as unknown as AgentConversationClient,
  conversationId,
  tenantId,
}: {
  actorKey: string;
  client?: AgentConversationClient;
  conversationId?: string;
  tenantId: string;
}) => {
  let conversation: ConversationRecord;
  if (conversationId?.startsWith(CONVERSATION_PREFIX)) {
    conversation = await client.conversations.retrieve(conversationId);
    if (!ownsConversation(conversation, tenantId, actorKey)) {
      throw new AgentConversationOwnershipError();
    }
  } else {
    conversation = await client.conversations.create({
      metadata: ownershipMetadata(tenantId, actorKey),
    });
  }
  return {
    conversationId: conversation.id,
    session: new OpenAIConversationsSession({
      conversationId: conversation.id,
      client: client as OpenAI,
    }),
  };
};

export const removeAgentConversation = async ({
  actorKey,
  client = new OpenAI() as unknown as AgentConversationClient,
  conversationId,
  tenantId,
}: {
  actorKey: string;
  client?: AgentConversationClient;
  conversationId: string;
  tenantId: string;
}) => {
  if (!conversationId.startsWith(CONVERSATION_PREFIX)) return false;
  const conversation = await client.conversations.retrieve(conversationId);
  if (!ownsConversation(conversation, tenantId, actorKey)) {
    throw new AgentConversationOwnershipError();
  }
  await client.conversations.delete(conversation.id);
  return true;
};
