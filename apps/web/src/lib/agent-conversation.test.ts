import { describe, expect, it, vi } from "vitest";

import {
  AgentConversationOwnershipError,
  openAgentConversation,
  removeAgentConversation,
  type AgentConversationClient,
} from "./agent-conversation";

const fakeClient = () => {
  let metadata: Record<string, unknown> | null = null;
  const client: AgentConversationClient = {
    conversations: {
      create: vi.fn(async (input) => {
        metadata = input.metadata;
        return { id: "conv_owned", metadata };
      }),
      retrieve: vi.fn(async (id) => ({ id, metadata })),
      delete: vi.fn(async () => ({})),
    },
  };
  return { client, setMetadata: (value: Record<string, unknown>) => { metadata = value; } };
};

describe("agent conversation ownership", () => {
  it("creates a provider conversation and resumes it for the same actor and tenant", async () => {
    const { client } = fakeClient();
    const created = await openAgentConversation({
      actorKey: "actor-a",
      client,
      tenantId: "tenant-a",
    });
    expect(created.conversationId).toBe("conv_owned");

    await expect(openAgentConversation({
      actorKey: "actor-a",
      client,
      conversationId: "conv_owned",
      tenantId: "tenant-a",
    })).resolves.toMatchObject({ conversationId: "conv_owned" });
  });

  it("rejects cross-tenant or cross-actor conversation reuse", async () => {
    const { client } = fakeClient();
    await openAgentConversation({ actorKey: "actor-a", client, tenantId: "tenant-a" });
    await expect(openAgentConversation({
      actorKey: "actor-b",
      client,
      conversationId: "conv_owned",
      tenantId: "tenant-a",
    })).rejects.toBeInstanceOf(AgentConversationOwnershipError);
  });

  it("checks ownership before deleting provider state", async () => {
    const { client } = fakeClient();
    await openAgentConversation({ actorKey: "actor-a", client, tenantId: "tenant-a" });
    await expect(removeAgentConversation({
      actorKey: "actor-a",
      client,
      conversationId: "conv_owned",
      tenantId: "tenant-a",
    })).resolves.toBe(true);
    expect(client.conversations.delete).toHaveBeenCalledWith("conv_owned");
  });
});
