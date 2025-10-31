import { describe, expect, it } from "vitest";

import {
  AgentNotificationsClient,
  AgentTicketsClient,
  InMemoryNotificationsAdapter,
  InMemoryTicketsAdapter,
} from "../src/clients/agentNotifications";

describe("Agent notifications and tickets", () => {
  it("enqueues and marks notifications delivered", async () => {
    const client = new AgentNotificationsClient(new InMemoryNotificationsAdapter());

    const created = await client.enqueue({
      orgId: "org-1",
      taskId: "task-1",
      channel: "slack",
      payload: { room: "#alerts" },
    });

    expect(created.status).toBe("PENDING");

    const delivered = await client.markDelivered(created.notificationId);
    expect(delivered?.status).toBe("DELIVERED");
  });

  it("creates and closes tickets", async () => {
    const tickets = new AgentTicketsClient(new InMemoryTicketsAdapter());

    const created = await tickets.createTicket({
      orgId: "org-1",
      taskId: "task-1",
      system: "jira",
      summary: "Investigate alert",
    });

    expect(created.status).toBe("OPEN");

    const closed = await tickets.closeTicket(created.ticketId, { externalId: "JIRA-1" });
    expect(closed?.status).toBe("CLOSED");

    const all = await tickets.listTickets("task-1");
    expect(all).toHaveLength(1);
    expect(all[0].externalId).toBe("JIRA-1");
  });
});
