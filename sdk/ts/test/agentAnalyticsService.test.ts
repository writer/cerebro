import { describe, expect, it, vi } from "vitest";

import { AgentAnalyticsService } from "../src/agents";
import { AgentsClient } from "../src/clients/agents";
import { AgentSessionDetail, AgentSessionList, AgentSessionRecord, AgentAnalyticsSummary } from "../src/types";

function buildSession(partial: Partial<AgentSessionRecord>): AgentSessionRecord {
  return {
    sessionId: partial.sessionId ?? "session-1",
    orgId: partial.orgId ?? "org-1",
    agentType: partial.agentType ?? "security_analyst",
    status: partial.status ?? "active",
    title: partial.title ?? null,
    createdBy: partial.createdBy ?? "user",
    createdAt: partial.createdAt ?? new Date(),
    context: partial.context ?? {},
  };
}

describe("AgentAnalyticsService", () => {
  it("summarizes sessions, messages, and events", async () => {
    const createdAt = new Date();
    const sessions: AgentSessionList = {
      limit: 50,
      offset: 0,
      total: 2,
      sessions: [
        buildSession({ sessionId: "s1", agentType: "security_analyst", createdAt, context: { _skill_tags: ["triage"] } }),
        buildSession({ sessionId: "s2", agentType: "incident_responder", status: "closed", createdAt }),
      ],
    };

    const listSessions = vi.fn().mockResolvedValue(sessions);
    const getSession = vi
      .fn()
      .mockResolvedValueOnce(buildSessionDetail(5))
      .mockResolvedValueOnce(buildSessionDetail(2));
    const getSessionAnalyticsSummary = vi
      .fn()
      .mockResolvedValueOnce([{ eventType: "tool_invocation", eventCount: 3, firstSeen: null, lastSeen: null }])
      .mockResolvedValueOnce([{ eventType: "message", eventCount: 1, firstSeen: null, lastSeen: null }]);

    const fakeClient = {
      listSessions,
      getSession,
      getSessionAnalyticsSummary,
    } as unknown as AgentsClient;

    const service = new AgentAnalyticsService(fakeClient);
    const summary = await service.summarizeOrg("org-1", { windowHours: 12 });

    expect(summary).toEqual<AgentAnalyticsSummary>({
      totalSessions: 2,
      activeSessions: 1,
      messageCount: 7,
      eventCount: 4,
      skillTagCounts: { triage: 1 },
      agentTypeCounts: { security_analyst: 1, incident_responder: 1 },
    });

    expect(listSessions).toHaveBeenCalledWith({ limit: 100 });
    expect(getSession).toHaveBeenCalledTimes(2);
    expect(getSessionAnalyticsSummary).toHaveBeenCalledTimes(2);
  });

  it("returns zeros when no sessions are present", async () => {
    const fakeClient = {
      listSessions: vi.fn().mockResolvedValue({ limit: 50, offset: 0, total: 0, sessions: [] }),
    } as unknown as AgentsClient;

    const service = new AgentAnalyticsService(fakeClient);
    const summary = await service.summarizeOrg("org-1");

    expect(summary).toEqual({
      totalSessions: 0,
      activeSessions: 0,
      messageCount: 0,
      eventCount: 0,
      skillTagCounts: {},
      agentTypeCounts: {},
    });
  });
});

function buildSessionDetail(messageCount: number): AgentSessionDetail {
  return {
    session: buildSession({}),
    messageCount,
    messages: [],
    toolInvocations: [],
  };
}
