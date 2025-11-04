import { AgentsClient } from "../clients/agents.js";
import { AgentAnalyticsSummary, AgentSessionRecord } from "../types.js";

export interface SummarizeOrgOptions {
  windowHours?: number;
  sessionLimit?: number;
}

export class AgentAnalyticsService {
  constructor(private readonly agents: AgentsClient) {}

  async summarizeOrg(orgId: string, options: SummarizeOrgOptions = {}): Promise<AgentAnalyticsSummary> {
    const windowHours = options.windowHours ?? 24;
    const sessionLimit = options.sessionLimit ?? 100;

    const windowStart = new Date(Date.now() - windowHours * 60 * 60 * 1000);
    const page = await this.agents.listSessions({ limit: sessionLimit });

    const sessions = page.sessions.filter((session) => session.createdAt >= windowStart);

    if (sessions.length === 0) {
      return {
        totalSessions: 0,
        activeSessions: 0,
        messageCount: 0,
        eventCount: 0,
        skillTagCounts: {},
        agentTypeCounts: {},
      };
    }

    const details = await Promise.all(
      sessions.map(async (session) => {
        const summary = await this.agents.getSession(session.sessionId, { messageLimit: 0 });
        const analytics = await this.agents.getSessionAnalyticsSummary(session.sessionId);

        return {
          session,
          messageCount: summary.messageCount ?? summary.messages.length,
          eventCount: analytics.reduce((acc, entry) => acc + entry.eventCount, 0),
        };
      }),
    );

    const agentTypeCounts: Record<string, number> = {};
    const skillTagCounts: Record<string, number> = {};

    let activeSessions = 0;
    let totalMessages = 0;
    let totalEvents = 0;

    for (const detail of details) {
      const { session, messageCount, eventCount } = detail;

      totalMessages += messageCount;
      totalEvents += eventCount;

      const agentType = session.agentType ?? "unknown";
      agentTypeCounts[agentType] = (agentTypeCounts[agentType] ?? 0) + 1;

      if (isSessionActive(session)) {
        activeSessions += 1;
      }

      const context = session.context ?? {};
      const skillTagsRaw = (context as { _skill_tags?: unknown })._skill_tags;
      const skillTags = Array.isArray(skillTagsRaw) ? skillTagsRaw : [];
      for (const tag of skillTags) {
        if (typeof tag === "string" && tag.length > 0) {
          skillTagCounts[tag] = (skillTagCounts[tag] ?? 0) + 1;
        }
      }
    }

    return {
      totalSessions: sessions.length,
      activeSessions,
      messageCount: totalMessages,
      eventCount: totalEvents,
      skillTagCounts,
      agentTypeCounts,
    };
  }
}

function isSessionActive(session: AgentSessionRecord): boolean {
  const candidate = session as unknown as { isActive?: boolean };
  if (typeof candidate.isActive === "boolean") {
    return candidate.isActive;
  }
  return session.status?.toLowerCase() === "active";
}
