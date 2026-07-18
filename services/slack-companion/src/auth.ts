import type { AppConfig, ActorMapping } from "./config/index.js";

export type WriteCapability = "findings" | "source" | "runtimeResponse" | "graphActions" | "autonomy";

export interface SlackActor {
  slackUserId: string;
  actorId: string;
  displayName?: string;
  known?: boolean;
  operator?: boolean;
  writeCapabilities?: WriteCapability[];
}

export class Authorization {
  constructor(private readonly config: AppConfig) {}

  actorFor(slackUserId: string): SlackActor {
    const mapped: ActorMapping | undefined = this.config.cerebro.slackUsers.get(slackUserId);
    return {
      slackUserId,
      actorId: mapped?.actorId ?? `slack:${slackUserId}`,
      displayName: mapped?.displayName,
      known: Boolean(mapped),
      operator: this.canUseOperatorCommands(slackUserId),
      writeCapabilities: this.writeCapabilitiesFor(slackUserId),
    };
  }

  canWrite(slackUserId: string, capability: WriteCapability): boolean {
    const allowed = this.allowedSet(capability);
    return allowed.has(slackUserId);
  }

  requireWrite(slackUserId: string, capability: WriteCapability): void {
    if (!this.canWrite(slackUserId, capability)) {
      throw new Error(`Slack user ${slackUserId} is not allowed to use ${capability} writes`);
    }
  }

  canUseOperatorCommands(slackUserId: string): boolean {
    return this.config.slack.operatorUserIds.has(slackUserId);
  }

  requireOperator(slackUserId: string): void {
    if (!this.canUseOperatorCommands(slackUserId)) {
      throw new Error("Only configured Cerebro operators can use this command.");
    }
  }

  writeCapabilitiesFor(slackUserId: string): WriteCapability[] {
    return WRITE_CAPABILITIES.filter((capability) => this.canWrite(slackUserId, capability));
  }

  private allowedSet(capability: WriteCapability): Set<string> {
    switch (capability) {
      case "findings":
        return this.config.slack.findingWriteUserIds;
      case "source":
        return this.config.slack.sourceWriteUserIds;
      case "runtimeResponse":
        return this.config.slack.responseWriteUserIds;
      case "graphActions":
        return this.config.slack.graphActionUserIds;
      case "autonomy":
        return this.config.slack.autonomyApprovalUserIds;
    }
  }
}

const WRITE_CAPABILITIES: WriteCapability[] = ["findings", "source", "runtimeResponse", "graphActions", "autonomy"];
