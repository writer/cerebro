import type { Authorization } from "../../auth.js";
import type { CerebroClient } from "../../cerebro/client.js";
import type { AppConfig } from "../../config/index.js";
import type { SecurityAssistantService } from "../../agent/security-assistant.js";
import type { DailyNotesService } from "../../learning/daily-notes.js";
import type { SlackChannelLearningService } from "../../learning/slack-channel-learning.js";
import type { SecurityMemoryStore } from "../../learning/security-memory/index.js";
import type { SlackThreadSessionStateStore } from "../../triage/slack-thread-state.js";
import type { CompanionWorkLoop } from "../../work/companion-work-loop.js";
import type { SlackEventCoordinator } from "../coordination.js";
import type { A2AFleetService } from "../../a2a/index.js";
import type { ImprovementSignalRecorder } from "../../improvement/types.js";

export interface EventDeps {
  config: AppConfig;
  auth: Authorization;
  cerebro: CerebroClient;
  memory: SecurityMemoryStore;
  channelLearning?: Pick<SlackChannelLearningService, "observe">;
  coordinator: SlackEventCoordinator;
  notes: DailyNotesService;
  threadState?: SlackThreadSessionStateStore;
  assistant?: SecurityAssistantService;
  workLoop?: CompanionWorkLoop;
  a2a?: A2AFleetService;
  improvement?: ImprovementSignalRecorder;
}
