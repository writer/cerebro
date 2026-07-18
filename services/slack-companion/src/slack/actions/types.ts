import type { Authorization } from "../../auth.js";
import type { AutonomyGoalService } from "../../autonomy/goal-service.js";
import type { CerebroClient } from "../../cerebro/client.js";
import type { AppConfig } from "../../config/index.js";
import type { DailyNotesService } from "../../learning/daily-notes.js";
import type { AssistantFeedbackService } from "../../learning/assistant-feedback.js";
import type { ScheduledJobService } from "../../schedules/scheduled-jobs/index.js";
import type { SlackThreadSessionStateStore } from "../../triage/slack-thread-state.js";
import type { RiskAttestationService } from "../risk-attestation.js";
import type { A2AFleetService } from "../../a2a/index.js";

export interface ActionDeps {
  config: AppConfig;
  auth: Authorization;
  cerebro: CerebroClient;
  notes: DailyNotesService;
  goals: AutonomyGoalService;
  scheduler: ScheduledJobService;
  threadState?: SlackThreadSessionStateStore;
  feedback?: AssistantFeedbackService;
  riskAttestations?: Pick<RiskAttestationService, "respond">;
  a2a?: A2AFleetService;
}
