import { App as SlackApp } from "@slack/bolt";
import type { ServerResponse } from "node:http";
import type { AppConfig } from "../config/index.js";
import type { Authorization } from "../auth.js";
import type { AutonomyGoalService } from "../autonomy/goal-service.js";
import type { CerebroClient } from "../cerebro/client.js";
import type { SecurityAssistantService } from "../agent/security-assistant.js";
import type { DailyNotesService } from "../learning/daily-notes.js";
import type { SlackChannelLearningService } from "../learning/slack-channel-learning.js";
import type { SecurityMemoryStore } from "../learning/security-memory/index.js";
import type { ScheduledJobService } from "../schedules/scheduled-jobs/index.js";
import type { SecuritySkillService } from "../skills/security-skill-service.js";
import type { SlackThreadSessionStateStore } from "../triage/slack-thread-state.js";
import type { CompanionWorkLoop } from "../work/companion-work-loop.js";
import type { AssistantFeedbackService } from "../learning/assistant-feedback.js";
import type { SlackEventCoordinator } from "./coordination.js";
import type { RiskAttestationService } from "./risk-attestation.js";
import { registerActionHandlers } from "./actions/index.js";
import { registerCommandHandlers } from "./commands/index.js";
import { registerEventHandlers } from "./events/index.js";
import { metricsCustomRoute } from "../telemetry.js";
import type { A2AFleetService } from "../a2a/index.js";
import type { ImprovementSignalRecorder } from "../improvement/types.js";
import { collectRuntimeHealth, recordRuntimeHealthMetrics, renderRuntimeHealth, runtimeHealthHttpStatus } from "../runtime/health.js";

interface SlackAppDeps {
  config: AppConfig;
  auth: Authorization;
  cerebro: CerebroClient;
  memory: SecurityMemoryStore;
  channelLearning?: SlackChannelLearningService;
  coordinator: SlackEventCoordinator;
  notes: DailyNotesService;
  skills: SecuritySkillService;
  scheduler: ScheduledJobService;
  goals: AutonomyGoalService;
  threadState?: SlackThreadSessionStateStore;
  assistant?: SecurityAssistantService;
  workLoop?: CompanionWorkLoop;
  feedback: AssistantFeedbackService;
  riskAttestations: RiskAttestationService;
  a2a?: A2AFleetService;
  improvement?: ImprovementSignalRecorder;
}

export function createSlackApp(deps: SlackAppDeps): SlackApp {
  const customRoutes = [
    healthzCustomRoute(),
    readyzCustomRoute(deps),
    ...(deps.a2a ? [agentCardCustomRoute(deps.a2a)] : []),
    ...(deps.config.telemetry.metricsEnabled ? [metricsCustomRoute()] : []),
  ];
  const app = new SlackApp({
    token: deps.config.slack.botToken,
    signingSecret: deps.config.slack.signingSecret,
    socketMode: deps.config.slack.socketMode,
    appToken: deps.config.slack.appToken,
    customRoutes,
    installerOptions: deps.config.slack.socketMode ? { port: deps.config.port } : undefined,
  });
  registerCommandHandlers(app, deps);
  registerActionHandlers(app, deps);
  registerEventHandlers(app, deps);
  return app;
}

function agentCardCustomRoute(a2a: A2AFleetService) {
  return {
    path: "/.well-known/agent-card.json",
    method: "GET",
    handler: (_req: unknown, res: ServerResponse) => {
      res.statusCode = 200;
      res.setHeader("Content-Type", "application/json; charset=utf-8");
      res.setHeader("Cache-Control", "no-store");
      res.end(`${JSON.stringify(a2a.agentCard())}\n`);
    },
  };
}

function healthzCustomRoute() {
  return {
    path: "/healthz",
    method: "GET",
    handler: (_req: unknown, res: ServerResponse) => {
      res.statusCode = 200;
      res.setHeader("Content-Type", "text/plain; charset=utf-8");
      res.end("ok\n");
    },
  };
}

function readyzCustomRoute(deps: SlackAppDeps) {
  return {
    path: "/readyz",
    method: "GET",
    handler: (_req: unknown, res: ServerResponse) => {
      void collectRuntimeHealth(deps)
        .then((snapshot) => {
          recordRuntimeHealthMetrics(snapshot);
          res.statusCode = runtimeHealthHttpStatus(snapshot);
          res.setHeader("Content-Type", "text/plain; charset=utf-8");
          res.end(renderRuntimeHealth(snapshot));
        })
        .catch((error) => {
          res.statusCode = 503;
          res.setHeader("Content-Type", "text/plain; charset=utf-8");
          const message = error instanceof Error ? error.message : String(error);
          res.end(`status=not_ready\nready=false\ncheck.runtime_health=fail ${message.replace(/\s+/g, " ").trim()}\n`);
        });
    },
  };
}
