import { SecurityAssistantService } from "../../agent/security-assistant.js";
import { AlertTriageService } from "../../triage/alert-triage.js";
import { CompanionWorkLoop } from "../../work/companion-work-loop.js";
import { handleAppHomeOpened } from "./app-home-route.js";
import { handleAppMention } from "./app-mention-route.js";
import { handleMessageEvent } from "./message-route.js";
import { withSlackEventTelemetry } from "./telemetry.js";
import type { EventDeps } from "./types.js";

export type { EventDeps } from "./types.js";

export function registerEventHandlers(app: any, deps: EventDeps): void {
  const triage = new AlertTriageService(deps.config, deps.cerebro, deps.memory, { threadState: deps.threadState });
  const assistant = deps.assistant ?? new SecurityAssistantService(deps.config, deps.cerebro, deps.memory);
  const workLoop = deps.workLoop ?? new CompanionWorkLoop({ config: deps.config, assistant, memory: deps.memory, notes: deps.notes });

  app.event("app_home_opened", async ({ event, client }: any) =>
    withSlackEventTelemetry("app_home_opened", event, (span) => handleAppHomeOpened(deps, client, event, span)));

  app.event("app_mention", async ({ event, client, say, context }: any) =>
    withSlackEventTelemetry("app_mention", event, (span) => handleAppMention(deps, workLoop, client, say, context, event, span)));

  app.event("message", async ({ event, client, context }: any) =>
    withSlackEventTelemetry("message", event, (span) => handleMessageEvent(deps, triage, workLoop, client, event, span, context)));
}
