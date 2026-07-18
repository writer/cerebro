import { annotateMainDependency, type TelemetrySpan } from "../../telemetry.js";
import { publishHome } from "../home.js";
import { logSkippedEvent, recordClaimTelemetry } from "./telemetry.js";
import type { EventDeps } from "./types.js";

export async function handleAppHomeOpened(deps: EventDeps, client: any, event: any, span: TelemetrySpan): Promise<void> {
  const claim = await deps.coordinator.claimSlackEvent({
    kind: "app_home_opened",
    channelId: event.user,
    ts: event.event_ts ?? event.ts,
    eventId: event.event_ts,
    teamId: event.team,
  });
  recordClaimTelemetry(span, "app_home_opened", claim);
  if (!claim.claimed) {
    logSkippedEvent("app_home_opened", claim, event.user, event.event_ts ?? event.ts);
    return;
  }
  await publishHome(client, event.user, deps.config, deps.cerebro, deps.a2a);
  annotateMainDependency("slack", "events", "publish_home", "completed");
}
