import { logger } from "../../logger.js";
import {
  annotateSpan,
  captureTelemetryError,
  recordMetric,
  slackTelemetryAttributes,
  telemetryEvent,
  withTelemetrySpan,
  type TelemetrySpan,
} from "../../telemetry.js";
import type { SlackEventClaimResult } from "../coordination.js";

export async function withSlackEventTelemetry(kind: string, event: any, work: (span: TelemetrySpan) => Promise<void>): Promise<void> {
  let finalStatus: "completed" | "skipped" | "failed" = "completed";
  await withTelemetrySpan(`slack.event.${kind}`, {
    component: "slack-events",
    operation: kind,
    "slack.event.text.length": typeof event?.text === "string" ? event.text.length : 0,
    "slack.event.bot_present": Boolean(event?.bot_id),
    "slack.event.subtype.present": Boolean(event?.subtype),
    ...slackTelemetryAttributes({
      eventKind: kind,
      channelId: event?.channel ?? event?.user,
      userId: event?.user,
      ts: event?.ts ?? event?.event_ts,
      threadTs: event?.thread_ts,
      teamId: event?.team,
    }),
  }, async (span) => {
    try {
      await work(span);
      if (span.annotations["slack.event.claimed"] === false || span.annotations["slack.message.triage_candidate"] === false) {
        finalStatus = "skipped";
      }
    } catch (error) {
      finalStatus = "failed";
      captureTelemetryError(`slack.event.${kind}.error`, error, { component: "slack-events", operation: kind });
      throw error;
    }
  }, {
    main: true,
    statusForResult: () => finalStatus,
    errorEventName: `slack.event.${kind}.error`,
  });
}

export function recordClaimTelemetry(span: TelemetrySpan, kind: string, claim: SlackEventClaimResult): void {
  annotateSpan(span, {
    "slack.event.claim_kind": kind,
    "slack.event.claimed": claim.claimed,
    "slack.event.claim_reason": claim.reason ?? "",
  });
  recordMetric("cerebro_slack_companion_slack_event_claims_total", {
    kind,
    result: claim.claimed ? "claimed" : "skipped",
    reason: claim.reason ?? "claimed",
  }, 1);
}

export function logSkippedEvent(kind: string, claim: SlackEventClaimResult, channel: string | undefined, ts: string | undefined): void {
  telemetryEvent("slack.event.skipped", {
    component: "slack-events",
    operation: "skip",
    "slack.event.kind": kind,
    "slack.event.claim_reason": claim.reason ?? "",
    ...slackTelemetryAttributes({ eventKind: kind, channelId: channel, ts }),
  });
  if (claim.reason === "local_duplicate" || claim.reason === "durable_duplicate") {
    logger.info("slack event duplicate skipped", { kind, channel, ts, reason: claim.reason, eventKey: claim.eventKey });
    return;
  }
  logger.warn("slack event skipped", { kind, channel, ts, reason: claim.reason, detail: claim.detail, eventKey: claim.eventKey });
}
