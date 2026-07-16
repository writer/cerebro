import type {
  PresenceSnapshotV1,
  RunReceiptV1,
} from "@writer/cerebro-sdk";

export type SlackVisibleStatusCode =
  | "degraded"
  | "partial_source"
  | "queued"
  | "recovering";

export interface SourceCoverage {
  available_source_count: number;
  expected_source_count: number;
}

export interface SlackVisibleStatus {
  code: SlackVisibleStatusCode;
  expires_at: string;
  idempotency_key: string;
  message: string;
  observed_at: string;
  run_id: string;
}

export function deriveSlackVisibleStatuses(
  run: RunReceiptV1,
  presence: PresenceSnapshotV1,
  now: string,
  coverage?: SourceCoverage,
): SlackVisibleStatus[] {
  if (Date.parse(presence.expires_at) <= Date.parse(now)) {
    return [];
  }

  const statuses: SlackVisibleStatus[] = [];
  if (run.state === "queued") {
    statuses.push(
      createStatus(
        "queued",
        "Cerebro saved this request. It is queued for execution.",
        run.run_id,
        presence,
      ),
    );
  }
  if (presence.service_state === "degraded") {
    statuses.push(
      createStatus(
        "degraded",
        "Cerebro accepted this request, but service capacity is reduced. Work remains durably queued.",
        run.run_id,
        presence,
      ),
    );
  }
  if (presence.service_state === "recovering") {
    statuses.push(
      createStatus(
        "recovering",
        "Cerebro is recovering this request from its last durable checkpoint.",
        run.run_id,
        presence,
      ),
    );
  }
  if (
    coverage !== undefined &&
    coverage.available_source_count < coverage.expected_source_count
  ) {
    statuses.push(
      createStatus(
        "partial_source",
        `Cerebro can reach ${coverage.available_source_count} of ${coverage.expected_source_count} expected sources. The response will identify missing coverage.`,
        run.run_id,
        presence,
      ),
    );
  }
  return statuses;
}

function createStatus(
  code: SlackVisibleStatusCode,
  message: string,
  runId: string,
  presence: PresenceSnapshotV1,
): SlackVisibleStatus {
  return {
    code,
    expires_at: presence.expires_at,
    idempotency_key: `${runId}:${code}:${presence.observed_at}`,
    message,
    observed_at: presence.observed_at,
    run_id: runId,
  };
}
