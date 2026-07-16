import type {
  PresenceSnapshotV1,
  RunReceiptV1,
} from "@writer/cerebro-sdk";

export type SlackVisibleStatusCode =
  | "checkpoint_recovery"
  | "degraded"
  | "partial_source"
  | "queued"
  | "recovering"
  | "reduced_capacity";

export interface SourceCoverage {
  available_source_count: number;
  expected_source_count: number;
}

export interface SlackVisibleStatus {
  code: SlackVisibleStatusCode;
  evidence_ref?: string;
  expires_at: string;
  idempotency_key: string;
  message: string;
  observed_at: string;
  run_id: string;
}

export interface CheckpointRecoveryEvidence {
  checkpoint_ref: string;
  generation: number;
  run_id: string;
}

export function deriveSlackVisibleStatuses(
  run: RunReceiptV1,
  presence: PresenceSnapshotV1,
  now: string,
  coverage?: SourceCoverage,
  recovery?: CheckpointRecoveryEvidence,
): SlackVisibleStatus[] {
  const expiresAt = Date.parse(presence.expires_at);
  const observedAt = Date.parse(now);
  if (
    !Number.isFinite(expiresAt) ||
    !Number.isFinite(observedAt) ||
    expiresAt <= observedAt
  ) {
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
    if (isActiveWork(run)) {
      statuses.push(
        createStatus(
          "reduced_capacity",
          run.state === "queued"
            ? "Cerebro saved this request. Service capacity is reduced, and the work remains queued."
            : "Cerebro is processing this request with reduced service capacity.",
          run.run_id,
          presence,
        ),
      );
    }
  }
  if (
    presence.service_state === "recovering" &&
    recovery !== undefined &&
    recovery.run_id === run.run_id &&
    recovery.generation === presence.active_generation &&
    isRecoverableWork(run) &&
    isOpaqueReference(recovery.checkpoint_ref)
  ) {
    statuses.push(
      createStatus(
        "checkpoint_recovery",
        "Cerebro is recovering this request from its last durable checkpoint.",
        run.run_id,
        presence,
        recovery.checkpoint_ref,
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
  evidenceRef?: string,
): SlackVisibleStatus {
  return {
    code,
    ...(evidenceRef === undefined ? {} : { evidence_ref: evidenceRef }),
    expires_at: presence.expires_at,
    idempotency_key: `${runId}:${code}:${presence.observed_at}${
      evidenceRef === undefined ? "" : `:${evidenceRef}`
    }`,
    message,
    observed_at: presence.observed_at,
    run_id: runId,
  };
}

function isActiveWork(run: RunReceiptV1): boolean {
  return [
    "queued",
    "leased",
    "running",
    "waiting",
    "paused",
    "delivering",
  ].includes(run.state);
}

function isRecoverableWork(run: RunReceiptV1): boolean {
  return ["queued", "leased", "running", "waiting", "paused"].includes(
    run.state,
  );
}

function isOpaqueReference(value: string): boolean {
  return /^[a-z][a-z0-9+.-]*:\/\/\S+$/.test(value);
}
