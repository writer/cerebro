import type {
  CapabilityCompatibilityDecision,
  PresenceSnapshotV1,
  ReleaseReceiptV2,
} from "@writer/cerebro-sdk";
import { readinessGate } from "./compatibility.js";

export type MaintenanceMode = "forced" | "graceful";

export interface MaintenanceRun {
  checkpointable: boolean;
  run_id: string;
}

export interface MaintenanceDelivery {
  delivery_id: string;
  state: "delivering" | "pending";
}

export interface MaintenanceAction {
  action:
    | "checkpoint_and_pause"
    | "drain_delivery"
    | "mark_for_reconciliation"
    | "pause_delivery"
    | "stop_new_leases"
    | "wait_for_safe_boundary";
  subject_id: string;
}

export interface MaintenancePlan {
  actions: MaintenanceAction[];
  admission_behavior: "durable_queue";
  blockers: string[];
  forced_stop_permitted_after_actions: boolean;
  mode: MaintenanceMode;
  new_leases_allowed: false;
  safe_to_stop: boolean;
}

export interface MaintenanceInput {
  active_runs: readonly MaintenanceRun[];
  compatibility: CapabilityCompatibilityDecision;
  deliveries: readonly MaintenanceDelivery[];
  mode: MaintenanceMode;
  now: string;
  replacement_presence?: PresenceSnapshotV1;
}

export interface ReleaseVerification {
  passed: boolean;
  reasons: string[];
}

export function planMaintenance(input: MaintenanceInput): MaintenancePlan {
  const actions: MaintenanceAction[] = [
    { action: "stop_new_leases", subject_id: "service" },
  ];
  const blockers: string[] = [];

  if (input.mode === "graceful") {
    if (input.replacement_presence === undefined) {
      blockers.push("replacement_presence_missing");
    } else {
      const replacement = readinessGate(
        input.replacement_presence,
        { decision: input.compatibility, reasons: [] },
        input.now,
      );
      if (!replacement.allowed) {
        blockers.push(`replacement_${replacement.reason}`);
      }
    }
  }

  for (const run of input.active_runs) {
    if (run.checkpointable) {
      actions.push({ action: "checkpoint_and_pause", subject_id: run.run_id });
    } else if (input.mode === "forced") {
      actions.push({ action: "mark_for_reconciliation", subject_id: run.run_id });
    } else {
      actions.push({ action: "wait_for_safe_boundary", subject_id: run.run_id });
      blockers.push(`run_not_checkpointable:${run.run_id}`);
    }
  }

  for (const delivery of input.deliveries) {
    actions.push({
      action: input.mode === "forced" ? "pause_delivery" : "drain_delivery",
      subject_id: delivery.delivery_id,
    });
  }

  const activeWorkRemains =
    input.active_runs.length > 0 || input.deliveries.length > 0;

  return {
    actions,
    admission_behavior: "durable_queue",
    blockers,
    forced_stop_permitted_after_actions: input.mode === "forced",
    mode: input.mode,
    new_leases_allowed: false,
    safe_to_stop:
      !activeWorkRemains && (input.mode === "forced" || blockers.length === 0),
  };
}

export function verifyReleaseReceipt(
  receipt: ReleaseReceiptV2,
): ReleaseVerification {
  const reasons: string[] = [];
  if (receipt.orphaned_run_count > 0) {
    reasons.push("orphaned_runs_present");
  }
  if (receipt.stuck_delivery_count > 0) {
    reasons.push("stuck_deliveries_present");
  }
  if (receipt.compatibility === "blocked" || receipt.compatibility === "incompatible") {
    reasons.push("release_incompatible");
  }
  if (receipt.state === "failed") {
    reasons.push("release_failed");
  }
  return { passed: reasons.length === 0, reasons };
}
