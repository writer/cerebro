import type { MigrationReceiptV1 } from "@writer/cerebro-sdk";

export interface SlackThreadIdentity {
  binding_id: string;
  conversation_id: string;
  durable_thread_state_digest: string;
  installation_id: string;
  slack_app_id: string;
  thread_id: string;
}

export interface CreateMigrationInput {
  binding_id: string;
  checkpoint_count: number;
  created_at: string;
  migration_id: string;
  pending_delivery_count: number;
  rollback_generation: number;
  route_generation: number;
  source_generation: number;
  target_generation: number;
}

export type MigrationChangeResult =
  | { changed: true; receipt: MigrationReceiptV1 }
  | {
      changed: false;
      reason: "identity_changed" | "invalid_state" | "route_generation_conflict";
      receipt: MigrationReceiptV1;
    };

const transitions: Readonly<Record<MigrationReceiptV1["state"], readonly MigrationReceiptV1["state"][]>> = {
  completed: [],
  cutting_over: ["recovering", "rolling_back", "failed"],
  draining: ["cutting_over", "rolling_back", "failed"],
  failed: ["rolling_back"],
  proposed: ["validating", "failed"],
  recovering: ["completed", "rolling_back", "failed"],
  rolled_back: [],
  rolling_back: ["rolled_back", "failed"],
  validating: ["draining", "rolling_back", "failed"],
};

export function createMigrationReceipt(
  input: CreateMigrationInput,
): MigrationReceiptV1 {
  return {
    binding_id: input.binding_id,
    checkpoint_count: input.checkpoint_count,
    created_at: input.created_at,
    migration_id: input.migration_id,
    pending_delivery_count: input.pending_delivery_count,
    rollback_generation: input.rollback_generation,
    route_generation: input.route_generation,
    schema_version: "migration-receipt/v1",
    source_generation: input.source_generation,
    state: "proposed",
    target_generation: input.target_generation,
    updated_at: input.created_at,
  };
}

export function advanceMigration(
  receipt: MigrationReceiptV1,
  state: MigrationReceiptV1["state"],
  now: string,
): MigrationChangeResult {
  if (!transitions[receipt.state].includes(state)) {
    return { changed: false, reason: "invalid_state", receipt };
  }
  return { changed: true, receipt: { ...receipt, state, updated_at: now } };
}

export function cutOverRoute(
  receipt: MigrationReceiptV1,
  observedRouteGeneration: number,
  before: SlackThreadIdentity,
  after: SlackThreadIdentity,
  now: string,
): MigrationChangeResult {
  if (receipt.state !== "cutting_over") {
    return { changed: false, reason: "invalid_state", receipt };
  }
  if (observedRouteGeneration !== receipt.route_generation) {
    return { changed: false, reason: "route_generation_conflict", receipt };
  }
  if (!sameIdentity(before, after) || receipt.binding_id !== before.binding_id) {
    return {
      changed: false,
      reason: "identity_changed",
      receipt: { ...receipt, state: "failed", updated_at: now },
    };
  }
  return {
    changed: true,
    receipt: {
      ...receipt,
      route_generation: receipt.route_generation + 1,
      state: "recovering",
      updated_at: now,
    },
  };
}

export function rollBackRoute(
  receipt: MigrationReceiptV1,
  observedRouteGeneration: number,
  before: SlackThreadIdentity,
  after: SlackThreadIdentity,
  now: string,
): MigrationChangeResult {
  if (receipt.state !== "rolling_back") {
    return { changed: false, reason: "invalid_state", receipt };
  }
  if (observedRouteGeneration !== receipt.route_generation) {
    return { changed: false, reason: "route_generation_conflict", receipt };
  }
  if (!sameIdentity(before, after) || receipt.binding_id !== before.binding_id) {
    return {
      changed: false,
      reason: "identity_changed",
      receipt: { ...receipt, state: "failed", updated_at: now },
    };
  }
  return {
    changed: true,
    receipt: {
      ...receipt,
      route_generation: receipt.route_generation + 1,
      state: "rolled_back",
      updated_at: now,
    },
  };
}

function sameIdentity(
  before: SlackThreadIdentity,
  after: SlackThreadIdentity,
): boolean {
  return (
    before.slack_app_id === after.slack_app_id &&
    before.binding_id === after.binding_id &&
    before.installation_id === after.installation_id &&
    before.conversation_id === after.conversation_id &&
    before.thread_id === after.thread_id &&
    before.durable_thread_state_digest === after.durable_thread_state_digest
  );
}
