import { createHash } from "node:crypto";
import type {
  ComplianceWorkCommand,
  ComplianceWorkItem,
  ComplianceWorkItemRecord,
} from "@writer/cerebro-sdk";
import type {
  CanonicalWorkCaseCommitResult,
  CanonicalWorkCaseV1,
  CanonicalWorkCommandApprovalV1,
  CanonicalWorkCommandExecutionResult,
  CanonicalWorkCommandIntentCommitResult,
  CanonicalWorkCommandIntentV1,
  OpenCanonicalWorkCaseInput,
} from "./contracts.js";
import type {
  CanonicalWorkClockPort,
  CanonicalWorkItemPort,
  DurableCanonicalWorkCasePort,
} from "./ports.js";

export class CanonicalWorkConflictError extends Error {}
export class CanonicalWorkInputError extends Error {}

export interface CanonicalWorkCoordinatorOptions {
  canonical: CanonicalWorkItemPort;
  clock: CanonicalWorkClockPort;
  store: DurableCanonicalWorkCasePort;
}

export class CanonicalWorkCoordinator {
  private readonly canonical: CanonicalWorkItemPort;
  private readonly clock: CanonicalWorkClockPort;
  private readonly store: DurableCanonicalWorkCasePort;

  constructor(options: CanonicalWorkCoordinatorOptions) {
    this.canonical = options.canonical;
    this.clock = options.clock;
    this.store = options.store;
  }

  async open(input: OpenCanonicalWorkCaseInput): Promise<CanonicalWorkCaseCommitResult> {
    const workItemId = requiredRef(input.work_item_id, "work_item_id", 160);
    const title = optionalRef(input.title, "title", 300);
    const record = await this.canonical.get(workItemId);
    validateRecord(record, workItemId);
    const now = this.clock.now().toISOString();
    const candidate = projectCase(record.item, title, now);
    const committed = await this.store.putCaseIfAbsent({
      case: candidate,
      payload_fingerprint: digest([workItemId, title ?? ""]),
    });
    if (committed.created) return committed;
    const refreshed = await this.syncFromRecord(committed.case, record);
    return { case: refreshed, created: false };
  }

  async refresh(caseId: string): Promise<CanonicalWorkCaseV1> {
    const current = await this.requireCase(caseId);
    const record = await this.canonical.get(current.work_item_id);
    return this.syncFromRecord(current, record);
  }

  list(options: Parameters<CanonicalWorkItemPort["list"]>[0] = {}) {
    return this.canonical.list(options);
  }

  async planCommand(
    caseId: string,
    command: ComplianceWorkCommand,
  ): Promise<CanonicalWorkCommandIntentCommitResult> {
    const current = await this.requireCase(caseId);
    validateCommand(command);
    const record = await this.canonical.get(current.work_item_id);
    validateRecord(record, current.work_item_id);
    await this.syncFromRecord(current, record);
    if (record.item.version !== command.expected_version) {
      throw new CanonicalWorkConflictError(
        `Expected work-item version ${command.expected_version}, current version is ${record.item.version}.`,
      );
    }
    rejectNoopCommand(command, record.item);

    const commandDigest = digest(command);
    const now = this.clock.now().toISOString();
    const intentId = `canonical-command-${digestHex([current.case_id, commandDigest]).slice(0, 32)}`;
    const intent: CanonicalWorkCommandIntentV1 = {
      baseline: baselineFor(record.item),
      case_id: current.case_id,
      command: clone(command),
      command_digest: commandDigest,
      created_at: now,
      intent_id: intentId,
      revision: 1,
      schema_version: "canonical-work-command-intent/v1",
      status: "planned",
      updated_at: now,
      work_item_id: current.work_item_id,
    };
    return this.store.putIntentIfAbsent({
      intent,
      payload_fingerprint: digest([
        intent.case_id,
        intent.work_item_id,
        intent.command_digest,
        intent.baseline,
      ]),
    });
  }

  async executeApproved(
    intentId: string,
    approval: CanonicalWorkCommandApprovalV1,
  ): Promise<CanonicalWorkCommandExecutionResult> {
    const intent = await this.requireIntent(intentId);
    validateApproval(approval, intent);
    const currentCase = await this.requireCase(intent.case_id);
    if (intent.status === "applied" || intent.status === "conflicted") {
      const refreshed = await this.refresh(currentCase.case_id);
      return {
        case: refreshed,
        duplicate: true,
        intent,
        outcome: intent.status,
      };
    }

    const now = this.clock.now().toISOString();
    const begun = await this.store.beginIntent({
      approval,
      expected_revision: intent.revision,
      intent_id: intent.intent_id,
      updated_at: now,
    });
    if (!begun.created && begun.intent.status === "executing") {
      return {
        case: currentCase,
        duplicate: true,
        intent: begun.intent,
        outcome: "in_progress",
      };
    }
    if (!begun.created && begun.intent.status === "applied") {
      return {
        case: currentCase,
        duplicate: true,
        intent: begun.intent,
        outcome: "applied",
      };
    }

    const record = await this.canonical.get(intent.work_item_id);
    validateRecord(record, intent.work_item_id);
    if (record.item.version !== intent.command.expected_version) {
      const status = commandEffectSatisfied(intent, record.item)
        ? "applied"
        : "conflicted";
      const reason = status === "applied"
        ? "canonical_effect_already_applied"
        : "canonical_version_advanced";
      const finished = await this.store.finishIntent({
        expected_revision: begun.intent.revision,
        intent_id: intent.intent_id,
        reason_code: reason,
        record,
        status,
        updated_at: this.clock.now().toISOString(),
      });
      const caseRecord = await this.syncFromRecord(currentCase, record);
      return {
        case: caseRecord,
        duplicate: status === "applied",
        intent: finished,
        outcome: status,
        record,
      };
    }

    let applied: ComplianceWorkItemRecord;
    try {
      applied = await this.canonical.command(
        intent.work_item_id,
        clone(intent.command),
        { idempotency_key: intent.intent_id },
      );
      validateRecord(applied, intent.work_item_id);
    } catch (error) {
      const unknown = await this.store.finishIntent({
        expected_revision: begun.intent.revision,
        intent_id: intent.intent_id,
        reason_code: "canonical_command_result_unknown",
        status: "unknown",
        updated_at: this.clock.now().toISOString(),
      });
      return {
        case: currentCase,
        duplicate: false,
        intent: unknown,
        outcome: "unknown",
      };
    }
    if (applied.item.version <= intent.command.expected_version) {
      const unknown = await this.store.finishIntent({
        expected_revision: begun.intent.revision,
        intent_id: intent.intent_id,
        reason_code: "canonical_command_version_not_advanced",
        record: applied,
        status: "unknown",
        updated_at: this.clock.now().toISOString(),
      });
      return {
        case: currentCase,
        duplicate: false,
        intent: unknown,
        outcome: "unknown",
        record: applied,
      };
    }
    const finished = await this.store.finishIntent({
      expected_revision: begun.intent.revision,
      intent_id: intent.intent_id,
      record: applied,
      status: "applied",
      updated_at: this.clock.now().toISOString(),
    });
    const caseRecord = await this.syncFromRecord(currentCase, applied);
    return {
      case: caseRecord,
      duplicate: false,
      intent: finished,
      outcome: "applied",
      record: applied,
    };
  }

  private async requireCase(caseId: string): Promise<CanonicalWorkCaseV1> {
    const id = requiredRef(caseId, "case_id", 200);
    const value = await this.store.readCase(id);
    if (value === undefined) throw new CanonicalWorkInputError("Canonical work case does not exist.");
    return value;
  }

  private async requireIntent(intentId: string): Promise<CanonicalWorkCommandIntentV1> {
    const id = requiredRef(intentId, "intent_id", 200);
    const value = await this.store.readIntent(id);
    if (value === undefined) throw new CanonicalWorkInputError("Canonical work command intent does not exist.");
    return value;
  }

  private async syncFromRecord(
    current: CanonicalWorkCaseV1,
    record: ComplianceWorkItemRecord,
  ): Promise<CanonicalWorkCaseV1> {
    validateRecord(record, current.work_item_id);
    if (record.item.basis.tenant_id !== current.basis.tenant_id) {
      throw new CanonicalWorkConflictError("Canonical work item changed tenant scope.");
    }
    if (
      record.item.version === current.work_item_version &&
      record.item.updated_at === current.work_item_updated_at
    ) {
      return current;
    }
    if (record.item.version < current.work_item_version) {
      throw new CanonicalWorkConflictError("Canonical work item version moved backwards.");
    }
    const now = this.clock.now().toISOString();
    return this.store.syncCase({
      case_id: current.case_id,
      expected_revision: current.revision,
      next: projectCase(
        record.item,
        current.title,
        now,
        current.created_at,
        current.revision + 1,
      ),
    });
  }
}

export function canonicalWorkCaseIdentity(item: ComplianceWorkItem): string {
  return `canonical-work-case-${digestHex([item.basis.tenant_id, item.id]).slice(0, 32)}`;
}

export function canonicalWorkCaseState(item: ComplianceWorkItem): CanonicalWorkCaseV1["state"] {
  switch (item.state) {
    case "resolved":
    case "accepted":
    case "superseded":
      return "closed";
    case "blocked":
      return "blocked";
    case "snoozed":
      return "waiting_on_owner";
    case "in_progress":
      return item.verification ? "verifying" : "needs_evidence";
    case "open":
      return "ready_to_act";
  }
}

function projectCase(
  item: ComplianceWorkItem,
  title: string | undefined,
  updatedAt: string,
  createdAt = updatedAt,
  revision = 1,
): CanonicalWorkCaseV1 {
  const remediated = Boolean(item.last_remediated_at || item.verification);
  const verified = Boolean(item.verification);
  const terminal = item.state === "resolved" || item.state === "accepted" || item.state === "superseded";
  const steps: CanonicalWorkCaseV1["steps"] = [
    { depends_on: [], step_id: "inspect-work-item", state: "completed", title: "Inspect the canonical work item" },
    {
      depends_on: ["inspect-work-item"],
      step_id: "record-remediation",
      state: remediated ? "completed" : "pending",
      title: "Record the completed remediation",
    },
    {
      depends_on: ["record-remediation"],
      step_id: "record-post-change-assurance",
      state: verified ? "completed" : "pending",
      title: "Record a fresh post-change assurance decision",
    },
    {
      depends_on: ["record-post-change-assurance"],
      step_id: "verify-canonical-work",
      state: terminal ? "completed" : "pending",
      title: "Verify and resolve the canonical work item",
    },
  ];
  const next = steps.find((step) => step.state === "pending");
  return {
    basis: clone(item.basis),
    case_id: canonicalWorkCaseIdentity(item),
    created_at: createdAt,
    finding_ids: distinctFindingIds(item),
    next_action: next?.title,
    owner_id: item.owner_id || undefined,
    revision,
    schema_version: "canonical-work-case/v1",
    state: canonicalWorkCaseState(item),
    steps,
    title: title ?? defaultTitle(item),
    updated_at: updatedAt,
    verification: item.verification === undefined ? undefined : clone(item.verification),
    work_item_id: item.id,
    work_item_state: item.state,
    work_item_updated_at: item.updated_at,
    work_item_version: item.version,
  };
}

function validateCommand(command: ComplianceWorkCommand): void {
  if (!Number.isSafeInteger(command.expected_version) || command.expected_version < 1) {
    throw new CanonicalWorkInputError("expected_version must be a positive integer.");
  }
  if (command.operation === "invalidate") {
    if (!INVALIDATION_TRIGGERS.includes(command.trigger as never)) {
      throw new CanonicalWorkInputError("Invalidation commands require a supported trigger.");
    }
    requiredRef(command.source_ref, "source_ref", 2_048);
    if (command.action !== undefined) {
      throw new CanonicalWorkInputError("Invalidation commands cannot include an action.");
    }
    return;
  }
  if (command.operation !== "action" || command.action === undefined) {
    throw new CanonicalWorkInputError("Action commands require a supported action.");
  }
  if (!WORK_ITEM_ACTIONS.includes(command.action as never)) {
    throw new CanonicalWorkInputError("Action commands require a supported action.");
  }
  if (command.action === "assign") requiredRef(command.owner_id, "owner_id", 240);
  if (command.action === "block") requiredRef(command.blocker_reason, "blocker_reason", 500);
  if (command.action === "snooze") requiredTimestamp(command.snooze_until, "snooze_until");
  if (command.action === "remediate") requiredRef(command.rationale, "rationale", 2_000);
  if (command.action === "verify" && (command.evidence_ids?.length ?? 0) === 0) {
    throw new CanonicalWorkInputError("Verification requires at least one evidence ID.");
  }
  if (command.action === "verify_assurance") {
    requiredRef(command.assurance_decision_id, "assurance_decision_id", 240);
  }
  if ((command.evidence_ids?.length ?? 0) > 100) {
    throw new CanonicalWorkInputError("A command can reference at most 100 evidence IDs.");
  }
  for (const evidenceId of command.evidence_ids ?? []) {
    requiredRef(evidenceId, "evidence_id", 240);
  }
}

function validateApproval(
  approval: CanonicalWorkCommandApprovalV1,
  intent: CanonicalWorkCommandIntentV1,
): void {
  if (approval.schema_version !== "canonical-work-command-approval/v1") {
    throw new CanonicalWorkInputError("Canonical work approval version is unsupported.");
  }
  if (approval.intent_id !== intent.intent_id || approval.command_digest !== intent.command_digest) {
    throw new CanonicalWorkInputError("Approval does not match the exact command intent.");
  }
  requiredRef(approval.approval_ref, "approval_ref", 2_048);
  requiredRef(approval.approval_digest, "approval_digest", 240);
  requiredRef(approval.approved_by_ref, "approved_by_ref", 2_048);
  const approvedAt = requiredTimestamp(approval.approved_at, "approved_at");
  if (Date.parse(approvedAt) < Date.parse(intent.created_at)) {
    throw new CanonicalWorkInputError("Approval predates the command intent.");
  }
  if (
    (intent.approval_digest !== undefined && intent.approval_digest !== approval.approval_digest) ||
    (intent.approval_ref !== undefined && intent.approval_ref !== approval.approval_ref) ||
    (intent.approved_by_ref !== undefined && intent.approved_by_ref !== approval.approved_by_ref)
  ) {
    throw new CanonicalWorkInputError("Approval does not match the recorded execution receipt.");
  }
}

function commandEffectSatisfied(
  intent: CanonicalWorkCommandIntentV1,
  item: ComplianceWorkItem,
): boolean {
  const command = intent.command;
  const baseline = intent.baseline;
  if (command.operation === "invalidate") return false;
  switch (command.action) {
    case "assign":
      return baseline.owner_id !== command.owner_id && item.owner_id === command.owner_id;
    case "block":
      return (
        (baseline.state !== "blocked" || baseline.blocker_reason !== command.blocker_reason) &&
        item.state === "blocked" &&
        item.blocker_reason === command.blocker_reason
      );
    case "snooze":
      return (
        (baseline.state !== "snoozed" || baseline.snooze_until !== command.snooze_until) &&
        item.state === "snoozed" &&
        item.snooze_until === command.snooze_until
      );
    case "accept":
      return baseline.state !== "accepted" && item.state === "accepted";
    case "remediate":
      return (
        item.last_remediated_at !== undefined &&
        item.last_remediated_at !== baseline.last_remediated_at
      );
    case "verify":
      return (
        baseline.state !== "resolved" &&
        item.state === "resolved" &&
        includesEvery(item.verification_evidence_ids ?? [], command.evidence_ids ?? [])
      );
    case "verify_assurance":
      return (
        baseline.verification_decision_id !== command.assurance_decision_id &&
        item.verification?.assurance_decision_id === command.assurance_decision_id
      );
    case "close":
      return baseline.state !== "resolved" && item.state === "resolved";
    case "supersede":
      return baseline.state !== "superseded" && item.state === "superseded";
    case "request_evidence":
    case undefined:
      return false;
  }
}

function rejectNoopCommand(command: ComplianceWorkCommand, item: ComplianceWorkItem): void {
  if (command.operation === "invalidate") return;
  const noop =
    (command.action === "assign" && item.owner_id === command.owner_id) ||
    (command.action === "block" && item.state === "blocked" && item.blocker_reason === command.blocker_reason) ||
    (command.action === "snooze" && item.state === "snoozed" && item.snooze_until === command.snooze_until) ||
    (command.action === "accept" && item.state === "accepted") ||
    (command.action === "verify_assurance" && item.verification?.assurance_decision_id === command.assurance_decision_id) ||
    (command.action === "close" && item.state === "resolved") ||
    (command.action === "supersede" && item.state === "superseded");
  if (noop) throw new CanonicalWorkInputError("The canonical work command is already satisfied.");
}

function baselineFor(item: ComplianceWorkItem): CanonicalWorkCommandIntentV1["baseline"] {
  return {
    blocker_reason: item.blocker_reason,
    last_remediated_at: item.last_remediated_at,
    last_reopen_trigger: item.last_reopen_trigger,
    owner_id: item.owner_id,
    snooze_until: item.snooze_until,
    state: item.state,
    verification_decision_id: item.verification?.assurance_decision_id,
    verification_evidence_ids: [...(item.verification_evidence_ids ?? [])],
  };
}

function includesEvery(actual: string[], expected: string[]): boolean {
  const values = new Set(actual);
  return expected.every((value) => values.has(value));
}

function validateRecord(record: ComplianceWorkItemRecord, expectedId: string): void {
  if (record.item.id !== expectedId) {
    throw new CanonicalWorkConflictError("Canonical work response does not match the requested item.");
  }
  if (!Number.isSafeInteger(record.item.version) || record.item.version < 1) {
    throw new CanonicalWorkInputError("Canonical work item version is invalid.");
  }
  if (!WORK_ITEM_STATES.includes(record.item.state as never)) {
    throw new CanonicalWorkInputError("Canonical work item state is unsupported.");
  }
  requiredTimestamp(record.item.updated_at, "work_item.updated_at");
  for (const [label, value] of Object.entries({
    "basis.control_id": record.item.basis.control_id,
    "basis.objective_id": record.item.basis.objective_id,
    "basis.program_id": record.item.basis.program_id,
    "basis.scope_revision_id": record.item.basis.scope_revision_id,
    "basis.source_id": record.item.basis.source_id,
    "basis.subject_id": record.item.basis.subject_id,
    "basis.tenant_id": record.item.basis.tenant_id,
  })) {
    requiredRef(value, label, 2_048);
  }
}

function defaultTitle(item: ComplianceWorkItem): string {
  return `${item.basis.control_id}: ${item.basis.subject_id}`.slice(0, 300);
}

function distinctFindingIds(item: ComplianceWorkItem): string[] {
  return [...new Set(item.occurrences.flatMap((occurrence) => occurrence.finding_ids ?? []))]
    .filter((id) => id.trim() !== "")
    .slice(0, 100);
}

function requiredRef(value: unknown, label: string, max: number): string {
  if (typeof value !== "string" || value.trim() === "") {
    throw new CanonicalWorkInputError(`${label} is required.`);
  }
  const normalized = value.trim();
  if (normalized.length > max) {
    throw new CanonicalWorkInputError(`${label} exceeds the portable reference limit.`);
  }
  return normalized;
}

function optionalRef(value: unknown, label: string, max: number): string | undefined {
  if (value === undefined) return undefined;
  return requiredRef(value, label, max);
}

function requiredTimestamp(value: unknown, label: string): string {
  const timestamp = requiredRef(value, label, 100);
  if (!Number.isFinite(Date.parse(timestamp))) {
    throw new CanonicalWorkInputError(`${label} must be an ISO timestamp.`);
  }
  return timestamp;
}

function digest(value: unknown): string {
  return `sha256:${digestHex(value)}`;
}

function digestHex(value: unknown): string {
  return createHash("sha256").update(stableJson(value)).digest("hex");
}

function stableJson(value: unknown): string {
  if (Array.isArray(value)) return `[${value.map(stableJson).join(",")}]`;
  if (value !== null && typeof value === "object") {
    const entries = Object.entries(value as Record<string, unknown>)
      .filter(([, entry]) => entry !== undefined)
      .sort(([left], [right]) => left.localeCompare(right));
    return `{${entries.map(([key, entry]) => `${JSON.stringify(key)}:${stableJson(entry)}`).join(",")}}`;
  }
  return JSON.stringify(value);
}

function clone<T>(value: T): T {
  return structuredClone(value);
}

const WORK_ITEM_ACTIONS = [
  "assign",
  "request_evidence",
  "block",
  "snooze",
  "accept",
  "remediate",
  "verify",
  "verify_assurance",
  "close",
  "supersede",
] as const;

const INVALIDATION_TRIGGERS = [
  "exception_expired",
  "evidence_stale",
  "evidence_revoked",
  "finding_reopened",
  "source_coverage_lost",
  "scope_subject_added",
] as const;

const WORK_ITEM_STATES = [
  "open",
  "in_progress",
  "blocked",
  "resolved",
  "accepted",
  "snoozed",
  "superseded",
] as const;
