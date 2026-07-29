import { createHash } from "node:crypto";

import { encodeSlackActionEnvelope } from "../commands/codec.js";
import {
  createSlackActionRegistry,
  type SlackActionCatalogV1,
} from "../commands/contracts.js";
import {
  contentBoundSlackIdentifier,
  normalizeSlackText,
  projectSlackBlocks,
  slackPlainText,
  stableSlackIdentifier,
  type SlackActionInputV1,
  type SlackBlockV1,
  type SlackBlocksProjectionV1,
} from "../projections/blocks.js";

const MAX_FINDINGS = 25;
const MAX_RECENT_CHANGES = 25;
const MAX_SAVED_VIEWS = 20;
const UUID_PATTERN =
  /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;

export type ArchetypeSeverityV1 =
  | "critical"
  | "high"
  | "info"
  | "low"
  | "medium";

export interface ArchetypeAssigneeV1 {
  readonly display_name: string;
  readonly email?: string;
  readonly id: string;
  readonly kind: "team" | "user";
  readonly source: string;
}

export interface ArchetypeTodayFindingV1 {
  readonly assignee: ArchetypeAssigneeV1 | null;
  readonly description: string;
  readonly due_at: string | null;
  readonly finding_uuid: string;
  readonly fingerprint: string;
  readonly priority_reasons: readonly string[];
  readonly priority_score: number;
  readonly repository: string;
  readonly severity: ArchetypeSeverityV1;
  readonly sla_state: "due_soon" | "not_applicable" | "on_track" | "overdue";
  readonly status: string;
}

export interface ArchetypeRecentChangeV1 {
  readonly actor: string;
  readonly finding_ref: string;
  readonly occurred_at: string;
  readonly status: string;
  readonly summary: string;
}

export interface ArchetypeDailyDigestV1 {
  readonly actor_id: string;
  readonly date: string;
  readonly generated_at: string;
  readonly saved_views: readonly {
    readonly id: string;
    readonly name: string;
    readonly queue_mode: "evidence" | "investigations";
  }[];
  readonly today: {
    readonly actor_id: string;
    readonly assigned_to_me: readonly ArchetypeTodayFindingV1[];
    readonly counts: {
      readonly assigned_to_me: number;
      readonly changed_last_24_hours: number;
      readonly due_soon: number;
      readonly overdue: number;
      readonly unassigned_critical: number;
    };
    readonly generated_at: string;
    readonly needs_attention: readonly ArchetypeTodayFindingV1[];
    readonly recent_changes: readonly ArchetypeRecentChangeV1[];
  };
}

export interface ArchetypeFindingActionIntentV1 {
  readonly action: "start_work";
  readonly created_at: string;
  readonly executed_at: string | null;
  readonly expires_at: string;
  readonly finding_ref: string;
  readonly id: string;
  readonly status: "executed" | "expired" | "pending";
  readonly summary: string;
}

export interface ArchetypeFindingActionExecutionV1 {
  readonly finding: ArchetypeTodayFindingV1;
  readonly intent: ArchetypeFindingActionIntentV1;
}

export interface ArchetypeTodayProjectionV1 {
  readonly actor_id: string;
  readonly blocks: SlackBlocksProjectionV1;
  readonly fallback_text: string;
  readonly generated_at: string;
  readonly schema_version: "archetype-today-slack-projection/v1";
}

export class ArchetypeWorkspaceContractError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "ArchetypeWorkspaceContractError";
  }
}

const ARCHETYPE_ACTION_CATALOG: SlackActionCatalogV1 = Object.freeze({
  actions: Object.freeze([
    Object.freeze({
      action_id: "archetype.start_work.preview",
      command: "archetype_start_work_preview",
      parameters: Object.freeze([]),
      required_capabilities: Object.freeze([{
        capability_id: "archetype.findings.assign_self",
        level: "required" as const,
        version: "v1",
      }]),
      retry_policy: "idempotent" as const,
      schema_version: "slack-action-contract/v1" as const,
      subject_requirement: "required" as const,
    }),
    Object.freeze({
      action_id: "archetype.start_work.confirm",
      command: "archetype_start_work_confirm",
      parameters: Object.freeze([]),
      required_capabilities: Object.freeze([{
        capability_id: "archetype.findings.assign_self",
        level: "required" as const,
        version: "v1",
      }]),
      retry_policy: "idempotent" as const,
      schema_version: "slack-action-contract/v1" as const,
      subject_requirement: "required" as const,
    }),
  ]),
  catalog_id: "cerebro.slack.archetype_workspace",
  revision: 1,
  schema_version: "slack-action-catalog/v1",
});

export const ARCHETYPE_SLACK_ACTION_REGISTRY = createSlackActionRegistry(
  ARCHETYPE_ACTION_CATALOG,
);

export function parseArchetypeDailyDigest(
  value: unknown,
): ArchetypeDailyDigestV1 {
  const digest = record(value, "Archetype daily digest");
  const actorId = text(digest.actor_id, "daily digest actor_id", 320);
  const today = record(digest.today, "Archetype Today");
  const todayActorId = text(today.actor_id, "Today actor_id", 320);
  if (todayActorId !== actorId) {
    throw new ArchetypeWorkspaceContractError(
      "Archetype returned different actors for the digest and Today records.",
    );
  }
  const counts = record(today.counts, "Archetype Today counts");
  return Object.freeze({
    actor_id: actorId,
    date: date(digest.date, "daily digest date"),
    generated_at: timestamp(digest.generated_at, "daily digest generated_at"),
    saved_views: boundedArray(
      digest.saved_views,
      MAX_SAVED_VIEWS,
      "saved views",
    ).map(parseSavedView),
    today: Object.freeze({
      actor_id: todayActorId,
      assigned_to_me: boundedArray(
        today.assigned_to_me,
        MAX_FINDINGS,
        "assigned findings",
      ).map((item, index) => parseFinding(item, `assigned finding ${index + 1}`)),
      counts: Object.freeze({
        assigned_to_me: count(counts.assigned_to_me, "assigned_to_me"),
        changed_last_24_hours: count(
          counts.changed_last_24_hours,
          "changed_last_24_hours",
        ),
        due_soon: count(counts.due_soon, "due_soon"),
        overdue: count(counts.overdue, "overdue"),
        unassigned_critical: count(
          counts.unassigned_critical,
          "unassigned_critical",
        ),
      }),
      generated_at: timestamp(today.generated_at, "Today generated_at"),
      needs_attention: boundedArray(
        today.needs_attention,
        MAX_FINDINGS,
        "findings needing attention",
      ).map((item, index) =>
        parseFinding(item, `finding needing attention ${index + 1}`)
      ),
      recent_changes: boundedArray(
        today.recent_changes,
        MAX_RECENT_CHANGES,
        "recent finding changes",
      ).map(parseRecentChange),
    }),
  });
}

export function parseArchetypeFindingActionIntent(
  value: unknown,
): ArchetypeFindingActionIntentV1 {
  const intent = record(value, "Archetype finding action intent");
  if (intent.action !== "start_work") {
    throw new ArchetypeWorkspaceContractError(
      "Archetype returned an unsupported finding action.",
    );
  }
  if (
    intent.status !== "pending"
    && intent.status !== "executed"
    && intent.status !== "expired"
  ) {
    throw new ArchetypeWorkspaceContractError(
      "Archetype returned an unsupported finding action state.",
    );
  }
  return Object.freeze({
    action: "start_work",
    created_at: timestamp(intent.created_at, "action intent created_at"),
    executed_at: optionalTimestamp(intent.executed_at, "action intent executed_at"),
    expires_at: timestamp(intent.expires_at, "action intent expires_at"),
    finding_ref: text(intent.finding_ref, "action intent finding_ref", 512),
    id: uuid(intent.id, "action intent id"),
    status: intent.status,
    summary: text(intent.summary, "action intent summary", 1_500),
  });
}

export function parseArchetypeFindingActionExecution(
  value: unknown,
): ArchetypeFindingActionExecutionV1 {
  const execution = record(value, "Archetype finding action execution");
  const intent = parseArchetypeFindingActionIntent(execution.intent);
  if (intent.status !== "executed") {
    throw new ArchetypeWorkspaceContractError(
      "Archetype did not return an executed finding action.",
    );
  }
  return Object.freeze({
    finding: parseFinding(execution.finding, "executed finding"),
    intent,
  });
}

export function projectArchetypeToday(
  digest: ArchetypeDailyDigestV1,
): ArchetypeTodayProjectionV1 {
  const actions = digest.today.needs_attention
    .filter((finding) =>
      finding.assignee === null
      && finding.status !== "in_progress"
      && (finding.severity === "critical" || finding.severity === "high")
    )
    .slice(0, 5)
    .map((finding) => projectStartWorkAction(finding, digest.generated_at));
  const sections = [
    countsLine(digest),
    findingSection("Assigned to you", digest.today.assigned_to_me),
    findingSection("Needs attention", digest.today.needs_attention),
    recentChangesSection(digest.today.recent_changes),
  ];
  const projectionKey = `archetype-today:${sha256([
    digest.actor_id,
    digest.generated_at,
  ].join(":"))}`;
  const base = projectSlackBlocks({
    projection_key: projectionKey,
    sections,
    title: "Archetype · Today",
  });
  const blocks = withArchetypeActions(base, projectionKey, actions);
  return Object.freeze({
    actor_id: digest.actor_id,
    blocks,
    fallback_text: `Archetype Today: ${countsLine(digest)}`,
    generated_at: digest.generated_at,
    schema_version: "archetype-today-slack-projection/v1",
  });
}

function withArchetypeActions(
  base: SlackBlocksProjectionV1,
  projectionKey: string,
  actions: readonly SlackActionInputV1[],
): SlackBlocksProjectionV1 {
  if (actions.length === 0) return base;
  const elements = Object.freeze(actions.map((action) =>
    Object.freeze({
      action_id: action.action_key,
      ...(action.style === undefined ? {} : { style: action.style }),
      text: slackPlainText(action.label, "Archetype action label", 75),
      type: "button" as const,
      value: normalizeSlackText(
        action.value,
        "Archetype action value",
        2_000,
      ),
    })
  ));
  const actionBlock = Object.freeze({
    block_id: stableSlackIdentifier("archetype_actions", [
      projectionKey,
      JSON.stringify(elements),
    ]),
    elements,
    type: "actions" as const,
  });
  const blocks = Object.freeze([
    ...base.blocks,
    actionBlock,
  ]) as readonly SlackBlockV1[];
  const truth = {
    blocks,
    schema_version: "slack-blocks-projection/v1" as const,
  };
  return Object.freeze({
    ...truth,
    projection_id: contentBoundSlackIdentifier(
      "archetype_today",
      projectionKey,
      truth,
    ),
  });
}

export function projectArchetypeStartWorkConfirmation(
  intent: ArchetypeFindingActionIntentV1,
): {
  readonly action: SlackActionInputV1;
  readonly expires_at: string;
  readonly summary: string;
} {
  if (intent.status !== "pending") {
    throw new ArchetypeWorkspaceContractError(
      "Only a pending Archetype action can be confirmed.",
    );
  }
  return Object.freeze({
    action: Object.freeze({
      action_key: `archetype_confirm_start_work_${compactId(intent.id)}`,
      label: "Assign to me",
      style: "primary" as const,
      value: encodeSlackActionEnvelope({
        action: "archetype.start_work.confirm",
        command: "archetype_start_work_confirm",
        idempotency_key: `archetype-confirm:${sha256(intent.id)}`,
        issued_at: intent.created_at,
        schema_version: "slack-action-envelope/v1",
        subject_ref: `archetype-intent://${intent.id}`,
      }),
    }),
    expires_at: intent.expires_at,
    summary: intent.summary,
  });
}

function projectStartWorkAction(
  finding: ArchetypeTodayFindingV1,
  issuedAt: string,
): SlackActionInputV1 {
  return Object.freeze({
    action_key: `archetype_start_work_${compactId(finding.finding_uuid)}`,
    label: "Start work",
    value: encodeSlackActionEnvelope({
      action: "archetype.start_work.preview",
      command: "archetype_start_work_preview",
      idempotency_key: `archetype-preview:${sha256([
        finding.finding_uuid,
        issuedAt,
      ].join(":"))}`,
      issued_at: issuedAt,
      schema_version: "slack-action-envelope/v1",
      subject_ref: `archetype-finding://${finding.finding_uuid}`,
    }),
  });
}

function parseFinding(value: unknown, field: string): ArchetypeTodayFindingV1 {
  const finding = record(value, field);
  const severity = finding.severity;
  if (
    severity !== "critical"
    && severity !== "high"
    && severity !== "medium"
    && severity !== "low"
    && severity !== "info"
  ) {
    throw new ArchetypeWorkspaceContractError(`${field} severity is invalid.`);
  }
  const slaState = finding.sla_state;
  if (
    slaState !== "not_applicable"
    && slaState !== "on_track"
    && slaState !== "due_soon"
    && slaState !== "overdue"
  ) {
    throw new ArchetypeWorkspaceContractError(`${field} SLA state is invalid.`);
  }
  return Object.freeze({
    assignee: parseAssignee(finding.assignee, `${field} assignee`),
    description: text(finding.description, `${field} description`, 2_000),
    due_at: optionalTimestamp(finding.due_at, `${field} due_at`),
    finding_uuid: uuid(finding.finding_uuid, `${field} finding_uuid`),
    fingerprint: text(finding.fingerprint, `${field} fingerprint`, 512),
    priority_reasons: boundedArray(
      finding.priority_reasons,
      20,
      `${field} priority reasons`,
    ).map((reason, index) =>
      text(reason, `${field} priority reason ${index + 1}`, 500)
    ),
    priority_score: integer(
      finding.priority_score,
      `${field} priority score`,
      -1_000_000,
      1_000_000,
    ),
    repository: text(finding.repository, `${field} repository`, 300),
    severity,
    sla_state: slaState,
    status: text(finding.status, `${field} status`, 80),
  });
}

function parseAssignee(
  value: unknown,
  field: string,
): ArchetypeAssigneeV1 | null {
  if (value === null) return null;
  const assignee = record(value, field);
  if (assignee.kind !== "user" && assignee.kind !== "team") {
    throw new ArchetypeWorkspaceContractError(`${field} kind is invalid.`);
  }
  return Object.freeze({
    display_name: text(assignee.display_name, `${field} display_name`, 300),
    ...(assignee.email === null || assignee.email === undefined
      ? {}
      : { email: email(assignee.email, `${field} email`) }),
    id: text(assignee.id, `${field} id`, 300),
    kind: assignee.kind,
    source: text(assignee.source, `${field} source`, 80),
  });
}

function parseRecentChange(value: unknown, index: number): ArchetypeRecentChangeV1 {
  const field = `recent finding change ${index + 1}`;
  const change = record(value, field);
  return Object.freeze({
    actor: text(change.actor, `${field} actor`, 320),
    finding_ref: text(change.finding_ref, `${field} finding_ref`, 512),
    occurred_at: timestamp(change.occurred_at, `${field} occurred_at`),
    status: text(change.status, `${field} status`, 80),
    summary: text(change.summary, `${field} summary`, 1_000),
  });
}

function parseSavedView(value: unknown, index: number): {
  readonly id: string;
  readonly name: string;
  readonly queue_mode: "evidence" | "investigations";
} {
  const field = `saved view ${index + 1}`;
  const view = record(value, field);
  if (view.queue_mode !== "evidence" && view.queue_mode !== "investigations") {
    throw new ArchetypeWorkspaceContractError(`${field} queue mode is invalid.`);
  }
  return Object.freeze({
    id: uuid(view.id, `${field} id`),
    name: text(view.name, `${field} name`, 80),
    queue_mode: view.queue_mode,
  });
}

function countsLine(digest: ArchetypeDailyDigestV1): string {
  const counts = digest.today.counts;
  return [
    `${counts.assigned_to_me} assigned`,
    `${counts.overdue} overdue`,
    `${counts.due_soon} due soon`,
    `${counts.unassigned_critical} unassigned critical`,
    `${counts.changed_last_24_hours} changed in 24h`,
  ].join(" · ");
}

function findingSection(
  title: string,
  findings: readonly ArchetypeTodayFindingV1[],
): string {
  if (findings.length === 0) return `${title}\nNone.`;
  return [
    title,
    ...findings.slice(0, 5).map((finding) => {
      const ownership = finding.assignee?.display_name ?? "Unassigned";
      const deadline = finding.sla_state === "overdue"
        ? " · Overdue"
        : finding.sla_state === "due_soon"
          ? " · Due soon"
          : "";
      return `• ${finding.severity.toUpperCase()} · ${finding.repository} · ${ownership}${deadline}\n  ${finding.description}`;
    }),
    ...(findings.length > 5 ? [`${findings.length - 5} more in Archetype.`] : []),
  ].join("\n");
}

function recentChangesSection(
  changes: readonly ArchetypeRecentChangeV1[],
): string {
  if (changes.length === 0) return "Recent changes\nNone in the last 24 hours.";
  return [
    "Recent changes",
    ...changes.slice(0, 5).map((change) => `• ${change.summary}`),
    ...(changes.length > 5 ? [`${changes.length - 5} more in Archetype.`] : []),
  ].join("\n");
}

function record(value: unknown, field: string): Record<string, unknown> {
  if (
    value === null
    || typeof value !== "object"
    || Array.isArray(value)
    || Object.getPrototypeOf(value) !== Object.prototype
    || Object.prototype.hasOwnProperty.call(value, "toJSON")
  ) {
    throw new ArchetypeWorkspaceContractError(`${field} must be a plain record.`);
  }
  return value as Record<string, unknown>;
}

function boundedArray(
  value: unknown,
  maximum: number,
  field: string,
): readonly unknown[] {
  if (
    !Array.isArray(value)
    || value.length > maximum
    || Object.getPrototypeOf(value) !== Array.prototype
    || Object.prototype.hasOwnProperty.call(value, "toJSON")
  ) {
    throw new ArchetypeWorkspaceContractError(`${field} must be a bounded array.`);
  }
  for (let index = 0; index < value.length; index += 1) {
    if (!Object.prototype.hasOwnProperty.call(value, index)) {
      throw new ArchetypeWorkspaceContractError(`${field} must not be sparse.`);
    }
  }
  return value;
}

function text(value: unknown, field: string, maximum: number): string {
  if (typeof value !== "string") {
    throw new ArchetypeWorkspaceContractError(`${field} must be text.`);
  }
  const normalized = value.replace(/\r\n?/g, "\n").normalize("NFC").trim();
  if (
    normalized.length === 0
    || Array.from(normalized).length > maximum
    || /[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f]/.test(normalized)
  ) {
    throw new ArchetypeWorkspaceContractError(`${field} is invalid.`);
  }
  return normalized;
}

function uuid(value: unknown, field: string): string {
  const normalized = text(value, field, 36);
  if (!UUID_PATTERN.test(normalized)) {
    throw new ArchetypeWorkspaceContractError(`${field} must be a UUID.`);
  }
  return normalized.toLowerCase();
}

function email(value: unknown, field: string): string {
  const normalized = text(value, field, 320).toLowerCase();
  if (!/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(normalized)) {
    throw new ArchetypeWorkspaceContractError(`${field} must be an email address.`);
  }
  return normalized;
}

function timestamp(value: unknown, field: string): string {
  const normalized = text(value, field, 64);
  const parsed = Date.parse(normalized);
  if (!Number.isFinite(parsed) || new Date(parsed).toISOString() !== normalized) {
    throw new ArchetypeWorkspaceContractError(
      `${field} must be a canonical timestamp.`,
    );
  }
  return normalized;
}

function optionalTimestamp(value: unknown, field: string): string | null {
  return value === null ? null : timestamp(value, field);
}

function date(value: unknown, field: string): string {
  const normalized = text(value, field, 10);
  if (!/^\d{4}-\d{2}-\d{2}$/.test(normalized)) {
    throw new ArchetypeWorkspaceContractError(`${field} must be a date.`);
  }
  return normalized;
}

function count(value: unknown, field: string): number {
  return integer(value, field, 0, Number.MAX_SAFE_INTEGER);
}

function integer(
  value: unknown,
  field: string,
  minimum: number,
  maximum: number,
): number {
  if (
    typeof value !== "number"
    || !Number.isSafeInteger(value)
    || value < minimum
    || value > maximum
  ) {
    throw new ArchetypeWorkspaceContractError(`${field} must be an integer.`);
  }
  return value;
}

function compactId(value: string): string {
  return value.replaceAll("-", "").slice(0, 16).toLowerCase();
}

function sha256(value: string): string {
  return createHash("sha256").update(value).digest("hex");
}
