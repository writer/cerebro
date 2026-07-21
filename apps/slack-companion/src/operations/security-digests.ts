import { createHash } from "node:crypto";

const SHA256 = /^sha256:[0-9a-f]{64}$/;
const REF = /^[a-z][a-z0-9_.-]*:[^\s\u0000-\u001f]{1,500}$/;

export type SecurityDigestKindV1 = "repository_hygiene" | "security_board";
export type SecurityDigestSourceStateV1 = "succeeded" | "unavailable";

export interface SecurityDigestArtifactSpecV1 {
  readonly artifact_id: string;
  readonly format: "csv" | "png";
  readonly purpose: "operator_queue" | "status_chart";
  readonly title: string;
}

export interface SecurityOperationWorkflowV1 {
  readonly artifact_specs: readonly SecurityDigestArtifactSpecV1[];
  readonly kind: SecurityDigestKindV1;
  readonly schema_version: "security-operation-workflow/v1";
  readonly workflow_id: "security.board-daily/v1" | "security.repo-hygiene-weekly/v1";
}

/** Portable product behavior. Hosts bind destinations, providers, and schedules. */
export const SECURITY_OPERATION_WORKFLOWS_V1: readonly SecurityOperationWorkflowV1[] = Object.freeze([
  Object.freeze({
    artifact_specs: Object.freeze([
      Object.freeze({ artifact_id: "security_work_by_priority", format: "png", purpose: "status_chart", title: "Security work by priority" }),
      Object.freeze({ artifact_id: "security_operator_queue", format: "csv", purpose: "operator_queue", title: "Security operator queue" }),
    ]),
    kind: "security_board",
    schema_version: "security-operation-workflow/v1",
    workflow_id: "security.board-daily/v1",
  }),
  Object.freeze({
    artifact_specs: Object.freeze([
      Object.freeze({ artifact_id: "repository_risk_by_age", format: "png", purpose: "status_chart", title: "Repository risk by age" }),
      Object.freeze({ artifact_id: "repository_hygiene_queue", format: "csv", purpose: "operator_queue", title: "Repository hygiene queue" }),
    ]),
    kind: "repository_hygiene",
    schema_version: "security-operation-workflow/v1",
    workflow_id: "security.repo-hygiene-weekly/v1",
  }),
]);

export interface SecurityDigestSourceReceiptV1 {
  readonly coverage?: "complete" | "partial";
  readonly fresh_until?: string;
  readonly observed_at: string;
  readonly required: boolean;
  readonly result_digest?: string;
  readonly result_ref?: string;
  readonly source_id: string;
  readonly state: SecurityDigestSourceStateV1;
}

export interface SecurityDigestItemV1 {
  readonly detail: string;
  readonly item_id: string;
  readonly owner_ref?: string;
  readonly priority: "critical" | "high" | "medium" | "low" | "none";
  readonly source_ids: readonly string[];
  readonly state: string;
  readonly title: string;
}

export interface SecurityDigestSectionV1 {
  readonly items: readonly SecurityDigestItemV1[];
  readonly section_id: string;
  readonly title: string;
}

export interface SecurityDigestPolicyInputV1 {
  readonly generated_at: string;
  readonly kind: SecurityDigestKindV1;
  readonly previous_content_digest?: string;
  readonly run_key: string;
  readonly schema_version: "security-digest-policy-input/v1";
  readonly sections: readonly SecurityDigestSectionV1[];
  readonly sources: readonly SecurityDigestSourceReceiptV1[];
}

export type SecurityDigestPlanV1 =
  | {
      readonly completeness: "complete" | "partial";
      readonly artifact_specs: readonly SecurityDigestArtifactSpecV1[];
      readonly content_digest: string;
      readonly disposition: "publish";
      readonly generated_at: string;
      readonly kind: SecurityDigestKindV1;
      readonly plan_id: string;
      readonly schema_version: "security-digest-plan/v1";
      readonly sections: readonly SecurityDigestSectionV1[];
      readonly source_refs: readonly string[];
      readonly source_receipts: readonly SecurityDigestSourceReceiptV1[];
    }
  | {
      readonly content_digest: string;
      readonly disposition: "suppress";
      readonly plan_id: string;
      readonly reason_code: "unchanged";
      readonly schema_version: "security-digest-plan/v1";
    }
  | {
      readonly disposition: "unavailable";
      readonly plan_id: string;
      readonly reason_code:
        | "item_source_unavailable"
        | "required_source_incomplete"
        | "required_source_unavailable"
        | "required_source_stale"
        | "no_successful_sources";
      readonly schema_version: "security-digest-plan/v1";
    };

export class SecurityDigestPolicyError extends Error {}

export function planSecurityDigest(
  input: SecurityDigestPolicyInputV1,
): SecurityDigestPlanV1 {
  if (input.schema_version !== "security-digest-policy-input/v1") {
    throw new SecurityDigestPolicyError("The security digest policy version is unsupported.");
  }
  const generatedAt = timestamp(input.generated_at, "generated_at");
  const runKey = text(input.run_key, "run_key", 200);
  if (input.kind !== "security_board" && input.kind !== "repository_hygiene") {
    throw new SecurityDigestPolicyError("The security digest kind is invalid.");
  }
  if (input.previous_content_digest !== undefined) digest(input.previous_content_digest);

  const sources = canonicalSources(input.sources);
  const sections = canonicalSections(input.sections, new Set(sources.map((source) => source.source_id)));
  const successful = sources.filter((source) =>
    source.state === "succeeded" && Date.parse(source.fresh_until!) >= Date.parse(generatedAt)
  );
  const requiredUnavailable = sources.some(
    (source) => source.required && source.state !== "succeeded",
  );
  const requiredStale = sources.some((source) =>
    source.required && source.state === "succeeded" && Date.parse(source.fresh_until!) < Date.parse(generatedAt)
  );
  const requiredIncomplete = sources.some((source) =>
    source.required && source.state === "succeeded" && source.coverage !== "complete"
  );
  const planSeed = [input.kind, runKey, ...sources.map(sourceIdentity), ...sections.map(sectionIdentity)];
  const planId = `security-digest-plan:${hash(planSeed).slice(7, 39)}`;
  if (requiredUnavailable || requiredStale || requiredIncomplete || successful.length === 0) {
    return Object.freeze({
      disposition: "unavailable",
      plan_id: planId,
      reason_code: requiredUnavailable
        ? "required_source_unavailable"
        : requiredStale
        ? "required_source_stale"
        : requiredIncomplete
        ? "required_source_incomplete"
        : "no_successful_sources",
      schema_version: "security-digest-plan/v1",
    });
  }
  const successfulSourceIds = new Set(successful.map((source) => source.source_id));
  if (sections.some((section) => section.items.some(
    (item) => item.source_ids.some((sourceId) => !successfulSourceIds.has(sourceId)),
  ))) {
    return Object.freeze({
      disposition: "unavailable",
      plan_id: planId,
      reason_code: "item_source_unavailable",
      schema_version: "security-digest-plan/v1",
    });
  }

  const contentDigest = hash([
    input.kind,
    ...successful.map(sourceContentIdentity),
    ...sections.map(sectionIdentity),
  ]);
  if (input.previous_content_digest === contentDigest) {
    return Object.freeze({
      content_digest: contentDigest,
      disposition: "suppress",
      plan_id: planId,
      reason_code: "unchanged",
      schema_version: "security-digest-plan/v1",
    });
  }
  return Object.freeze({
    artifact_specs: artifactSpecs(input.kind),
    completeness: sources.every((source) =>
      source.state === "succeeded"
      && source.coverage === "complete"
      && Date.parse(source.fresh_until!) >= Date.parse(generatedAt)
    ) ? "complete" : "partial",
    content_digest: contentDigest,
    disposition: "publish",
    generated_at: generatedAt,
    kind: input.kind,
    plan_id: planId,
    schema_version: "security-digest-plan/v1",
    sections,
    source_refs: Object.freeze(successful.map((source) => source.result_ref!)),
    source_receipts: successful,
  });
}

function canonicalSources(
  values: readonly SecurityDigestSourceReceiptV1[],
): readonly SecurityDigestSourceReceiptV1[] {
  if (values.length === 0 || values.length > 32) {
    throw new SecurityDigestPolicyError("Security digests require between 1 and 32 sources.");
  }
  const seen = new Set<string>();
  return Object.freeze(values.map((value) => {
    const sourceId = token(value.source_id, "source_id");
    if (seen.has(sourceId)) throw new SecurityDigestPolicyError("Security digest source ids must be unique.");
    seen.add(sourceId);
    timestamp(value.observed_at, "observed_at");
    if (value.state === "succeeded") {
      if (value.result_ref === undefined || value.result_digest === undefined || value.fresh_until === undefined || value.coverage === undefined) {
        throw new SecurityDigestPolicyError("Successful sources require result, freshness, and coverage receipts.");
      }
      ref(value.result_ref, "result_ref");
      digest(value.result_digest);
      timestamp(value.fresh_until, "fresh_until");
      if (Date.parse(value.fresh_until) < Date.parse(value.observed_at)) {
        throw new SecurityDigestPolicyError("fresh_until must not predate observed_at.");
      }
      if (value.coverage !== "complete" && value.coverage !== "partial") {
        throw new SecurityDigestPolicyError("Successful sources require valid coverage.");
      }
    } else if (value.state !== "unavailable" || value.result_ref !== undefined || value.result_digest !== undefined || value.fresh_until !== undefined || value.coverage !== undefined) {
      throw new SecurityDigestPolicyError("Unavailable sources cannot include result data.");
    }
    return Object.freeze({ ...value, source_id: sourceId });
  }).sort((left, right) => left.source_id.localeCompare(right.source_id)));
}

function canonicalSections(
  values: readonly SecurityDigestSectionV1[],
  sourceIds: ReadonlySet<string>,
): readonly SecurityDigestSectionV1[] {
  if (values.length === 0 || values.length > 12) {
    throw new SecurityDigestPolicyError("Security digests require between 1 and 12 sections.");
  }
  const sectionIds = new Set<string>();
  return Object.freeze(values.map((section) => {
    const sectionId = token(section.section_id, "section_id");
    if (sectionIds.has(sectionId)) throw new SecurityDigestPolicyError("Security digest section ids must be unique.");
    sectionIds.add(sectionId);
    if (section.items.length > 50) throw new SecurityDigestPolicyError("A security digest section exceeds 50 items.");
    const itemIds = new Set<string>();
    const items = section.items.map((item) => {
      const itemId = text(item.item_id, "item_id", 200);
      if (itemIds.has(itemId)) throw new SecurityDigestPolicyError("Security digest item ids must be unique within a section.");
      itemIds.add(itemId);
      const refs = [...new Set(item.source_ids)].sort();
      if (refs.length === 0 || refs.some((id) => !sourceIds.has(id))) {
        throw new SecurityDigestPolicyError("Every security digest item must cite a known source.");
      }
      return Object.freeze({
        ...item,
        detail: text(item.detail, "detail", 2_000),
        item_id: itemId,
        owner_ref: item.owner_ref === undefined ? undefined : ref(item.owner_ref, "owner_ref"),
        source_ids: Object.freeze(refs),
        state: text(item.state, "state", 100),
        title: text(item.title, "title", 300),
      });
    }).sort((left, right) => left.item_id.localeCompare(right.item_id));
    return Object.freeze({
      items: Object.freeze(items),
      section_id: sectionId,
      title: text(section.title, "section title", 200),
    });
  }).sort((left, right) => left.section_id.localeCompare(right.section_id)));
}

function sourceIdentity(source: SecurityDigestSourceReceiptV1): string {
  return source.state === "unavailable"
    ? [source.source_id, source.required, source.state, source.observed_at].join("|")
    : [source.source_id, source.required, source.state, source.coverage, source.observed_at, source.fresh_until, source.result_ref, source.result_digest].join("|");
}

function sourceContentIdentity(source: SecurityDigestSourceReceiptV1): string {
  if (source.state !== "succeeded") throw new SecurityDigestPolicyError("Only successful sources have content identity.");
  return [source.source_id, source.required, source.coverage, source.result_ref, source.result_digest].join("|");
}

function artifactSpecs(kind: SecurityDigestKindV1): readonly SecurityDigestArtifactSpecV1[] {
  return SECURITY_OPERATION_WORKFLOWS_V1.find((workflow) => workflow.kind === kind)!.artifact_specs;
}

function sectionIdentity(section: SecurityDigestSectionV1): string {
  return JSON.stringify(section);
}

function hash(values: readonly unknown[]): string {
  return `sha256:${createHash("sha256").update(JSON.stringify(values)).digest("hex")}`;
}

function digest(value: string): string {
  if (!SHA256.test(value)) throw new SecurityDigestPolicyError("A lowercase SHA-256 digest is required.");
  return value;
}

function ref(value: string, field: string): string {
  if (!REF.test(value)) throw new SecurityDigestPolicyError(`${field} is invalid.`);
  return value;
}

function token(value: string, field: string): string {
  if (!/^[a-z][a-z0-9_.-]{0,95}$/.test(value)) throw new SecurityDigestPolicyError(`${field} is invalid.`);
  return value;
}

function text(value: string, field: string, limit: number): string {
  const normalized = value.trim();
  if (normalized.length === 0 || Buffer.byteLength(normalized, "utf8") > limit || /[\u0000-\u001f\u007f]/.test(normalized)) {
    throw new SecurityDigestPolicyError(`${field} is invalid.`);
  }
  return normalized;
}

function timestamp(value: string, field: string): string {
  const parsed = Date.parse(value);
  if (!Number.isFinite(parsed)) throw new SecurityDigestPolicyError(`${field} is invalid.`);
  return new Date(parsed).toISOString();
}
