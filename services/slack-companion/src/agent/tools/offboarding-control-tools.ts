import { createHash } from "node:crypto";
import type { AgentTool } from "@earendil-works/pi-agent-core";
import { Type } from "@earendil-works/pi-ai";
import { canonicalResourceRef, type AgentAcceptanceCriterion } from "../../autonomy/agent-run.js";
import type { AutonomyPlanStep } from "../../autonomy/goals.js";
import type { DecisionPacket, Finding, JsonRecord, RuntimeHealth } from "../../cerebro/types.js";
import { shortError, stringValue, unique } from "./normalizers.js";
import type { SecurityToolDeps } from "./types.js";
import { safeToolResult, toolResult } from "./tool-result.js";

const OFFBOARDING_RULE_IDS = [
  "identity-okta-deprovisioned-active-in-github",
  "identity-okta-deprovisioned-active-cloud-access",
] as const;
const PROVIDERS = ["okta", "github", "aws"] as const;
const SUCCESS_ACTION_STATES = new Set(["succeeded", "success", "completed", "complete"]);
const SUCCESS_SYNC_STATES = new Set([...SUCCESS_ACTION_STATES, "healthy", "ok", "passing", "passed"]);

type OffboardingProvider = typeof PROVIDERS[number];
type RuntimeSets = Record<OffboardingProvider, string[]>;

interface PreflightArgs {
  subject_urn?: string;
  finding_id?: string;
  max_stale_minutes?: number;
  persist_receipt?: boolean;
  create_snapshot_when_ready?: boolean;
}

interface SnapshotArgs {
  okta_runtime_ids: string[];
  github_runtime_ids: string[];
  aws_runtime_ids: string[];
  subject_urn?: string;
  finding_id?: string;
  rule_ids?: string[];
  max_stale_minutes?: number;
  persist_receipt?: boolean;
}

interface RefreshArgs extends SnapshotArgs {
  reason?: string;
  idempotency_key?: string;
  baseline_snapshot_digest?: string;
  execute?: boolean;
  approved?: boolean;
}

interface ActionArgs {
  action: "identity.okta.suspend_user" | "identity.okta.unsuspend_user";
  finding_id: string;
  target: string;
  reason: string;
  idempotency_key: string;
  expected_proposal_digest?: string;
  execute?: boolean;
  approved?: boolean;
}

interface VerifyArgs extends SnapshotArgs {
  subject_urn: string;
  finding_id: string;
  baseline_snapshot_digest: string;
  baseline_runtime_revisions: Record<string, string>;
  baseline_subject_revision: string;
  action_actor_id: string;
  verifier_id?: string;
}

interface StartArgs extends VerifyArgs {
  finding_runtime_id: string;
  action: "identity.okta.suspend_user" | "identity.okta.unsuspend_user";
  target: string;
  reason: string;
  idempotency_key: string;
  proposal_digest: string;
  baseline_decision_packet_id?: string;
  requested_by_slack_user_id?: string;
  requested_by_display_name?: string;
  channel_id?: string;
  thread_ts?: string;
}

interface RuntimeState {
  provider: OffboardingProvider;
  runtime_id: string;
  observed: boolean;
  source_id?: string;
  status: string;
  sync_status?: string;
  contract_probe_status?: string;
  last_synced_at?: string;
  generated_at?: string;
  graph_run_id?: string;
  graph_run_status?: string;
  finding_evaluation_id?: string;
  finding_evaluation_status?: string;
  checkpoint_digest?: string;
  revision: string;
  fresh: boolean;
  healthy: boolean;
  provider_sync_validated: boolean;
  read_error?: string;
}

interface SnapshotResult extends Record<string, unknown> {
  schema_version: "cerebro.offboarding-control/v1";
  snapshot_id: string;
  snapshot_digest: string;
  observed_at: string;
  subject_urn?: string;
  subject_bound: boolean;
  subject_revision: string;
  provider_coverage_complete: boolean;
  source_systems_validated: OffboardingProvider[];
  runtime_revisions: Record<string, string>;
  runtime_state: RuntimeState[];
  source_ids: string[];
  findings: Array<Record<string, unknown>>;
  open_finding_count: number;
  exact_finding_open: boolean;
  fresh: boolean;
  healthy: boolean;
  ready_for_discovery: boolean;
  ready_for_action: boolean;
  blockers: string[];
  evidence_refs: string[];
  decision_packet_id?: string;
  decision_packet_digest?: string;
  decision_packet?: Record<string, unknown>;
}

const runtimeSetsSchema = {
  okta_runtime_ids: Type.Array(Type.String(), { minItems: 1, maxItems: 12 }),
  github_runtime_ids: Type.Array(Type.String(), { minItems: 1, maxItems: 12 }),
  aws_runtime_ids: Type.Array(Type.String(), { minItems: 1, maxItems: 12 }),
};

const snapshotParams = Type.Object({
  ...runtimeSetsSchema,
  subject_urn: Type.Optional(Type.String()),
  finding_id: Type.Optional(Type.String()),
  rule_ids: Type.Optional(Type.Array(Type.String(), { maxItems: 12 })),
  max_stale_minutes: Type.Optional(Type.Number({ minimum: 1, maximum: 10_080 })),
  persist_receipt: Type.Optional(Type.Boolean()),
});

export function createOffboardingControlTools(deps: SecurityToolDeps): AgentTool[] {
  return [
    {
      name: "cerebro_offboarding_preflight",
      label: "Offboarding provider preflight",
      description: "Run one bounded read-only preflight for terminated-identity coverage. Discovers exact Okta, GitHub, and AWS runtimes only from explicit source identities, verifies recent completed provider syncs and connector evidence, returns precise missing-runtime setup actions, and can create the existing durable snapshot only when all three providers are ready. Never refreshes a source or changes provider state.",
      parameters: Type.Object({
        subject_urn: Type.Optional(Type.String()),
        finding_id: Type.Optional(Type.String()),
        max_stale_minutes: Type.Optional(Type.Number({ minimum: 1, maximum: 10_080 })),
        persist_receipt: Type.Optional(Type.Boolean()),
        create_snapshot_when_ready: Type.Optional(Type.Boolean()),
      }),
      execute: async (_toolCallId, params) => safeToolResult(async () => offboardingPreflight(deps, params as PreflightArgs)),
    },
    {
      name: "cerebro_offboarding_snapshot",
      label: "Offboarding control snapshot",
      description: "Read exact Okta, GitHub, and AWS source runtimes, subject claims, cross-source offboarding findings, freshness, graph runs, and finding evaluations. Returns a digest-bound snapshot and, by default, a durable Cerebro decision receipt. This never changes provider state.",
      parameters: snapshotParams,
      execute: async (_toolCallId, params) => safeToolResult(async () => collectSnapshot(deps, params as SnapshotArgs)),
    },
    {
      name: "cerebro_offboarding_refresh",
      label: "Offboarding source refresh",
      description: "Plan or execute a reviewed source-system recollection. Execution synchronizes exact Okta, GitHub, and AWS runtimes, ingests their graph projections, evaluates offboarding findings on the Okta runtime, and proves the runtime revisions changed. Requires execute=true and approved=true.",
      parameters: Type.Object({
        ...runtimeSetsSchema,
        subject_urn: Type.Optional(Type.String()),
        finding_id: Type.Optional(Type.String()),
        rule_ids: Type.Optional(Type.Array(Type.String(), { maxItems: 12 })),
        max_stale_minutes: Type.Optional(Type.Number({ minimum: 1, maximum: 10_080 })),
        persist_receipt: Type.Optional(Type.Boolean()),
        reason: Type.String(),
        idempotency_key: Type.String(),
        baseline_snapshot_digest: Type.Optional(Type.String()),
        execute: Type.Optional(Type.Boolean()),
        approved: Type.Optional(Type.Boolean()),
      }),
      execute: async (_toolCallId, params) => safeToolResult(async () => refreshSources(deps, params as RefreshArgs)),
    },
    {
      name: "cerebro_offboarding_action",
      label: "Offboarding provider action",
      description: "Dry-run or execute one finding-scoped Okta suspend or unsuspend action through Cerebro. Mutation requires execute=true, approved=true, a reviewed proposal digest, an exact target, and an idempotency key. The tool repeats the dry-run immediately before mutation and rejects a stale proposal.",
      parameters: Type.Object({
        action: Type.Union([Type.Literal("identity.okta.suspend_user"), Type.Literal("identity.okta.unsuspend_user")]),
        finding_id: Type.String(),
        target: Type.String(),
        reason: Type.String(),
        idempotency_key: Type.String(),
        expected_proposal_digest: Type.Optional(Type.String()),
        execute: Type.Optional(Type.Boolean()),
        approved: Type.Optional(Type.Boolean()),
      }),
      execute: async (_toolCallId, params) => safeToolResult(async () => offboardingAction(deps, params as ActionArgs)),
    },
    {
      name: "cerebro_offboarding_verify",
      label: "Offboarding closure verification",
      description: "Recollect exact Okta, GitHub, and AWS evidence and issue a closure receipt only when provider coverage is complete, sources are healthy and fresh, every runtime and the subject revision changed, the action receipt succeeded, the exact finding is no longer open, and Cerebro's independent verifier allows close-loop.",
      parameters: Type.Object({
        ...runtimeSetsSchema,
        subject_urn: Type.String(),
        finding_id: Type.String(),
        rule_ids: Type.Optional(Type.Array(Type.String(), { maxItems: 12 })),
        max_stale_minutes: Type.Optional(Type.Number({ minimum: 1, maximum: 10_080 })),
        persist_receipt: Type.Optional(Type.Boolean()),
        baseline_snapshot_digest: Type.String(),
        baseline_runtime_revisions: Type.Record(Type.String(), Type.String()),
        baseline_subject_revision: Type.String(),
        action_actor_id: Type.String(),
        verifier_id: Type.Optional(Type.String()),
      }),
      execute: async (_toolCallId, params) => safeToolResult(async () => verifyClosure(deps, params as VerifyArgs)),
    },
    {
      name: "operator_offboarding_control_start",
      label: "Start offboarding control run",
      description: "Create one durable offboarding-control run from a reviewed dry-run proposal and baseline source snapshot. The run waits for reviewed approval before provider execution and post-action recollection, then stores acceptance evidence and a completion receipt only after independent closure verification.",
      parameters: Type.Object({
        ...runtimeSetsSchema,
        subject_urn: Type.String(),
        finding_id: Type.String(),
        finding_runtime_id: Type.String(),
        action: Type.Union([Type.Literal("identity.okta.suspend_user"), Type.Literal("identity.okta.unsuspend_user")]),
        target: Type.String(),
        reason: Type.String(),
        idempotency_key: Type.String(),
        proposal_digest: Type.String(),
        baseline_snapshot_digest: Type.String(),
        baseline_runtime_revisions: Type.Record(Type.String(), Type.String()),
        baseline_subject_revision: Type.String(),
        baseline_decision_packet_id: Type.Optional(Type.String()),
        action_actor_id: Type.String(),
        verifier_id: Type.Optional(Type.String()),
        rule_ids: Type.Optional(Type.Array(Type.String(), { maxItems: 12 })),
        max_stale_minutes: Type.Optional(Type.Number({ minimum: 1, maximum: 10_080 })),
        persist_receipt: Type.Optional(Type.Boolean()),
        requested_by_slack_user_id: Type.Optional(Type.String()),
        requested_by_display_name: Type.Optional(Type.String()),
        channel_id: Type.Optional(Type.String()),
        thread_ts: Type.Optional(Type.String()),
      }),
      execute: async (_toolCallId, params) => toolResult(await startControlRun(deps, params as StartArgs)),
    },
  ];
}

async function offboardingPreflight(deps: SecurityToolDeps, args: PreflightArgs): Promise<Record<string, unknown>> {
  const observedAt = new Date().toISOString();
  const maxStaleMinutes = boundedStaleMinutes(args.max_stale_minutes);
  const providerReads = await Promise.all(PROVIDERS.map(async (provider) => {
    const [connectorResult, coverageResult, runtimeResult, healthResult] = await Promise.all([
      settle(() => deps.cerebro.getConnector(provider)),
      settle(() => deps.cerebro.connectorCoverage({ sourceId: provider })),
      settle(() => deps.cerebro.listSourceRuntimes({ sourceId: provider, limit: 200 })),
      settle(() => deps.cerebro.listRuntimeHealth({ sourceId: provider, limit: 200 })),
    ]);
    const runtimeRows = recordsFrom(runtimeResult.value, "runtimes", "source_runtimes", "items")
      .filter((row) => providerForExplicitSource(row.source_id ?? row.provider) === provider);
    const healthRows = (Array.isArray(healthResult.value) ? healthResult.value : [])
      .filter((row) => providerForExplicitSource(row.source_id ?? row.provider) === provider);
    const runtimeByID = new Map<string, JsonRecord>(runtimeRows.flatMap((row) => {
      const id = runtimeID(row);
      return id ? [[id, row] as const] : [];
    }));
    const healthByID = new Map<string, RuntimeHealth>(healthRows.flatMap((row) => {
      const id = runtimeID(row);
      return id ? [[id, row] as const] : [];
    }));
    const runtimeIDs = unique([...runtimeRows.map(runtimeID), ...healthRows.map(runtimeID)].filter(Boolean));
    const readErrors = unique([
      connectorResult.error,
      coverageResult.error,
      runtimeResult.error,
      healthResult.error,
    ].filter((value): value is string => Boolean(value)));
    const states = runtimeIDs.map((id) => buildRuntimeState({
      id,
      provider,
      health: healthByID.get(id),
      runtime: runtimeByID.get(id),
      maxStaleMinutes,
      readError: runtimeResult.error ?? healthResult.error,
    }));
    return {
      provider,
      sourceID: provider,
      connectorResult,
      coverageResult,
      runtimeIDs,
      states,
      readErrors,
    };
  }));
  const runtimeSets = Object.fromEntries(providerReads.map((read) => [read.provider, read.runtimeIDs])) as RuntimeSets;
  const runtimeState = providerReads.flatMap((read) => read.states);
  const providerState = providerReads.map((read) => {
    const { provider, states, sourceID, readErrors } = read;
    const validatedRuntimeIDs = states.filter((row) => row.provider_sync_validated).map((row) => row.runtime_id);
    const invalidRuntimeIDs = states.filter((row) => !row.provider_sync_validated).map((row) => row.runtime_id);
    const coverageReady = states.length > 0;
    const validationReady = coverageReady && validatedRuntimeIDs.length === states.length && readErrors.length === 0;
    const blockers = unique([
      coverageReady ? undefined : `No ${providerLabel(provider)} source runtime is enrolled.`,
      invalidRuntimeIDs.length > 0 ? `${providerLabel(provider)} runtimes without a fresh successful provider sync: ${invalidRuntimeIDs.join(", ")}.` : undefined,
      readErrors.length > 0 ? `${providerLabel(provider)} provider evidence reads failed: ${readErrors.join("; ")}` : undefined,
    ].filter((value): value is string => Boolean(value)));
    return {
      provider,
      source_ids: [sourceID],
      runtime_ids: states.map((row) => row.runtime_id),
      validated_runtime_ids: validatedRuntimeIDs,
      coverage_ready: coverageReady,
      provider_sync_validated: validationReady,
      connector_catalog_present: Boolean(read.connectorResult.value),
      connector_attestation: compactConnectorAttestation(read.connectorResult.value),
      coverage_attestation: compactCoverageAttestation(read.coverageResult.value),
      required_read_errors: readErrors,
      protected_credential_metadata: {
        status: "not_requested_by_design",
        reason: "Provider contract and runtime metadata are sufficient for this read-only preflight.",
      },
      blockers,
      next_operator_action: validationReady
        ? undefined
        : readErrors.length > 0
          ? `Restore read access for ${providerLabel(provider)} provider evidence (${sourceID}), then rerun cerebro_offboarding_preflight.`
          : providerNextAction(provider, [sourceID], states),
    };
  });
  const topLevelErrors = unique(providerReads.flatMap((read) => read.readErrors));
  const providerCoverageComplete = providerState.every((row) => row.coverage_ready);
  const providerValidationComplete = providerState.every((row) => row.provider_sync_validated) && topLevelErrors.length === 0;
  const readyForSnapshot = providerCoverageComplete && providerValidationComplete;
  const shouldCreateSnapshot = args.create_snapshot_when_ready === true;
  const snapshot = shouldCreateSnapshot && readyForSnapshot
    ? await collectSnapshot(deps, {
        okta_runtime_ids: runtimeSets.okta,
        github_runtime_ids: runtimeSets.github,
        aws_runtime_ids: runtimeSets.aws,
        subject_urn: args.subject_urn,
        finding_id: args.finding_id,
        max_stale_minutes: maxStaleMinutes,
        persist_receipt: args.persist_receipt,
      })
    : undefined;
  const blockers = unique([
    ...providerState.flatMap((row) => row.blockers),
    ...topLevelErrors.map((error) => `Offboarding preflight read failed: ${error}`),
    shouldCreateSnapshot && !readyForSnapshot ? "Snapshot creation was gated off because provider coverage or validation is incomplete." : undefined,
  ].filter((value): value is string => Boolean(value)));
  return {
    schema_version: "cerebro.offboarding-preflight/v1",
    observed_at: observedAt,
    validation_contract: "Recent completed provider sync, healthy runtime, freshness bound, and passing contract probe when the runtime reports one. No source refresh is performed.",
    provider_coverage_complete: providerCoverageComplete,
    provider_validation_complete: providerValidationComplete,
    ready_for_snapshot: readyForSnapshot,
    provider_state: providerState,
    runtime_state: runtimeState,
    provider_attestation_digest: digest(providerState),
    source_read_contract: {
      provider_scoped: true,
      requested_source_ids: [...PROVIDERS],
      reads_per_provider: ["connector_detail", "connector_coverage", "source_runtimes", "runtime_health"],
      protected_credential_metadata_requested: false,
    },
    snapshot_requested: shouldCreateSnapshot,
    snapshot_created: Boolean(snapshot),
    snapshot: snapshot ? compactSnapshot(snapshot) : undefined,
    blockers,
    next_operator_actions: providerState.flatMap((row) => row.next_operator_action ? [row.next_operator_action] : []),
    answer_complete: true,
    stop_after_preflight: true,
    prohibited_followup_tools: [
      "cerebro_connector_catalog",
      "cerebro_connector_detail",
      "cerebro_connector_coverage",
      "cerebro_connector_activity",
      "cerebro_connector_credentials",
      "cerebro_connector_preflight",
      "cerebro_source_runtimes",
      "cerebro_runtime_health",
      "cerebro_offboarding_snapshot",
    ],
    mutations_attempted: false,
  };
}

async function collectSnapshot(deps: SecurityToolDeps, args: SnapshotArgs): Promise<SnapshotResult> {
  const observedAt = new Date().toISOString();
  const runtimeSets = normalizeRuntimeSets(args);
  const runtimeIDs = unique(PROVIDERS.flatMap((provider) => runtimeSets[provider])).slice(0, 36);
  const maxStaleMinutes = boundedStaleMinutes(args.max_stale_minutes);
  const subjectURN = stringValue(args.subject_urn);
  const ruleIDs = normalizedRuleIDs(args.rule_ids);
  const [healthResult, runtimeResult, findingRows, claimRows] = await Promise.all([
    settle(() => deps.cerebro.listRuntimeHealth({ runtimeIds: runtimeIDs, limit: runtimeIDs.length })),
    settle(() => deps.cerebro.listSourceRuntimes({ runtimeIds: runtimeIDs, limit: runtimeIDs.length })),
    Promise.all(runtimeIDs.map(async (runtimeID) => ({
      runtime_id: runtimeID,
      ...(await settle(() => listOffboardingFindings(deps, runtimeID, ruleIDs, args.finding_id))),
    }))),
    Promise.all(runtimeIDs.map(async (runtimeID) => ({
      runtime_id: runtimeID,
      ...(subjectURN
        ? await settle(() => deps.cerebro.listClaims(runtimeID, { subjectUrn: subjectURN, limit: 100 }))
        : { value: {} as JsonRecord }),
    }))),
  ]);
  const health = Array.isArray(healthResult.value) ? healthResult.value : [];
  const runtimeRecords = recordsFrom(runtimeResult.value, "runtimes", "items");
  const healthByID = new Map(health.map((row) => [runtimeID(row), row]));
  const runtimeByID = new Map(runtimeRecords.map((row) => [runtimeID(row), row]));
  const providerByRuntime = new Map(PROVIDERS.flatMap((provider) => runtimeSets[provider].map((id) => [id, provider] as const)));
  const runtimeState = runtimeIDs.map((id) => buildRuntimeState({
    id,
    provider: providerByRuntime.get(id) ?? "okta",
    health: healthByID.get(id),
    runtime: runtimeByID.get(id),
    maxStaleMinutes,
    readError: healthResult.error ?? runtimeResult.error,
  }));
  const findings = findingRows.flatMap((row) => (row.value ?? []).map((finding) => compactFinding(row.runtime_id, finding)));
  const claimObservations = claimRows.map((row) => {
    const claims = recordsFrom(row.value, "claims", "items");
    return {
      runtime_id: row.runtime_id,
      claim_count: claims.length,
      claim_digest: digest(claims),
      error: row.error,
    };
  });
  const providerCoverage = PROVIDERS.map((provider) => ({
    provider,
    runtime_ids: runtimeSets[provider],
    observed_runtime_ids: runtimeSets[provider].filter((id) => runtimeState.some((row) => row.runtime_id === id && row.observed && !row.read_error)),
  }));
  const providerCoverageComplete = providerCoverage.every((row) => row.runtime_ids.length > 0 && row.observed_runtime_ids.length === row.runtime_ids.length);
  const fresh = runtimeState.length > 0 && runtimeState.every((row) => row.fresh);
  const healthy = runtimeState.length > 0 && runtimeState.every((row) => row.healthy);
  const readErrors = unique([
    healthResult.error,
    runtimeResult.error,
    ...findingRows.map((row) => row.error),
    ...claimRows.map((row) => row.error),
  ].filter((value): value is string => Boolean(value)));
  const exactFindingOpen = Boolean(args.finding_id && findings.some((finding) => finding.id === args.finding_id));
  const subjectRevision = digest({ subject_urn: subjectURN, claims: claimObservations, findings });
  const sourceIDs = unique(runtimeState.map((row) => row.source_id).filter((value): value is string => Boolean(value)));
  const runtimeRevisions = Object.fromEntries(runtimeState.map((row) => [row.runtime_id, row.revision]));
  const blockers = unique([
    providerCoverageComplete ? undefined : "Required Okta, GitHub, and AWS runtime coverage is incomplete.",
    healthy ? undefined : "One or more source runtimes are not healthy.",
    fresh ? undefined : `One or more source runtimes exceed the ${maxStaleMinutes}-minute freshness bound.`,
    subjectURN ? undefined : "An exact subject_urn is required before provider action or closure.",
    readErrors.length > 0 ? `Source reads failed: ${readErrors.join("; ")}` : undefined,
  ].filter((value): value is string => Boolean(value)));
  const snapshotCore = {
    schema_version: "cerebro.offboarding-control/v1" as const,
    observed_at: observedAt,
    subject_urn: subjectURN,
    subject_bound: Boolean(subjectURN),
    subject_revision: subjectRevision,
    provider_coverage: providerCoverage,
    provider_coverage_complete: providerCoverageComplete,
    source_systems_validated: PROVIDERS.filter((provider) => providerCoverage.find((row) => row.provider === provider)?.observed_runtime_ids.length),
    runtime_revisions: runtimeRevisions,
    runtime_state: runtimeState,
    source_ids: sourceIDs,
    claim_observations: claimObservations,
    findings,
    open_finding_count: findings.length,
    exact_finding_open: exactFindingOpen,
    fresh,
    healthy,
    ready_for_discovery: providerCoverageComplete && healthy && fresh && readErrors.length === 0,
    blockers,
  };
  const snapshotDigest = digest(snapshotCore);
  const snapshotID = `offboarding-snapshot-${snapshotDigest.slice(-32)}`;
  let decisionPacket: DecisionPacket | undefined;
  let decisionPacketError: string | undefined;
  if (args.persist_receipt !== false && providerCoverageComplete && readErrors.length === 0) {
    try {
      decisionPacket = await deps.cerebro.buildDecisionPacket({
        workflow: "terminated_identity_access_control",
        question: subjectURN
          ? "Does the exact terminated identity retain active access in Okta, GitHub, or AWS?"
          : "Do current Okta, GitHub, or AWS findings show terminated identities retaining active access?",
        scope_urn: subjectURN,
        finding_ids: unique(findings.map((finding) => stringValue(finding.id)).filter((value): value is string => Boolean(value))).slice(0, 25),
        required_sources: sourceIDs,
        requested_action: "verify_offboarding_control",
      });
    } catch (error) {
      decisionPacketError = shortError(error);
    }
  }
  const durableReceiptReady = args.persist_receipt === false || Boolean(decisionPacket?.id);
  const finalBlockers = unique([
    ...blockers,
    decisionPacketError ? `Durable decision receipt failed: ${decisionPacketError}` : undefined,
    durableReceiptReady ? undefined : "A durable Cerebro decision receipt is required before action.",
  ].filter((value): value is string => Boolean(value)));
  const evidenceRefs = unique([
    ...runtimeState.map((row) => `cerebro://source-runtime/${row.runtime_id}?revision=${encodeURIComponent(row.revision)}`),
    ...findings.map((finding) => `cerebro://finding/${String(finding.id)}`),
    decisionPacket?.id ? `cerebro://decision-packet/${decisionPacket.id}` : undefined,
  ].filter((value): value is string => Boolean(value)));
  return {
    ...snapshotCore,
    snapshot_id: snapshotID,
    snapshot_digest: snapshotDigest,
    ready_for_action: snapshotCore.ready_for_discovery && Boolean(subjectURN) && findings.length > 0 && durableReceiptReady,
    blockers: finalBlockers,
    evidence_refs: evidenceRefs,
    decision_packet_id: decisionPacket?.id,
    decision_packet_digest: decisionPacket?.provenance.evidence_digest,
    decision_packet: decisionPacket ? compactDecisionPacket(decisionPacket) : undefined,
  };
}

async function refreshSources(deps: SecurityToolDeps, args: RefreshArgs): Promise<Record<string, unknown>> {
  const runtimeSets = normalizeRuntimeSets(args);
  const runtimeIDs = unique(PROVIDERS.flatMap((provider) => runtimeSets[provider]));
  const plan = {
    runtime_ids: runtimeSets,
    stages: ["provider_sync", "graph_ingest", "finding_evaluate", "source_recollection"],
    reason: stringValue(args.reason),
    idempotency_key: stringValue(args.idempotency_key),
    execute_requested: args.execute === true,
    approved: args.approved === true,
    approval_required: true,
  };
  if (args.execute !== true) {
    return { ...plan, attempted: false, dry_run: true, next_step: "Obtain reviewed approval, then set execute=true and approved=true." };
  }
  if (args.approved !== true) {
    return { ...plan, attempted: false, error: "approval_required", next_step: "Reviewed approval is required before source-system recollection." };
  }
  const before = await collectSnapshot(deps, { ...args, persist_receipt: false });
  if (args.baseline_snapshot_digest && args.baseline_snapshot_digest !== before.snapshot_digest) {
    return {
      ...plan,
      attempted: false,
      error: "stale_baseline_snapshot",
      expected_snapshot_digest: args.baseline_snapshot_digest,
      observed_snapshot_digest: before.snapshot_digest,
    };
  }
  const sync = await runStage(runtimeIDs, (runtimeID) => deps.cerebro.syncRuntime(runtimeID));
  const graph = await runStage(runtimeIDs, (runtimeID) => deps.cerebro.runGraphIngest(runtimeID));
  const evaluation = await runStage(runtimeSets.okta, (runtimeID) => deps.cerebro.evaluateFindings(runtimeID));
  const after = await collectSnapshot(deps, { ...args, persist_receipt: args.persist_receipt !== false });
  const changedRuntimeIDs = runtimeIDs.filter((runtimeID) => before.runtime_revisions[runtimeID] !== after.runtime_revisions[runtimeID]);
  const stageErrors = [...sync, ...graph, ...evaluation].filter((row) => row.error);
  const refreshVerified = stageErrors.length === 0 && changedRuntimeIDs.length === runtimeIDs.length && after.ready_for_discovery;
  const receiptCore = {
    schema_version: "cerebro.offboarding-refresh/v1",
    idempotency_key: args.idempotency_key,
    before_snapshot_digest: before.snapshot_digest,
    after_snapshot_digest: after.snapshot_digest,
    changed_runtime_ids: changedRuntimeIDs,
    stages: {
      sync: sync.map(compactStageResult),
      graph_ingest: graph.map(compactStageResult),
      finding_evaluate: evaluation.map(compactStageResult),
    },
    completed_at: new Date().toISOString(),
  };
  const receiptDigest = digest(receiptCore);
  return {
    ...plan,
    attempted: true,
    dry_run: false,
    refresh_verified: refreshVerified,
    refresh_receipt: { ...receiptCore, digest: receiptDigest },
    before_snapshot: compactSnapshot(before),
    post_snapshot: compactSnapshot(after),
    evidence_refs: unique([...before.evidence_refs, ...after.evidence_refs, `cerebro://offboarding-refresh/${receiptDigest}`]),
    blockers: unique([
      stageErrors.length > 0 ? `Source stages failed for ${stageErrors.map((row) => row.runtime_id).join(", ")}.` : undefined,
      changedRuntimeIDs.length === runtimeIDs.length ? undefined : "Not every provider runtime produced a new revision.",
      ...after.blockers,
    ].filter((value): value is string => Boolean(value))),
    ...(!refreshVerified ? { error: "source_refresh_not_verified" } : {}),
  };
}

async function offboardingAction(deps: SecurityToolDeps, args: ActionArgs): Promise<Record<string, unknown>> {
  const baseRequest = {
    action: args.action,
    finding_id: args.finding_id.trim(),
    target: args.target.trim(),
    reason: args.reason.trim(),
    idempotency_key: args.idempotency_key.trim(),
  };
  const dryRun = await deps.cerebro.executeGraphAction({ ...baseRequest, dry_run: true, approved: false });
  const proposal = graphActionProposal(baseRequest, dryRun);
  const proposalDigest = digest(proposal);
  if (args.execute !== true) {
    return {
      attempted: false,
      dry_run: true,
      approval_required: true,
      proposal,
      proposal_digest: proposalDigest,
      evidence_refs: [`cerebro://offboarding-proposal/${proposalDigest}`],
      next_step: "Review the exact target and proposal digest, then approve a durable offboarding-control run.",
    };
  }
  if (args.approved !== true) {
    return { attempted: false, dry_run: false, error: "approval_required", proposal, proposal_digest: proposalDigest };
  }
  if (!args.expected_proposal_digest || args.expected_proposal_digest !== proposalDigest) {
    return {
      attempted: false,
      dry_run: false,
      error: "stale_proposal",
      expected_proposal_digest: args.expected_proposal_digest,
      observed_proposal_digest: proposalDigest,
      proposal,
    };
  }
  const response = await deps.cerebro.executeGraphAction({ ...baseRequest, dry_run: false, approved: true });
  const action = recordValue(response.action);
  const externalID = stringValue(action?.external_id ?? action?.id);
  const status = normalizedStatus(action?.external_status ?? action?.status);
  const receiptCore = {
    schema_version: "cerebro.offboarding-action/v1",
    action: baseRequest.action,
    finding_id: baseRequest.finding_id,
    target: baseRequest.target,
    idempotency_key: baseRequest.idempotency_key,
    proposal_digest: proposalDigest,
    external_id: externalID,
    status,
    provider: stringValue(action?.provider),
    completed_at: stringValue(action?.completed_at) ?? unixTimestamp(action?.completed_at_unix),
  };
  const receiptDigest = digest(receiptCore);
  return {
    attempted: true,
    dry_run: false,
    action_succeeded: SUCCESS_ACTION_STATES.has(status),
    proposal,
    proposal_digest: proposalDigest,
    action_receipt: { ...receiptCore, digest: receiptDigest },
    evidence_refs: unique([
      externalID ? `cerebro://graph-action/${externalID}` : undefined,
      `cerebro://offboarding-action/${receiptDigest}`,
    ].filter((value): value is string => Boolean(value))),
  };
}

async function verifyClosure(deps: SecurityToolDeps, args: VerifyArgs): Promise<Record<string, unknown>> {
  const verifierID = stringValue(args.verifier_id) ?? "cerebro:source-recollection-verifier";
  const snapshot = await collectSnapshot(deps, { ...args, persist_receipt: true });
  const runtimeIDs = Object.keys(args.baseline_runtime_revisions);
  const changedRuntimeIDs = runtimeIDs.filter((runtimeID) => args.baseline_runtime_revisions[runtimeID] !== snapshot.runtime_revisions[runtimeID]);
  const finding = await findFindingAnyStatus(deps, args.finding_id, normalizeRuntimeSets(args));
  const actionRef = successfulGraphActionRef(finding);
  const sourceRevisionChanged = runtimeIDs.length > 0 && changedRuntimeIDs.length === runtimeIDs.length;
  const subjectRevisionChanged = args.baseline_subject_revision !== snapshot.subject_revision;
  const exactFindingClosed = !snapshot.exact_finding_open;
  const verifierIndependent = verifierID !== args.action_actor_id.trim();
  const evidenceURNs = unique([
    ...snapshot.evidence_refs,
    ...recordsFrom(finding?.external_refs).flatMap((ref) => [stringValue(ref.url), stringValue(ref.external_id)]),
  ].filter((value): value is string => Boolean(value))).slice(0, 50);
  const verification = await settle(() => deps.cerebro.verifyAgentClaim({
    claim: "Fresh Okta, GitHub, and AWS evidence shows the exact terminated identity no longer retains active access.",
    claim_type: "offboarding_control_closure",
    scope_urn: args.subject_urn,
    supporting_evidence_urns: evidenceURNs,
    missing_evidence: snapshot.blockers,
    freshness_state: snapshot.fresh ? "fresh" : "stale",
    requested_action_stage: "close_loop",
    human_approved: true,
  }));
  const claimVerification = verification.value;
  const verifierAllowsClosure = claimVerification?.verdict === "supported" && claimVerification.allowed_next_stage === "close_loop";
  const closureVerified = snapshot.provider_coverage_complete
    && snapshot.healthy
    && snapshot.fresh
    && sourceRevisionChanged
    && subjectRevisionChanged
    && exactFindingClosed
    && Boolean(actionRef)
    && verifierIndependent
    && Boolean(snapshot.decision_packet_id)
    && verifierAllowsClosure;
  const blockers = unique([
    snapshot.provider_coverage_complete ? undefined : "Okta, GitHub, and AWS coverage is incomplete.",
    snapshot.healthy ? undefined : "A source runtime is unhealthy.",
    snapshot.fresh ? undefined : "A source runtime is stale.",
    sourceRevisionChanged ? undefined : "Not every provider runtime has a post-action revision.",
    subjectRevisionChanged ? undefined : "The subject evidence revision did not change after action.",
    exactFindingClosed ? undefined : "The exact offboarding finding remains open.",
    actionRef ? undefined : "No successful provider action receipt is linked to the finding.",
    verifierIndependent ? undefined : "The verifier must be distinct from the action actor.",
    snapshot.decision_packet_id ? undefined : "The durable decision receipt is missing.",
    verification.error ? `Independent verifier failed: ${verification.error}` : undefined,
    verifierAllowsClosure ? undefined : "Cerebro's independent verifier did not allow close-loop.",
  ].filter((value): value is string => Boolean(value)));
  const receiptCore = {
    schema_version: "cerebro.offboarding-closure/v1",
    status: closureVerified ? "verified_closed" : "blocked",
    subject_urn: args.subject_urn,
    finding_id: args.finding_id,
    baseline_snapshot_digest: args.baseline_snapshot_digest,
    verification_snapshot_digest: snapshot.snapshot_digest,
    baseline_runtime_revisions: args.baseline_runtime_revisions,
    verification_runtime_revisions: snapshot.runtime_revisions,
    baseline_subject_revision: args.baseline_subject_revision,
    verification_subject_revision: snapshot.subject_revision,
    changed_runtime_ids: changedRuntimeIDs,
    action_external_id: actionRef ? stringValue(actionRef.external_id) : undefined,
    decision_packet_id: snapshot.decision_packet_id,
    verifier: verifierID,
    verified_at: snapshot.observed_at,
    evidence_refs: evidenceURNs,
  };
  const receiptDigest = digest(receiptCore);
  return {
    closure_verified: closureVerified,
    closure_receipt: { ...receiptCore, digest: receiptDigest },
    snapshot: compactSnapshot(snapshot),
    claim_verification: claimVerification,
    blockers,
    evidence_refs: unique([...evidenceURNs, `cerebro://offboarding-closure/${receiptDigest}`]),
  };
}

async function startControlRun(deps: SecurityToolDeps, args: StartArgs): Promise<Record<string, unknown>> {
  if (!deps.autonomyGoals?.createFromPlan) {
    return { created: false, error: "executable_agent_runs_unavailable", message: "Durable agent-run storage is not configured." };
  }
  const runtimeSets = normalizeRuntimeSets(args);
  if (!runtimeSets.okta.includes(args.finding_runtime_id.trim())) {
    return {
      created: false,
      error: "finding_runtime_not_in_okta_scope",
      finding_runtime_id: args.finding_runtime_id,
      okta_runtime_ids: runtimeSets.okta,
    };
  }
  const commonSnapshotArgs = {
    okta_runtime_ids: runtimeSets.okta,
    github_runtime_ids: runtimeSets.github,
    aws_runtime_ids: runtimeSets.aws,
    subject_urn: args.subject_urn,
    finding_id: args.finding_id,
    rule_ids: normalizedRuleIDs(args.rule_ids),
    max_stale_minutes: boundedStaleMinutes(args.max_stale_minutes),
  };
  const plan: AutonomyPlanStep[] = [
    {
      id: "execute-reviewed-provider-action",
      title: `Execute reviewed ${args.action} for finding ${args.finding_id}`,
      status: "pending",
      dependsOn: [],
      execution: {
        toolName: "cerebro_offboarding_action",
        arguments: {
          action: args.action,
          finding_id: args.finding_id,
          target: args.target,
          reason: args.reason,
          idempotency_key: args.idempotency_key,
          expected_proposal_digest: args.proposal_digest,
          execute: true,
          approved: true,
        },
        verificationToolName: "cerebro_offboarding_snapshot",
        verificationArguments: { ...commonSnapshotArgs, persist_receipt: false },
        approvalRequired: true,
        idempotencyKey: args.idempotency_key,
        rollback: rollbackFor(args.action, args.target),
        maxAttempts: 1,
        attempts: 0,
      },
      acceptanceCriteriaIds: ["provider-action-executed"],
    },
    {
      id: "recollect-provider-state",
      title: "Recollect Okta, GitHub, and AWS state after provider execution",
      status: "pending",
      dependsOn: ["execute-reviewed-provider-action"],
      execution: {
        toolName: "cerebro_offboarding_refresh",
        arguments: {
          ...commonSnapshotArgs,
          reason: `Post-action recollection for ${args.finding_id}`,
          idempotency_key: `${args.idempotency_key}:recollect`,
          execute: true,
          approved: true,
          persist_receipt: true,
        },
        verificationToolName: "cerebro_offboarding_snapshot",
        verificationArguments: { ...commonSnapshotArgs, persist_receipt: true },
        approvalRequired: true,
        idempotencyKey: `${args.idempotency_key}:recollect`,
        rollback: "Source recollection is non-destructive. Rerun the exact runtimes and retain both receipts if verification fails.",
        maxAttempts: 2,
        attempts: 0,
      },
      acceptanceCriteriaIds: ["provider-state-recollected"],
    },
    {
      id: "verify-offboarding-closure",
      title: "Verify the exact finding is closed from fresh independent source evidence",
      status: "pending",
      dependsOn: ["recollect-provider-state"],
      execution: {
        toolName: "cerebro_offboarding_verify",
        arguments: {
          ...commonSnapshotArgs,
          baseline_snapshot_digest: args.baseline_snapshot_digest,
          baseline_runtime_revisions: args.baseline_runtime_revisions,
          baseline_subject_revision: args.baseline_subject_revision,
          action_actor_id: args.action_actor_id,
          ...(args.verifier_id ? { verifier_id: args.verifier_id } : {}),
          persist_receipt: true,
        },
        verificationArguments: {},
        approvalRequired: false,
        maxAttempts: 3,
        attempts: 0,
      },
      acceptanceCriteriaIds: ["closure-verified"],
    },
  ];
  const acceptanceCriteria: AgentAcceptanceCriterion[] = [
    { id: "provider-action-executed", description: "The reviewed provider action and independent read completed.", kind: "tool_success", status: "pending", evidenceRefs: [] },
    { id: "provider-state-recollected", description: "Post-action source recollection and independent read completed.", kind: "tool_success", status: "pending", evidenceRefs: [] },
    { id: "closure-verified", description: "Fresh source evidence produced a verified closure receipt.", kind: "field_equals", field: "closure_verified", expected: true, status: "pending", evidenceRefs: [] },
  ];
  const actorSlackID = stringValue(args.requested_by_slack_user_id) ?? "unknown";
  const goal = await deps.autonomyGoals.createFromPlan({
    objective: `Verify terminated-identity access is removed across Okta, GitHub, and AWS for finding ${args.finding_id}.`,
    actor: {
      slackUserId: actorSlackID,
      actorId: actorSlackID === "unknown" ? "slack:unknown" : `slack:${actorSlackID}`,
      displayName: stringValue(args.requested_by_display_name),
    },
    channelId: stringValue(args.channel_id),
    threadTs: stringValue(args.thread_ts),
    capabilityId: "remediation",
    plan,
    resourceRefs: [
      canonicalResourceRef({ kind: "cerebro", id: `finding:${args.finding_id}`, source: args.finding_runtime_id, evidenceReceipt: args.baseline_snapshot_digest }),
      canonicalResourceRef({ kind: "person", id: args.subject_urn, source: "cerebro_source_claims", evidenceReceipt: args.baseline_subject_revision }),
      ...PROVIDERS.flatMap((provider) => runtimeSets[provider].map((runtimeID) => canonicalResourceRef({
        kind: provider === "aws" ? "aws" : "cerebro",
        id: `source-runtime:${runtimeID}`,
        source: provider,
        evidenceReceipt: args.baseline_runtime_revisions[runtimeID],
      }))),
      ...(args.baseline_decision_packet_id
        ? [canonicalResourceRef({ kind: "evidence", id: `decision-packet:${args.baseline_decision_packet_id}`, source: "cerebro_decision_packet" })]
        : []),
    ],
    acceptanceCriteria,
    assumptions: ["The supplied proposal digest was reviewed against the exact finding and target."],
  });
  deps.researchState?.recordCreatedGoal(goal.id);
  return {
    created: true,
    goal_id: goal.id,
    status: goal.status,
    next_wake_at: goal.nextWakeAt,
    plan_steps: goal.currentPlan.map((step) => ({ id: step.id, title: step.title, approval_required: step.execution?.approvalRequired === true })),
    evidence_refs: unique([
      `cerebro://agent-run/${goal.id}`,
      `cerebro://offboarding-snapshot/${args.baseline_snapshot_digest}`,
      args.baseline_decision_packet_id ? `cerebro://decision-packet/${args.baseline_decision_packet_id}` : undefined,
    ].filter((value): value is string => Boolean(value))),
  };
}

function normalizeRuntimeSets(args: SnapshotArgs): RuntimeSets {
  return {
    okta: unique(args.okta_runtime_ids.map((value) => value.trim()).filter(Boolean)).slice(0, 12),
    github: unique(args.github_runtime_ids.map((value) => value.trim()).filter(Boolean)).slice(0, 12),
    aws: unique(args.aws_runtime_ids.map((value) => value.trim()).filter(Boolean)).slice(0, 12),
  };
}

function normalizedRuleIDs(values: string[] | undefined): string[] {
  const normalized = unique((values ?? OFFBOARDING_RULE_IDS).map((value) => value.trim()).filter(Boolean));
  return normalized.length > 0 ? normalized.slice(0, 12) : [...OFFBOARDING_RULE_IDS];
}

async function listOffboardingFindings(
  deps: SecurityToolDeps,
  runtimeID: string,
  ruleIDs: string[],
  findingID: string | undefined,
): Promise<Finding[]> {
  if (findingID) return deps.cerebro.listFindings(runtimeID, { findingId: findingID, status: "open", limit: 5 });
  const rows = await Promise.all(ruleIDs.map((ruleID) => deps.cerebro.listFindings(runtimeID, { ruleId: ruleID, status: "open", limit: 25 })));
  return uniqueFindings(rows.flat());
}

async function findFindingAnyStatus(deps: SecurityToolDeps, findingID: string, runtimeSets: RuntimeSets): Promise<Finding | undefined> {
  for (const runtimeID of unique(PROVIDERS.flatMap((provider) => runtimeSets[provider]))) {
    for (const status of ["open", "resolved", "suppressed"] as const) {
      const result = await settle(() => deps.cerebro.listFindings(runtimeID, { findingId: findingID, status, limit: 5 }));
      const finding = result.value?.find((row) => row.id === findingID) ?? result.value?.[0];
      if (finding) return finding;
    }
  }
  return undefined;
}

function buildRuntimeState(input: {
  id: string;
  provider: OffboardingProvider;
  health?: RuntimeHealth;
  runtime?: JsonRecord;
  maxStaleMinutes: number;
  readError?: string;
}): RuntimeState {
  const latestGraph = recordValue(input.health?.latest_graph_run);
  const latestFinding = recordValue(input.health?.latest_finding_evaluation);
  const contractProbe = recordValue(input.health?.contract_probe ?? input.health?.latest_contract_probe ?? input.runtime?.contract_probe);
  const lastSynced = stringValue(input.health?.last_synced_at ?? input.health?.last_sync_at ?? input.runtime?.last_synced_at);
  const observedMillis = Date.parse(lastSynced ?? "");
  const fresh = Number.isFinite(observedMillis) && Date.now() - observedMillis <= input.maxStaleMinutes * 60_000;
  const status = normalizedStatus(input.health?.status ?? input.health?.sync_status ?? "unknown");
  const syncStatus = normalizedStatus(input.health?.sync_status ?? input.health?.status ?? input.runtime?.sync_status ?? "unknown");
  const contractProbeStatus = stringValue(input.health?.contract_probe_status ?? contractProbe?.status);
  const normalizedContractProbeStatus = contractProbeStatus ? normalizedStatus(contractProbeStatus) : undefined;
  const healthy = status === "healthy" && !input.readError;
  const providerSyncValidated = Boolean(input.health || input.runtime)
    && healthy
    && fresh
    && SUCCESS_SYNC_STATES.has(syncStatus)
    && (!normalizedContractProbeStatus || SUCCESS_SYNC_STATES.has(normalizedContractProbeStatus));
  const revisionInput = {
    runtime_id: input.id,
    source_id: stringValue(input.health?.source_id ?? input.runtime?.source_id),
    last_synced_at: lastSynced,
    checkpoint: input.runtime?.checkpoint,
    next_cursor: input.runtime?.next_cursor,
    graph_run_id: stringValue(latestGraph?.id),
    graph_run_status: stringValue(latestGraph?.status),
    graph_checkpoint_cursor: stringValue(latestGraph?.checkpoint_cursor),
    finding_evaluation_id: stringValue(latestFinding?.id),
    finding_evaluation_status: stringValue(latestFinding?.status),
  };
  return {
    provider: input.provider,
    runtime_id: input.id,
    observed: Boolean(input.health || input.runtime),
    source_id: revisionInput.source_id,
    status,
    sync_status: syncStatus,
    contract_probe_status: normalizedContractProbeStatus,
    last_synced_at: lastSynced,
    generated_at: stringValue(input.health?.generated_at),
    graph_run_id: revisionInput.graph_run_id,
    graph_run_status: revisionInput.graph_run_status,
    finding_evaluation_id: revisionInput.finding_evaluation_id,
    finding_evaluation_status: revisionInput.finding_evaluation_status,
    checkpoint_digest: digest({ checkpoint: input.runtime?.checkpoint, next_cursor: input.runtime?.next_cursor }),
    revision: digest(revisionInput),
    fresh,
    healthy,
    provider_sync_validated: providerSyncValidated,
    read_error: input.readError,
  };
}

function compactFinding(runtimeID: string, finding: Finding): Record<string, unknown> {
  return {
    id: finding.id,
    runtime_id: finding.runtime_id ?? runtimeID,
    rule_id: finding.rule_id,
    status: finding.status,
    severity: finding.severity,
    resource_urn: finding.primary_resource_urn ?? finding.resource_urn,
    last_observed_at: finding.last_observed_at ?? finding.observed_at,
    external_refs: finding.external_refs,
  };
}

function compactDecisionPacket(packet: DecisionPacket): Record<string, unknown> {
  return {
    id: packet.id,
    generated_at: packet.generated_at,
    decision: packet.decision,
    confidence: packet.confidence,
    freshness: packet.freshness,
    coverage_gaps: packet.coverage_gaps,
    contradictions: packet.contradictions,
    evidence_digest: packet.provenance.evidence_digest,
    coverage_digest: packet.provenance.coverage_digest,
    source_ids: packet.provenance.source_ids,
  };
}

function compactSnapshot(snapshot: SnapshotResult): Record<string, unknown> {
  return {
    snapshot_id: snapshot.snapshot_id,
    snapshot_digest: snapshot.snapshot_digest,
    observed_at: snapshot.observed_at,
    subject_revision: snapshot.subject_revision,
    runtime_revisions: snapshot.runtime_revisions,
    provider_coverage_complete: snapshot.provider_coverage_complete,
    source_systems_validated: snapshot.source_systems_validated,
    healthy: snapshot.healthy,
    fresh: snapshot.fresh,
    exact_finding_open: snapshot.exact_finding_open,
    open_finding_count: snapshot.open_finding_count,
    decision_packet_id: snapshot.decision_packet_id,
    blockers: snapshot.blockers,
  };
}

function compactConnectorAttestation(value: unknown): Record<string, unknown> {
  const connector = recordValue(value) ?? {};
  const summary = recordValue(connector.summary) ?? {};
  const connections = recordsFrom(connector, "connections", "items");
  const latestActivityAt = latestTimestamp([
    connector,
    summary,
    ...connections,
  ]);
  return {
    source_id: stringValue(connector.source_id ?? connector.id),
    status: normalizedStatus(connector.status ?? connector.availability ?? connector.access_status),
    availability: stringValue(connector.availability),
    access_status: stringValue(connector.access_status),
    connection_summary: {
      total: optionalNumber(summary.total_connections ?? summary.connection_count ?? connector.total_connections ?? connector.connection_count) ?? connections.length,
      healthy: optionalNumber(summary.healthy_connections ?? summary.healthy_count),
      needs_refresh: optionalNumber(summary.needs_refresh_connections ?? summary.needs_refresh_count),
      statuses: statusCounts(connections),
      latest_activity_at: latestActivityAt,
    },
    provider_contract: {
      auth_model: stringValue(connector.auth_model),
      has_api_contract: connector.has_provider_api_contract === true,
      has_api_mapping: connector.has_provider_api_mapping === true,
      has_api_proof: connector.has_provider_api_proof === true,
      proof_level: stringValue(connector.provider_api_proof_level),
      proof_score: optionalNumber(connector.provider_api_proof_score),
      status: stringValue(connector.provider_api_status),
      verified_at: stringValue(connector.provider_api_verified_at),
      base_url: stringValue(connector.provider_api_base_url),
      authorization_model: stringValue(connector.provider_api_auth),
      authorization_mechanics: stringValue(connector.provider_api_auth_mechanics),
      verification_endpoint: stringValue(connector.verification_endpoint),
    },
    connection_methods: compactLabels(connector.connection_methods, 8),
    setup_guidance: stringValue(connector.setup_guidance ?? connector.setup),
    digest: digest(value ?? {}),
  };
}

function compactCoverageAttestation(value: unknown): Record<string, unknown> {
  const coverage = recordValue(value) ?? {};
  const summary = recordValue(coverage.summary) ?? {};
  const gate = recordValue(coverage.gate ?? coverage.coverage_gate ?? summary.gate) ?? {};
  const dimensions = recordsFrom(coverage, "coverage", "dimensions", "items");
  return {
    dimension_count: dimensions.length,
    statuses: statusCounts(dimensions),
    gate: {
      status: stringValue(gate.status ?? gate.state ?? coverage.gate_status),
      reason: stringValue(gate.reason ?? gate.code ?? coverage.gate_reason),
    },
    healthy: optionalNumber(summary.healthy ?? summary.healthy_count),
    partial: optionalNumber(summary.partial ?? summary.partial_count),
    unconfigured: optionalNumber(summary.unconfigured ?? summary.unconfigured_count),
    digest: digest(value ?? {}),
  };
}

function statusCounts(rows: JsonRecord[]): Record<string, number> {
  const counts = new Map<string, number>();
  for (const row of rows) {
    const status = normalizedStatus(row.status ?? row.state ?? row.health ?? row.availability);
    counts.set(status, (counts.get(status) ?? 0) + 1);
  }
  return Object.fromEntries([...counts.entries()].sort(([left], [right]) => left.localeCompare(right)).slice(0, 20));
}

function compactLabels(value: unknown, limit: number): string[] {
  if (!Array.isArray(value)) return [];
  return unique(value.flatMap((item) => {
    if (typeof item === "string") return [item.trim()];
    const record = recordValue(item);
    const label = stringValue(record?.id ?? record?.name ?? record?.type ?? record?.method);
    return label ? [label] : [];
  }).filter(Boolean)).slice(0, limit);
}

function optionalNumber(value: unknown): number | undefined {
  const number = typeof value === "number" ? value : Number(value);
  return Number.isFinite(number) ? number : undefined;
}

function graphActionProposal(baseRequest: Record<string, unknown>, response: JsonRecord): Record<string, unknown> {
  const action = recordValue(response.action);
  return {
    action: stringValue(action?.action) ?? baseRequest.action,
    provider: stringValue(action?.provider),
    target: stringValue(action?.target) ?? baseRequest.target,
    finding_id: baseRequest.finding_id,
    reason: baseRequest.reason,
    idempotency_key: stringValue(action?.idempotency_key) ?? baseRequest.idempotency_key,
    status: normalizedStatus(action?.status ?? "dry_run"),
    reversible_by: baseRequest.action === "identity.okta.suspend_user"
      ? "identity.okta.unsuspend_user"
      : "identity.okta.suspend_user",
  };
}

function successfulGraphActionRef(finding: Finding | undefined): JsonRecord | undefined {
  return recordsFrom(finding?.external_refs).find((ref) => {
    const kind = normalizedStatus(ref.kind ?? ref.system);
    const status = normalizedStatus(ref.external_status ?? ref.status);
    return (kind.includes("graph_action") || kind.includes("graph-action") || kind === "access-approvals")
      && SUCCESS_ACTION_STATES.has(status);
  });
}

async function runStage(runtimeIDs: string[], run: (runtimeID: string) => Promise<JsonRecord>) {
  return Promise.all(runtimeIDs.map(async (runtimeID) => {
    const result = await settle(() => run(runtimeID));
    return { runtime_id: runtimeID, result: result.value, error: result.error };
  }));
}

function compactStageResult(row: { runtime_id: string; result?: JsonRecord; error?: string }) {
  return {
    runtime_id: row.runtime_id,
    ok: !row.error,
    receipt_digest: row.result ? digest(row.result) : undefined,
    status: stringValue(row.result?.status ?? recordValue(row.result?.result)?.status),
    error: row.error,
  };
}

async function settle<T>(run: () => Promise<T>): Promise<{ value?: T; error?: string }> {
  try {
    return { value: await run() };
  } catch (error) {
    return { error: shortError(error) };
  }
}

function recordsFrom(value: unknown, ...keys: string[]): JsonRecord[] {
  if (Array.isArray(value)) return value.filter(isRecord);
  const record = recordValue(value);
  if (!record) return [];
  for (const key of keys) {
    const candidate = record[key];
    if (Array.isArray(candidate)) return candidate.filter(isRecord);
  }
  return [];
}

function recordValue(value: unknown): JsonRecord | undefined {
  return isRecord(value) ? value : undefined;
}

function isRecord(value: unknown): value is JsonRecord {
  return Boolean(value) && typeof value === "object" && !Array.isArray(value);
}

function runtimeID(row: JsonRecord | RuntimeHealth): string {
  return stringValue(row.runtime_id ?? row.id) ?? "";
}

function explicitSourceID(row: JsonRecord): string | undefined {
  return stringValue(row.source_id ?? row.source ?? row.provider ?? row.id);
}

function providerForExplicitSource(value: unknown): OffboardingProvider | undefined {
  const normalized = String(value ?? "").trim().toLowerCase().replace(/[^a-z0-9]+/g, "-");
  const tokens = new Set(normalized.split("-").filter(Boolean));
  if (tokens.has("okta")) return "okta";
  if (tokens.has("github")) return "github";
  if (tokens.has("aws") || normalized.includes("amazon-web-services")) return "aws";
  return undefined;
}

function providerLabel(provider: OffboardingProvider): string {
  return provider === "aws" ? "AWS" : provider === "github" ? "GitHub" : "Okta";
}

function providerNextAction(provider: OffboardingProvider, sourceIDs: string[], states: RuntimeState[]): string {
  const label = providerLabel(provider);
  if (states.length === 0) {
    if (sourceIDs.length === 0) {
      return `Register an approved ${label} connector, configure one source runtime with non-secret credential references, complete one provider sync, then rerun cerebro_offboarding_preflight.`;
    }
    return `Configure one ${label} source runtime from connector ${sourceIDs.join(", ")}, validate its credential references, complete one provider sync, then rerun cerebro_offboarding_preflight.`;
  }
  const blocked = states.filter((row) => !row.provider_sync_validated).map((row) => row.runtime_id);
  return `Repair ${blocked.join(", ")} until each runtime has a recent completed provider sync and any reported contract probe passes, then rerun cerebro_offboarding_preflight.`;
}

function latestTimestamp(rows: JsonRecord[]): string | undefined {
  const values = rows.flatMap((row) => {
    const value = stringValue(row.last_activity_at ?? row.last_synced_at ?? row.updated_at ?? row.completed_at ?? row.finished_at ?? row.observed_at ?? row.created_at ?? row.started_at ?? row.timestamp);
    return value && Number.isFinite(Date.parse(value)) ? [value] : [];
  });
  return values.sort((left, right) => Date.parse(right) - Date.parse(left))[0];
}

function normalizedStatus(value: unknown): string {
  return String(value ?? "unknown").trim().toLowerCase().replace(/[^a-z0-9]+/g, "_");
}

function boundedStaleMinutes(value: number | undefined): number {
  return Number.isFinite(value) ? Math.max(1, Math.min(10_080, Math.floor(value!))) : 180;
}

function digest(value: unknown): string {
  return `sha256:${createHash("sha256").update(JSON.stringify(canonicalize(value))).digest("hex")}`;
}

function canonicalize(value: unknown): unknown {
  if (Array.isArray(value)) return value.map(canonicalize);
  if (!isRecord(value)) return value;
  return Object.fromEntries(Object.keys(value).sort().flatMap((key) => value[key] === undefined ? [] : [[key, canonicalize(value[key])]]));
}

function uniqueFindings(values: Finding[]): Finding[] {
  const seen = new Set<string>();
  return values.filter((finding) => {
    const key = finding.id ?? digest(finding);
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });
}

function rollbackFor(action: ActionArgs["action"], target: string): string {
  const reverse = action === "identity.okta.suspend_user" ? "identity.okta.unsuspend_user" : "identity.okta.suspend_user";
  return `Dry-run ${reverse} for exact target ${target}, obtain reviewed approval, execute with a new idempotency key, then recollect Okta, GitHub, and AWS evidence.`;
}

function unixTimestamp(value: unknown): string | undefined {
  const seconds = typeof value === "number" ? value : Number(value);
  return Number.isFinite(seconds) && seconds > 0 ? new Date(seconds * 1_000).toISOString() : undefined;
}
