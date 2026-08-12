import { createHash, randomUUID } from "node:crypto";
import { mkdir, readFile, readdir, rename, stat, unlink, writeFile } from "node:fs/promises";
import { dirname, join } from "node:path";
import {
  evaluateAssistantTurn,
  recordAnswerFeedback,
  type AnswerFeedbackCategoryV1,
  type AnswerFeedbackRecordV1,
  type AssistantTurnEvaluationV1,
} from "@writer/cerebro-slack-companion";
import {
  ASSISTANT_EXECUTION_LANES,
  AssistantTurnHostAdapter,
  type AssistantExecutionLane,
  type AssistantTurnHostTelemetryEvent,
  type AssistantTurnOutcomeAssessment,
  type AssistantTurnReceiptPort,
  type AssistantTurnTelemetryPort,
  type SlackMultipartProjection,
  type SlackStatusProjection,
} from "../assistant-turn.js";

export const OUTCOME_OBSERVATION_WINDOW_MS = 24 * 60 * 60 * 1_000;
export const OUTCOME_RETENTION_MS = 30 * 24 * 60 * 60 * 1_000;
export const TELEMETRY_RETENTION_MS = 7 * 24 * 60 * 60 * 1_000;
const MAX_TELEMETRY_RECEIPTS = 100_000;

export interface PendingAssistantOutcome {
  assessed_at?: string;
  delivered_message_ts: string;
  execution_lane: AssistantExecutionLane;
  feedback_categories?: AnswerFeedbackCategoryV1[];
  feedback_record_refs?: string[];
  latency_budget_ms: number;
  negative_feedback_count: number;
  opened_at: string;
  outcome_state: "blocked" | "completed" | "needs_user" | "owned" | "unknown";
  request_id: string;
  schema_version: "assistant-turn-pending-outcome/v1";
  user_correction_count: number;
  useful_answer_at?: string;
  verified: boolean;
}

export interface AssistantOutcomeStoreSummary {
  assessment_count: number;
  evaluation_count: number;
  feedback_count: number;
  pending_count: number;
}

export interface RecordAssistantFeedbackInput {
  actor_ref: string;
  answer_ref: string;
  category: AnswerFeedbackCategoryV1;
  delivered_message_ts: string;
  observed_at: string;
  tenant_ref: string;
  thread_ref: string;
}

export interface OutcomeStoreOptions {
  clock?: () => Date;
  log?: (event: AssistantTurnHostTelemetryEvent) => void;
}

export class FileOutcomeStore
  implements AssistantTurnReceiptPort, AssistantTurnTelemetryPort {
  private readonly clock: () => Date;
  private readonly log: (event: AssistantTurnHostTelemetryEvent) => void;
  private mutationQueue: Promise<void> = Promise.resolve();

  constructor(
    private readonly root: string,
    options: OutcomeStoreOptions = {},
  ) {
    this.clock = options.clock ?? (() => new Date());
    this.log = options.log ?? ((event) => {
      process.stdout.write(`${JSON.stringify({ component: "slack-outcomes", ...event })}\n`);
    });
  }

  async initialize(): Promise<void> {
    await Promise.all([
      mkdir(this.directory("pending"), { recursive: true }),
      mkdir(this.directory("assessments"), { recursive: true }),
      mkdir(this.directory("delivery"), { recursive: true }),
      mkdir(this.directory("evaluations"), { recursive: true }),
      mkdir(this.directory("feedback"), { recursive: true }),
      mkdir(this.directory("status"), { recursive: true }),
      mkdir(this.directory("telemetry"), { recursive: true }),
    ]);
  }

  async recordPending(outcome: PendingAssistantOutcome): Promise<void> {
    validatePending(outcome);
    await this.serialize(async () => {
      await this.atomicWrite(this.path("pending", outcome.request_id), outcome);
    });
  }

  async recordNegativeFeedback(deliveredMessageTs: string): Promise<boolean> {
    let recorded = false;
    await this.serialize(async () => {
      for (const file of await this.pendingFiles()) {
        const pending = await this.readPending(file);
        if (pending.delivered_message_ts !== deliveredMessageTs) continue;
        await this.atomicWrite(this.path("pending", pending.request_id), {
          ...pending,
          assessed_at: undefined,
          negative_feedback_count: pending.negative_feedback_count + 1,
        });
        recorded = true;
        return;
      }
    });
    return recorded;
  }

  async recordFeedback(
    input: RecordAssistantFeedbackInput,
  ): Promise<AnswerFeedbackRecordV1 | undefined> {
    validateFeedbackInput(input);
    let recorded: AnswerFeedbackRecordV1 | undefined;
    await this.serialize(async () => {
      for (const file of await this.pendingFiles()) {
        const pending = await this.readPending(file);
        if (pending.delivered_message_ts !== input.delivered_message_ts) continue;
        let feedback = await this.findFeedback({
          actor_ref: input.actor_ref,
          answer_ref: input.answer_ref,
          category: input.category,
          feedback_key: pending.request_id,
        });
        if (feedback === undefined) {
          feedback = recordAnswerFeedback({
            actor_ref: input.actor_ref,
            answer_ref: input.answer_ref,
            category: input.category,
            feedback_key: pending.request_id,
            observed_at: input.observed_at,
            request_ref: `assistant-request://sha256/${digest(pending.request_id)}`,
            tenant_ref: input.tenant_ref,
            thread_ref: input.thread_ref,
          });
          const feedbackPath = this.path("feedback", feedback.record_ref);
          try {
            const collision = JSON.parse(
              await readFile(feedbackPath, "utf8"),
            ) as AnswerFeedbackRecordV1;
            if (JSON.stringify(collision) !== JSON.stringify(feedback)) {
              throw new Error("Assistant feedback identity changed content.");
            }
            feedback = collision;
          } catch (error) {
            if (errorCode(error) !== "ENOENT") throw error;
            await this.atomicWrite(feedbackPath, feedback);
          }
        }
        recorded = feedback;
        if ((pending.feedback_record_refs ?? []).includes(feedback.record_ref)) {
          return;
        }
        const feedbackCategories = [
          ...new Set([...(pending.feedback_categories ?? []), input.category]),
        ];
        await this.atomicWrite(this.path("pending", pending.request_id), {
          ...pending,
          assessed_at: undefined,
          feedback_categories: feedbackCategories,
          feedback_record_refs: [
            ...(pending.feedback_record_refs ?? []),
            feedback.record_ref,
          ],
          negative_feedback_count: pending.negative_feedback_count
            + (input.category === "helpful" ? 0 : 1),
        });
        return;
      }
    });
    return recorded;
  }

  async summary(): Promise<AssistantOutcomeStoreSummary> {
    await this.initialize();
    const count = async (name: string): Promise<number> =>
      (await readdir(this.directory(name))).filter((file) => file.endsWith(".json")).length;
    const [assessmentCount, evaluationCount, feedbackCount, pendingFiles] =
      await Promise.all([
        count("assessments"),
        count("evaluations"),
        count("feedback"),
        this.pendingFiles(),
      ]);
    let pendingCount = 0;
    for (const file of pendingFiles) {
      if ((await this.readPending(file)).assessed_at === undefined) pendingCount += 1;
    }
    return {
      assessment_count: assessmentCount,
      evaluation_count: evaluationCount,
      feedback_count: feedbackCount,
      pending_count: pendingCount,
    };
  }

  async assessDue(host: AssistantTurnHostAdapter): Promise<number> {
    let assessed = 0;
    await this.initialize();
    await this.serialize(async () => {
      await this.pruneTelemetryReceipts();
      for (const file of await this.pendingFiles()) {
        const pending = await this.readPending(file);
        if (pending.assessed_at !== undefined) {
          if (this.clock().getTime() - Date.parse(pending.assessed_at) >= OUTCOME_RETENTION_MS) {
            await unlink(file);
          }
          continue;
        }
        const openedAt = Date.parse(pending.opened_at);
        if (this.clock().getTime() - openedAt < OUTCOME_OBSERVATION_WINDOW_MS) continue;
        const assessment = await host.recordOutcome({
          assessment_at: this.clock().toISOString(),
          evaluation_blockers: pending.verified ? [] : ["outcome_unknown"],
          execution_lane: pending.execution_lane,
          latency_budget_ms: pending.latency_budget_ms,
          negative_feedback_count: pending.negative_feedback_count,
          opened_at: pending.opened_at,
          outcome_state: pending.outcome_state,
          request_id: pending.request_id,
          request_kind: "human",
          user_correction_count: pending.user_correction_count,
          useful_answer_at: pending.useful_answer_at,
          verified: pending.verified,
        });
        const evaluation = productionEvaluation(pending, assessment.outcome_state);
        await this.atomicWrite(
          this.path("evaluations", `${pending.request_id}:production`),
          evaluation,
        );
        await this.atomicWrite(this.path("pending", pending.request_id), {
          ...pending,
          assessed_at: this.clock().toISOString(),
        });
        assessed += 1;
      }
    });
    return assessed;
  }

  async persistOutcome(
    assessment: AssistantTurnOutcomeAssessment,
  ): Promise<{ receipt_ref: string }> {
    await this.atomicWrite(
      this.path("assessments", assessment.assessment_digest),
      assessment,
    );
    return { receipt_ref: `receipt://assistant-outcome/${digest(assessment.assessment_digest)}` };
  }

  async persistMultipartDelivery(
    projection: SlackMultipartProjection,
  ): Promise<{ receipt_ref: string }> {
    await this.atomicWrite(this.path("delivery", projection.projection_id), projection);
    return { receipt_ref: `receipt://slack-delivery/${digest(projection.projection_id)}` };
  }

  async persistStatus(
    projection: SlackStatusProjection,
  ): Promise<{ receipt_ref: string }> {
    await this.atomicWrite(this.path("status", projection.projection_id), projection);
    return { receipt_ref: `receipt://slack-status/${digest(projection.projection_id)}` };
  }

  async recordIdempotent(event: AssistantTurnHostTelemetryEvent): Promise<void> {
    await this.initialize();
    try {
      await writeFile(this.path("telemetry", event.event_id), `${JSON.stringify(event)}\n`, {
        encoding: "utf8",
        flag: "wx",
        mode: 0o600,
      });
    } catch (error) {
      if (errorCode(error) === "EEXIST") return;
      throw error;
    }
    this.log(event);
  }

  private async pendingFiles(): Promise<string[]> {
    await this.initialize();
    return (await readdir(this.directory("pending")))
      .filter((file) => file.endsWith(".json"))
      .sort()
      .map((file) => join(this.directory("pending"), file));
  }

  private async readPending(file: string): Promise<PendingAssistantOutcome> {
    const decoded: unknown = JSON.parse(await readFile(file, "utf8"));
    validatePending(decoded);
    return decoded;
  }

  private async findFeedback(
    identity: Pick<
      AnswerFeedbackRecordV1,
      "actor_ref" | "answer_ref" | "category" | "feedback_key"
    >,
  ): Promise<AnswerFeedbackRecordV1 | undefined> {
    for (const file of (await readdir(this.directory("feedback"))).sort()) {
      if (!file.endsWith(".json")) continue;
      const decoded = JSON.parse(
        await readFile(join(this.directory("feedback"), file), "utf8"),
      ) as AnswerFeedbackRecordV1;
      if (
        decoded.actor_ref === identity.actor_ref
        && decoded.answer_ref === identity.answer_ref
        && decoded.category === identity.category
        && decoded.feedback_key === identity.feedback_key
      ) return decoded;
    }
    return undefined;
  }

  private async atomicWrite(path: string, value: unknown): Promise<void> {
    await mkdir(dirname(path), { recursive: true });
    const temporary = `${path}.${randomUUID()}.tmp`;
    await writeFile(temporary, `${JSON.stringify(value)}\n`, { encoding: "utf8", mode: 0o600 });
    await rename(temporary, path);
  }

  private async pruneTelemetryReceipts(): Promise<void> {
    const directory = this.directory("telemetry");
    const receipts = await Promise.all(
      (await readdir(directory))
        .filter((file) => file.endsWith(".json"))
        .map(async (file) => {
          const path = join(directory, file);
          return { path, modifiedAt: (await stat(path)).mtimeMs };
        }),
    );
    receipts.sort((left, right) => right.modifiedAt - left.modifiedAt);
    const cutoff = this.clock().getTime() - TELEMETRY_RETENTION_MS;
    const expired = receipts.filter((receipt) => receipt.modifiedAt < cutoff);
    const retained = receipts.filter((receipt) => receipt.modifiedAt >= cutoff);
    const overLimit = retained.slice(MAX_TELEMETRY_RECEIPTS);
    await Promise.all([...expired, ...overLimit].map(async ({ path }) => {
      await unlink(path).catch((error: unknown) => {
        if (errorCode(error) !== "ENOENT") throw error;
      });
    }));
  }

  private directory(name: string): string {
    return join(this.root, name);
  }

  private path(directory: string, key: string): string {
    return join(this.directory(directory), `${digest(key)}.json`);
  }

  private async serialize<T>(operation: () => Promise<T>): Promise<T> {
    const prior = this.mutationQueue;
    let release!: () => void;
    this.mutationQueue = new Promise<void>((resolve) => {
      release = resolve;
    });
    await prior;
    try {
      return await operation();
    } finally {
      release();
    }
  }
}

function productionEvaluation(
  pending: PendingAssistantOutcome,
  outcomeState: PendingAssistantOutcome["outcome_state"],
): AssistantTurnEvaluationV1 {
  const evaluatedOutcomeState = pending.verified ? outcomeState : "unknown";
  const feedbackCategory = preferredFeedbackCategory(
    pending.feedback_categories ?? [],
  );
  const observation = {
    delivered_message_ts: pending.delivered_message_ts,
    feedback_categories: pending.feedback_categories ?? [],
    outcome_state: evaluatedOutcomeState,
    request_id: pending.request_id,
    verified: pending.verified,
  };
  const latency = pending.useful_answer_at === undefined
    ? pending.latency_budget_ms + 1
    : Math.max(0, Date.parse(pending.useful_answer_at) - Date.parse(pending.opened_at));
  return evaluateAssistantTurn({
    // This host observes delivery, latency, outcome, verification, and feedback.
    // It does not infer claim, source, capability, or tool counts from the lane.
    case_digest: `sha256:${digest(pending.request_id)}`,
    case_ref: `assistant-case://sha256/${digest(pending.request_id)}`,
    claim_count: 0,
    coverage_boundary_disclosed: false,
    coverage_boundary_required: false,
    delivery: {
      complete: true,
      disposition: "respond",
      planned_part_count: 1,
      posted_part_count: 1,
    },
    delivered_action_count: 0,
    disclosed_source_failure_count: 0,
    evaluator_ref: "evaluator://assistant-turn/production-outcome-feedback-v1",
    execution_lane: pending.execution_lane,
    ...(feedbackCategory === undefined
      ? pending.negative_feedback_count > 0
        ? { explicit_feedback: "negative" as const }
        : {}
      : {
          explicit_feedback: feedbackCategory === "helpful" ? "positive" as const : "negative" as const,
          explicit_feedback_category: feedbackCategory,
        }),
    grounded_claim_count: 0,
    internal_machinery_exposure_count: 0,
    latency_ms: latency,
    observation_digest: `sha256:${digest(JSON.stringify(observation))}`,
    observation_ref: `assistant-observation://sha256/${digest(JSON.stringify(observation))}`,
    outcome_state: evaluatedOutcomeState,
    partition: "train",
    policy_ref: "policy://slack-companion/deployed-outcome-feedback",
    redundant_tool_call_count: 0,
    relevant_evidence_source_count: 0,
    required_action_count: 0,
    requires_evidence: false,
    response_expected: true,
    selected_capability_count: 0,
    source_failure_count: 0,
    subject_bound_claim_count: 0,
    tool_call_count: 0,
    unnecessary_clarification_count: 0,
    used_evidence_source_count: 0,
    user_correction: pending.user_correction_count > 0,
  });
}

function preferredFeedbackCategory(
  categories: readonly AnswerFeedbackCategoryV1[],
): AnswerFeedbackCategoryV1 | undefined {
  for (const category of [
    "missed_source",
    "wrong_owner",
    "needs_followup",
    "helpful",
  ] as const) {
    if (categories.includes(category)) return category;
  }
  return undefined;
}

function validatePending(value: unknown): asserts value is PendingAssistantOutcome {
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    throw new Error("Pending assistant outcome is invalid.");
  }
  const pending = value as Partial<PendingAssistantOutcome>;
  if (
    pending.schema_version !== "assistant-turn-pending-outcome/v1"
    || (pending.assessed_at !== undefined
      && (typeof pending.assessed_at !== "string"
        || !Number.isFinite(Date.parse(pending.assessed_at))))
    || typeof pending.request_id !== "string"
    || pending.request_id.length === 0
    || typeof pending.delivered_message_ts !== "string"
    || !ASSISTANT_EXECUTION_LANES.includes(pending.execution_lane as AssistantExecutionLane)
    || !Number.isSafeInteger(pending.latency_budget_ms)
    || !Number.isSafeInteger(pending.negative_feedback_count)
    || !Number.isSafeInteger(pending.user_correction_count)
    || typeof pending.opened_at !== "string"
    || !Number.isFinite(Date.parse(pending.opened_at))
    || typeof pending.verified !== "boolean"
    || (pending.feedback_categories !== undefined
      && (!Array.isArray(pending.feedback_categories)
        || new Set(pending.feedback_categories).size !== pending.feedback_categories.length
        || pending.feedback_categories.some((category) =>
          !["helpful", "missed_source", "wrong_owner", "needs_followup"].includes(category))))
    || (pending.feedback_record_refs !== undefined
      && (!Array.isArray(pending.feedback_record_refs)
        || new Set(pending.feedback_record_refs).size !== pending.feedback_record_refs.length
        || pending.feedback_record_refs.some((reference) =>
          typeof reference !== "string"
          || !/^feedback:\/\/answer\/[a-f0-9]{64}$/u.test(reference))))
  ) {
    throw new Error("Pending assistant outcome is invalid.");
  }
}

function validateFeedbackInput(input: RecordAssistantFeedbackInput): void {
  if (
    !["helpful", "missed_source", "wrong_owner", "needs_followup"].includes(input.category)
    || !input.delivered_message_ts.trim()
    || !Number.isFinite(Date.parse(input.observed_at))
  ) {
    throw new Error("Assistant feedback input is invalid.");
  }
  for (const value of [
    input.actor_ref,
    input.answer_ref,
    input.tenant_ref,
    input.thread_ref,
  ]) {
    if (!/^[a-z][a-z0-9+.-]*:\/\/\S+$/u.test(value)) {
      throw new Error("Assistant feedback references are invalid.");
    }
  }
}

function digest(value: string): string {
  return createHash("sha256").update(value, "utf8").digest("hex");
}

function errorCode(value: unknown): string | undefined {
  return value !== null && typeof value === "object" && "code" in value
    ? String((value as { code?: unknown }).code)
    : undefined;
}
