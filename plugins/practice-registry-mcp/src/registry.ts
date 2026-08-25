import path from "node:path";
import { validateResearchApprovalSources } from "./approval.js";
import { getGuardrails } from "./guardrails.js";
import { normalizeRepoPath } from "./filePaths.js";
import { loadPractices } from "./loader.js";
import { checkPractices, searchPractices } from "./matcher.js";
import { isPassingDecision, outcomeForDecision } from "./outcome.js";
import { defaultPracticesRoot } from "./paths.js";
import { parseAddedLines, scanDiff } from "./scan.js";
import { writeSemgrepConfig } from "./semgrepRules.js";
import type {
  PracticeCheckInput,
  PracticeCheckResult,
  PracticeApprovalInput,
  PracticeApprovalResult,
  PracticeExceptionInput,
  PracticeExceptionResult,
  PracticeFinalizeInput,
  PracticeFinalizeResult,
  PracticeGuardrailInput,
  PracticeGuardrailResult,
  PracticeMatch,
  PracticeObservation,
  PracticeObservationDetail,
  PracticeObservationStats,
  PracticePlanCheckReference,
  PracticePreflightInput,
  PracticePreflightResult,
  PracticeProposalInput,
  PracticeProposalResult,
  PracticeRecord,
  PracticeReviewQueueItem,
  PracticeReviewQueueResult,
  PracticeScanResult,
} from "./schema.js";
import { PracticeStore } from "./store.js";

export type RegistryOptions = {
  practicesRoot?: string;
  dbPath?: string;
  semgrepBin?: string;
  semgrepRulesPath?: string;
};

export class PracticeRegistry {
  private readonly practicesRoot: string;
  private readonly semgrepBin: string;
  private readonly semgrepRulesPath: string | undefined;
  private readonly store: PracticeStore;

  constructor(options: RegistryOptions = {}) {
    this.practicesRoot = path.resolve(options.practicesRoot ?? defaultPracticesRoot());
    this.semgrepBin = options.semgrepBin ?? "semgrep";
    this.semgrepRulesPath = options.semgrepRulesPath;
    const dbPath = path.resolve(options.dbPath ?? ".practice-registry/practices.db");
    this.store = new PracticeStore(dbPath);
  }

  rebuild(): PracticeRecord[] {
    const records = loadPractices(this.practicesRoot);
    this.store.replacePractices(records);
    return records;
  }

  all(): PracticeRecord[] {
    const indexed = this.store.allPractices();
    return indexed.length > 0 ? indexed : this.rebuild();
  }

  explain(id: string): PracticeRecord | undefined {
    this.all();
    return this.store.getPractice(id);
  }

  search(query: string, filters = {}): PracticeMatch[] {
    const result = searchPractices(this.all(), query, filters);
    this.store.recordObservation("search", { query, ...filters }, { matched_practices: result });
    return result;
  }

  check(kind: "plan" | "diff", input: PracticeCheckInput): PracticeCheckResult {
    const result = checkPractices(this.all(), input);
    const observationId = this.store.recordObservation(kind, input, result);
    return { ...result, observation_id: observationId };
  }

  getGuardrails(input: PracticeGuardrailInput = {}): PracticeGuardrailResult {
    const result = getGuardrails(this.all(), input);
    this.store.recordObservation("guardrails", input, result);
    return result;
  }

  preflight(input: PracticePreflightInput = {}): PracticePreflightResult {
    const guardrails = getGuardrails(this.all(), input);
    const hasPlan = Boolean(input.planned_approach || input.proposed_code);
    const planCheck = hasPlan
      ? checkPractices(this.all(), {
          ...input,
          intent: input.intent ?? input.topic,
        })
      : null;
    const decision = planCheck?.decision ?? (guardrails.practices.length > 0 ? "follow_guidance" : "needs_review");
    const outcome = outcomeForDecision(decision);
    const result: PracticePreflightResult = {
      decision,
      blocking: planCheck?.blocking ?? false,
      ...outcome,
      summary: preflightSummary({ decision, guardrails, planCheck }),
      next_steps: preflightNextSteps({ decision, guardrails, planCheck }),
      required_calls: hasPlan ? ["check_plan", "finalize_change"] : ["check_plan", "finalize_change"],
      guardrails,
      plan_check: planCheck,
    };
    const observationId = this.store.recordObservation("preflight", input, result);
    return { ...result, observation_id: observationId };
  }

  scanDiff(diff: string, options: { cwd?: string; rulesPath?: string; semgrepBin?: string; useSemgrep?: boolean } = {}): PracticeScanResult {
    const result = scanDiff(this.all(), diff, {
      ...options,
      rulesPath: options.rulesPath ?? this.semgrepRulesPath,
      semgrepBin: options.semgrepBin ?? this.semgrepBin,
    });
    const observationId = this.store.recordObservation("scan-diff", { diff }, result);
    return { ...result, observation_id: observationId };
  }

  finalizeChange(input: PracticeFinalizeInput, options: { cwd?: string } = {}): PracticeFinalizeResult {
    const requiredPlanCheck = input.require_plan_check !== false;
    const cwd = path.resolve(options.cwd ?? process.cwd());
    const finalContext = finalContextFor(input, cwd);
    const planCheck = requiredPlanCheck
      ? this.findPlanCheck({
          providedObservationId: input.plan_observation_id,
          finalFiles: finalContext.files,
          finalLanguage: finalContext.language,
        })
      : skippedPlanCheck(input.plan_observation_id, finalContext);
    const passingPlanFound = planCheck.passed;
    const scan = this.scanDiff(input.diff, {
      cwd,
      rulesPath: input.rules_path,
      useSemgrep: input.use_semgrep,
    });
    const missingPlan = requiredPlanCheck && !passingPlanFound;
    const decision = missingPlan && isPassingDecision(scan.decision) ? "needs_review" : scan.decision;
    const outcome = outcomeForDecision(decision);
    const nextSteps = finalizeNextSteps({
      missingPlan,
      scanPassed: scan.passed,
      scanNextSteps: scan.next_steps,
      passed: outcome.passed,
    });
    const result: PracticeFinalizeResult = {
      decision,
      blocking: scan.blocking,
      ...outcome,
      summary: finalizeSummary({ missingPlan, scanPassed: scan.passed, scanSummary: scan.summary, passed: outcome.passed }),
      next_steps: nextSteps,
      scan_diff: scan,
      observations: {
        required_plan_check: requiredPlanCheck,
        passing_plan_found: passingPlanFound,
        plan_check: planCheck,
        recent: this.store.recentObservations({ limit: 10 }),
        stats: this.store.observationStats(100),
      },
    };
    const observationId = this.store.recordObservation("finalize", input, result);
    return { ...result, observation_id: observationId };
  }

  recentObservations(options: { kind?: string; limit?: number; actionRequiredOnly?: boolean } = {}): PracticeObservation[] {
    return this.store.recentObservations(options);
  }

  observationStats(limit = 100): PracticeObservationStats {
    return this.store.observationStats(limit);
  }

  proposePractice(input: PracticeProposalInput): PracticeProposalResult {
    const owner = input.owner?.trim() || "practice-owners";
    const result: PracticeProposalResult = {
      decision: "needs_review",
      blocking: false,
      ...outcomeForDecision("needs_review"),
      summary: `Practice proposal recorded for ${owner}: ${input.title}.`,
      next_steps: [
        `Ask ${owner} to accept, revise, or reject this proposal.`,
        "Add or update a practice record when the decision should be reused.",
        "Add eval coverage if the proposal becomes blocking or fixes a false positive.",
      ],
      proposal: {
        title: input.title,
        owner,
        language: normalizeTerm(input.language) ?? null,
        framework: normalizeTerm(input.framework) ?? null,
        files: normalizeFiles(input.files ?? []),
        suggested_status: input.suggested_status ?? "needs_review",
        suggested_enforcement: input.suggested_enforcement ?? "review",
        evidence: input.evidence?.trim() || null,
      },
    };
    const observationId = this.store.recordObservation("practice-proposal", input, result);
    return { ...result, observation_id: observationId };
  }

  recordException(input: PracticeExceptionInput): PracticeExceptionResult {
    const practice = this.explain(input.practice_id);
    const owner = input.owner?.trim() || practice?.owner || "practice-owners";
    const result: PracticeExceptionResult = {
      decision: "needs_review",
      blocking: false,
      ...outcomeForDecision("needs_review"),
      summary: `Exception request recorded for ${input.practice_id}.`,
      next_steps: [
        `Ask ${owner} to approve, reject, or replace this exception.`,
        "Keep the exception scoped to the recorded files and context.",
        "Add an expiry date before treating the exception as accepted.",
      ],
      exception: {
        practice_id: input.practice_id,
        owner,
        accepted_context: input.accepted_context,
        expires_at: input.expires_at?.trim() || null,
        files: normalizeFiles(input.files ?? []),
        evidence: input.evidence?.trim() || null,
        replacement_plan: input.replacement_plan?.trim() || null,
      },
    };
    const observationId = this.store.recordObservation("practice-exception", input, result);
    return { ...result, observation_id: observationId };
  }

  recordApproval(input: PracticeApprovalInput): PracticeApprovalResult {
    const practice = this.explain(input.practice_id);
    const sources = input.sources ?? [];
    const relatedObservationIDs = [...new Set(input.related_observation_ids ?? [])]
      .filter((id) => Number.isInteger(id) && id > 0)
      .sort((left, right) => left - right);
    let decision: PracticeApprovalResult["decision"] = "allowed";
    const nextSteps: string[] = [];

    if (!practice) {
      decision = "needs_review";
      nextSteps.push("Add the approved practice record before resolving review observations.");
    } else if (input.method === "owner" && input.approved_by.trim() !== practice.owner) {
      decision = "ask_owner";
      nextSteps.push(`Ask ${practice.owner} to record the owner approval.`);
    } else if (input.method === "research") {
      const validation = validateResearchApprovalSources(sources);
      if (!validation.valid) {
        decision = "needs_review";
        nextSteps.push(...validation.errors);
      }
    }

    if (decision === "allowed") {
      nextSteps.push("Rebuild the registry and rerun the plan that previously needed review.");
    }
    const result: PracticeApprovalResult = {
      decision,
      blocking: false,
      ...outcomeForDecision(decision),
      summary:
        decision === "allowed"
          ? `Approval recorded for ${input.practice_id} by ${input.approved_by.trim()}.`
          : `Approval for ${input.practice_id} still needs action.`,
      next_steps: nextSteps,
      approval: {
        practice_id: input.practice_id,
        owner: practice?.owner ?? null,
        method: input.method,
        approved_by: input.approved_by.trim(),
        conclusion: input.conclusion.trim(),
        related_observation_ids: relatedObservationIDs,
        sources,
      },
    };
    const observationId = this.store.recordObservation("practice-approval", input, result);
    return { ...result, observation_id: observationId };
  }

  reviewQueue(options: { limit?: number; record?: boolean } = {}): PracticeReviewQueueResult {
    const limit = Math.max(1, Math.min(options.limit ?? 25, 100));
    const details = this.store.recentObservationDetails({ limit: 200 });
    const items = buildReviewQueue(details).slice(0, limit);
    const stats = {
      total: items.length,
      needs_review: items.filter((item) => item.kind === "needs_review_observation").length,
      proposals: items.filter((item) => item.kind === "practice_proposal").length,
      exceptions: items.filter((item) => item.kind === "practice_exception").length,
      owner_decisions: items.filter((item) => item.kind === "owner_decision").length,
    };
    const decision = items.length > 0 ? "needs_review" : "allowed";
    const result: PracticeReviewQueueResult = {
      decision,
      blocking: false,
      ...outcomeForDecision(decision),
      summary: items.length > 0 ? `${items.length} practice review items need owner follow-up.` : "No practice review items need owner follow-up.",
      next_steps:
        items.length > 0
          ? [
              "Start with the oldest repeated item or an exception without an expiry date.",
              "Convert repeated needs_review items into practice records or accepted contexts.",
              "Record owner decisions by updating practice records and rerunning the relevant evals.",
            ]
          : ["Continue. The review queue is empty."],
      stats,
      items,
    };
    if (options.record === false) {
      return result;
    }
    const observationId = this.store.recordObservation("review-queue", options, result);
    return { ...result, observation_id: observationId };
  }

  writeSemgrepConfig(outputPath: string): { rules: unknown[] } {
    const result = writeSemgrepConfig(this.all(), outputPath);
    return { rules: result.rules };
  }

  close(): void {
    this.store.close();
  }

  private findPlanCheck(input: {
    providedObservationId?: number;
    finalFiles: string[];
    finalLanguage?: string;
  }): PracticePlanCheckReference {
    if (input.providedObservationId !== undefined) {
      const observation = this.store.getObservationDetail(input.providedObservationId);
      return planReferenceFromObservation(observation, {
        providedObservationId: input.providedObservationId,
        matchType: "provided",
        finalFiles: input.finalFiles,
        finalLanguage: input.finalLanguage,
      });
    }

    for (const observation of this.store.recentObservationDetails({ kind: "plan", limit: 25 })) {
      const reference = planReferenceFromObservation(observation, {
        providedObservationId: undefined,
        matchType: "recent_context",
        finalFiles: input.finalFiles,
        finalLanguage: input.finalLanguage,
      });
      if (reference.passed) {
        return reference;
      }
    }

    return missingPlanReference({
      providedObservationId: null,
      finalFiles: input.finalFiles,
      finalLanguage: input.finalLanguage,
      reason: "No recent passing check_plan matched the final diff files or language.",
    });
  }
}

function preflightSummary(input: {
  decision: string;
  guardrails: PracticeGuardrailResult;
  planCheck: PracticeCheckResult | null;
}): string {
  if (input.planCheck) {
    return `Preflight checked the plan. ${input.planCheck.summary}`;
  }
  if (input.guardrails.practices.length === 0) {
    return "No matching practice records were found before coding.";
  }
  return `${input.guardrails.practices.length} practice records should shape the implementation before coding.`;
}

function preflightNextSteps(input: {
  decision: string;
  guardrails: PracticeGuardrailResult;
  planCheck: PracticeCheckResult | null;
}): string[] {
  if (input.planCheck && !input.planCheck.passed) {
    return input.planCheck.next_steps;
  }
  if (input.guardrails.practices.length === 0) {
    return [
      "Ask the owning team for a practice decision before treating the approach as approved.",
      "Submit a practice proposal if this pattern should be reused.",
      "Call check_plan after the implementation approach is explicit.",
    ];
  }
  return [
    "Review the matched practices before editing.",
    "Call check_plan with the concrete implementation approach before writing code.",
    "Run finalize_change on the final diff before the final response.",
  ];
}

function buildReviewQueue(observations: PracticeObservationDetail[]): PracticeReviewQueueItem[] {
  const grouped = new Map<string, PracticeReviewQueueItem>();
  const resolvedObservationIDs = new Set(
    observations
      .filter((observation) => observation.kind === "practice-approval" && observation.passed)
      .flatMap((observation) => readNumberArray(readRecord(observation.result.approval).related_observation_ids)),
  );
  for (const observation of observations) {
    if (
      observation.kind === "practice-approval" ||
      observation.kind === "review-queue" ||
      resolvedObservationIDs.has(observation.id)
    ) {
      continue;
    }
    const item = reviewItemFromObservation(observation);
    if (!item) {
      continue;
    }
    const existing = grouped.get(item.key);
    if (existing) {
      existing.count += 1;
      existing.observation_ids.push(...item.observation_ids);
      if (item.latest_observation_id > existing.latest_observation_id) {
        existing.latest_observation_id = item.latest_observation_id;
        existing.created_at = item.created_at;
      }
    } else {
      grouped.set(item.key, item);
    }
  }
  return [...grouped.values()].sort(
    (left, right) => right.count - left.count || right.latest_observation_id - left.latest_observation_id,
  );
}

function reviewItemFromObservation(observation: PracticeObservationDetail): PracticeReviewQueueItem | undefined {
  if (observation.kind === "practice-proposal") {
    const proposal = readRecord(observation.result.proposal);
    const title = readString(proposal.title) ?? "Practice proposal";
    return {
      key: `proposal:${title}:${readString(proposal.language) ?? ""}:${readString(proposal.framework) ?? ""}`,
      kind: "practice_proposal",
      title,
      summary: observation.summary ?? title,
      owner: readString(proposal.owner) ?? null,
      practice_ids: observation.practice_ids,
      files: readStringArray(proposal.files),
      language: readString(proposal.language) ?? null,
      count: 1,
      latest_observation_id: observation.id,
      observation_ids: [observation.id],
      created_at: observation.created_at,
      evidence: readString(proposal.evidence) ?? null,
      expires_at: null,
      next_step: "Review the proposed practice and add a YAML record if accepted.",
    };
  }

  if (observation.kind === "practice-exception") {
    const exception = readRecord(observation.result.exception);
    const practiceId = readString(exception.practice_id) ?? observation.practice_ids[0] ?? "unknown";
    return {
      key: `exception:${practiceId}:${readString(exception.accepted_context) ?? ""}`,
      kind: "practice_exception",
      title: `Exception request for ${practiceId}`,
      summary: observation.summary ?? `Exception request for ${practiceId}.`,
      owner: readString(exception.owner) ?? null,
      practice_ids: [practiceId],
      files: readStringArray(exception.files),
      language: readString(observation.input.language) ?? null,
      count: 1,
      latest_observation_id: observation.id,
      observation_ids: [observation.id],
      created_at: observation.created_at,
      evidence: readString(exception.evidence) ?? null,
      expires_at: readString(exception.expires_at) ?? null,
      next_step: readString(exception.expires_at)
        ? "Review the exception request and record the owner decision."
        : "Add an expiry date before approving this exception.",
    };
  }

  if (observation.decision === "needs_review" || observation.decision === "ask_owner") {
    const summary = observation.summary ?? "Owner decision needed.";
    return {
      key: `decision:${observation.decision}:${summary}:${observation.practice_ids.join(",")}`,
      kind: observation.decision === "needs_review" ? "needs_review_observation" : "owner_decision",
      title: observation.decision === "needs_review" ? "Practice gap" : "Owner decision",
      summary,
      owner: null,
      practice_ids: observation.practice_ids,
      files: readStringArray(observation.input.files),
      language: readString(observation.input.language) ?? null,
      count: 1,
      latest_observation_id: observation.id,
      observation_ids: [observation.id],
      created_at: observation.created_at,
      evidence: null,
      expires_at: null,
      next_step:
        observation.decision === "needs_review"
          ? "Add a practice record, record an exception, or ask the owner for a reusable decision."
          : "Ask the practice owner for a decision before continuing.",
    };
  }

  return undefined;
}

function finalizeSummary(input: { missingPlan: boolean; scanPassed: boolean; scanSummary: string; passed: boolean }): string {
  if (!input.scanPassed) {
    return input.scanSummary;
  }
  if (input.missingPlan) {
    return "No matching passing check_plan observation was found for this final diff. Run check_plan for this change before finalizing generated code.";
  }
  if (input.passed) {
    return "Final practice gate passed. The final diff has no required Practice Registry follow-up.";
  }
  return input.scanSummary;
}

function finalizeNextSteps(input: { missingPlan: boolean; scanPassed: boolean; scanNextSteps: string[]; passed: boolean }): string[] {
  if (!input.scanPassed) {
    return input.scanNextSteps;
  }
  if (input.missingPlan) {
    return [
      "Call check_plan with the implementation approach for the same files or language as the final diff.",
      "Apply any next_steps from check_plan.",
      "Rerun finalize_change before the final response.",
    ];
  }
  if (input.passed) {
    return ["Continue with the final response and cite any practice ids that shaped the implementation."];
  }
  return input.scanNextSteps;
}

function finalContextFor(input: PracticeFinalizeInput, cwd: string): { files: string[]; language?: string } {
  const explicitFiles = normalizeFiles(input.files ?? [], cwd);
  const diffFiles = [...new Set(parseAddedLines(input.diff, cwd).map((line) => line.path))];
  const files = explicitFiles.length > 0 ? explicitFiles : diffFiles;
  return {
    files,
    language: normalizeTerm(input.language) ?? inferLanguageFromFiles(files),
  };
}

function planReferenceFromObservation(
  observation: PracticeObservationDetail | undefined,
  input: {
    providedObservationId?: number;
    matchType: "provided" | "recent_context";
    finalFiles: string[];
    finalLanguage?: string;
  },
): PracticePlanCheckReference {
  if (!observation) {
    return missingPlanReference({
      providedObservationId: input.providedObservationId ?? null,
      finalFiles: input.finalFiles,
      finalLanguage: input.finalLanguage,
      reason: input.providedObservationId ? `Observation ${input.providedObservationId} was not found.` : "No plan observation was found.",
    });
  }
  const planContext = planContextFor(observation);
  const match = contextMatchesPlan({
    finalFiles: input.finalFiles,
    finalLanguage: input.finalLanguage,
    planFiles: planContext.files,
    planLanguage: planContext.language,
  });
  const passed = observation.kind === "plan" && observation.passed && match.matches;
  const reason =
    observation.kind !== "plan"
      ? `Observation ${observation.id} is ${observation.kind}, not check_plan.`
      : !observation.passed
        ? `Observation ${observation.id} did not pass.`
        : match.reason;
  return {
    required: true,
    provided_observation_id: input.providedObservationId ?? null,
    matched_observation_id: passed ? observation.id : null,
    match_type: passed ? input.matchType : "missing",
    passed,
    reason,
    final_files: input.finalFiles,
    final_language: input.finalLanguage ?? null,
    plan_files: planContext.files,
    plan_language: planContext.language ?? null,
  };
}

function skippedPlanCheck(providedObservationId: number | undefined, finalContext: { files: string[]; language?: string }): PracticePlanCheckReference {
  return {
    required: false,
    provided_observation_id: providedObservationId ?? null,
    matched_observation_id: null,
    match_type: "missing",
    passed: true,
    reason: "Plan check requirement was disabled for this finalization.",
    final_files: finalContext.files,
    final_language: finalContext.language ?? null,
    plan_files: [],
    plan_language: null,
  };
}

function missingPlanReference(input: {
  providedObservationId: number | null;
  finalFiles: string[];
  finalLanguage?: string;
  reason: string;
}): PracticePlanCheckReference {
  return {
    required: true,
    provided_observation_id: input.providedObservationId,
    matched_observation_id: null,
    match_type: "missing",
    passed: false,
    reason: input.reason,
    final_files: input.finalFiles,
    final_language: input.finalLanguage ?? null,
    plan_files: [],
    plan_language: null,
  };
}

function planContextFor(observation: PracticeObservationDetail): { files: string[]; language?: string } {
  const files = normalizeFiles(readStringArray(observation.input.files));
  return {
    files,
    language: normalizeTerm(readString(observation.input.language)) ?? inferLanguageFromFiles(files),
  };
}

function contextMatchesPlan(input: {
  finalFiles: string[];
  finalLanguage?: string;
  planFiles: string[];
  planLanguage?: string;
}): { matches: boolean; reason: string } {
  if (input.finalFiles.length > 0 && input.planFiles.length > 0) {
    const overlap = input.finalFiles.filter((file) => input.planFiles.includes(file));
    if (overlap.length > 0) {
      return { matches: true, reason: `Plan files match final diff: ${overlap.slice(0, 3).join(", ")}.` };
    }
    return { matches: false, reason: "Plan files do not overlap the final diff files." };
  }
  if (input.finalLanguage && input.planLanguage) {
    if (input.finalLanguage === input.planLanguage) {
      return { matches: true, reason: `Plan language matches final diff: ${input.finalLanguage}.` };
    }
    return { matches: false, reason: `Plan language ${input.planLanguage} does not match final diff language ${input.finalLanguage}.` };
  }
  return {
    matches: false,
    reason: "Finalization needs matching files or language to link this plan to the final diff.",
  };
}

function readString(value: unknown): string | undefined {
  return typeof value === "string" ? value : undefined;
}

function readRecord(value: unknown): Record<string, unknown> {
  return value && typeof value === "object" && !Array.isArray(value) ? (value as Record<string, unknown>) : {};
}

function readStringArray(value: unknown): string[] {
  return Array.isArray(value) ? value.filter((item): item is string => typeof item === "string") : [];
}

function readNumberArray(value: unknown): number[] {
  return Array.isArray(value) ? value.filter((item): item is number => typeof item === "number" && Number.isInteger(item)) : [];
}

function normalizeFiles(files: string[], cwd = process.cwd()): string[] {
  return files.map((file) => normalizeRepoPath(file, cwd)).filter(Boolean);
}

function normalizeTerm(value: string | undefined): string | undefined {
  return value?.trim().toLowerCase() || undefined;
}

function inferLanguageFromFiles(files: string[]): string | undefined {
  const values: Array<string | undefined> = files.map((file) => {
    if (file.endsWith("Cargo.toml") || file.endsWith("Cargo.lock")) return "rust";
    if (file.endsWith(".py")) return "python";
    if (file.endsWith(".scala") || file.endsWith(".sc")) return "scala";
    if (file.endsWith(".ts") || file.endsWith(".tsx")) return "typescript";
    if (file.endsWith(".js") || file.endsWith(".jsx") || file.endsWith(".mjs") || file.endsWith(".cjs")) return "javascript";
    if (file.endsWith(".rs")) return "rust";
    return undefined;
  });
  const languages = new Set<string>(values.filter((value): value is string => Boolean(value)));
  return languages.size === 1 ? [...languages][0] : undefined;
}
