import { createHash } from "node:crypto";
import { mkdir, readFile, readdir, writeFile } from "node:fs/promises";
import { resolve } from "node:path";
import type { ThinkingLevel } from "@earendil-works/pi-agent-core";
import { systemPrompt } from "../src/agent/security-assistant-prompts.js";
import { loadConfig, type AppConfig } from "../src/config/index.js";
import { loadConversationCorpusCases } from "../src/learning/assistant-conversation-corpus.js";
import { loadEncounterRequestSeeds, type EncounterRequestSeed } from "../src/learning/assistant-encounter-corpus.js";
import {
  FRONTIER_JUDGE_PANEL,
  deliberateFrontierTournament,
  frontierPromotionEligibleCandidateIds,
  generateAdversarialCases,
  generatePolicyMutations,
  selectDiverseFrontierCases,
  type FrontierDeliberation,
  type FrontierFailureSummary,
  type FrontierPanelCase,
} from "../src/learning/assistant-frontier-eval.js";
import {
  hardCorpusDigest,
  parseAssistantHardCorpusLine,
  parseAssistantHillClimbObservation,
  type AssistantHardCorpusCase,
  type AssistantPolicyCandidate,
} from "../src/learning/assistant-hillclimb.js";
import {
  judgeOfflineAssistantCase,
  offlineJudgeCacheKey,
  type OfflineCaseJudgment,
  type OfflineJudgeIdentity,
} from "../src/learning/assistant-offline-judge.js";
import {
  OFFLINE_PRODUCTION_CANDIDATE,
  OFFLINE_ENSEMBLE_CANDIDATE,
  OFFLINE_DISTRIBUTED_CANDIDATE,
  offlineHarnessCacheKey,
  runOfflineAssistantCase,
  type OfflineAssistantRunResult,
} from "../src/learning/assistant-offline-harness.js";

const DEFAULT_MODEL = "amazon-bedrock/us.anthropic.claude-opus-4-8";
const DEFAULT_REPORT_ROOT = resolve("tmp/assistant-frontier-hillclimb");
const DEFAULT_CORPUS = "evals/assistant-hard-corpus.jsonl";

interface CliOptions {
  corpus: string;
  tableName?: string;
  conversationBucket?: string;
  encounterLimit: number;
  conversationLimit: number;
  generatedTrainCases: number;
  generatedValidationCases: number;
  trainCases: number;
  validationCases: number;
  heldOutCases: number;
  mutations: number;
  children: number;
  concurrency: number;
  modelRef: string;
  executionModelRef: string;
  thinking: ThinkingLevel;
  executionThinking: ThinkingLevel;
  refresh: boolean;
  reportRoot: string;
  runId: string;
}

async function main(): Promise<void> {
  const options = parseArgs(process.argv.slice(2));
  const staticCases = await loadCorpus(options.corpus);
  const heldOutStatic = staticCases.filter((item) => item.partition === "held_out");
  if (heldOutStatic.length < 8) throw new Error("Frontier hillclimb requires at least eight sealed static held-out cases.");
  const root = resolve(options.reportRoot, options.runId);
  const cacheRoot = resolve(options.reportRoot, "cache");
  await Promise.all([mkdir(root, { recursive: true }), mkdir(cacheRoot, { recursive: true })]);
  const [loadedConversationCases, loadedEncounterSeeds] = await Promise.all([
    options.conversationBucket
      ? loadConversationCorpusCases({ bucket: options.conversationBucket, limit: options.conversationLimit })
      : Promise.resolve([]),
    options.tableName
      ? loadEncounterRequestSeeds({ tableName: options.tableName, limit: options.encounterLimit })
      : Promise.resolve([]),
  ]);
  const { conversationCases, encounterSeeds } = await pinRunInputs({
    root,
    conversationCases: loadedConversationCases,
    encounterSeeds: loadedEncounterSeeds,
  });
  if (encounterSeeds.length < 20) throw new Error("Frontier hillclimb requires at least twenty historical human request seeds.");
  const staticDigest = hardCorpusDigest(staticCases);
  const [runtimeFingerprintValue, evaluatorFingerprintValue] = await Promise.all([
    runtimeFingerprint(),
    evaluatorFingerprint(),
  ]);
  logEvent("frontier_hillclimb.started", {
    run_id: options.runId,
    static_case_count: staticCases.length,
    sealed_held_out_count: heldOutStatic.length,
    conversation_case_count: conversationCases.length,
    encounter_seed_count: encounterSeeds.length,
    judge_count: FRONTIER_JUDGE_PANEL.length,
    model: options.modelRef,
  });

  const orderedSeeds = [...encounterSeeds].sort((left, right) => stableToken(options.runId, left.id).localeCompare(stableToken(options.runId, right.id)));
  const validationSeedCount = Math.max(10, Math.floor(orderedSeeds.length * 0.25));
  const validationSeeds = orderedSeeds.slice(0, validationSeedCount);
  const trainSeeds = orderedSeeds.slice(validationSeedCount);
  const generatedTrain = await cachedAdversarialCurriculum({
    cacheRoot,
    staticDigest,
    generatorFingerprint: evaluatorFingerprintValue,
    seeds: trainSeeds,
    archetypes: staticCases.filter((item) => item.partition === "train"),
    partition: "train",
    count: options.generatedTrainCases,
    options,
  });
  const generatedValidation = await cachedAdversarialCurriculum({
    cacheRoot,
    staticDigest,
    generatorFingerprint: evaluatorFingerprintValue,
    seeds: validationSeeds,
    archetypes: staticCases.filter((item) => item.partition === "validation"),
    partition: "validation",
    count: options.generatedValidationCases,
    options,
  });
  const trainPool = uniqueCases([
    ...staticCases.filter((item) => item.partition === "train"),
    ...conversationCases.filter((item) => item.partition === "train"),
    ...generatedTrain,
  ]);
  const validationPool = uniqueCases([
    ...staticCases.filter((item) => item.partition === "validation"),
    ...generatedValidation,
  ]);
  const trainCases = selectDiverseFrontierCases(trainPool, options.trainCases, `${options.runId}-train-selection`);
  const validationCases = selectDiverseFrontierCases(validationPool, options.validationCases, `${options.runId}-validation-selection`);
  const heldOutCases = selectDiverseFrontierCases(heldOutStatic, options.heldOutCases, `${options.runId}-heldout-selection`);
  const config = offlineConfig(options);
  const runContext = {
    options,
    config,
    cacheRoot,
    runtimeFingerprint: runtimeFingerprintValue,
    evaluatorFingerprint: evaluatorFingerprintValue,
    runMemo: new Map<string, Promise<OfflineAssistantRunResult>>(),
  };
  logEvent("frontier_hillclimb.curriculum_ready", {
    run_id: options.runId,
    generated_train_count: generatedTrain.length,
    generated_validation_count: generatedValidation.length,
    selected_train_count: trainCases.length,
    selected_validation_count: validationCases.length,
    selected_held_out_count: heldOutCases.length,
  });

  const production = OFFLINE_PRODUCTION_CANDIDATE;
  const ensemble = OFFLINE_ENSEMBLE_CANDIDATE;
  const distributed = OFFLINE_DISTRIBUTED_CANDIDATE;
  const discoveryRuns = await evaluateCandidates([production], trainCases, runContext);
  const discoveryJudgments = await mapLimit(trainCases, options.concurrency, (item) => judgeWithCache({
    item,
    runs: runsFor(discoveryRuns, item.id),
    judge: FRONTIER_JUDGE_PANEL[2]!,
    context: runContext,
  }));
  const discoveryFailures = discoveryJudgments.map((judgment) => failureFromJudgment(
    requiredCase(trainCases, judgment.caseId),
    judgment,
    production.id,
  ));
  const firstGeneration = await cachedCandidates({
    path: resolve(cacheRoot, artifactKey("policy-generation-1", {
      parent: production,
      failures: discoveryFailures,
      count: options.mutations,
      model: options.modelRef,
      thinking: options.thinking,
      evaluatorFingerprint: evaluatorFingerprintValue,
    })),
    refresh: options.refresh,
    create: () => generatePolicyMutations({
      parent: production,
      failures: discoveryFailures,
      count: options.mutations,
      modelRef: options.modelRef,
      thinking: options.thinking,
      generation: 1,
    }),
  });
  const trainCandidates = [production, ensemble, distributed, ...firstGeneration];
  const trainRuns = await evaluateCandidates(trainCandidates, trainCases, runContext);
  const trainPanels = await evaluatePanel(trainCases, trainRuns, runContext);
  const trainDecision = await cachedDeliberation({
    path: resolve(cacheRoot, artifactKey("train-deliberation", {
      candidates: trainCandidates,
      panels: trainPanels,
      model: options.modelRef,
      thinking: options.thinking,
      evaluatorFingerprint: evaluatorFingerprintValue,
    })),
    refresh: options.refresh,
    create: () => deliberateFrontierTournament({
      phase: "train",
      candidates: trainCandidates,
      panels: trainPanels,
      modelRef: options.modelRef,
      thinking: options.thinking,
    }),
  });
  const trainWinner = requiredCandidate(trainCandidates, trainDecision.selectedCandidateId);
  logEvent("frontier_hillclimb.train_selected", {
    run_id: options.runId,
    candidate_id: trainWinner.id,
    confidence: trainDecision.confidence,
    regression_case_count: trainDecision.regressionCases.length,
  });

  const childFailures = failuresFromPanels(trainCases, trainPanels, trainWinner.id);
  const children = await cachedCandidates({
    path: resolve(cacheRoot, artifactKey("policy-generation-2", {
      parent: trainWinner,
      failures: childFailures,
      count: options.children,
      model: options.modelRef,
      thinking: options.thinking,
      evaluatorFingerprint: evaluatorFingerprintValue,
    })),
    refresh: options.refresh,
    create: () => generatePolicyMutations({
      parent: trainWinner,
      failures: childFailures,
      count: options.children,
      modelRef: options.modelRef,
      thinking: options.thinking,
      generation: 2,
    }),
  });
  const validationCandidates = uniqueCandidates([production, ensemble, distributed, trainWinner, ...children]);
  const validationRuns = await evaluateCandidates(validationCandidates, validationCases, runContext);
  const validationPanels = await evaluatePanel(validationCases, validationRuns, runContext);
  const validationDecision = await cachedDeliberation({
    path: resolve(cacheRoot, artifactKey("validation-deliberation", {
      candidates: validationCandidates,
      panels: validationPanels,
      model: options.modelRef,
      thinking: options.thinking,
      evaluatorFingerprint: evaluatorFingerprintValue,
    })),
    refresh: options.refresh,
    create: () => deliberateFrontierTournament({
      phase: "validation",
      candidates: validationCandidates,
      panels: validationPanels,
      modelRef: options.modelRef,
      thinking: options.thinking,
    }),
  });
  const validationFinalist = requiredCandidate(validationCandidates, validationDecision.selectedCandidateId);
  logEvent("frontier_hillclimb.validation_selected", {
    run_id: options.runId,
    candidate_id: validationFinalist.id,
    confidence: validationDecision.confidence,
    regression_case_count: validationDecision.regressionCases.length,
  });

  let shadowCases: AssistantHardCorpusCase[] = [];
  if (validationFinalist.id !== production.id) {
    const usedSeedIds = new Set([
      ...curriculumPromptSeedIds(trainSeeds, options.generatedTrainCases),
      ...curriculumPromptSeedIds(validationSeeds, options.generatedValidationCases),
    ]);
    const shadowSeeds = orderedSeeds.filter((seed) => !usedSeedIds.has(seed.id));
    if (shadowSeeds.length < 24) throw new Error("Frontier confirmation requires at least twenty-four unused historical request seeds.");
    const selectedDevelopmentIds = new Set([...trainCases, ...validationCases].map((item) => item.id));
    const shadowArchetypes = staticCases.filter((item) => item.partition !== "held_out" && !selectedDevelopmentIds.has(item.id));
    shadowCases = await cachedAdversarialCurriculum({
      cacheRoot,
      staticDigest,
      generatorFingerprint: evaluatorFingerprintValue,
      seeds: shadowSeeds,
      archetypes: shadowArchetypes,
      partition: "validation",
      cacheLabel: "shadow-held-out",
      count: 8,
      options,
    });
    logEvent("frontier_hillclimb.shadow_holdout_sealed", {
      run_id: options.runId,
      case_count: shadowCases.length,
      unused_seed_count: shadowSeeds.length,
    });
  }

  let heldOutRuns: OfflineAssistantRunResult[] = [];
  let heldOutPanels: FrontierPanelCase[] = [];
  let heldOutDecision: FrontierDeliberation | undefined;
  if (validationFinalist.id !== production.id) {
    const heldOutCandidates = [production, validationFinalist];
    heldOutRuns = await evaluateCandidates(heldOutCandidates, heldOutCases, runContext);
    heldOutPanels = await evaluatePanel(heldOutCases, heldOutRuns, runContext);
    heldOutDecision = await cachedDeliberation({
      path: resolve(cacheRoot, artifactKey("heldout-deliberation", {
        candidates: heldOutCandidates,
        panels: heldOutPanels,
        model: options.modelRef,
        thinking: options.thinking,
        evaluatorFingerprint: evaluatorFingerprintValue,
      })),
      refresh: options.refresh,
      create: () => deliberateFrontierTournament({
        phase: "held_out",
        candidates: heldOutCandidates,
        panels: heldOutPanels,
        modelRef: options.modelRef,
        thinking: options.thinking,
      }),
    });
  }
  let finalist = validationFinalist;
  const staticPromotionReady = Boolean(heldOutDecision?.promotionRecommended && heldOutDecision.selectedCandidateId === validationFinalist.id);
  let promotionReady = false;
  let repairCandidates: AssistantPolicyCandidate[] = [];
  let shadowRuns: OfflineAssistantRunResult[] = [];
  let shadowPanels: FrontierPanelCase[] = [];
  let shadowDecision: FrontierDeliberation | undefined;
  if (heldOutDecision && validationFinalist.id !== production.id) {
    if (!staticPromotionReady) {
      const heldOutFailures = failuresFromPanels(heldOutCases, heldOutPanels, validationFinalist.id);
      repairCandidates = await cachedCandidates({
        path: resolve(cacheRoot, artifactKey("policy-generation-3", {
          parent: validationFinalist,
          failures: heldOutFailures,
          count: options.children,
          model: options.modelRef,
          thinking: options.thinking,
          evaluatorFingerprint: evaluatorFingerprintValue,
        })),
        refresh: options.refresh,
        create: () => generatePolicyMutations({
          parent: validationFinalist,
          failures: heldOutFailures,
          count: options.children,
          modelRef: options.modelRef,
          thinking: options.thinking,
          generation: 3,
        }),
      });
    }
    const shadowCandidates = uniqueCandidates([production, validationFinalist, ...repairCandidates]);
    const eligiblePromotionIds = new Set(frontierPromotionEligibleCandidateIds({
      staticPromotionReady,
      validationFinalistId: validationFinalist.id,
      repairCandidateIds: repairCandidates.map((candidate) => candidate.id),
    }));
    shadowRuns = await evaluateCandidates(shadowCandidates, shadowCases, runContext);
    shadowPanels = await evaluatePanel(shadowCases, shadowRuns, runContext);
    shadowDecision = await cachedDeliberation({
      path: resolve(cacheRoot, artifactKey("shadow-heldout-deliberation", {
        candidates: shadowCandidates,
        panels: shadowPanels,
        model: options.modelRef,
        thinking: options.thinking,
        evaluatorFingerprint: evaluatorFingerprintValue,
      })),
      refresh: options.refresh,
      create: () => deliberateFrontierTournament({
        phase: "held_out",
        candidates: shadowCandidates,
        panels: shadowPanels,
        modelRef: options.modelRef,
        thinking: options.thinking,
      }),
    });
    finalist = requiredCandidate(shadowCandidates, shadowDecision.selectedCandidateId);
    promotionReady = Boolean(shadowDecision.promotionRecommended && eligiblePromotionIds.has(finalist.id));
    logEvent("frontier_hillclimb.shadow_selected", {
      run_id: options.runId,
      candidate_id: finalist.id,
      confidence: shadowDecision.confidence,
      static_promotion_ready: staticPromotionReady,
      promotion_ready: promotionReady,
    });
  }
  const report = {
    schema_version: 1,
    run_id: options.runId,
    model: options.modelRef,
    execution_model: options.executionModelRef,
    runtime_fingerprint: runtimeFingerprintValue,
    evaluator_fingerprint: evaluatorFingerprintValue,
    static_corpus_digest: staticDigest,
    corpus_counts: {
      static: staticCases.length,
      conversation: conversationCases.length,
      encounter_seeds: encounterSeeds.length,
      generated_train: generatedTrain.length,
      generated_validation: generatedValidation.length,
      generated_shadow_held_out: shadowCases.length,
    },
    selected_cases: {
      train: trainCases.map(caseSummary),
      validation: validationCases.map(caseSummary),
      held_out: heldOutCases.map(caseSummary),
      shadow_held_out: shadowCases.map(caseSummary),
    },
    candidates: uniqueCandidates([...trainCandidates, ...validationCandidates, ...repairCandidates]),
    train: { decision: trainDecision, panels: trainPanels, runs: trainRuns },
    validation: { decision: validationDecision, panels: validationPanels, runs: validationRuns },
    held_out: { decision: heldOutDecision, panels: heldOutPanels, runs: heldOutRuns },
    shadow_held_out: { decision: shadowDecision, panels: shadowPanels, runs: shadowRuns },
    finalist,
    static_promotion_ready: staticPromotionReady,
    promotion_ready: promotionReady,
  };
  await Promise.all([
    writeFile(resolve(root, "report.json"), `${JSON.stringify(report, null, 2)}\n`, "utf8"),
    writeFile(resolve(root, "report.md"), renderMarkdown(report), "utf8"),
    writeFile(resolve(root, "failures.jsonl"), renderFailures([...trainPanels, ...validationPanels, ...heldOutPanels, ...shadowPanels]), "utf8"),
  ]);
  logEvent("frontier_hillclimb.completed", {
    run_id: options.runId,
    finalist_id: finalist.id,
    promotion_ready: promotionReady,
    report: resolve(root, "report.json"),
  });
  if (!promotionReady) process.exitCode = 1;
}

interface RunContext {
  options: CliOptions;
  config: AppConfig;
  cacheRoot: string;
  runtimeFingerprint: string;
  evaluatorFingerprint: string;
  runMemo: Map<string, Promise<OfflineAssistantRunResult>>;
}

async function evaluateCandidates(
  candidates: AssistantPolicyCandidate[],
  cases: AssistantHardCorpusCase[],
  context: RunContext,
): Promise<OfflineAssistantRunResult[]> {
  const groups = await mapLimit(candidates, 1, async (candidate) => {
    logEvent("frontier_hillclimb.candidate_started", { candidate_id: candidate.id, case_count: cases.length });
    const results = await mapLimit(cases, context.options.concurrency, (item) => evaluateCase(candidate, item, context));
    logEvent("frontier_hillclimb.candidate_completed", { candidate_id: candidate.id, case_count: cases.length });
    return results;
  });
  return groups.flat();
}

async function evaluateCase(
  candidate: AssistantPolicyCandidate,
  item: AssistantHardCorpusCase,
  context: RunContext,
): Promise<OfflineAssistantRunResult> {
  const protocolPrompt = systemPrompt(context.config, "", "", "", candidate.instructions);
  const key = offlineHarnessCacheKey({
    runtimeFingerprint: context.runtimeFingerprint,
    model: context.options.modelRef,
    thinking: context.options.thinking,
    executionModel: context.options.executionModelRef,
    executionThinking: context.options.executionThinking,
    protocolPrompt,
    candidate,
    item,
  });
  const memoized = context.runMemo.get(key);
  if (memoized) return memoized;

  const pending = loadOrRunCase(candidate, item, context, key);
  context.runMemo.set(key, pending);
  try {
    return await pending;
  } catch (error) {
    context.runMemo.delete(key);
    throw error;
  }
}

async function loadOrRunCase(
  candidate: AssistantPolicyCandidate,
  item: AssistantHardCorpusCase,
  context: RunContext,
  key: string,
): Promise<OfflineAssistantRunResult> {
  const path = resolve(context.cacheRoot, "runs", `${key}.json`);
  if (!context.options.refresh) {
    const cached = await readRun(path, item.id, candidate.id);
    if (cached) return cached;
  }
  const result = await runOfflineAssistantCase({ config: context.config, item, candidate });
  await writeJson(path, result);
  logEvent("frontier_hillclimb.case_completed", {
    candidate_id: candidate.id,
    case_id: item.id,
    latency_ms: result.observation.latency_ms,
  });
  return result;
}

async function evaluatePanel(
  cases: AssistantHardCorpusCase[],
  runs: OfflineAssistantRunResult[],
  context: RunContext,
): Promise<FrontierPanelCase[]> {
  return mapLimit(cases, context.options.concurrency, async (item) => ({
    caseId: item.id,
    challenge: item.challenge,
    judgments: await Promise.all(FRONTIER_JUDGE_PANEL.map(async (judge) => ({
      judgeId: judge.id,
      judgment: await judgeWithCache({ item, runs: runsFor(runs, item.id), judge, context }),
    }))),
  }));
}

async function judgeWithCache(input: {
  item: AssistantHardCorpusCase;
  runs: OfflineAssistantRunResult[];
  judge: OfflineJudgeIdentity;
  context: RunContext;
}): Promise<OfflineCaseJudgment> {
  const key = offlineJudgeCacheKey({
    item: input.item,
    runs: input.runs,
    modelRef: input.context.options.modelRef,
    thinking: input.context.options.thinking,
    judge: input.judge,
    evaluatorFingerprint: input.context.evaluatorFingerprint,
  });
  const path = resolve(input.context.cacheRoot, "judgments", `${key}.json`);
  if (!input.context.options.refresh) {
    const cached = await readJudgment(path, input.item.id, input.runs.map((run) => run.candidateId));
    if (cached) return cached;
  }
  const judgment = await judgeOfflineAssistantCase({
    item: input.item,
    runs: input.runs,
    modelRef: input.context.options.modelRef,
    thinking: input.context.options.thinking,
    judge: input.judge,
    onAttemptFailure: (failure) => logEvent("frontier_hillclimb.judge_attempt_failed", {
      case_id: input.item.id,
      judge_id: input.judge.id,
      attempt: failure.attempt,
      failure_kind: failure.kind,
      will_retry: failure.willRetry,
    }),
  });
  await writeJson(path, judgment);
  logEvent("frontier_hillclimb.case_judged", {
    case_id: input.item.id,
    judge_id: input.judge.id,
    winner_id: judgment.winnerCandidateId,
    tie: judgment.tie,
    confidence: judgment.confidence,
  });
  return judgment;
}

function failureFromJudgment(
  item: AssistantHardCorpusCase,
  judgment: OfflineCaseJudgment,
  candidateId: string,
): FrontierFailureSummary {
  const evaluation = judgment.evaluations.find((candidate) => candidate.candidateId === candidateId);
  if (!evaluation) throw new Error(`Missing ${candidateId} judgment for ${item.id}.`);
  return {
    caseId: item.id,
    challenge: item.challenge,
    score: evaluation.overallScore,
    pass: evaluation.pass,
    severeFailure: evaluation.severeFailure,
    failureModes: evaluation.failureModes,
    actionableFeedback: evaluation.actionableFeedback,
    comparison: judgment.comparison,
  };
}

function failuresFromPanels(
  cases: AssistantHardCorpusCase[],
  panels: FrontierPanelCase[],
  candidateId: string,
): FrontierFailureSummary[] {
  return panels.map((panel) => {
    const reviews = panel.judgments.map(({ judgment }) => failureFromJudgment(requiredCase(cases, panel.caseId), judgment, candidateId));
    return {
      caseId: panel.caseId,
      challenge: panel.challenge,
      score: Math.min(...reviews.map((review) => review.score)),
      pass: reviews.every((review) => review.pass),
      severeFailure: reviews.some((review) => review.severeFailure),
      failureModes: unique(reviews.flatMap((review) => review.failureModes)),
      actionableFeedback: unique(reviews.flatMap((review) => review.actionableFeedback)),
      comparison: unique(reviews.map((review) => review.comparison)).join(" | ").slice(0, 5_000),
    };
  });
}

function offlineConfig(options: CliOptions): AppConfig {
  const model = splitModel(options.modelRef);
  const execution = splitModel(options.executionModelRef);
  if (model.provider !== execution.provider) throw new Error("Planner and execution models must use the same provider.");
  const placeholder = (name: string) => `offline-${name}-not-used`;
  return loadConfig({
    ...process.env,
    NODE_ENV: "test",
    SLACK_SOCKET_MODE: "false",
    SLACK_BOT_TOKEN: placeholder("slack-token"),
    SLACK_SIGNING_SECRET: placeholder("slack-signing"),
    CEREBRO_BASE_URL: "https://offline.invalid",
    CEREBRO_TENANT_ID: "offline-frontier-hillclimb",
    CEREBRO_READ_API_KEY: placeholder("cerebro-key"),
    CEREBRO_DEFAULT_RUNTIME_IDS: "",
    CEREBRO_ASSISTANT_HELP_MENTION: "",
    CEREBRO_ASSISTANT_RUNTIME: "flue",
    CEREBRO_TRIAGE_TIMEOUT_MS: "300000",
    CEREBRO_TRIAGE_MAX_CONCURRENT: String(options.concurrency),
    PI_ENABLED: "true",
    PI_PROVIDER: model.provider,
    PI_MODEL: model.model,
    PI_THINKING_LEVEL: options.thinking,
    PI_EXECUTION_MODEL: execution.model,
    PI_EXECUTION_THINKING_LEVEL: options.executionThinking,
    SECURITY_LEARNING_ENABLED: "false",
    SECURITY_WORKING_MEMORY_ENABLED: "false",
    SECURITY_LEARNING_DOCS_ENABLED: "false",
    CEREBRO_SLACK_CHANNEL_LEARNING_ENABLED: "false",
    CEREBRO_AUTONOMY_GOALS_ENABLED: "false",
    CEREBRO_AUTONOMY_RUNNER_ENABLED: "false",
    CEREBRO_WORK_FLEET_ENABLED: "true",
    CEREBRO_CODE_WRITE_ENABLED: "false",
    INFISICAL_ENABLED: "false",
    CEREBRO_TELEMETRY_ENABLED: "false",
    CEREBRO_METRICS_ENABLED: "false",
  });
}

function parseArgs(args: string[]): CliOptions {
  const now = new Date().toISOString().replace(/[:.]/g, "-");
  const options: CliOptions = {
    corpus: DEFAULT_CORPUS,
    tableName: process.env.CEREBRO_LEARNING_TABLE_NAME?.trim() || "cerebro-slack-companion-sec-dev-learning",
    conversationBucket: process.env.CEREBRO_IMPROVEMENT_ARTIFACT_BUCKET?.trim() || undefined,
    encounterLimit: 500,
    conversationLimit: 200,
    generatedTrainCases: 8,
    generatedValidationCases: 6,
    trainCases: 14,
    validationCases: 12,
    heldOutCases: 11,
    mutations: 4,
    children: 2,
    concurrency: 2,
    modelRef: DEFAULT_MODEL,
    executionModelRef: DEFAULT_MODEL,
    thinking: "high",
    executionThinking: "medium",
    refresh: false,
    reportRoot: DEFAULT_REPORT_ROOT,
    runId: `frontier-${now}`,
  };
  const numericFlags: Record<string, keyof CliOptions> = {
    "--encounter-limit": "encounterLimit",
    "--conversation-limit": "conversationLimit",
    "--generated-train": "generatedTrainCases",
    "--generated-validation": "generatedValidationCases",
    "--train-cases": "trainCases",
    "--validation-cases": "validationCases",
    "--held-out-cases": "heldOutCases",
    "--mutations": "mutations",
    "--children": "children",
    "--concurrency": "concurrency",
  };
  for (let index = 0; index < args.length; index += 1) {
    const arg = args[index]!;
    if (arg === "--refresh") { options.refresh = true; continue; }
    if (numericFlags[arg]) {
      (options[numericFlags[arg]!] as number) = Number(requiredArg(args, ++index, arg));
      continue;
    }
    if (arg === "--corpus") { options.corpus = requiredArg(args, ++index, arg); continue; }
    if (arg === "--table") { options.tableName = requiredArg(args, ++index, arg); continue; }
    if (arg === "--no-table") { options.tableName = undefined; continue; }
    if (arg === "--conversation-bucket") { options.conversationBucket = requiredArg(args, ++index, arg); continue; }
    if (arg === "--model") { options.modelRef = requiredArg(args, ++index, arg); continue; }
    if (arg === "--execution-model") { options.executionModelRef = requiredArg(args, ++index, arg); continue; }
    if (arg === "--thinking") { options.thinking = thinkingLevel(requiredArg(args, ++index, arg)); continue; }
    if (arg === "--execution-thinking") { options.executionThinking = thinkingLevel(requiredArg(args, ++index, arg)); continue; }
    if (arg === "--report-root") { options.reportRoot = resolve(requiredArg(args, ++index, arg)); continue; }
    if (arg === "--run-id") { options.runId = requiredArg(args, ++index, arg); continue; }
    throw new Error(`Unknown argument ${arg}.`);
  }
  requireOpus(options.modelRef, "Planner, adversary, optimizer, and judge");
  requireOpus(options.executionModelRef, "Execution");
  bounded(options.concurrency, 1, 4, "Concurrency");
  bounded(options.generatedTrainCases, 1, 12, "Generated train cases");
  bounded(options.generatedValidationCases, 1, 12, "Generated validation cases");
  bounded(options.trainCases, 4, 100, "Train cases");
  bounded(options.validationCases, 4, 100, "Validation cases");
  bounded(options.heldOutCases, 8, 100, "Held-out cases");
  bounded(options.mutations, 2, 6, "Mutations");
  bounded(options.children, 1, 6, "Children");
  return options;
}

async function runtimeFingerprint(): Promise<string> {
  const files = await collectFingerprintFiles([
    "src/agent",
    "src/cerebro",
    "src/config",
    "src/learning/security-memory",
    "src/security",
    "src/slack",
  ]);
  return fileFingerprint([
    ...files,
    "src/telemetry.ts",
    "src/learning/assistant-offline-fixtures.ts",
    "src/learning/assistant-offline-harness.ts",
  ]);
}

async function evaluatorFingerprint(): Promise<string> {
  return fileFingerprint([
    "src/learning/assistant-encounter-corpus.ts",
    "src/learning/assistant-offline-judge.ts",
    "src/learning/assistant-frontier-eval.ts",
  ]);
}

async function fileFingerprint(files: string[]): Promise<string> {
  const content = await Promise.all([...files].sort().map(async (path) => `${path}\0${await readFile(resolve(path), "utf8")}`));
  return createHash("sha256").update(content.join("\0")).digest("hex");
}

async function collectFingerprintFiles(roots: string[]): Promise<string[]> {
  const files: string[] = [];
  async function visit(path: string): Promise<void> {
    const entries = await readdir(resolve(path), { withFileTypes: true });
    await Promise.all(entries.map(async (entry) => {
      const child = `${path}/${entry.name}`;
      if (entry.isDirectory()) await visit(child);
      else if (entry.isFile() && entry.name.endsWith(".ts")) files.push(child);
    }));
  }
  await Promise.all(roots.map(visit));
  return files;
}

async function loadCorpus(path: string): Promise<AssistantHardCorpusCase[]> {
  const raw = await readFile(resolve(path), "utf8");
  return raw.split(/\r?\n/).map((line) => line.trim()).filter(Boolean).map((line, index) => {
    try { return parseAssistantHardCorpusLine(JSON.parse(line)); }
    catch (error) { throw new Error(`Invalid hard corpus line ${index + 1}: ${errorMessage(error)}`); }
  });
}

async function pinRunInputs(input: {
  root: string;
  conversationCases: AssistantHardCorpusCase[];
  encounterSeeds: EncounterRequestSeed[];
}): Promise<{ conversationCases: AssistantHardCorpusCase[]; encounterSeeds: EncounterRequestSeed[] }> {
  const path = resolve(input.root, "input-snapshot.json");
  try {
    const parsed = JSON.parse(await readFile(path, "utf8")) as {
      conversation_cases?: unknown[];
      encounter_seeds?: unknown[];
    };
    const conversationCases = (parsed.conversation_cases ?? []).map(parseAssistantHardCorpusLine);
    const encounterSeeds = (parsed.encounter_seeds ?? []).map(parseEncounterSeed);
    logEvent("frontier_hillclimb.input_snapshot_loaded", {
      conversation_case_count: conversationCases.length,
      encounter_seed_count: encounterSeeds.length,
    });
    return { conversationCases, encounterSeeds };
  } catch (error) {
    if (!isMissing(error)) throw error;
  }

  let conversationCases = input.conversationCases;
  let encounterSeeds = input.encounterSeeds;
  try {
    const prior = JSON.parse(await readFile(resolve(input.root, "report.json"), "utf8")) as {
      corpus_counts?: { conversation?: number; encounter_seeds?: number };
      selected_cases?: { train?: Array<{ id?: string }> };
    };
    const priorSeedCount = prior.corpus_counts?.encounter_seeds;
    if (typeof priorSeedCount === "number" && Number.isInteger(priorSeedCount)
      && priorSeedCount > 0 && input.encounterSeeds.length >= priorSeedCount) {
      encounterSeeds = input.encounterSeeds.slice(input.encounterSeeds.length - priorSeedCount);
    }
    const priorConversationCount = prior.corpus_counts?.conversation;
    const priorConversationIds = new Set((prior.selected_cases?.train ?? [])
      .flatMap((item) => typeof item.id === "string" && /^(?:live|traffic)-/.test(item.id) ? [item.id] : []));
    if (typeof priorConversationCount === "number" && Number.isInteger(priorConversationCount)
      && priorConversationCount === priorConversationIds.size) {
      const recovered = input.conversationCases.filter((item) => priorConversationIds.has(item.id));
      if (recovered.length === priorConversationCount) conversationCases = recovered;
    }
  } catch (error) {
    if (!isMissing(error)) throw error;
  }
  await writeJson(path, {
    schema_version: 1,
    captured_at: new Date().toISOString(),
    conversation_cases: conversationCases,
    encounter_seeds: encounterSeeds,
  });
  logEvent("frontier_hillclimb.input_snapshot_created", {
    conversation_case_count: conversationCases.length,
    encounter_seed_count: encounterSeeds.length,
  });
  return { conversationCases, encounterSeeds };
}

function parseEncounterSeed(value: unknown): EncounterRequestSeed {
  if (!value || typeof value !== "object") throw new Error("Invalid encounter seed in run input snapshot.");
  const record = value as Record<string, unknown>;
  if (typeof record.id !== "string" || typeof record.question !== "string" || !Array.isArray(record.tags)
    || record.tags.some((tag) => typeof tag !== "string")
    || (record.occurredAt !== undefined && typeof record.occurredAt !== "string")) {
    throw new Error("Invalid encounter seed in run input snapshot.");
  }
  return {
    id: record.id,
    question: record.question,
    occurredAt: record.occurredAt as string | undefined,
    tags: record.tags as string[],
  };
}

async function cachedAdversarialCurriculum(input: {
  cacheRoot: string;
  staticDigest: string;
  generatorFingerprint: string;
  seeds: EncounterRequestSeed[];
  archetypes: AssistantHardCorpusCase[];
  partition: "train" | "validation";
  cacheLabel?: string;
  count: number;
  options: CliOptions;
}): Promise<AssistantHardCorpusCase[]> {
  const result: AssistantHardCorpusCase[] = [];
  const cacheLabel = input.cacheLabel ?? input.partition;
  for (let offset = 0; offset < input.count; offset += 2) {
    const batchCount = Math.min(2, input.count - offset);
    const batchNumber = offset / 2 + 1;
    const seeds = rotateValues(input.seeds, offset * 19);
    const archetypes = rotateValues(input.archetypes, offset * 7);
    const generationId = `${cacheLabel}-batch-${batchNumber}`;
    const batch = await cachedGeneratedCases({
      path: resolve(input.cacheRoot, artifactKey(`adversarial-${cacheLabel}-batch-${batchNumber}`, {
        staticDigest: input.staticDigest,
        generatorFingerprint: input.generatorFingerprint,
        seeds: seeds.slice(0, 18),
        archetypes: archetypes.slice(0, 10).map((item) => ({ id: item.id, challenge: item.challenge, question: item.question })),
        count: batchCount,
        model: input.options.modelRef,
        thinking: input.options.executionThinking,
      })),
      refresh: input.options.refresh,
      create: () => generateAdversarialCases({
        seeds,
        archetypes,
        partition: input.partition,
        count: batchCount,
        modelRef: input.options.modelRef,
        thinking: input.options.executionThinking,
        generationId,
      }),
    });
    result.push(...batch);
    logEvent("frontier_hillclimb.curriculum_batch_ready", {
      partition: cacheLabel,
      batch: batchNumber,
      case_count: batch.length,
    });
  }
  return result;
}

async function cachedGeneratedCases(input: {
  path: string;
  refresh: boolean;
  create: () => Promise<AssistantHardCorpusCase[]>;
}): Promise<AssistantHardCorpusCase[]> {
  if (!input.refresh) {
    try {
      const value = JSON.parse(await readFile(input.path, "utf8")) as unknown[];
      return value.map(parseAssistantHardCorpusLine);
    } catch (error) { if (!isMissing(error)) throw error; }
  }
  const value = await input.create();
  await writeJson(input.path, value);
  return value;
}

async function cachedCandidates(input: {
  path: string;
  refresh: boolean;
  create: () => Promise<AssistantPolicyCandidate[]>;
}): Promise<AssistantPolicyCandidate[]> {
  if (!input.refresh) {
    try {
      const value = JSON.parse(await readFile(input.path, "utf8")) as AssistantPolicyCandidate[];
      if (value.every(validCandidate)) return value;
      throw new Error("Cached frontier candidates are invalid.");
    } catch (error) { if (!isMissing(error)) throw error; }
  }
  const value = await input.create();
  await writeJson(input.path, value);
  return value;
}

async function cachedDeliberation(input: {
  path: string;
  refresh: boolean;
  create: () => Promise<FrontierDeliberation>;
}): Promise<FrontierDeliberation> {
  if (!input.refresh) {
    try {
      const value = JSON.parse(await readFile(input.path, "utf8")) as FrontierDeliberation;
      if (value.selectedCandidateId && typeof value.reasoning === "string") return value;
      throw new Error("Cached frontier deliberation is invalid.");
    } catch (error) { if (!isMissing(error)) throw error; }
  }
  const value = await input.create();
  await writeJson(input.path, value);
  return value;
}

async function readRun(path: string, caseId: string, candidateId: string): Promise<OfflineAssistantRunResult | undefined> {
  try {
    const value = JSON.parse(await readFile(path, "utf8")) as OfflineAssistantRunResult;
    if (value.caseId !== caseId || value.candidateId !== candidateId || !value.answer || !value.trace) return undefined;
    return { ...value, observation: parseAssistantHillClimbObservation(value.observation) };
  } catch (error) { if (!isMissing(error)) throw error; return undefined; }
}

async function readJudgment(path: string, caseId: string, candidateIds: string[]): Promise<OfflineCaseJudgment | undefined> {
  try {
    const value = JSON.parse(await readFile(path, "utf8")) as OfflineCaseJudgment;
    const expected = new Set(candidateIds);
    if (value.caseId !== caseId || value.evaluations.length !== expected.size) return undefined;
    if (value.evaluations.some((evaluation) => !expected.has(evaluation.candidateId))) return undefined;
    return value;
  } catch (error) { if (!isMissing(error)) throw error; return undefined; }
}

async function writeJson(path: string, value: unknown): Promise<void> {
  await mkdir(resolve(path, ".."), { recursive: true });
  await writeFile(path, `${JSON.stringify(value, null, 2)}\n`, "utf8");
}

function renderMarkdown(report: {
  run_id: string;
  model: string;
  corpus_counts: Record<string, number>;
  candidates: AssistantPolicyCandidate[];
  train: { decision: FrontierDeliberation; panels: FrontierPanelCase[] };
  validation: { decision: FrontierDeliberation; panels: FrontierPanelCase[] };
  held_out: { decision?: FrontierDeliberation; panels: FrontierPanelCase[] };
  shadow_held_out: { decision?: FrontierDeliberation; panels: FrontierPanelCase[] };
  finalist: AssistantPolicyCandidate;
  promotion_ready: boolean;
}): string {
  const phase = (name: string, panels: FrontierPanelCase[], decision?: FrontierDeliberation) => [
    `## ${name}`,
    "",
    `Cases: ${panels.length}`,
    `Independent judgments: ${panels.reduce((sum, panel) => sum + panel.judgments.length, 0)}`,
    decision ? `Selected policy: \`${decision.selectedCandidateId}\`` : "Selected policy: none",
    decision ? `Panel confidence: ${decision.confidence.toFixed(2)}` : "",
    decision ? `Decision: ${decision.reasoning}` : "",
    "",
  ].filter(Boolean);
  return [
    "# Frontier security-agent hillclimb",
    "",
    `Run: \`${report.run_id}\``,
    `Model: \`${report.model}\``,
    `Historical request seeds: ${report.corpus_counts.encounter_seeds}`,
    `Generated adversarial cases: ${report.corpus_counts.generated_train + report.corpus_counts.generated_validation + (report.corpus_counts.generated_shadow_held_out ?? 0)}`,
    `Candidate policies evaluated: ${report.candidates.length}`,
    `Finalist: \`${report.finalist.id}\``,
    `Held-out promotion: ${report.promotion_ready ? "recommended" : "not recommended"}`,
    "",
    ...phase("Train tournament", report.train.panels, report.train.decision),
    ...phase("Validation tournament", report.validation.panels, report.validation.decision),
    ...phase("Sealed held-out tournament", report.held_out.panels, report.held_out.decision),
    ...phase("Repair shadow held-out tournament", report.shadow_held_out.panels, report.shadow_held_out.decision),
    "## Finalist policy",
    "",
    report.finalist.mutation,
    "",
    ...report.finalist.instructions.map((instruction) => `- ${instruction}`),
    "",
  ].join("\n");
}

function renderFailures(panels: FrontierPanelCase[]): string {
  const lines = panels.flatMap((panel) => panel.judgments.flatMap(({ judgeId, judgment }) => judgment.evaluations
    .filter((evaluation) => !evaluation.pass)
    .map((evaluation) => JSON.stringify({
      schema_version: 1,
      case_id: panel.caseId,
      challenge: panel.challenge,
      judge_id: judgeId,
      candidate_id: evaluation.candidateId,
      score: evaluation.overallScore,
      severe_failure: evaluation.severeFailure,
      failure_modes: evaluation.failureModes,
      actionable_feedback: evaluation.actionableFeedback,
    }))));
  return lines.length > 0 ? `${lines.join("\n")}\n` : "";
}

function caseSummary(item: AssistantHardCorpusCase) {
  return { id: item.id, partition: item.partition, challenge: item.challenge, evidence_packets: item.evidence.length, thread_turns: item.threadContext.length };
}

function runsFor(runs: OfflineAssistantRunResult[], caseId: string): OfflineAssistantRunResult[] {
  return runs.filter((run) => run.caseId === caseId);
}

function requiredCase(cases: AssistantHardCorpusCase[], id: string): AssistantHardCorpusCase {
  const item = cases.find((candidate) => candidate.id === id);
  if (!item) throw new Error(`Missing case ${id}.`);
  return item;
}

function requiredCandidate(candidates: AssistantPolicyCandidate[], id: string): AssistantPolicyCandidate {
  const candidate = candidates.find((item) => item.id === id);
  if (!candidate) throw new Error(`Missing candidate ${id}.`);
  return candidate;
}

function uniqueCases(cases: AssistantHardCorpusCase[]): AssistantHardCorpusCase[] {
  return [...new Map(cases.map((item) => [item.id, item])).values()];
}

function uniqueCandidates(candidates: AssistantPolicyCandidate[]): AssistantPolicyCandidate[] {
  return [...new Map(candidates.map((item) => [item.id, item])).values()];
}

function validCandidate(value: AssistantPolicyCandidate): boolean {
  return typeof value?.id === "string" && typeof value.mutation === "string"
    && Array.isArray(value.instructions) && value.instructions.every((item) => typeof item === "string");
}

function artifactKey(kind: string, value: unknown): string {
  return `${kind}-${createHash("sha256").update(JSON.stringify(value)).digest("hex")}.json`;
}

function stableToken(left: string, right: string): string {
  return createHash("sha256").update(left).update("\0").update(right).digest("hex");
}

function rotateValues<T>(values: readonly T[], offset: number): T[] {
  if (values.length === 0) return [];
  const boundedOffset = offset % values.length;
  return [...values.slice(boundedOffset), ...values.slice(0, boundedOffset)];
}

function curriculumPromptSeedIds(seeds: readonly EncounterRequestSeed[], count: number): string[] {
  const ids: string[] = [];
  for (let offset = 0; offset < count; offset += 2) {
    ids.push(...rotateValues(seeds, offset * 19).slice(0, 18).map((seed) => seed.id));
  }
  return unique(ids);
}

function splitModel(value: string): { provider: string; model: string } {
  const separator = value.indexOf("/");
  if (separator < 1 || separator === value.length - 1) throw new Error("Model must use provider/model format.");
  return { provider: value.slice(0, separator), model: value.slice(separator + 1) };
}

function requireOpus(value: string, label: string): void {
  if (!value.toLowerCase().includes("anthropic.claude-opus")) throw new Error(`${label} must use an Anthropic Claude Opus model.`);
}

function thinkingLevel(value: string): ThinkingLevel {
  if (["off", "minimal", "low", "medium", "high", "xhigh"].includes(value)) return value as ThinkingLevel;
  throw new Error(`Unknown thinking level ${value}.`);
}

function bounded(value: number, minimum: number, maximum: number, label: string): void {
  if (!Number.isInteger(value) || value < minimum || value > maximum) throw new Error(`${label} must be an integer from ${minimum} through ${maximum}.`);
}

function requiredArg(args: string[], index: number, flag: string): string {
  const value = args[index];
  if (!value) throw new Error(`${flag} requires a value.`);
  return value;
}

async function mapLimit<T, U>(values: readonly T[], limit: number, worker: (value: T) => Promise<U>): Promise<U[]> {
  const results = new Array<U>(values.length);
  let cursor = 0;
  async function run(): Promise<void> {
    while (cursor < values.length) {
      const index = cursor++;
      results[index] = await worker(values[index] as T);
    }
  }
  await Promise.all(Array.from({ length: Math.min(limit, values.length) }, () => run()));
  return results;
}

function unique(values: string[]): string[] { return [...new Set(values)]; }
function isMissing(error: unknown): boolean { return (error as NodeJS.ErrnoException).code === "ENOENT"; }
function errorMessage(error: unknown): string { return error instanceof Error ? error.message : String(error); }
function logEvent(event: string, fields: Record<string, unknown>): void { process.stdout.write(`${JSON.stringify({ event, ...fields })}\n`); }

main().catch((error) => {
  logEvent("frontier_hillclimb.failed", { error_kind: error instanceof Error ? error.name : "unknown", message: errorMessage(error) });
  process.exitCode = 1;
});
