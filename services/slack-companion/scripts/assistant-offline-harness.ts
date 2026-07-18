import { createHash } from "node:crypto";
import { mkdir, readFile, writeFile } from "node:fs/promises";
import { resolve } from "node:path";
import type { ThinkingLevel } from "@earendil-works/pi-agent-core";
import { systemPrompt } from "../src/agent/security-assistant-prompts.js";
import { loadConfig, type AppConfig } from "../src/config/index.js";
import { loadConversationCorpusCases } from "../src/learning/assistant-conversation-corpus.js";
import {
  judgeOfflineAssistantCase,
  offlineJudgeCacheKey,
  type OfflineCaseJudgment,
} from "../src/learning/assistant-offline-judge.js";
import {
  OFFLINE_ASSISTANT_POLICY_CANDIDATES,
  offlineHarnessCacheKey,
  runOfflineAssistantCase,
  selectOfflineCases,
  type OfflineAssistantRunResult,
} from "../src/learning/assistant-offline-harness.js";
import {
  hardCorpusDigest,
  parseAssistantHardCorpusLine,
  parseAssistantHillClimbObservation,
  type AssistantHardCorpusCase,
  type AssistantPolicyCandidate,
} from "../src/learning/assistant-hillclimb.js";

const DEFAULT_MODEL = "amazon-bedrock/us.anthropic.claude-opus-4-8";
const DEFAULT_REPORT_ROOT = resolve("tmp/assistant-offline-harness");

interface CliOptions {
  corpus: string;
  modelRef: string;
  executionModelRef: string;
  thinking: ThinkingLevel;
  executionThinking: ThinkingLevel;
  concurrency: number;
  heldOut: boolean;
  candidateIds: string[];
  caseIds: Set<string>;
  limit?: number;
  refresh: boolean;
  reportRoot: string;
  conversationBucket?: string;
  conversationLimit: number;
}

interface OfflineCandidateScore {
  candidateId: string;
  partition: AssistantHardCorpusCase["partition"];
  caseCount: number;
  passed: number;
  passRate: number;
  averageScore: number;
  severeFailures: number;
  wins: number;
  ties: number;
  failureModes: Record<string, number>;
}

async function main(): Promise<void> {
  const options = parseArgs(process.argv.slice(2));
  const staticCases = await loadCorpus(options.corpus);
  const conversationCases = options.conversationBucket
    ? await loadConversationCorpusCases({ bucket: options.conversationBucket, limit: options.conversationLimit })
    : [];
  const allCases = mergeCorpus(staticCases, conversationCases);
  const cases = selectOfflineCases({
    cases: allCases,
    heldOut: options.heldOut,
    caseIds: options.caseIds,
    limit: options.limit,
  });
  if (cases.length === 0) throw new Error("No corpus cases matched the requested partition and case filters.");
  const candidates = resolveCandidates(options.candidateIds);
  const config = offlineConfig(options);
  const runtimeFingerprintValue = await runtimeFingerprint();
  const digest = hardCorpusDigest(allCases);
  const cacheDir = resolve(options.reportRoot, "cache");
  await mkdir(cacheDir, { recursive: true });
  logEvent("offline_harness.started", {
    phase: options.heldOut ? "held_out" : "development",
    corpus_digest: digest,
    case_count: cases.length,
    candidate_count: candidates.length,
    static_case_count: staticCases.length,
    conversation_case_count: conversationCases.length,
    model: options.modelRef,
    execution_model: options.executionModelRef,
  });

  const results = (await mapLimit(candidates, 1, async (candidate) => {
    logEvent("offline_harness.candidate_started", { candidate_id: candidate.id, case_count: cases.length });
    const candidateResults = await mapLimit(cases, options.concurrency, (item) => evaluateCase({
      candidate,
      item,
      options,
      config,
      cacheDir,
      runtimeFingerprint: runtimeFingerprintValue,
    }));
    logEvent("offline_harness.candidate_completed", { candidate_id: candidate.id, case_count: candidateResults.length });
    return candidateResults;
  })).flat();

  const judgmentCacheDir = resolve(options.reportRoot, "judge-cache");
  await mkdir(judgmentCacheDir, { recursive: true });
  const judgments = await mapLimit(cases, options.concurrency, (item) => judgeCase({
    item,
    runs: results.filter((result) => result.caseId === item.id),
    options,
    cacheDir: judgmentCacheDir,
  }));
  const scores = candidateScores(candidates, cases, judgments);
  const selection = options.heldOut ? undefined : developmentSelection(candidates, cases, scores);
  const promotionReady = options.heldOut ? heldOutResult(candidates, scores, judgments.length) : undefined;
  const report = {
    schema_version: 1,
    phase: options.heldOut ? "held_out" : "development",
    corpus_digest: digest,
    model: options.modelRef,
    thinking: options.thinking,
    execution_model: options.executionModelRef,
    execution_thinking: options.executionThinking,
    static_case_count: staticCases.length,
    conversation_case_count: conversationCases.length,
    evaluated_case_count: cases.length,
    candidate_ids: candidates.map((candidate) => candidate.id),
    scores,
    selection,
    promotion_ready: promotionReady,
    runs: results,
    judgments,
  };
  const phase = options.heldOut ? "held-out" : "development";
  const stem = `${phase}-${digest.slice(0, 12)}`;
  await mkdir(options.reportRoot, { recursive: true });
  await Promise.all([
    writeFile(resolve(options.reportRoot, `${stem}.json`), `${JSON.stringify(report, null, 2)}\n`, "utf8"),
    writeFile(resolve(options.reportRoot, `${stem}.md`), renderMarkdown(report), "utf8"),
    writeFile(resolve(options.reportRoot, `${stem}-failures.jsonl`), failureJsonl(results, judgments), "utf8"),
  ]);
  logEvent("offline_harness.completed", {
    report: resolve(options.reportRoot, `${stem}.json`),
    failures: judgments.flatMap((judgment) => judgment.evaluations).filter((evaluation) => !evaluation.pass).length,
    winner_id: selection?.winnerId,
    promotion_ready: promotionReady,
  });
  if (options.heldOut && promotionReady === false) process.exitCode = 1;
}

async function evaluateCase(input: {
  candidate: AssistantPolicyCandidate;
  item: AssistantHardCorpusCase;
  options: CliOptions;
  config: AppConfig;
  cacheDir: string;
  runtimeFingerprint: string;
}): Promise<OfflineAssistantRunResult> {
  const protocolPrompt = systemPrompt(input.config, "", "", "", input.candidate.instructions);
  const key = offlineHarnessCacheKey({
    runtimeFingerprint: input.runtimeFingerprint,
    model: input.options.modelRef,
    thinking: input.options.thinking,
    executionModel: input.options.executionModelRef,
    executionThinking: input.options.executionThinking,
    protocolPrompt,
    candidate: input.candidate,
    item: input.item,
  });
  const path = resolve(input.cacheDir, `${key}.json`);
  if (!input.options.refresh) {
    const cached = await readCachedResult(path, input.item, input.candidate.id);
    if (cached) {
      logEvent("offline_harness.case_cached", { candidate_id: input.candidate.id, case_id: input.item.id });
      return cached;
    }
  }
  const result = await runOfflineAssistantCase({ config: input.config, item: input.item, candidate: input.candidate });
  await writeFile(path, `${JSON.stringify(result, null, 2)}\n`, "utf8");
  logEvent("offline_harness.case_completed", {
    candidate_id: input.candidate.id,
    case_id: input.item.id,
    latency_ms: result.observation.latency_ms,
  });
  return result;
}

async function runtimeFingerprint(): Promise<string> {
  const files = [
    "src/agent/flue-security-assistant.ts",
    "src/agent/distributed-work.ts",
    "src/agent/security-assistant.ts",
    "src/agent/security-assistant-output.ts",
    "src/agent/security-assistant-presentation.ts",
    "src/agent/security-assistant-prompts.ts",
    "src/agent/security-assistant-recovery.ts",
    "src/learning/assistant-offline-fixtures.ts",
    "src/learning/assistant-offline-harness.ts",
  ];
  const contents = await Promise.all(files.map(async (path) => `${path}\0${await readFile(resolve(path), "utf8")}`));
  return createHash("sha256").update(contents.join("\0")).digest("hex");
}

async function readCachedResult(
  path: string,
  item: AssistantHardCorpusCase,
  candidateId: string,
): Promise<OfflineAssistantRunResult | undefined> {
  try {
    const value = JSON.parse(await readFile(path, "utf8")) as OfflineAssistantRunResult;
    const observation = parseAssistantHillClimbObservation(value.observation);
    if (value.caseId !== item.id || value.candidateId !== candidateId || !value.answer || !value.trace) return undefined;
    return { ...value, observation };
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code !== "ENOENT") {
      logEvent("offline_harness.cache_rejected", { path, error_kind: errorKind(error) });
    }
    return undefined;
  }
}

async function judgeCase(input: {
  item: AssistantHardCorpusCase;
  runs: OfflineAssistantRunResult[];
  options: CliOptions;
  cacheDir: string;
}): Promise<OfflineCaseJudgment> {
  const key = offlineJudgeCacheKey({
    item: input.item,
    runs: input.runs,
    modelRef: input.options.modelRef,
    thinking: input.options.thinking,
  });
  const path = resolve(input.cacheDir, `${key}.json`);
  if (!input.options.refresh) {
    const cached = await readCachedJudgment(path, input.item.id, input.runs.map((run) => run.candidateId));
    if (cached) {
      logEvent("offline_harness.judgment_cached", { case_id: input.item.id });
      return cached;
    }
  }
  const judgment = await judgeOfflineAssistantCase({
    item: input.item,
    runs: input.runs,
    modelRef: input.options.modelRef,
    thinking: input.options.thinking,
  });
  await writeFile(path, `${JSON.stringify(judgment, null, 2)}\n`, "utf8");
  logEvent("offline_harness.case_judged", {
    case_id: input.item.id,
    winner_id: judgment.winnerCandidateId,
    tie: judgment.tie,
    confidence: judgment.confidence,
    evaluations: judgment.evaluations.map((evaluation) => ({
      candidate_id: evaluation.candidateId,
      pass: evaluation.pass,
      score: evaluation.overallScore,
      severe_failure: evaluation.severeFailure,
    })),
  });
  return judgment;
}

async function readCachedJudgment(path: string, caseId: string, candidateIds: string[]): Promise<OfflineCaseJudgment | undefined> {
  try {
    const value = JSON.parse(await readFile(path, "utf8")) as OfflineCaseJudgment;
    const expected = new Set(candidateIds);
    if (value.caseId !== caseId || value.evaluations.length !== expected.size) return undefined;
    if (value.evaluations.some((evaluation) => !expected.has(evaluation.candidateId))) return undefined;
    return value;
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code !== "ENOENT") {
      logEvent("offline_harness.judge_cache_rejected", { path, error_kind: errorKind(error) });
    }
    return undefined;
  }
}

function offlineConfig(options: CliOptions): AppConfig {
  const model = splitModel(options.modelRef);
  const executionModel = splitModel(options.executionModelRef);
  if (model.provider !== executionModel.provider) throw new Error("Planner and execution models must use the same provider.");
  return loadConfig({
    ...process.env,
    NODE_ENV: "test",
    SLACK_SOCKET_MODE: "false",
    SLACK_BOT_TOKEN: "offline-not-used",
    SLACK_SIGNING_SECRET: "offline-not-used",
    CEREBRO_BASE_URL: "https://offline.invalid",
    CEREBRO_TENANT_ID: "offline-harness",
    CEREBRO_READ_API_KEY: "offline-not-used",
    CEREBRO_DEFAULT_RUNTIME_IDS: "",
    CEREBRO_ASSISTANT_HELP_MENTION: "",
    CEREBRO_ASSISTANT_RUNTIME: "flue",
    CEREBRO_TRIAGE_TIMEOUT_MS: "300000",
    CEREBRO_TRIAGE_MAX_CONCURRENT: String(options.concurrency),
    PI_ENABLED: "true",
    PI_PROVIDER: model.provider,
    PI_MODEL: model.model,
    PI_THINKING_LEVEL: options.thinking,
    PI_EXECUTION_MODEL: executionModel.model,
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
  let corpus = "evals/assistant-hard-corpus.jsonl";
  let modelRef = DEFAULT_MODEL;
  let executionModelRef = DEFAULT_MODEL;
  let thinking: ThinkingLevel = "high";
  let executionThinking: ThinkingLevel = "medium";
  let concurrency = 1;
  let heldOut = false;
  let refresh = false;
  let reportRoot = DEFAULT_REPORT_ROOT;
  let limit: number | undefined;
  let conversationBucket = process.env.CEREBRO_IMPROVEMENT_ARTIFACT_BUCKET?.trim() || undefined;
  let conversationLimit = 100;
  const candidateIds: string[] = [];
  const caseIds = new Set<string>();
  for (let index = 0; index < args.length; index += 1) {
    const arg = args[index];
    if (arg === "--held-out") { heldOut = true; continue; }
    if (arg === "--refresh") { refresh = true; continue; }
    if (arg === "--all-candidates") { candidateIds.push(...OFFLINE_ASSISTANT_POLICY_CANDIDATES.map((item) => item.id)); continue; }
    if (arg === "--corpus") { corpus = requiredArg(args, ++index, arg); continue; }
    if (arg === "--model") { modelRef = requiredArg(args, ++index, arg); continue; }
    if (arg === "--execution-model") { executionModelRef = requiredArg(args, ++index, arg); continue; }
    if (arg === "--thinking") { thinking = thinkingLevel(requiredArg(args, ++index, arg)); continue; }
    if (arg === "--execution-thinking") { executionThinking = thinkingLevel(requiredArg(args, ++index, arg)); continue; }
    if (arg === "--concurrency") { concurrency = Number(requiredArg(args, ++index, arg)); continue; }
    if (arg === "--candidate") { candidateIds.push(requiredArg(args, ++index, arg)); continue; }
    if (arg === "--case") { caseIds.add(requiredArg(args, ++index, arg)); continue; }
    if (arg === "--limit") { limit = Number(requiredArg(args, ++index, arg)); continue; }
    if (arg === "--report-root") { reportRoot = resolve(requiredArg(args, ++index, arg)); continue; }
    if (arg === "--conversation-bucket") { conversationBucket = requiredArg(args, ++index, arg); continue; }
    if (arg === "--conversation-limit") { conversationLimit = Number(requiredArg(args, ++index, arg)); continue; }
    throw new Error(`Unknown argument ${arg}.`);
  }
  if (candidateIds.length === 0) candidateIds.push("production");
  requireOpus(modelRef, "Planner");
  requireOpus(executionModelRef, "Execution");
  if (!Number.isInteger(concurrency) || concurrency < 1 || concurrency > 4) throw new Error("Concurrency must be an integer from 1 through 4.");
  if (limit !== undefined && (!Number.isInteger(limit) || limit < 1)) throw new Error("Limit must be a positive integer.");
  if (!Number.isInteger(conversationLimit) || conversationLimit < 1 || conversationLimit > 500) throw new Error("Conversation limit must be an integer from 1 through 500.");
  return {
    corpus, modelRef, executionModelRef, thinking, executionThinking, concurrency, heldOut,
    candidateIds: unique(candidateIds), caseIds, limit, refresh, reportRoot, conversationBucket, conversationLimit,
  };
}

function candidateScores(
  candidates: AssistantPolicyCandidate[],
  cases: AssistantHardCorpusCase[],
  judgments: OfflineCaseJudgment[],
): OfflineCandidateScore[] {
  const partitions = [...new Set(cases.map((item) => item.partition))];
  const partitionByCase = new Map(cases.map((item) => [item.id, item.partition]));
  return candidates.flatMap((candidate) => partitions.map((partition) => {
    const selected = judgments.filter((judgment) => partitionByCase.get(judgment.caseId) === partition);
    const evaluations = selected.flatMap((judgment) => judgment.evaluations.filter((item) => item.candidateId === candidate.id));
    const failureModes = evaluations.flatMap((item) => item.failureModes).reduce<Record<string, number>>((counts, failure) => {
      counts[failure] = (counts[failure] ?? 0) + 1;
      return counts;
    }, {});
    return {
      candidateId: candidate.id,
      partition,
      caseCount: evaluations.length,
      passed: evaluations.filter((item) => item.pass).length,
      passRate: ratio(evaluations.filter((item) => item.pass).length, evaluations.length),
      averageScore: average(evaluations.map((item) => item.overallScore)),
      severeFailures: evaluations.filter((item) => item.severeFailure).length,
      wins: selected.filter((judgment) => judgment.winnerCandidateId === candidate.id).length,
      ties: selected.filter((judgment) => judgment.tie).length,
      failureModes,
    };
  }));
}

function developmentSelection(
  candidates: AssistantPolicyCandidate[],
  cases: AssistantHardCorpusCase[],
  scores: OfflineCandidateScore[],
) {
  if (candidates.length < 2 || !["train", "validation"].every((partition) => cases.some((item) => item.partition === partition))) return undefined;
  const ranked = candidates.map((candidate) => candidateAggregate(candidate.id, scores)).sort(compareCandidateAggregate);
  const winner = ranked[0];
  return winner ? {
    winnerId: winner.candidateId,
    reason: "Selected from blind Opus judgments across train and validation responses.",
    candidates: ranked,
  } : undefined;
}

function heldOutResult(candidates: AssistantPolicyCandidate[], scores: OfflineCandidateScore[], caseCount: number): boolean | undefined {
  if (candidates.length !== 2 || caseCount < 8) return undefined;
  const baseline = candidateAggregate(candidates[0]!.id, scores);
  const candidate = candidateAggregate(candidates[1]!.id, scores);
  return candidate.wins > baseline.wins
    && candidate.passRate >= baseline.passRate
    && candidate.averageScore >= baseline.averageScore
    && candidate.severeFailures <= baseline.severeFailures;
}

function renderMarkdown(report: {
  phase: string;
  corpus_digest: string;
  model: string;
  execution_model: string;
  evaluated_case_count: number;
  scores: OfflineCandidateScore[];
  selection?: { winnerId: string };
  promotion_ready?: boolean;
}): string {
  return [
    "# Offline assistant evaluation",
    "",
    `Phase: ${report.phase}`,
    `Corpus: \`${report.corpus_digest}\``,
    `Cases: ${report.evaluated_case_count}`,
    `Planner model: \`${report.model}\``,
    `Execution model: \`${report.execution_model}\``,
    report.selection ? `Selected candidate: \`${report.selection.winnerId}\`` : "",
    report.promotion_ready === undefined ? "" : `Promotion ready: ${report.promotion_ready ? "yes" : "no"}`,
    "",
    "| Candidate | Partition | Pass rate | Score | Wins | Severe failures |",
    "| --- | --- | ---: | ---: | ---: | ---: |",
    ...report.scores.map((score) => `| ${score.candidateId} | ${score.partition} | ${percent(score.passRate)} | ${score.averageScore.toFixed(1)} | ${score.wins} | ${score.severeFailures} |`),
    "",
  ].filter((line, index, lines) => line !== "" || lines[index - 1] !== "").join("\n");
}

function failureJsonl(results: OfflineAssistantRunResult[], judgments: OfflineCaseJudgment[]): string {
  const runs = new Map(results.map((result) => [`${result.caseId}\0${result.candidateId}`, result]));
  const lines = judgments.flatMap((judgment) => judgment.evaluations.filter((evaluation) => !evaluation.pass).map((evaluation) => {
    const run = runs.get(`${judgment.caseId}\0${evaluation.candidateId}`);
    return JSON.stringify({
      schema_version: 1,
      case_id: judgment.caseId,
      candidate_id: evaluation.candidateId,
      score: evaluation.overallScore,
      severe_failure: evaluation.severeFailure,
      failure_modes: evaluation.failureModes,
      actionable_feedback: evaluation.actionableFeedback,
      answer: run?.observation.answer,
      next_actions: run?.observation.next_actions,
      source_calls: run?.trace.calls,
      delivery: run?.delivery,
    });
  }));
  return lines.length > 0 ? `${lines.join("\n")}\n` : "";
}

function candidateAggregate(candidateId: string, scores: OfflineCandidateScore[]) {
  const selected = scores.filter((score) => score.candidateId === candidateId);
  const caseCount = selected.reduce((sum, score) => sum + score.caseCount, 0);
  return {
    candidateId,
    caseCount,
    passed: selected.reduce((sum, score) => sum + score.passed, 0),
    passRate: ratio(selected.reduce((sum, score) => sum + score.passed, 0), caseCount),
    averageScore: ratio(selected.reduce((sum, score) => sum + score.averageScore * score.caseCount, 0), caseCount),
    severeFailures: selected.reduce((sum, score) => sum + score.severeFailures, 0),
    wins: selected.reduce((sum, score) => sum + score.wins, 0),
    ties: selected.reduce((sum, score) => sum + score.ties, 0),
  };
}

function compareCandidateAggregate(left: ReturnType<typeof candidateAggregate>, right: ReturnType<typeof candidateAggregate>): number {
  if (left.severeFailures !== right.severeFailures) return left.severeFailures - right.severeFailures;
  if (left.wins !== right.wins) return right.wins - left.wins;
  if (left.passRate !== right.passRate) return right.passRate - left.passRate;
  if (left.averageScore !== right.averageScore) return right.averageScore - left.averageScore;
  return left.candidateId.localeCompare(right.candidateId);
}

async function loadCorpus(path: string): Promise<AssistantHardCorpusCase[]> {
  const raw = await readFile(resolve(path), "utf8");
  return raw.split(/\r?\n/).map((line) => line.trim()).filter(Boolean).map((line, index) => {
    try { return parseAssistantHardCorpusLine(JSON.parse(line)); }
    catch (error) { throw new Error(`Invalid hard corpus line ${index + 1}: ${errorMessage(error)}`); }
  });
}

function mergeCorpus(staticCases: AssistantHardCorpusCase[], conversationCases: AssistantHardCorpusCase[]): AssistantHardCorpusCase[] {
  const result = new Map(staticCases.map((item) => [item.id, item]));
  for (const item of conversationCases) if (item.partition !== "held_out" && !result.has(item.id)) result.set(item.id, item);
  return [...result.values()];
}

function resolveCandidates(ids: string[]): AssistantPolicyCandidate[] {
  return ids.map((id) => {
    const candidate = OFFLINE_ASSISTANT_POLICY_CANDIDATES.find((item) => item.id === id);
    if (!candidate) throw new Error(`Unknown candidate ${id}. Available candidates: ${OFFLINE_ASSISTANT_POLICY_CANDIDATES.map((item) => item.id).join(", ")}.`);
    return candidate;
  });
}

function splitModel(value: string): { provider: string; model: string } {
  const separator = value.indexOf("/");
  if (separator < 1 || separator === value.length - 1) throw new Error("Model must use provider/model format.");
  return { provider: value.slice(0, separator), model: value.slice(separator + 1) };
}

function requireOpus(value: string, label: string): void {
  if (!value.toLowerCase().includes("anthropic.claude-opus")) throw new Error(`${label} model must be an Anthropic Claude Opus model.`);
}

function thinkingLevel(value: string): ThinkingLevel {
  if (["off", "minimal", "low", "medium", "high", "xhigh"].includes(value)) return value as ThinkingLevel;
  throw new Error(`Unknown thinking level ${value}.`);
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

function requiredArg(args: string[], index: number, flag: string): string {
  const value = args[index];
  if (!value) throw new Error(`${flag} requires a value.`);
  return value;
}

function unique(values: string[]): string[] { return [...new Set(values)]; }
function average(values: number[]): number { return values.length > 0 ? values.reduce((sum, value) => sum + value, 0) / values.length : 0; }
function ratio(numerator: number, denominator: number): number { return denominator > 0 ? numerator / denominator : 0; }
function percent(value: number): string { return `${Math.round(value * 1_000) / 10}%`; }
function errorKind(error: unknown): string { return error instanceof Error ? error.name : "unknown"; }
function errorMessage(error: unknown): string { return error instanceof Error ? error.message : String(error); }
function logEvent(event: string, fields: Record<string, unknown>): void { process.stdout.write(`${JSON.stringify({ event, ...fields })}\n`); }

main().catch((error) => {
  logEvent("offline_harness.failed", { error_kind: errorKind(error), message: errorMessage(error) });
  process.exitCode = 1;
});
