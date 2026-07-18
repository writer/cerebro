import { mkdir, readFile, writeFile } from "node:fs/promises";
import { resolve } from "node:path";
import { Agent, type ThinkingLevel } from "@earendil-works/pi-agent-core";
import { builtinModels } from "@earendil-works/pi-ai/providers/all";
import {
  ASSISTANT_POLICY_CANDIDATES,
  assistantHillClimbObservationKey,
  hardCorpusDigest,
  heldOutPromotionReady,
  parseAssistantHardCorpusLine,
  parseAssistantHillClimbObservation,
  scoreAssistantHardCase,
  selectAssistantHillClimbWinner,
  summarizeAssistantCandidate,
  type AssistantCandidateScore,
  type AssistantHardCorpusCase,
  type AssistantHardCaseReceipt,
  type AssistantHillClimbObservation,
  type AssistantPolicyCandidate,
} from "../src/learning/assistant-hillclimb.js";
import { latestAssistantText } from "../src/agent/security-assistant-transcript.js";
import { loadConversationCorpusCases } from "../src/learning/assistant-conversation-corpus.js";

const DEFAULT_MODEL = "amazon-bedrock/us.anthropic.claude-opus-4-8";
const REPORT_ROOT = resolve("tmp/assistant-hillclimb");

interface CliOptions {
  corpus: string;
  provider: string;
  model: string;
  modelRef: string;
  thinking: ThinkingLevel;
  concurrency: number;
  developmentOnly: boolean;
  conversationBucket?: string;
  conversationLimit: number;
}

interface EvaluatedCandidate {
  candidate: AssistantPolicyCandidate;
  receipts: AssistantHardCaseReceipt[];
  observations: Array<{ caseId: string; partition: AssistantHardCorpusCase["partition"]; observation: AssistantHillClimbObservation }>;
}

async function main(): Promise<void> {
  const options = parseArgs(process.argv.slice(2));
  const staticCases = await loadCorpus(options.corpus);
  const conversationCases = options.conversationBucket
    ? await loadConversationCorpusCases({ bucket: options.conversationBucket, limit: options.conversationLimit })
    : [];
  const cases = mergeCorpus(staticCases, conversationCases);
  assertCorpusShape(cases);
  const digest = hardCorpusDigest(cases);
  const cacheDirs = [
    resolve(REPORT_ROOT, "cache", "observations"),
    resolve(REPORT_ROOT, "cache", digest),
    resolve(REPORT_ROOT, "cache", hardCorpusDigest(staticCases)),
  ];
  await mkdir(cacheDirs[0] as string, { recursive: true });

  logEvent("hillclimb.started", {
    corpus_digest: digest,
    case_count: cases.length,
    development_case_count: cases.filter((item) => item.partition !== "held_out").length,
    held_out_case_count: cases.filter((item) => item.partition === "held_out").length,
    candidate_count: ASSISTANT_POLICY_CANDIDATES.length,
    static_case_count: staticCases.length,
    conversation_case_count: conversationCases.length,
    model: options.modelRef,
    thinking: options.thinking,
  });

  const developmentCases = cases.filter((item) => item.partition !== "held_out");
  const development = await mapLimit(
    ASSISTANT_POLICY_CANDIDATES,
    1,
    (candidate) => evaluateCandidate(candidate, developmentCases, options, cacheDirs),
  );
  const developmentScores = development.flatMap(({ candidate, receipts }) => [
    summarizeAssistantCandidate(candidate.id, "train", receipts),
    summarizeAssistantCandidate(candidate.id, "validation", receipts),
  ]);
  const selection = selectAssistantHillClimbWinner(ASSISTANT_POLICY_CANDIDATES, developmentScores);
  const developmentReport = {
    schema_version: 1,
    phase: "development",
    corpus_digest: digest,
    model: options.modelRef,
    thinking: options.thinking,
    selection,
    scores: developmentScores,
    cases: development.flatMap(({ receipts }) => receipts),
    observations: development.flatMap(({ candidate, observations }) => observations.map((item) => ({ candidate_id: candidate.id, ...item }))),
  };
  await writeReports("development", digest, developmentReport, renderDevelopmentMarkdown(developmentReport));
  logEvent("hillclimb.development_completed", { winner_id: selection.winnerId, accepted: selection.accepted, rejected: selection.rejected });

  if (options.developmentOnly) {
    logEvent("hillclimb.stopped_before_held_out", { report: reportPath("development", digest, "json") });
    return;
  }

  const baseline = ASSISTANT_POLICY_CANDIDATES[0];
  const winner = ASSISTANT_POLICY_CANDIDATES.find((candidate) => candidate.id === selection.winnerId);
  if (!baseline || !winner) throw new Error("Hillclimb selection did not resolve baseline and winner candidates.");
  const heldOutCases = cases.filter((item) => item.partition === "held_out");
  const heldCandidates = baseline.id === winner.id ? [baseline] : [baseline, winner];
  const heldOut = await mapLimit(heldCandidates, 1, (candidate) => evaluateCandidate(candidate, heldOutCases, options, cacheDirs));
  const heldScores = heldOut.map(({ candidate, receipts }) => summarizeAssistantCandidate(candidate.id, "held_out", receipts));
  const baselineScore = requiredScore(heldScores, baseline.id);
  const winnerScore = requiredScore(heldScores, winner.id);
  const promotionReady = heldOutPromotionReady({ baseline: baselineScore, winner: winnerScore });
  const finalReport = {
    schema_version: 1,
    phase: "held_out",
    corpus_digest: digest,
    model: options.modelRef,
    thinking: options.thinking,
    selection,
    development_scores: developmentScores,
    held_out_scores: heldScores,
    held_out_cases: heldOut.flatMap(({ receipts }) => receipts),
    promotion_ready: promotionReady,
  };
  await writeReports("held-out", digest, finalReport, renderHeldOutMarkdown(finalReport));
  logEvent("hillclimb.held_out_completed", {
    winner_id: winner.id,
    baseline_score: baselineScore.averageScore,
    winner_score: winnerScore.averageScore,
    baseline_blockers: baselineScore.hardBlockerCount,
    winner_blockers: winnerScore.hardBlockerCount,
    promotion_ready: promotionReady,
  });
  if (!promotionReady) process.exitCode = 1;
}

async function evaluateCandidate(
  candidate: AssistantPolicyCandidate,
  cases: AssistantHardCorpusCase[],
  options: CliOptions,
  cacheDirs: string[],
): Promise<EvaluatedCandidate> {
  logEvent("hillclimb.candidate_started", { candidate_id: candidate.id, case_count: cases.length });
  const observations = await mapLimit(cases, options.concurrency, async (item) => ({
    caseId: item.id,
    partition: item.partition,
    observation: await observe(candidate, item, options, cacheDirs),
  }));
  const receipts = observations.map(({ caseId, observation }) => {
    const item = cases.find((candidateCase) => candidateCase.id === caseId);
    if (!item) throw new Error(`Missing corpus case ${caseId}.`);
    return scoreAssistantHardCase(item, candidate.id, observation);
  });
  logEvent("hillclimb.candidate_completed", {
    candidate_id: candidate.id,
    passed: receipts.filter((receipt) => receipt.passed).length,
    case_count: receipts.length,
    blocker_count: receipts.reduce((sum, receipt) => sum + receipt.blockers.length, 0),
  });
  return { candidate, receipts, observations };
}

async function observe(candidate: AssistantPolicyCandidate, item: AssistantHardCorpusCase, options: CliOptions, cacheDirs: string[]): Promise<AssistantHillClimbObservation> {
  const protocolPrompt = systemPrompt(candidate);
  const cacheKey = assistantHillClimbObservationKey({ model: options.modelRef, thinking: options.thinking, candidate, item, protocolPrompt });
  const cachePath = resolve(cacheDirs[0] as string, `${cacheKey}.json`);
  for (const cacheDir of [...new Set(cacheDirs)]) {
    try {
      const cached = parseAssistantHillClimbObservation(JSON.parse(await readFile(resolve(cacheDir, `${cacheKey}.json`), "utf8")));
      if (cacheDir !== cacheDirs[0]) await writeFile(cachePath, `${JSON.stringify(cached, null, 2)}\n`, "utf8");
      return cached;
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code !== "ENOENT") {
        logEvent("hillclimb.cache_rejected", { candidate_id: candidate.id, case_id: item.id, error_kind: errorKind(error) });
      }
    }
  }

  const models = builtinModels();
  const model = models.getModel(options.provider, options.model);
  if (!model) throw new Error(`Model ${options.modelRef} is not available.`);
  const agent = new Agent({
    initialState: {
      systemPrompt: protocolPrompt,
      model,
      thinkingLevel: options.thinking,
      tools: [],
    },
    streamFn: (requestModel, context, requestOptions) => models.streamSimple(requestModel, context, requestOptions),
  });
  const timeout = setTimeout(() => agent.abort(), 180_000);
  const startedAt = Date.now();
  timeout.unref?.();
  try {
    await agent.prompt(userPrompt(item));
  } finally {
    clearTimeout(timeout);
  }
  if (agent.state.errorMessage) throw new Error(`Candidate ${candidate.id} case ${item.id} failed: ${agent.state.errorMessage}`);
  const raw = latestAssistantText(agent.state.messages);
  const parsed = parseAssistantHillClimbObservation(parseJsonObject(raw));
  const observation = parseAssistantHillClimbObservation({
    ...parsed,
    latency_ms: Date.now() - startedAt,
    human_follow_ups: clarifyingQuestionCount(parsed.answer),
  });
  await writeFile(cachePath, `${JSON.stringify(observation, null, 2)}\n`, "utf8");
  logEvent("hillclimb.case_completed", { candidate_id: candidate.id, case_id: item.id, partition: item.partition });
  return observation;
}

function systemPrompt(candidate: AssistantPolicyCandidate): string {
  return [
    "You are Cerebro, a helpful company security teammate responding in Slack.",
    "Answer the human request using only the supplied thread and evidence. Do not claim actions or checks that are absent.",
    "The sender_kind field is authoritative. For sender_kind=human, disposition must be respond and the answer must never be [IGNORE], even when evidence is empty or the request is terse, frustrated, or conversational. [IGNORE] is available only for sender_kind=bot.",
    "Machine digests should be ignored unless the thread contains an explicit human request to analyze one.",
    "Private specialist work may inform the answer but must never be mentioned as roles, receipts, orchestration, or internal errors.",
    ...candidate.instructions.map((instruction) => `- ${instruction}`),
    "Return one JSON object only with this exact shape:",
    "For each factual conclusion, copy the narrowest subject id from the evidence packet into subject_bindings. Keep every status, timestamp, count, and owner attached to that subject.",
    '{"answer":"Slack-ready answer or [IGNORE]","disposition":"respond|ignore","cited_receipts":["completed evidence receipt ids only"],"next_actions":["concrete next action already supported by evidence"],"subject_bindings":[{"claim":"factual conclusion","subject":"exact subject id from evidence"}],"specialist_work":[{"role":"librarian|researcher|analyst|coordinator|triage|qa|developer|compliance","status":"completed|blocked","findings":[],"recommendations":[],"actions":[],"checks":[],"blockers":[],"evidence_receipts":[]}]}'
  ].join("\n");
}

function userPrompt(item: AssistantHardCorpusCase): string {
  return JSON.stringify({
    case_id: item.id,
    sender_kind: item.senderKind,
    question: item.question,
    thread_context: item.threadContext,
    evidence_packets: item.evidence,
    assigned_specialists: item.assignedRoles,
  });
}

async function loadCorpus(path: string): Promise<AssistantHardCorpusCase[]> {
  const raw = await readFile(resolve(path), "utf8");
  return raw.split(/\r?\n/).map((line) => line.trim()).filter(Boolean).map((line, index) => {
    try { return parseAssistantHardCorpusLine(JSON.parse(line)); }
    catch (error) { throw new Error(`Invalid hard corpus line ${index + 1}: ${errorMessage(error)}`); }
  });
}

function assertCorpusShape(cases: AssistantHardCorpusCase[]): void {
  const ids = new Set(cases.map((item) => item.id));
  const challenges = new Set(cases.map((item) => item.challenge));
  const counts = { train: 0, validation: 0, held_out: 0, difficultyFive: 0 };
  for (const item of cases) {
    counts[item.partition] += 1;
    if (item.difficulty === 5) counts.difficultyFive += 1;
  }
  if (ids.size !== cases.length) throw new Error("Hard corpus case ids must be unique.");
  if (challenges.size < 32) throw new Error("Hard corpus must cover at least 32 distinct challenge classes.");
  if (cases.length < 40 || counts.train < 20 || counts.validation < 10 || counts.held_out < 10 || counts.difficultyFive < 20) {
    throw new Error(`Hard corpus is too small: ${JSON.stringify(counts)} total=${cases.length}.`);
  }
}

function parseArgs(args: string[]): CliOptions {
  let corpus = "evals/assistant-hard-corpus.jsonl";
  let modelRef = DEFAULT_MODEL;
  let thinking: ThinkingLevel = "high";
  let concurrency = 3;
  let developmentOnly = false;
  let conversationBucket = process.env.CEREBRO_IMPROVEMENT_ARTIFACT_BUCKET?.trim() || undefined;
  let conversationLimit = 100;
  for (let index = 0; index < args.length; index += 1) {
    const arg = args[index];
    if (arg === "--development-only") { developmentOnly = true; continue; }
    if (arg === "--corpus") { corpus = requiredArg(args, ++index, arg); continue; }
    if (arg === "--model") { modelRef = requiredArg(args, ++index, arg); continue; }
    if (arg === "--thinking") { thinking = requiredArg(args, ++index, arg) as ThinkingLevel; continue; }
    if (arg === "--concurrency") { concurrency = Number(requiredArg(args, ++index, arg)); continue; }
    if (arg === "--conversation-bucket") { conversationBucket = requiredArg(args, ++index, arg); continue; }
    if (arg === "--conversation-limit") { conversationLimit = Number(requiredArg(args, ++index, arg)); continue; }
    throw new Error(`Unknown argument ${arg}.`);
  }
  if (!modelRef.toLowerCase().includes("anthropic.claude-opus")) throw new Error("The hard-corpus hillclimb requires an Anthropic Claude Opus model.");
  if (!Number.isInteger(concurrency) || concurrency < 1 || concurrency > 8) throw new Error("Concurrency must be an integer from 1 through 8.");
  if (!Number.isInteger(conversationLimit) || conversationLimit < 1 || conversationLimit > 500) throw new Error("Conversation limit must be an integer from 1 through 500.");
  const separator = modelRef.indexOf("/");
  if (separator < 1 || separator === modelRef.length - 1) throw new Error("Model must use provider/model format.");
  return { corpus, provider: modelRef.slice(0, separator), model: modelRef.slice(separator + 1), modelRef, thinking, concurrency, developmentOnly, conversationBucket, conversationLimit };
}

function mergeCorpus(staticCases: AssistantHardCorpusCase[], conversationCases: AssistantHardCorpusCase[]): AssistantHardCorpusCase[] {
  const cases = new Map(staticCases.map((item) => [item.id, item]));
  for (const item of conversationCases) {
    if (item.partition === "held_out") continue;
    if (!cases.has(item.id)) cases.set(item.id, item);
  }
  return [...cases.values()];
}

function requiredArg(args: string[], index: number, flag: string): string {
  const value = args[index];
  if (!value) throw new Error(`${flag} requires a value.`);
  return value;
}

function parseJsonObject(raw: string): unknown {
  const trimmed = raw.trim().replace(/^```(?:json)?\s*/i, "").replace(/\s*```$/, "");
  const start = trimmed.indexOf("{");
  const end = trimmed.lastIndexOf("}");
  if (start < 0 || end <= start) throw new Error("Model did not return a JSON object.");
  return JSON.parse(trimmed.slice(start, end + 1));
}

function clarifyingQuestionCount(answer: string): number {
  return /\b(?:which|what)\s+(?:repository|repo|ticket|project|owner|runtime|source|scope)\b[^?]*\?/i.test(answer)
    || /\b(?:provide|share|send)\b[^?]{0,100}\b(?:scope|details|context|identifier)\b[^?]*\?/i.test(answer) ? 1 : 0;
}

async function mapLimit<T, U>(values: readonly T[], limit: number, worker: (value: T) => Promise<U>): Promise<U[]> {
  const results = new Array<U>(values.length);
  let cursor = 0;
  async function run(): Promise<void> {
    while (cursor < values.length) {
      const index = cursor;
      cursor += 1;
      results[index] = await worker(values[index] as T);
    }
  }
  await Promise.all(Array.from({ length: Math.min(limit, values.length) }, () => run()));
  return results;
}

async function writeReports(phase: string, digest: string, report: unknown, markdown: string): Promise<void> {
  await mkdir(REPORT_ROOT, { recursive: true });
  await Promise.all([
    writeFile(reportPath(phase, digest, "json"), `${JSON.stringify(report, null, 2)}\n`, "utf8"),
    writeFile(reportPath(phase, digest, "md"), markdown, "utf8"),
  ]);
}

function reportPath(phase: string, digest: string, extension: string): string {
  return resolve(REPORT_ROOT, `${phase}-${digest.slice(0, 12)}.${extension}`);
}

function renderDevelopmentMarkdown(report: { corpus_digest: string; model: string; selection: { winnerId: string }; scores: AssistantCandidateScore[] }): string {
  return [
    "# Assistant hard-corpus development result",
    "",
    `Corpus: \`${report.corpus_digest}\``,
    `Model: \`${report.model}\``,
    `Selected candidate: \`${report.selection.winnerId}\``,
    "",
    "| Candidate | Partition | Pass rate | Score | Blockers |",
    "| --- | --- | ---: | ---: | ---: |",
    ...report.scores.map((score) => `| ${score.candidateId} | ${score.partition} | ${percent(score.passRate)} | ${score.averageScore.toFixed(3)} | ${score.hardBlockerCount} |`),
    "",
    "Held-out cases were not run for this report.",
    "",
  ].join("\n");
}

function renderHeldOutMarkdown(report: { corpus_digest: string; model: string; selection: { winnerId: string }; held_out_scores: AssistantCandidateScore[]; promotion_ready: boolean }): string {
  return [
    "# Assistant hard-corpus held-out result",
    "",
    `Corpus: \`${report.corpus_digest}\``,
    `Model: \`${report.model}\``,
    `Selected candidate: \`${report.selection.winnerId}\``,
    `Promotion ready: ${report.promotion_ready ? "yes" : "no"}`,
    "",
    "| Candidate | Pass rate | Score | Blockers |",
    "| --- | ---: | ---: | ---: |",
    ...report.held_out_scores.map((score) => `| ${score.candidateId} | ${percent(score.passRate)} | ${score.averageScore.toFixed(3)} | ${score.hardBlockerCount} |`),
    "",
  ].join("\n");
}

function requiredScore(scores: AssistantCandidateScore[], candidateId: string): AssistantCandidateScore {
  const score = scores.find((item) => item.candidateId === candidateId);
  if (!score) throw new Error(`Missing held-out score for ${candidateId}.`);
  return score;
}

function percent(value: number): string { return `${Math.round(value * 1_000) / 10}%`; }
function errorKind(error: unknown): string { return error instanceof Error ? error.name : "unknown"; }
function errorMessage(error: unknown): string { return error instanceof Error ? error.message : String(error); }
function logEvent(event: string, fields: Record<string, unknown>): void { process.stdout.write(`${JSON.stringify({ event, ...fields })}\n`); }

main().catch((error) => {
  logEvent("hillclimb.failed", { error_kind: errorKind(error), message: errorMessage(error) });
  process.exitCode = 1;
});
