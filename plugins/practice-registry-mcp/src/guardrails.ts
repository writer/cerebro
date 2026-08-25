import { minimatch } from "minimatch";
import type {
  PracticeGuardrail,
  PracticeGuardrailInput,
  PracticeGuardrailResult,
  PracticeRecord,
  PracticeStatus,
} from "./schema.js";

const statusRank = new Map<PracticeStatus, number>([
  ["banned", 70],
  ["discouraged", 55],
  ["legacy_accepted", 50],
  ["needs_review", 45],
  ["allowed_with_context", 35],
  ["preferred", 25],
  ["allowed", 10],
]);

export function getGuardrails(records: PracticeRecord[], input: PracticeGuardrailInput = {}): PracticeGuardrailResult {
  const files = normalizeFiles(input.files ?? []);
  const language = normalizeTerm(input.language) ?? inferLanguageFromFiles(files);
  const framework = normalizeTerm(input.framework);
  const query = normalizeText([input.repo, input.intent, input.topic, ...(input.dependencies ?? [])]);
  const limit = clamp(input.max_practices ?? 12, 1, 25);

  const scored = records
    .map((record) => scoreRecord(record, { files, framework, language, query }))
    .filter((practice): practice is PracticeGuardrail & { score: number; topical: boolean } => practice !== undefined);
  const topical = query ? scored.filter((practice) => practice.topical) : [];
  const pool = query ? topical : scored;
  const practices = pool
    .sort((left, right) => right.score - left.score || left.id.localeCompare(right.id))
    .slice(0, limit)
    .map(({ score: _score, topical: _topical, ...practice }) => practice);

  return {
    summary: summarize(practices),
    next_steps: nextSteps(practices),
    agent_contract: [
      "Call server_info when you need to confirm the active contract version.",
      "Call check_plan before generating non-trivial Scala, Python, TypeScript, JavaScript, or Rust code.",
      "Trust the passed field. Only allowed and follow_guidance are pass decisions.",
      "Take the listed next_steps when a result returns change_code, revise_or_justify, ask_owner, or needs_review.",
      "Run finalize_change on the final diff before summarizing the work.",
      "Do not treat an unlisted pattern as approved. Ask the owner or add a practice record.",
    ],
    practices,
  };
}

function scoreRecord(
  record: PracticeRecord,
  context: { files: string[]; framework?: string; language?: string; query: string },
): (PracticeGuardrail & { score: number; topical: boolean }) | undefined {
  const reasons: string[] = [];
  let score = statusRank.get(record.status) ?? 0;
  let topical = false;

  const scopedLanguages = normalizeTerms(record.scope.languages);
  if (context.language && scopedLanguages.length > 0 && !scopedLanguages.includes(context.language)) {
    return undefined;
  }
  if (context.language && scopedLanguages.includes(context.language)) {
    score += 35;
    reasons.push(`language: ${context.language}`);
  }

  const scopedFrameworks = normalizeTerms(record.scope.frameworks);
  if (context.framework && scopedFrameworks.length > 0 && !scopedFrameworks.includes(context.framework)) {
    return undefined;
  }
  if (context.framework && scopedFrameworks.includes(context.framework)) {
    score += 20;
    reasons.push(`framework: ${context.framework}`);
  }

  const pathScore = scorePaths(record, context.files);
  if (pathScore.excluded) {
    return undefined;
  }
  score += pathScore.score;
  reasons.push(...pathScore.reasons);

  const queryHits = context.query
    ? hits(
        [
          record.id,
          record.title,
          record.summary,
          record.rationale,
          ...record.applies_when.intents,
          ...record.applies_when.keywords,
          ...record.avoid,
          ...record.use_instead,
        ],
        context.query,
      )
    : [];
  if (context.query && queryHits.length === 0 && !context.language && context.files.length === 0) {
    return undefined;
  }
  if (queryHits.length > 0) {
    score += Math.min(50, queryHits.length * 10);
    reasons.push(`topic: ${queryHits.slice(0, 5).join(", ")}`);
    topical = true;
  }

  return {
    id: record.id,
    title: record.title,
    status: record.status,
    enforcement: record.enforcement,
    relevance: relevanceFor(score, topical),
    summary: record.summary,
    owner: record.owner,
    source_file: record.source_file,
    scope: record.scope,
    avoid: record.avoid,
    use_instead: record.use_instead,
    reasons,
    score,
    topical,
  };
}

function scorePaths(record: PracticeRecord, files: string[]): { score: number; reasons: string[]; excluded: boolean } {
  const include = record.scope.paths.include;
  const exclude = record.scope.paths.exclude;
  if (files.length === 0) {
    return { score: 0, reasons: [], excluded: false };
  }

  const excluded = files.some((file) => exclude.some((pattern) => minimatch(file, pattern, { dot: true })));
  if (excluded) {
    return { score: 0, reasons: [], excluded: true };
  }

  if (include.length === 0) {
    return { score: 8, reasons: ["path: any"], excluded: false };
  }

  const matched = files.filter((file) => include.some((pattern) => minimatch(file, pattern, { dot: true })));
  if (matched.length === 0) {
    return { score: 0, reasons: [], excluded: false };
  }

  return {
    score: 25,
    reasons: [`path: ${matched.slice(0, 3).join(", ")}`],
    excluded: false,
  };
}

function summarize(practices: PracticeGuardrail[]): string {
  if (practices.length === 0) {
    return "No matching practice records. Ask the owning team or add a practice before treating this as approved.";
  }

  const blocking = practices.filter((practice) => practice.status === "banned" || practice.enforcement === "blocking").length;
  const review = practices.filter((practice) => practice.status === "needs_review" || practice.enforcement === "review").length;
  return `${practices.length} practice records matched. ${blocking} blocking. ${review} need review.`;
}

function nextSteps(practices: PracticeGuardrail[]): string[] {
  if (practices.length === 0) {
    return [
      "Ask the owning team for a decision before generating code.",
      "Add a practice record when the decision should be reused.",
    ];
  }

  const firstBlocking = practices.find((practice) => practice.status === "banned" || practice.enforcement === "blocking");
  return [
    firstBlocking ? `Handle first: ${firstBlocking.id}.` : `Start with: ${practices[0].id}.`,
    "Call check_plan with the planned approach before writing code.",
    "Run finalize_change on the final diff.",
  ];
}

function hits(candidates: string[], query: string): string[] {
  const queryTerms = new Set(
    (query.match(/[a-z0-9_]+/g) ?? []).filter((term) => term.length >= 3 && !topicStopWords.has(term)),
  );
  const found = new Set<string>();
  for (const candidate of candidates) {
    const candidateTerms = new Set(normalizeText([candidate]).match(/[a-z0-9_]+/g) ?? []);
    for (const term of queryTerms) {
      if (candidateTerms.has(term)) {
        found.add(term);
      }
    }
  }
  return [...found];
}

const topicStopWords = new Set([
  "add",
  "and",
  "change",
  "changes",
  "code",
  "create",
  "helper",
  "implement",
  "implementation",
  "new",
  "plan",
  "result",
  "results",
  "the",
  "update",
  "use",
  "using",
  "with",
]);

function normalizeText(values: Array<string | undefined>): string {
  return values
    .filter((value): value is string => Boolean(value))
    .join(" ")
    .toLowerCase();
}

function normalizeTerm(value: string | undefined): string | undefined {
  return value?.trim().toLowerCase() || undefined;
}

function normalizeTerms(values: string[]): string[] {
  return values.map((value) => value.trim().toLowerCase()).filter(Boolean);
}

function normalizeFiles(files: string[]): string[] {
  return files.map((file) => file.replace(/\\/g, "/").replace(/^\.?\//, ""));
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
  const languages = new Set<string>(
    values.filter((value): value is string => Boolean(value)),
  );
  return languages.size === 1 ? [...languages][0] : undefined;
}

function relevanceFor(score: number, topical: boolean): "high" | "medium" | "low" {
  if (topical && score >= 80) {
    return "high";
  }
  if (score >= 70) {
    return "medium";
  }
  return "low";
}

function clamp(value: number, minimum: number, maximum: number): number {
  return Math.max(minimum, Math.min(maximum, value));
}
