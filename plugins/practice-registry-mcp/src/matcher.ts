import { matchesRepoPattern, normalizeRepoPath } from "./filePaths.js";
import { parseAddedLines, type AddedLine } from "./scan.js";
import { outcomeForDecision } from "./outcome.js";
import type {
  PracticeCheckInput,
  PracticeCheckResult,
  PracticeDecision,
  PracticeMatch,
  PracticeRecord,
} from "./schema.js";

const statusRank = new Map([
  ["banned", 6],
  ["legacy_accepted", 5],
  ["discouraged", 4],
  ["needs_review", 3],
  ["allowed_with_context", 2],
  ["preferred", 1],
  ["allowed", 0],
]);

export function checkPractices(records: PracticeRecord[], input: PracticeCheckInput): PracticeCheckResult {
  const files = normalizeFiles(input.files ?? []).concat(extractFilesFromDiff(input.diff ?? ""));
  const languages = normalizeTerms([input.language, ...files.map(inferLanguageFromPath)].filter(Boolean) as string[]);
  const frameworks = normalizeTerms([input.framework].filter(Boolean) as string[]);
  const addedDiffLines = parseAddedLines(input.diff ?? "");
  const narrativeText = normalizeText([
    input.repo,
    input.intent,
    input.planned_approach,
    ...(input.dependencies ?? []),
  ]);
  const codeText = normalizeText([input.proposed_code, ...addedDiffLines.map((line) => line.code)]);
  const text = normalizeText([narrativeText, codeText]);
  const diffOnly = Boolean(input.diff) && !input.intent && !input.planned_approach && !input.proposed_code;

  const matches = records
    .map((record) =>
      scoreRecord(record, {
        ...input,
        files,
        languages,
        frameworks,
        text,
        narrativeText,
        codeText,
        addedDiffLines,
        diffOnly,
      }),
    )
    .filter((match): match is PracticeMatch => match !== undefined)
    .sort((left, right) => {
      const riskDelta = (statusRank.get(right.status) ?? 0) - (statusRank.get(left.status) ?? 0);
      return riskDelta || right.score - left.score || left.id.localeCompare(right.id);
    })
    .slice(0, 8);

  const blocking = matches.some((match) => match.status === "banned" || match.enforcement === "blocking");
  const decision = decide(matches, blocking);

  return {
    decision,
    blocking,
    ...outcomeForDecision(decision),
    summary: summarize(decision, matches),
    next_steps: nextSteps(decision, matches),
    matched_practices: matches,
  };
}

export function searchPractices(records: PracticeRecord[], query: string, filters: Pick<PracticeCheckInput, "language" | "framework" | "files"> = {}): PracticeMatch[] {
  return checkPractices(records, {
    ...filters,
    intent: query,
    planned_approach: query,
  }).matched_practices;
}

function scoreRecord(
  record: PracticeRecord,
  context: PracticeCheckInput & {
    files: string[];
    languages: string[];
    frameworks: string[];
    text: string;
    narrativeText: string;
    codeText: string;
    addedDiffLines: AddedLine[];
    diffOnly: boolean;
  },
): PracticeMatch | undefined {
  let score = 0;
  const reasons: string[] = [];
  let semanticHit = false;

  const scopedLanguages = normalizeTerms(record.scope.languages);
  if (scopedLanguages.length > 0) {
    const overlap = intersection(scopedLanguages, context.languages);
    if (context.languages.length === 0 || overlap.length === 0) {
      return undefined;
    }
    if (overlap.length > 0) {
      score += 30;
      reasons.push(`language: ${overlap.join(", ")}`);
    }
  }

  const scopedFrameworks = normalizeTerms(record.scope.frameworks);
  if (scopedFrameworks.length > 0 && context.frameworks.length > 0) {
    const overlap = intersection(scopedFrameworks, context.frameworks);
    if (overlap.length === 0) {
      return undefined;
    }
    score += 20;
    reasons.push(`framework: ${overlap.join(", ")}`);
  }

  const pathScore = scorePaths(record, context.files);
  if (pathScore.excluded) {
    return undefined;
  }
  score += pathScore.score;
  reasons.push(...pathScore.reasons);

  const riskPatternHits = record.semgrep?.pattern_regex
    ? regexHits(record.semgrep.pattern_regex, [context.text], { ignoreNegated: true })
    : [];
  if (!context.diffOnly && riskPatternHits.length === 0 && compliantHits(record, context.text).length > 0) {
    return undefined;
  }

  if (context.diffOnly) {
    const scopedAddedLines = context.addedDiffLines
      .filter((line) => practiceAppliesToPath(record, line.path))
      .map((line) => line.code);
    if (record.semgrep?.pattern_regex) {
      const patternHits = regexHits(record.semgrep.pattern_regex, scopedAddedLines);
      if (patternHits.length > 0) {
        score += 60;
        reasons.push(`changed line: ${patternHits.length} pattern ${patternHits.length === 1 ? "match" : "matches"}`);
        semanticHit = true;
      }
    } else {
      const keywordHits = hits(record.applies_when.keywords, normalizeText(scopedAddedLines), { ignoreNegated: true });
      if (keywordHits.length > 0) {
        score += Math.min(50, keywordHits.length * 10);
        reasons.push(`changed line keyword: ${keywordHits.slice(0, 5).join(", ")}`);
        semanticHit = true;
      }
    }
  } else {
    const intentTerms =
      riskPatternHits.length === 0 && (record.status === "banned" || record.enforcement === "blocking")
        ? []
        : record.applies_when.intents;
    const intentHits = hits(intentTerms, context.narrativeText, { ignoreNegated: true });
    if (intentHits.length > 0) {
      score += Math.min(24, intentHits.length * 8);
      reasons.push(`intent: ${intentHits.join(", ")}`);
      semanticHit = true;
    }

    if (riskPatternHits.length > 0) {
      score += 60;
      reasons.push(`pattern: ${riskPatternHits.length} match${riskPatternHits.length === 1 ? "" : "es"}`);
      semanticHit = true;
    }

    const keywordHits = hits(record.applies_when.keywords, context.text, { ignoreNegated: true });
    if (keywordHits.length > 0) {
      score += Math.min(50, keywordHits.length * 10);
      reasons.push(`keyword: ${keywordHits.slice(0, 5).join(", ")}`);
      semanticHit = true;
    }

    const summaryHits = hits([record.title, record.summary, ...record.avoid, ...record.use_instead], context.narrativeText);
    if (summaryHits.length > 0) {
      score += Math.min(20, summaryHits.length * 5);
      semanticHit = true;
    }
  }

  const hasTriggers =
    record.applies_when.intents.length > 0 ||
    record.applies_when.keywords.length > 0 ||
    Boolean(context.diffOnly && record.semgrep?.pattern_regex);
  if (hasTriggers && !semanticHit) {
    return undefined;
  }

  if (score < 25) {
    return undefined;
  }

  return {
    id: record.id,
    title: record.title,
    status: record.status,
    enforcement: record.enforcement,
    summary: record.summary,
    rationale: record.rationale,
    owner: record.owner,
    source_file: record.source_file,
    use_instead: record.use_instead,
    avoid: record.avoid,
    confidence: score >= 65 ? "high" : score >= 40 ? "medium" : "low",
    score,
    reasons,
  };
}

function regexHits(pattern: string, lines: string[], options: { ignoreNegated?: boolean } = {}): string[] {
  const matches: string[] = [];
  for (const line of lines) {
    try {
      const regex = new RegExp(pattern, "gi");
      let match: RegExpExecArray | null;
      while ((match = regex.exec(line)) !== null) {
        if (!options.ignoreNegated || !isNegatedContext(line, match.index)) {
          matches.push(line);
          break;
        }
        if (match[0] === "") {
          regex.lastIndex += 1;
        }
      }
    } catch {
      continue;
    }
  }
  return matches.slice(0, 3);
}

function scorePaths(record: PracticeRecord, files: string[]): { score: number; reasons: string[]; excluded: boolean } {
  const include = record.scope.paths.include;
  const exclude = record.scope.paths.exclude;
  if (files.length === 0) {
    return { score: 0, reasons: [], excluded: false };
  }

  const candidates = files.filter((file) => !exclude.some((pattern) => matchesRepoPattern(file, pattern)));
  if (candidates.length === 0) {
    return { score: 0, reasons: [], excluded: true };
  }

  if (include.length === 0) {
    return { score: 8, reasons: ["path: any"], excluded: false };
  }

  const matched = candidates.filter((file) => include.some((pattern) => matchesRepoPattern(file, pattern)));
  if (matched.length === 0) {
    return { score: 0, reasons: [], excluded: true };
  }

  return {
    score: 25,
    reasons: [`path: ${matched.slice(0, 3).join(", ")}`],
    excluded: false,
  };
}

function decide(matches: PracticeMatch[], blocking: boolean): PracticeDecision {
  if (matches.length === 0) {
    return "needs_review";
  }
  if (blocking) {
    return "change_code";
  }
  if (matches.some((match) => match.status === "discouraged" || match.status === "legacy_accepted")) {
    return "revise_or_justify";
  }
  if (matches.some((match) => match.status === "needs_review")) {
    return "ask_owner";
  }
  if (matches.some((match) => match.status === "preferred" || match.status === "allowed_with_context")) {
    return "follow_guidance";
  }
  return "allowed";
}

function summarize(decision: PracticeDecision, matches: PracticeMatch[]): string {
  if (matches.length === 0) {
    return "No matching practice is indexed. Ask the owning team or add a practice before treating this as approved.";
  }

  const first = matches[0];
  if (decision === "change_code") {
    return `${first.title}: change the code before proceeding.`;
  }
  if (decision === "revise_or_justify") {
    return `${first.title}: revise the approach or document the accepted context.`;
  }
  if (decision === "ask_owner") {
    return `${first.title}: ask ${first.owner} for a decision.`;
  }
  if (decision === "follow_guidance") {
    return `${first.title}: follow the recorded practice.`;
  }
  return `${first.title}: allowed by the indexed practice.`;
}

function nextSteps(decision: PracticeDecision, matches: PracticeMatch[]): string[] {
  if (matches.length === 0) {
    return [
      "Ask the owning team for a practice decision before treating this as approved.",
      "Add a practice record when this decision should be reused.",
    ];
  }

  const first = matches[0];
  if (decision === "change_code") {
    return compact([
      first.use_instead[0] ? `Use instead: ${first.use_instead[0]}` : undefined,
      "Change the code before continuing.",
      "Run finalize_change on the final diff.",
    ]);
  }
  if (decision === "revise_or_justify") {
    return compact([
      first.use_instead[0] ? `Prefer: ${first.use_instead[0]}` : undefined,
      "Revise the approach or document the accepted context in the change.",
      "Run finalize_change on the final diff.",
    ]);
  }
  if (decision === "ask_owner") {
    return [`Ask ${first.owner} for a decision before continuing.`];
  }
  if (decision === "follow_guidance") {
    return compact([
      first.use_instead[0] ? `Use: ${first.use_instead[0]}` : undefined,
      "Keep the implementation inside the recorded context.",
    ]);
  }
  return ["Continue with the indexed practice."];
}

function compact(values: Array<string | undefined>): string[] {
  return values.filter((value): value is string => Boolean(value));
}

function extractFilesFromDiff(diff: string): string[] {
  const files = new Set<string>();
  for (const line of diff.split("\n")) {
    const match = line.match(/^diff --git a\/(.+?) b\/(.+)$/) ?? line.match(/^\+\+\+ b\/(.+)$/);
    if (match) {
      files.add(normalizeRepoPath(match[2] ?? match[1]));
    }
  }
  return [...files];
}

function practiceAppliesToPath(record: PracticeRecord, file: string): boolean {
  const include = record.scope.paths.include;
  const exclude = record.scope.paths.exclude;
  if (exclude.some((pattern) => matchesRepoPattern(file, pattern))) {
    return false;
  }
  return include.length === 0 || include.some((pattern) => matchesRepoPattern(file, pattern));
}

function inferLanguageFromPath(file: string): string | undefined {
  if (file.endsWith("Cargo.toml") || file.endsWith("Cargo.lock")) return "rust";
  if (file.endsWith(".py")) return "python";
  if (file.endsWith(".scala") || file.endsWith(".sc")) return "scala";
  if (file.endsWith(".ts") || file.endsWith(".tsx")) return "typescript";
  if (file.endsWith(".js") || file.endsWith(".jsx") || file.endsWith(".mjs") || file.endsWith(".cjs")) return "javascript";
  if (file.endsWith(".rs")) return "rust";
  return undefined;
}

function compliantHits(record: PracticeRecord, text: string): string[] {
  if (record.status === "preferred" || record.status === "allowed" || record.status === "allowed_with_context") {
    return [];
  }
  return hits(complianceTerms(record), text, { ignoreNegated: true });
}

function complianceTerms(record: PracticeRecord): string[] {
  const terms = new Set<string>();
  for (const value of [...record.use_instead, ...record.good_examples]) {
    for (const phrase of compliancePhrases(value)) {
      addComplianceTerm(terms, phrase);
    }
    for (const match of value.matchAll(/[A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_]*)+/g)) {
      addComplianceTerm(terms, match[0]);
    }
    for (const match of value.matchAll(/\b[A-Za-z_]*[A-Z][A-Za-z0-9_]*\b/g)) {
      addComplianceTerm(terms, match[0]);
    }
    if (/\btimeout\b/i.test(value)) {
      terms.add("timeout");
    }
    if (/\bverification enabled\b/i.test(value)) {
      terms.add("verification enabled");
    }
  }
  return [...terms];
}

function compliancePhrases(value: string): string[] {
  const words = (normalizeText([value]).match(/[a-z][a-z0-9_]+/g) ?? []).filter((word) => !complianceStopWords.has(word));
  const phrases = new Set<string>();
  for (const size of [2, 3]) {
    for (let index = 0; index <= words.length - size; index += 1) {
      const phrase = words.slice(index, index + size);
      if (phrase.some((word) => word.length >= 5)) {
        phrases.add(phrase.join(" "));
      }
    }
  }
  return [...phrases];
}

const complianceStopWords = new Set([
  "a",
  "an",
  "and",
  "are",
  "as",
  "for",
  "in",
  "of",
  "or",
  "the",
  "to",
  "with",
  "when",
]);

function addComplianceTerm(terms: Set<string>, term: string): void {
  if (term.length >= 3) {
    terms.add(term);
  }
}

function hits(terms: string[], text: string, options: { ignoreNegated?: boolean } = {}): string[] {
  return terms.filter((term) => termMatches(term, text, options)).slice(0, 8);
}

function termMatches(term: string, text: string, options: { ignoreNegated?: boolean } = {}): boolean {
  const normalizedTerm = normalizeText([term]).trim();
  if (!normalizedTerm) {
    return false;
  }

  if (/^[a-z0-9_ -]+$/.test(normalizedTerm)) {
    const pattern = normalizedTerm.split(/\s+/).map(escapeRegExp).join("\\s+");
    const regex = new RegExp(`(^|[^a-z0-9_])(${pattern})(?=[^a-z0-9_]|$)`, "gi");
    let match: RegExpExecArray | null;
    while ((match = regex.exec(text)) !== null) {
      const index = match.index + match[1].length;
      if (!options.ignoreNegated || !isNegatedContext(text, index)) {
        return true;
      }
      if (match[0] === "") {
        regex.lastIndex += 1;
      }
    }
    return false;
  }

  let index = text.indexOf(normalizedTerm);
  while (index !== -1) {
    if (!options.ignoreNegated || !isNegatedContext(text, index)) {
      return true;
    }
    index = text.indexOf(normalizedTerm, index + normalizedTerm.length);
  }
  return false;
}

function isNegatedContext(text: string, index: number): boolean {
  const before = text.slice(Math.max(0, index - 100), index);
  return /\b(avoid|do not|don't|dont|never|no|not|without)\b[\s\S]{0,100}$/i.test(before);
}

function escapeRegExp(value: string): string {
  return value.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

function normalizeFiles(files: string[]): string[] {
  return [...new Set(files.map((file) => normalizeRepoPath(file)))].filter(Boolean);
}

function normalizeTerms(terms: string[]): string[] {
  return [...new Set(terms.map((term) => term.trim().toLowerCase()).filter(Boolean))];
}

function normalizeText(parts: Array<string | undefined>): string {
  return parts.filter(Boolean).join("\n").toLowerCase();
}

function intersection(left: string[], right: string[]): string[] {
  return left.filter((item) => right.includes(item));
}
