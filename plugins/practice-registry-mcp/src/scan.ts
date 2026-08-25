import fs from "node:fs";
import path from "node:path";
import { spawnSync } from "node:child_process";
import { defaultSemgrepRulesPath } from "./paths.js";
import { outcomeForDecision } from "./outcome.js";
import type {
  PracticeDecision,
  PracticeFinding,
  PracticeRecord,
  PracticeScanResult,
  PracticeStatus,
} from "./schema.js";
import { matchesRepoPattern, normalizeRepoPath } from "./filePaths.js";
import { loadSemgrepConfig, type SemgrepConfig } from "./semgrepRules.js";

export type AddedLine = {
  path: string;
  line: number | null;
  code: string;
};

type ScanOptions = {
  cwd?: string;
  rulesPath?: string;
  semgrepBin?: string;
  useSemgrep?: boolean;
};

const statusRank = new Map<PracticeStatus, number>([
  ["banned", 6],
  ["legacy_accepted", 5],
  ["discouraged", 4],
  ["needs_review", 3],
  ["allowed_with_context", 2],
  ["preferred", 1],
  ["allowed", 0],
]);

export function scanDiff(records: PracticeRecord[], diff: string, options: ScanOptions = {}): PracticeScanResult {
  const cwd = path.resolve(options.cwd ?? process.cwd());
  const rulesPath = path.resolve(options.rulesPath ?? defaultSemgrepRulesPath());
  const config = loadSemgrepConfig(records, rulesPath);
  const addedLines = parseAddedLines(diff, cwd);
  const semgrepResult =
    options.useSemgrep === false
      ? { available: false, used: false, findings: [] as PracticeFinding[] }
      : runSemgrep(records, config, addedLines, { cwd, rulesPath, semgrepBin: options.semgrepBin });
  const fallbackFindings = scanAddedLinesWithRules(records, config, addedLines, cwd);
  const findings = dedupeFindings([...semgrepResult.findings, ...fallbackFindings]).sort(compareFindings);
  const blocking = findings.some((finding) => finding.blocking);
  const decision = decide(findings, blocking);

  return {
    decision,
    blocking,
    ...outcomeForDecision(decision),
    summary: summarizeScan(decision, findings),
    next_steps: nextSteps(decision, findings),
    findings,
    engine: {
      semgrep_available: semgrepResult.available,
      semgrep_used: semgrepResult.used,
      fallback_used: findings.some((finding) => finding.engine === "semgrep-rule-fallback") || !semgrepResult.used,
      rules_path: rulesPath,
    },
  };
}

export function parseAddedLines(diff: string, cwd = process.cwd()): AddedLine[] {
  const added: AddedLine[] = [];
  const root = path.resolve(cwd);
  let currentPath: string | undefined;
  let newLine: number | null = null;

  for (const rawLine of diff.split("\n")) {
    const gitDiffMatch = rawLine.match(/^diff --git a\/(.+?) b\/(.+)$/);
    if (gitDiffMatch) {
      currentPath = normalizeRepoPath(gitDiffMatch[2], root);
      newLine = null;
      continue;
    }

    const newFileMatch = rawLine.match(/^\+\+\+ b\/(.+)$/);
    if (newFileMatch) {
      currentPath = normalizeRepoPath(newFileMatch[1], root);
      continue;
    }

    const patchFileMatch = rawLine.match(/^\*\*\* (?:Add|Update) File: (.+)$/);
    if (patchFileMatch) {
      currentPath = normalizeRepoPath(patchFileMatch[1], root);
      newLine = null;
      continue;
    }

    const hunkMatch = rawLine.match(/^@@ -\d+(?:,\d+)? \+(\d+)(?:,\d+)? @@/);
    if (hunkMatch) {
      newLine = Number(hunkMatch[1]);
      continue;
    }

    if (!currentPath) {
      continue;
    }

    if (rawLine.startsWith("+") && !rawLine.startsWith("+++")) {
      added.push({ path: currentPath, line: newLine, code: rawLine.slice(1) });
      if (newLine !== null) {
        newLine += 1;
      }
      continue;
    }

    if ((rawLine.startsWith(" ") || rawLine === "") && newLine !== null) {
      newLine += 1;
    }
  }

  return added;
}

function runSemgrep(
  records: PracticeRecord[],
  config: SemgrepConfig,
  addedLines: AddedLine[],
  options: { cwd: string; rulesPath: string; semgrepBin?: string },
): { available: boolean; used: boolean; findings: PracticeFinding[] } {
  const targetFiles = [...new Set(addedLines.map((line) => line.path))]
    .filter((file) => fs.existsSync(path.resolve(options.cwd, file)))
    .filter((file) => config.rules.some((rule) => ruleAppliesToPath(rule, file)));
  if (targetFiles.length === 0 || !fs.existsSync(options.rulesPath)) {
    return { available: commandExists(options.semgrepBin ?? "semgrep"), used: false, findings: [] };
  }

  const semgrepBin = options.semgrepBin ?? "semgrep";
  const result = spawnSync(
    semgrepBin,
    ["scan", "--config", options.rulesPath, "--json", "--quiet", ...targetFiles],
    {
      cwd: options.cwd,
      encoding: "utf8",
      maxBuffer: 20 * 1024 * 1024,
    },
  );

  if (result.error && "code" in result.error && result.error.code === "ENOENT") {
    return { available: false, used: false, findings: [] };
  }
  if (result.error) {
    return { available: true, used: false, findings: [] };
  }
  if (!result.stdout.trim()) {
    return { available: true, used: true, findings: [] };
  }

  const parsed = JSON.parse(result.stdout) as {
    results?: Array<{
      check_id: string;
      path: string;
      start?: { line?: number };
      end?: { line?: number };
      extra?: {
        message?: string;
        severity?: "ERROR" | "WARNING" | "INFO";
        lines?: string;
        metadata?: { practice_id?: string };
      };
    }>;
  };
  const addedLinesByPath = groupAddedLinesByPath(addedLines);
  const findings = (parsed.results ?? [])
    .map((item) => {
      const itemPath = semgrepResultPath(item.path, options.cwd);
      const startLine = item.start?.line ?? null;
      if (startLine === null) {
        return undefined;
      }
      const endLine = Math.max(startLine, item.end?.line ?? startLine);
      const addedLine = addedLinesByPath
        .get(itemPath)
        ?.find((line) => line.line !== null && line.line >= startLine && line.line <= endLine);
      if (!addedLine) {
        return undefined;
      }
      const practiceId = item.extra?.metadata?.practice_id ?? item.check_id;
      const practice = records.find((record) => record.id === practiceId);
      return practice
        ? findingFromPractice(practice, {
            ruleId: practice.id,
            message: item.extra?.message ?? practice.summary,
            severity: item.extra?.severity ?? "WARNING",
            path: itemPath,
            line: addedLine.line,
            code: addedLine.code || item.extra?.lines || "",
            engine: "semgrep",
          })
        : undefined;
    })
    .filter((finding): finding is PracticeFinding => finding !== undefined);

  return { available: true, used: true, findings };
}

function scanAddedLinesWithRules(
  records: PracticeRecord[],
  config: SemgrepConfig,
  addedLines: AddedLine[],
  cwd: string,
): PracticeFinding[] {
  const findings: PracticeFinding[] = [];

  for (const line of addedLines) {
    for (const rule of config.rules) {
      if (!rule["pattern-regex"] || !ruleAppliesToPath(rule, line.path)) {
        continue;
      }

      const pattern = new RegExp(rule["pattern-regex"]);
      if (!pattern.test(line.code)) {
        continue;
      }

      const finding = fallbackFinding(records, rule, line);
      if (finding) {
        findings.push(finding);
      }
    }
  }

  const addedLinesByPath = groupAddedLinesByPath(addedLines);
  for (const [file, fileAddedLines] of addedLinesByPath) {
    const sourcePath = path.resolve(cwd, file);
    let source: string;
    try {
      source = fs.readFileSync(sourcePath, "utf8");
    } catch {
      continue;
    }
    const lineStarts = sourceLineStarts(source);

    for (const rule of config.rules) {
      if (!rule["pattern-regex"] || !ruleAppliesToPath(rule, file)) {
        continue;
      }
      const pattern = new RegExp(rule["pattern-regex"], "g");
      for (const match of source.matchAll(pattern)) {
        const startOffset = match.index;
        const endOffset = Math.max(startOffset, startOffset + match[0].length - 1);
        const startLine = lineNumberAtOffset(lineStarts, startOffset);
        const endLine = lineNumberAtOffset(lineStarts, endOffset);
        const addedLine = fileAddedLines.find(
          (line) => line.line !== null && line.line >= startLine && line.line <= endLine,
        );
        if (!addedLine) {
          continue;
        }
        const finding = fallbackFinding(records, rule, addedLine);
        if (finding) {
          findings.push(finding);
        }
      }
    }
  }

  return findings;
}

function groupAddedLinesByPath(addedLines: AddedLine[]): Map<string, AddedLine[]> {
  const grouped = new Map<string, AddedLine[]>();
  for (const line of addedLines) {
    if (line.line === null) {
      continue;
    }
    const existing = grouped.get(line.path) ?? [];
    existing.push(line);
    grouped.set(line.path, existing);
  }
  return grouped;
}

function sourceLineStarts(source: string): number[] {
  const starts = [0];
  for (let index = 0; index < source.length; index += 1) {
    if (source[index] === "\n") {
      starts.push(index + 1);
    }
  }
  return starts;
}

function lineNumberAtOffset(lineStarts: number[], offset: number): number {
  let low = 0;
  let high = lineStarts.length - 1;
  while (low <= high) {
    const middle = Math.floor((low + high) / 2);
    if (lineStarts[middle] <= offset) {
      low = middle + 1;
    } else {
      high = middle - 1;
    }
  }
  return high + 1;
}

function fallbackFinding(
  records: PracticeRecord[],
  rule: SemgrepConfig["rules"][number],
  line: AddedLine,
): PracticeFinding | undefined {
  const practice = records.find((record) => record.id === rule.metadata.practice_id);
  if (!practice || !practiceAppliesToPath(practice, line.path)) {
    return undefined;
  }
  return findingFromPractice(practice, {
    ruleId: rule.id,
    message: rule.message,
    severity: rule.severity,
    path: line.path,
    line: line.line,
    code: line.code,
    engine: "semgrep-rule-fallback",
  });
}

function findingFromPractice(
  practice: PracticeRecord,
  input: Pick<PracticeFinding, "message" | "severity" | "path" | "line" | "code" | "engine"> & {
    ruleId: string;
  },
): PracticeFinding {
  const blocking = practice.status === "banned" || practice.enforcement === "blocking";
  return {
    rule_id: input.ruleId,
    practice_id: practice.id,
    title: practice.title,
    status: practice.status,
    enforcement: practice.enforcement,
    blocking,
    severity: input.severity,
    message: input.message,
    path: input.path,
    line: input.line,
    code: input.code,
    engine: input.engine,
    source_file: practice.source_file,
    owner: practice.owner,
    use_instead: practice.use_instead,
  };
}

function practiceAppliesToPath(practice: PracticeRecord, file: string): boolean {
  const include = practice.scope.paths.include;
  const exclude = practice.scope.paths.exclude;
  if (exclude.some((pattern) => matchesRepoPattern(file, pattern))) {
    return false;
  }
  return include.length === 0 || include.some((pattern) => matchesRepoPattern(file, pattern));
}

function ruleAppliesToPath(rule: SemgrepConfig["rules"][number], file: string): boolean {
  const include = rule.paths?.include ?? [];
  const exclude = rule.paths?.exclude ?? [];
  if (exclude.some((pattern) => matchesRepoPattern(file, pattern))) {
    return false;
  }
  return include.length === 0 || include.some((pattern) => matchesRepoPattern(file, pattern));
}

function dedupeFindings(findings: PracticeFinding[]): PracticeFinding[] {
  const seen = new Set<string>();
  return findings.filter((finding) => {
    const key = [finding.practice_id, finding.path, finding.line ?? "unknown"].join("\0");
    if (seen.has(key)) {
      return false;
    }
    seen.add(key);
    return true;
  });
}

function compareFindings(left: PracticeFinding, right: PracticeFinding): number {
  const riskDelta = (statusRank.get(right.status) ?? 0) - (statusRank.get(left.status) ?? 0);
  return riskDelta || left.path.localeCompare(right.path) || (left.line ?? 0) - (right.line ?? 0);
}

function decide(findings: PracticeFinding[], blocking: boolean): PracticeDecision {
  if (blocking) {
    return "change_code";
  }
  if (findings.some((finding) => finding.status === "discouraged" || finding.status === "legacy_accepted")) {
    return "revise_or_justify";
  }
  if (findings.some((finding) => finding.status === "needs_review")) {
    return "ask_owner";
  }
  if (findings.some((finding) => finding.status === "preferred" || finding.status === "allowed_with_context")) {
    return "follow_guidance";
  }
  return "allowed";
}

function summarizeScan(decision: PracticeDecision, findings: PracticeFinding[]): string {
  if (findings.length === 0) {
    return "No concrete practice findings in changed Scala, Python, TypeScript, JavaScript, or Rust lines.";
  }

  const first = findings[0];
  if (decision === "change_code") {
    return `${first.title}: change the code before proceeding.`;
  }
  if (decision === "revise_or_justify") {
    return `${first.title}: revise the approach or document the accepted context.`;
  }
  return `${first.title}: review the recorded practice.`;
}

function nextSteps(decision: PracticeDecision, findings: PracticeFinding[]): string[] {
  if (findings.length === 0) {
    return ["Continue. No concrete practice findings were found in changed Scala, Python, TypeScript, JavaScript, or Rust lines."];
  }

  const first = findings[0];
  if (decision === "change_code") {
    return compact([
      first.use_instead[0] ? `Use instead: ${first.use_instead[0]}` : undefined,
      `Change ${location(first)} before continuing.`,
      "Rerun scan_diff on the final diff.",
    ]);
  }
  if (decision === "revise_or_justify") {
    return compact([
      first.use_instead[0] ? `Prefer: ${first.use_instead[0]}` : undefined,
      "Revise the changed lines or document the accepted context.",
      "Rerun scan_diff on the final diff.",
    ]);
  }
  if (decision === "ask_owner") {
    return [`Ask ${first.owner} for a decision before continuing.`];
  }
  if (decision === "follow_guidance") {
    return compact([
      first.use_instead[0] ? `Use: ${first.use_instead[0]}` : undefined,
      "Keep the changed lines inside the recorded context.",
    ]);
  }
  return ["Continue with the indexed practice."];
}

function location(finding: PracticeFinding): string {
  return finding.line ? `${finding.path}:${finding.line}` : finding.path;
}

function compact(values: Array<string | undefined>): string[] {
  return values.filter((value): value is string => Boolean(value));
}

function commandExists(command: string): boolean {
  const result = spawnSync(command, ["--version"], { encoding: "utf8" });
  return !result.error;
}

function semgrepResultPath(file: string, cwd: string): string {
  const absolutePath = path.isAbsolute(file) ? file : path.resolve(cwd, file);
  return normalizeRepoPath(absolutePath, cwd);
}
