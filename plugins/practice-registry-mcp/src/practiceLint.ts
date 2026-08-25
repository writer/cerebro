import { outcomeForDecision } from "./outcome.js";
import { validateResearchApprovalSources } from "./approval.js";
import type { PracticeDecision, PracticeLintFinding, PracticeLintResult, PracticeRecord } from "./schema.js";

const vagueTerms = [
  "best practice",
  "clean code",
  "robust",
  "simple",
  "better",
  "nice",
  "modern",
  "improve quality",
];

export function lintPractices(records: PracticeRecord[]): PracticeLintResult {
  const findings = records.flatMap(lintPractice).sort(compareFindings);
  const hasErrors = findings.some((finding) => finding.severity === "error");
  const decision: PracticeDecision = hasErrors ? "change_code" : "allowed";
  return {
    decision,
    ...outcomeForDecision(decision),
    summary: summarize(findings),
    next_steps: nextSteps(findings),
    findings,
  };
}

function lintPractice(record: PracticeRecord): PracticeLintFinding[] {
  const findings: PracticeLintFinding[] = [];
  const add = (severity: PracticeLintFinding["severity"], message: string) => {
    findings.push({
      practice_id: record.id,
      source_file: record.source_file,
      severity,
      message,
    });
  };

  if (!/^[a-z0-9]+(?:[.-][a-z0-9]+)+$/.test(record.id)) {
    add("error", "Use a stable lowercase dotted id such as python.security.no-shell-true.");
  }
  if (record.owner.includes("@") || record.owner.toLowerCase().includes("todo") || record.owner.toLowerCase().includes("owner")) {
    add("error", "Set owner to the owning team slug, not a placeholder.");
  }
  if (new Date(`${record.last_reviewed}T00:00:00Z`).getTime() > Date.now()) {
    add("error", "last_reviewed cannot be in the future.");
  }
  if (record.approval && new Date(`${record.approval.approved_at}T00:00:00Z`).getTime() > Date.now()) {
    add("error", "approval.approved_at cannot be in the future.");
  }
  if (record.approval && record.status === "needs_review") {
    add("error", "An approved practice must use a resolved status instead of needs_review.");
  }
  if (record.approval?.method === "owner" && record.approval.approved_by !== record.owner) {
    add("error", "Owner approval must name the practice owner in approval.approved_by.");
  }
  if (record.approval?.method === "research") {
    for (const error of validateResearchApprovalSources(record.approval.sources).errors) {
      add("error", error);
    }
  }
  if (containsVagueCopy([record.title, record.summary, record.rationale, ...record.avoid, ...record.use_instead])) {
    add("warning", "Replace vague practice copy with concrete states, actions, owners, or alternatives.");
  }

  const requiresAlternative = record.status === "banned" || record.status === "discouraged" || record.status === "legacy_accepted";
  if (requiresAlternative && record.use_instead.length === 0) {
    add("error", "Add at least one use_instead alternative for banned, discouraged, or legacy accepted practices.");
  }
  if (requiresAlternative && record.avoid.length === 0) {
    add("error", "Add at least one avoid pattern for banned, discouraged, or legacy accepted practices.");
  }
  if ((record.status === "banned" || record.enforcement === "blocking") && !record.semgrep) {
    add("warning", "Blocking records should include a semgrep block when the pattern can be detected in changed lines.");
  }
  if (record.semgrep && !record.semgrep.pattern && !record.semgrep.pattern_regex) {
    add("error", "Semgrep blocks must define pattern or pattern_regex.");
  }
  if (record.semgrep && record.scope.languages.length === 0 && !record.semgrep.languages?.length) {
    add("error", "Semgrep records must declare scope.languages or semgrep.languages.");
  }
  if (record.good_examples.length === 0 && record.use_instead.length === 0) {
    add("warning", "Add a good example or use_instead entry so agents have a concrete replacement.");
  }
  if (record.bad_examples.length === 0 && record.avoid.length === 0) {
    add("warning", "Add a bad example or avoid entry so agents can recognize the risky pattern.");
  }

  return findings;
}

function containsVagueCopy(values: string[]): boolean {
  const text = values.join(" ").toLowerCase();
  return vagueTerms.some((term) => text.includes(term));
}

function summarize(findings: PracticeLintFinding[]): string {
  if (findings.length === 0) {
    return "Practice records passed authoring lint.";
  }
  const errors = findings.filter((finding) => finding.severity === "error").length;
  const warnings = findings.length - errors;
  return `${findings.length} practice authoring findings. ${errors} errors. ${warnings} warnings.`;
}

function nextSteps(findings: PracticeLintFinding[]): string[] {
  if (findings.length === 0) {
    return ["Continue. Practice records are ready to index."];
  }
  const first = findings[0];
  return [
    `Fix ${first.source_file}: ${first.message}`,
    "Rerun lint-practices before publishing updated practice records.",
  ];
}

function compareFindings(left: PracticeLintFinding, right: PracticeLintFinding): number {
  const severity = severityRank(right.severity) - severityRank(left.severity);
  return severity || left.source_file.localeCompare(right.source_file) || left.message.localeCompare(right.message);
}

function severityRank(value: PracticeLintFinding["severity"]): number {
  return value === "error" ? 1 : 0;
}
