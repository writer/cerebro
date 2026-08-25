import type { PracticeObservation, PracticeRecord } from "./schema.js";

export type CoverageCount = {
  name: string;
  count: number;
};

export type LanguageCoverage = {
  language: string;
  total_practices: number;
  dedicated_practices: number;
  semgrep_rules: number;
  blocking_practices: number;
};

export type NeedsReviewSummary = {
  summary: string;
  count: number;
  latest_observation_id: number;
};

export type PracticeCoverageReport = {
  total_practices: number;
  semgrep_rules: number;
  blocking_practices: number;
  by_language: CoverageCount[];
  by_framework: CoverageCount[];
  by_status: CoverageCount[];
  by_owner: CoverageCount[];
  language_coverage: LanguageCoverage[];
  needs_review_summaries: NeedsReviewSummary[];
  needs_review_observations: PracticeObservation[];
  next_steps: string[];
};

const supportedLanguages = ["python", "scala", "typescript", "javascript", "rust"];

export function buildCoverageReport(records: PracticeRecord[], observations: PracticeObservation[] = []): PracticeCoverageReport {
  const semgrepRecords = records.filter((record) => record.semgrep);
  const blockingRecords = records.filter((record) => isBlocking(record));
  const needsReviewObservations = observations.filter((observation) => observation.decision === "needs_review");
  const languageCoverage = supportedLanguages.map((language) => {
    const scoped = records.filter((record) => record.scope.languages.includes(language));
    return {
      language,
      total_practices: scoped.length,
      dedicated_practices: records.filter((record) => record.source_file.startsWith(`${language}/`)).length,
      semgrep_rules: scoped.filter((record) => record.semgrep).length,
      blocking_practices: scoped.filter(isBlocking).length,
    };
  });

  return {
    total_practices: records.length,
    semgrep_rules: semgrepRecords.length,
    blocking_practices: blockingRecords.length,
    by_language: countBy(records.flatMap((record) => record.scope.languages.length > 0 ? record.scope.languages : ["(any)"])),
    by_framework: countBy(records.flatMap((record) => record.scope.frameworks.length > 0 ? record.scope.frameworks : ["(any)"])),
    by_status: countBy(records.map((record) => record.status)),
    by_owner: countBy(records.map((record) => record.owner)),
    language_coverage: languageCoverage,
    needs_review_summaries: summarizeNeedsReview(needsReviewObservations),
    needs_review_observations: needsReviewObservations.slice(0, 20),
    next_steps: nextSteps(languageCoverage, needsReviewObservations),
  };
}

export function formatCoverageReport(report: PracticeCoverageReport): string {
  return [
    "# Practice Coverage Report",
    "",
    `Practices: ${report.total_practices}`,
    `Semgrep rules: ${report.semgrep_rules}`,
    `Blocking practices: ${report.blocking_practices}`,
    "",
    "## Languages",
    ...report.language_coverage.map(
      (item) =>
        `- ${item.language}: ${item.total_practices} total, ${item.dedicated_practices} dedicated, ${item.semgrep_rules} Semgrep, ${item.blocking_practices} blocking`,
    ),
    "",
    "## Frameworks",
    ...formatCounts(report.by_framework),
    "",
    "## Owners",
    ...formatCounts(report.by_owner),
    "",
    "## Needs Review",
    ...formatNeedsReview(report.needs_review_summaries),
    "",
    "## Next Steps",
    ...report.next_steps.map((step) => `- ${step}`),
  ].join("\n");
}

function isBlocking(record: PracticeRecord): boolean {
  return record.status === "banned" || record.enforcement === "blocking";
}

function countBy(values: string[]): CoverageCount[] {
  const counts = new Map<string, number>();
  for (const value of values) {
    counts.set(value, (counts.get(value) ?? 0) + 1);
  }
  return [...counts.entries()]
    .sort((left, right) => right[1] - left[1] || left[0].localeCompare(right[0]))
    .map(([name, count]) => ({ name, count }));
}

function summarizeNeedsReview(observations: PracticeObservation[]): NeedsReviewSummary[] {
  const summaries = new Map<string, NeedsReviewSummary>();
  for (const observation of observations) {
    const summary = observation.summary ?? "No summary";
    const current = summaries.get(summary);
    if (current) {
      current.count += 1;
      current.latest_observation_id = Math.max(current.latest_observation_id, observation.id);
    } else {
      summaries.set(summary, {
        summary,
        count: 1,
        latest_observation_id: observation.id,
      });
    }
  }
  return [...summaries.values()].sort(
    (left, right) => right.count - left.count || right.latest_observation_id - left.latest_observation_id,
  );
}

function nextSteps(languageCoverage: LanguageCoverage[], needsReviewObservations: PracticeObservation[]): string[] {
  const steps: string[] = [];
  const thinLanguages = languageCoverage.filter((item) => item.dedicated_practices < 10).map((item) => item.language);
  if (thinLanguages.length > 0) {
    steps.push(`Add dedicated practice records for ${thinLanguages.join(", ")}.`);
  }
  if (needsReviewObservations.length > 0) {
    steps.push("Convert repeated needs_review observations into owned practice records or accepted contexts.");
  }
  steps.push("Add eval cases for every new blocking practice and every false-positive fix.");
  steps.push("Run lint-practices, eval:gates, smoke:mcp, smoke:plugin-config, and smoke:hooks before publishing.");
  return steps;
}

function formatCounts(counts: CoverageCount[]): string[] {
  return counts.length > 0 ? counts.map((item) => `- ${item.name}: ${item.count}`) : ["- None."];
}

function formatNeedsReview(summaries: NeedsReviewSummary[]): string[] {
  if (summaries.length === 0) {
    return ["- None."];
  }
  return summaries.map((item) => `- ${item.summary} (${item.count}, latest #${item.latest_observation_id})`);
}
