import { spawnSync } from "node:child_process";
import { mkdirSync, writeFileSync } from "node:fs";
import path from "node:path";

interface ScenarioResult {
  name: string;
  group: "plan_revision" | "runner";
  status: "pass" | "fail";
}

interface EvalReport {
  generatedAt: string;
  command: string[];
  exitCode: number | null;
  summary: Record<string, number>;
  groups: Record<string, { pass: number; fail: number; total: number }>;
  minimumScenarioCounts: Record<ScenarioResult["group"], number>;
  validationFailures: string[];
  scenarios: ScenarioResult[];
  stderr: string;
}

const minimumScenarioCounts: Record<ScenarioResult["group"], number> = {
  plan_revision: 14,
  runner: 21,
};
const command = [
  process.execPath,
  "--import",
  "tsx",
  "--test",
  "test/autonomy-synthetic-evals.test.ts",
];
const result = spawnSync(command[0]!, command.slice(1), {
  cwd: process.cwd(),
  encoding: "utf8",
});

const stdout = result.stdout ?? "";
const stderr = result.stderr ?? "";
const output = stdout + "\n" + stderr;
const scenarios = parseScenarioResults(output);
const groups = groupCounts(scenarios);
const validationFailures = scenarioCountFailures(groups);
const report: EvalReport = {
  generatedAt: new Date().toISOString(),
  command,
  exitCode: result.status,
  summary: parseSummary(output, scenarios),
  groups,
  minimumScenarioCounts,
  validationFailures,
  scenarios,
  stderr: stderr.trim(),
};

const outDir = path.join(process.cwd(), "tmp");
mkdirSync(outDir, { recursive: true });
const jsonPath = path.join(outDir, "autonomy-synthetic-evals.json");
const markdownPath = path.join(outDir, "autonomy-synthetic-evals.md");
writeFileSync(jsonPath, JSON.stringify(report, null, 2) + "\n", "utf8");
writeFileSync(markdownPath, renderMarkdown(report), "utf8");

const failed = report.summary.fail ?? 0;
console.log(`Autonomy synthetic evals: ${report.summary.pass ?? 0}/${report.summary.tests ?? scenarios.length} passed.`);
console.log(`JSON: ${jsonPath}`);
console.log(`Markdown: ${markdownPath}`);
for (const failure of validationFailures) {
  console.error(`Validation: ${failure}`);
}
if (failed > 0 || validationFailures.length > 0 || result.status !== 0) {
  process.exitCode = result.status || 1;
}

function parseScenarioResults(output: string): ScenarioResult[] {
  const results: ScenarioResult[] = [];
  for (const line of output.split(/\r?\n/)) {
    const match = line.match(/^(ok|not ok)\s+\d+\s+-\s+synthetic (plan revision|autonomy runner) eval: (.+)$/);
    if (!match) continue;
    results.push({
      status: match[1] === "ok" ? "pass" : "fail",
      group: match[2] === "plan revision" ? "plan_revision" : "runner",
      name: match[3] ?? "",
    });
  }
  return results;
}

function parseSummary(output: string, scenarios: ScenarioResult[]): Record<string, number> {
  const summary: Record<string, number> = {};
  for (const line of output.split(/\r?\n/)) {
    const match = line.match(/^#\s+(tests|pass|fail|cancelled|skipped|todo|duration_ms)\s+([0-9.]+)/);
    if (!match) continue;
    summary[match[1]!] = Number(match[2]);
  }
  summary.tests ??= scenarios.length;
  summary.pass ??= scenarios.filter((scenario) => scenario.status === "pass").length;
  summary.fail ??= scenarios.filter((scenario) => scenario.status === "fail").length;
  return summary;
}

function groupCounts(scenarios: ScenarioResult[]): EvalReport["groups"] {
  const groups: EvalReport["groups"] = {};
  for (const scenario of scenarios) {
    groups[scenario.group] ??= { pass: 0, fail: 0, total: 0 };
    groups[scenario.group]![scenario.status] += 1;
    groups[scenario.group]!.total += 1;
  }
  return groups;
}

function scenarioCountFailures(groups: EvalReport["groups"]): string[] {
  const failures: string[] = [];
  for (const [group, minimum] of Object.entries(minimumScenarioCounts) as Array<[ScenarioResult["group"], number]>) {
    const actual = groups[group]?.total ?? 0;
    if (actual < minimum) {
      failures.push(`${group} has ${actual} scenario(s); expected at least ${minimum}.`);
    }
  }
  return failures;
}

function renderMarkdown(report: EvalReport): string {
  const lines = [
    "# Autonomy Synthetic Eval Report",
    "",
    `Generated: ${report.generatedAt}`,
    `Command: \`${report.command.map(shellWord).join(" ")}\``,
    `Exit code: ${report.exitCode ?? "unknown"}`,
    "",
    "## Summary",
    "",
    "| Metric | Count |",
    "| --- | ---: |",
    `| Tests | ${report.summary.tests ?? report.scenarios.length} |`,
    `| Passed | ${report.summary.pass ?? 0} |`,
    `| Failed | ${report.summary.fail ?? 0} |`,
    `| Cancelled | ${report.summary.cancelled ?? 0} |`,
    `| Skipped | ${report.summary.skipped ?? 0} |`,
    "",
    "## Groups",
    "",
    "| Group | Passed | Failed | Total |",
    "| --- | ---: | ---: | ---: |",
    ...Object.entries(report.groups).map(([group, counts]) => (
      `| ${group} | ${counts.pass} | ${counts.fail} | ${counts.total} |`
    )),
    "",
    "## Minimums",
    "",
    "| Group | Minimum | Actual |",
    "| --- | ---: | ---: |",
    ...Object.entries(report.minimumScenarioCounts).map(([group, minimum]) => (
      `| ${group} | ${minimum} | ${report.groups[group]?.total ?? 0} |`
    )),
    "",
    "## Scenarios",
    "",
    "| Status | Group | Scenario |",
    "| --- | --- | --- |",
    ...report.scenarios.map((scenario) => (
      `| ${scenario.status.toUpperCase()} | ${scenario.group} | ${escapeTableCell(scenario.name)} |`
    )),
    "",
  ];
  if (report.validationFailures.length > 0) {
    lines.push(
      "## Validation Failures",
      "",
      ...report.validationFailures.map((failure) => `- ${failure}`),
      "",
    );
  }
  if (report.stderr) {
    lines.push("## Stderr", "", "```text", report.stderr.slice(0, 4000), "```", "");
  }
  return lines.join("\n");
}

function shellWord(value: string): string {
  return /^[A-Za-z0-9_./:=@-]+$/.test(value) ? value : JSON.stringify(value);
}

function escapeTableCell(value: string): string {
  return value.replaceAll("|", "\\|");
}
