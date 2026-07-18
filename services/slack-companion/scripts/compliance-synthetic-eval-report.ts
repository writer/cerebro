import { mkdirSync, writeFileSync } from "node:fs";
import path from "node:path";
import { runComplianceSyntheticEvals, type ComplianceEvalReport } from "../src/compliance/evals.js";

const report = runComplianceSyntheticEvals();
const outDir = path.join(process.cwd(), "tmp");
mkdirSync(outDir, { recursive: true });
const jsonPath = path.join(outDir, "compliance-synthetic-evals.json");
const markdownPath = path.join(outDir, "compliance-synthetic-evals.md");
writeFileSync(jsonPath, JSON.stringify(report, null, 2) + "\n", "utf8");
writeFileSync(markdownPath, renderMarkdown(report), "utf8");

console.log(`Compliance synthetic evals: ${report.summary.pass}/${report.summary.total} passed.`);
console.log(`JSON: ${jsonPath}`);
console.log(`Markdown: ${markdownPath}`);
if (report.summary.fail > 0) process.exitCode = 1;

function renderMarkdown(report: ComplianceEvalReport): string {
  return [
    "# Compliance Synthetic Eval Report",
    "",
    `Generated: ${report.generatedAt}`,
    "",
    "## Summary",
    "",
    "| Metric | Count |",
    "| --- | ---: |",
    `| Scenarios | ${report.summary.total} |`,
    `| Passed | ${report.summary.pass} |`,
    `| Failed | ${report.summary.fail} |`,
    "",
    "## Groups",
    "",
    "| Group | Passed | Failed | Total |",
    "| --- | ---: | ---: | ---: |",
    ...Object.entries(report.groups).map(([group, counts]) => `| ${group} | ${counts.pass} | ${counts.fail} | ${counts.total} |`),
    "",
    "## Scenarios",
    "",
    "| Status | Group | Scenario | Details |",
    "| --- | --- | --- | --- |",
    ...report.scenarios.map((scenario) => `| ${scenario.status.toUpperCase()} | ${scenario.group} | ${escapeTableCell(scenario.name)} | ${escapeTableCell(scenario.details)} |`),
    "",
  ].join("\n");
}

function escapeTableCell(value: string): string {
  return value.replaceAll("|", "\\|").replace(/\s+/g, " ");
}
