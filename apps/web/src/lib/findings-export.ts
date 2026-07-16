import type { GRCFinding } from "@/lib/grc";

const findingExportColumns = [
  { header: "id", value: (finding: GRCFinding) => finding.id },
  { header: "title", value: (finding: GRCFinding) => finding.title },
  { header: "severity", value: (finding: GRCFinding) => finding.severity },
  { header: "status", value: (finding: GRCFinding) => finding.status },
  { header: "disposition", value: (finding: GRCFinding) => finding.disposition },
  { header: "risk_score", value: (finding: GRCFinding) => finding.risk_score },
  { header: "likelihood_level", value: (finding: GRCFinding) => finding.likelihood_level },
  { header: "impact_level", value: (finding: GRCFinding) => finding.impact_level },
  { header: "owner", value: (finding: GRCFinding) => finding.owner },
  { header: "assignee", value: (finding: GRCFinding) => finding.assignee },
  { header: "sla_status", value: (finding: GRCFinding) => finding.sla_status },
  { header: "due_at", value: (finding: GRCFinding) => finding.due_at },
  { header: "tenant_id", value: (finding: GRCFinding) => finding.tenant_id },
  { header: "runtime_id", value: (finding: GRCFinding) => finding.runtime_id },
  { header: "source_id", value: (finding: GRCFinding) => finding.source_id },
  { header: "entity", value: (finding: GRCFinding) => finding.entity },
  { header: "resource_urns", value: (finding: GRCFinding) => finding.resource_urns?.join("; ") },
  { header: "rule_id", value: (finding: GRCFinding) => finding.rule_id },
  { header: "policy_id", value: (finding: GRCFinding) => finding.policy_id },
  { header: "policy_name", value: (finding: GRCFinding) => finding.policy_name },
  { header: "controls", value: (finding: GRCFinding) => finding.controls?.map((control) => `${control.framework_name} ${control.control_id}`).join("; ") },
  { header: "evidence_count", value: (finding: GRCFinding) => finding.evidence_count },
  { header: "first_observed_at", value: (finding: GRCFinding) => finding.first_observed_at },
  { header: "last_observed_at", value: (finding: GRCFinding) => finding.last_observed_at },
];

const valueString = (value: unknown) => {
  if (value === null || value === undefined) return "";
  return String(value);
};

const protectSpreadsheetFormula = (value: string) => {
  const trimmed = value.trimStart();
  if (trimmed === "") return value;
  return ["=", "+", "-", "@", "\t", "\r"].includes(trimmed[0]) ? `'${value}` : value;
};

const csvCell = (value: unknown) => {
  const rendered = protectSpreadsheetFormula(valueString(value));
  if (!/[",\n\r]/.test(rendered)) return rendered;
  return `"${rendered.replace(/"/g, '""')}"`;
};

export const findingsToCSV = (findings: GRCFinding[]) => {
  const rows = [
    findingExportColumns.map((column) => column.header).join(","),
    ...findings.map((finding) => findingExportColumns.map((column) => csvCell(column.value(finding))).join(",")),
  ];
  return `${rows.join("\n")}\n`;
};

export const downloadFindingsCSV = (findings: GRCFinding[], filename: string) => {
  const blob = new Blob([findingsToCSV(findings)], { type: "text/csv;charset=utf-8" });
  const url = window.URL.createObjectURL(blob);
  const anchor = document.createElement("a");
  anchor.href = url;
  anchor.download = filename;
  anchor.click();
  window.URL.revokeObjectURL(url);
};
