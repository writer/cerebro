import { GRCFinding } from "@/lib/grc";

export const FINDING_DISPOSITIONS = ["open", "in_triage", "risk_accepted", "false_positive", "resolved"] as const;

export type FindingDisposition = (typeof FINDING_DISPOSITIONS)[number];

export const FINDING_DISPOSITION_OPTIONS: { value: FindingDisposition; label: string }[] = [
  { value: "in_triage", label: "In Triage" },
  { value: "risk_accepted", label: "Accept Risk" },
  { value: "false_positive", label: "False Positive" },
  { value: "resolved", label: "Resolve" },
  { value: "open", label: "Reopen" },
];

export type FindingTriageBatch = {
  tenant_id: string;
  finding_ids: string[];
  disposition: FindingDisposition;
};

export function triageBatchesByTenant(
  findings: GRCFinding[],
  selectedIds: Iterable<string>,
  disposition: FindingDisposition,
): FindingTriageBatch[] {
  const selected = new Set(selectedIds);
  const byTenant = new Map<string, string[]>();
  for (const finding of findings) {
    if (!selected.has(finding.id)) continue;
    const tenant = (finding.tenant_id ?? "").trim();
    if (!tenant) continue;
    const ids = byTenant.get(tenant) ?? [];
    ids.push(finding.id);
    byTenant.set(tenant, ids);
  }
  return Array.from(byTenant.entries()).map(([tenant_id, finding_ids]) => ({
    tenant_id,
    finding_ids,
    disposition,
  }));
}
