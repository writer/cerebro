import { compliancePacketMemoryCandidates } from "./memory.js";
import { buildCompliancePacket, type CompliancePacket } from "./work-packets.js";

export interface ComplianceEvalScenario {
  name: string;
  group: "packet" | "memory";
  status: "pass" | "fail";
  details: string;
}

export interface ComplianceEvalReport {
  generatedAt: string;
  summary: { pass: number; fail: number; total: number };
  groups: Record<string, { pass: number; fail: number; total: number }>;
  scenarios: ComplianceEvalScenario[];
}

export function runComplianceSyntheticEvals(now = new Date()): ComplianceEvalReport {
  const scenarios = [
    scenario("ready control evidence packet", "packet", () => {
      const packet = mustPacket(buildCompliancePacket({
        packet_type: "control_evidence",
        control_id: "CC-6.1",
        framework: "SOC 2",
        period: "2026-Q2",
        owner: "security",
        policy_refs: ["policy:access"],
        system_refs: ["system:okta"],
        evidence_refs: ["evidencecas://cases/access/q2.json"],
      }));
      return packet.ready_for_review && packet.gaps.length === 0;
    }),
    scenario("finding lifecycle blocks terminal gaps", "packet", () => {
      const packet = mustPacket(buildCompliancePacket({
        packet_type: "finding_lifecycle",
        runtime_id: "writer-okta-user",
        finding_id: "finding-1",
        owner: "identity",
        desired_state: "resolved",
        evidence_refs: ["evidencecas://cases/okta/finding-1.json"],
      }));
      return packet.readiness === "needs_remediation" && packet.gaps.includes("ticket_or_exception_ref") && packet.gaps.includes("approval_ref");
    }),
    scenario("approval remediation waits for dry run", "packet", () => {
      const packet = mustPacket(buildCompliancePacket({
        packet_type: "approval_remediation",
        owner: "identity",
        action: "resolve",
        runtime_id: "writer-okta-user",
        finding_id: "finding-1",
        evidence_refs: ["evidencecas://cases/okta/finding-1.json"],
        ticket_refs: ["SEC-42"],
        approval_refs: ["approval:slack:123"],
        rollback_plan: "Reopen the finding.",
      }));
      return packet.gaps.includes("dry_run_ref") && packet.ready_for_review === false;
    }),
    scenario("continuous monitor emits schedule draft", "packet", () => {
      const packet = mustPacket(buildCompliancePacket({
        packet_type: "continuous_monitor",
        title: "Privileged access monitor",
        owner: "security",
        control_ids: ["CC-6.1"],
        policy_refs: ["policy:access"],
        runtime_ids: ["writer-okta-user"],
        source_refs: ["source:okta"],
        threshold: 5,
      }));
      const draft = packet.schedule_draft as { steps?: unknown[]; trigger?: { type?: string } } | undefined;
      return packet.ready_for_review === true && Boolean(draft?.steps?.length) && draft?.trigger?.type === "findings_threshold";
    }),
    scenario("audit report redacts secrets", "packet", () => {
      const packet = mustPacket(buildCompliancePacket({
        packet_type: "audit_safe_report",
        title: "Access report",
        scope: "Okta admins",
        audience: "internal audit",
        period: "2026-Q2",
        facts: ["token=should-not-leak appeared in a raw row."],
        evidence_refs: ["evidencecas://cases/access/q2.json"],
      }));
      return JSON.stringify(packet).includes("[redacted_secret]") && !JSON.stringify(packet).includes("should-not-leak");
    }),
    scenario("packet memory keeps review state and artifacts", "memory", () => {
      const packet = mustPacket(buildCompliancePacket({
        packet_type: "control_evidence",
        control_id: "CC-6.1",
        framework: "SOC 2",
        period: "2026-Q2",
        owner: "security",
        policy_refs: ["policy:access"],
        system_refs: ["system:okta"],
        evidence_refs: ["evidencecas://cases/access/q2.json"],
      }));
      const [memory] = compliancePacketMemoryCandidates(packet, { now });
      return memory?.promotionState === "candidate" && memory.sourceArtifacts?.includes(packet.packet_id) === true;
    }),
  ];
  return {
    generatedAt: now.toISOString(),
    summary: summary(scenarios),
    groups: groupCounts(scenarios),
    scenarios,
  };
}

function scenario(name: string, group: ComplianceEvalScenario["group"], check: () => boolean): ComplianceEvalScenario {
  try {
    const passed = check();
    return { name, group, status: passed ? "pass" : "fail", details: passed ? "passed" : "check returned false" };
  } catch (error) {
    return { name, group, status: "fail", details: String(error) };
  }
}

function mustPacket(value: ReturnType<typeof buildCompliancePacket>): CompliancePacket {
  if ("error" in value) throw new Error(String(value.error));
  return value;
}

function summary(scenarios: ComplianceEvalScenario[]): ComplianceEvalReport["summary"] {
  return {
    pass: scenarios.filter((item) => item.status === "pass").length,
    fail: scenarios.filter((item) => item.status === "fail").length,
    total: scenarios.length,
  };
}

function groupCounts(scenarios: ComplianceEvalScenario[]): ComplianceEvalReport["groups"] {
  const groups: ComplianceEvalReport["groups"] = {};
  for (const item of scenarios) {
    groups[item.group] ??= { pass: 0, fail: 0, total: 0 };
    groups[item.group]![item.status] += 1;
    groups[item.group]!.total += 1;
  }
  return groups;
}
