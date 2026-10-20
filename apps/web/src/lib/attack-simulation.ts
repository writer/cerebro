// Attack graph simulations run the service's risk-delta report: it replays the
// tenant's findings and graph neighbourhoods with one change applied to one
// entity and reports what the attack paths and risk would become.
export const ATTACK_SIMULATION_REPORT_ID = "risk-delta";

export type AttackSimulationScenarioID =
  | "remove_public_exposure"
  | "remove_privilege"
  | "patch_vulnerability"
  | "compromise_identity";

export type AttackSimulationScenario = {
  id: AttackSimulationScenarioID;
  label: string;
  question: string;
  // Defensive scenarios should shrink risk; an attacker scenario should grow it.
  intent: "defend" | "attack";
};

export const ATTACK_SIMULATION_SCENARIOS: AttackSimulationScenario[] = [
  { id: "remove_public_exposure", label: "Remove Public Exposure", question: "Which attack paths close if this stops being reachable from the internet?", intent: "defend" },
  { id: "remove_privilege", label: "Remove Privilege", question: "Which paths close if this loses its privileged access?", intent: "defend" },
  { id: "patch_vulnerability", label: "Patch Vulnerability", question: "How much risk goes away if the vulnerabilities on this are fixed?", intent: "defend" },
  { id: "compromise_identity", label: "Compromise Identity", question: "What can an attacker reach if this identity is taken over?", intent: "attack" },
];

export const attackSimulationScenarioFor = (value: string | undefined): AttackSimulationScenario | undefined =>
  ATTACK_SIMULATION_SCENARIOS.find((scenario) => scenario.id === value?.trim());

/** Reads the tenant out of a urn:cerebro:<tenant>:... URN; the report rejects targets from another tenant. */
export const tenantIDFromURN = (urn: string): string => {
  const parts = urn.trim().split(":");
  return parts.length > 3 && parts[0] === "urn" && parts[1] === "cerebro" ? parts[2].trim() : "";
};

/** Collects the runtime IDs whose findings the simulation should replay. */
export const simulationRuntimeIDs = (payload: unknown): string[] => {
  const runtimes = (payload as { source_runtimes?: unknown } | null)?.source_runtimes;
  if (!Array.isArray(runtimes)) return [];
  const ids = runtimes.flatMap((runtime) => {
    if (!runtime || typeof runtime !== "object") return [];
    const record = runtime as Record<string, unknown>;
    const id = String(record.runtime_id ?? record.id ?? "").trim();
    return id ? [id] : [];
  });
  return [...new Set(ids)].sort();
};

type SimulationPathNode = { urn: string; role?: string };

const SCENARIO_TARGET_ROLES: Record<AttackSimulationScenarioID, string[]> = {
  remove_public_exposure: ["exposed_resource", "crown_jewel"],
  remove_privilege: ["principal", "identity"],
  patch_vulnerability: ["exposed_resource"],
  compromise_identity: ["identity", "principal"],
};

const isPublicPseudoEntity = (node: SimulationPathNode) =>
  node.role === "public_principal" || /^urn:cerebro:[^:]+:internet:/.test(node.urn);

/**
 * Picks the path entity a scenario should change. The public principal that
 * starts an exposure path stands for "the internet" and cannot be remediated,
 * so it is never the target.
 */
export const simulationTargetForPath = <Node extends SimulationPathNode>(
  nodes: Node[],
  scenario: AttackSimulationScenarioID,
): Node | undefined => {
  for (const role of SCENARIO_TARGET_ROLES[scenario]) {
    const match = nodes.find((node) => node.role === role);
    if (match) return match;
  }
  return nodes.find((node) => !isPublicPseudoEntity(node));
};

export const attackSimulationRequest = ({
  runtimeIDs,
  scenario,
  targetURN,
  tenantID,
}: {
  runtimeIDs: string[];
  scenario: AttackSimulationScenarioID;
  targetURN: string;
  tenantID: string;
}) => ({
  path: `/reports/${ATTACK_SIMULATION_REPORT_ID}/runs`,
  body: {
    parameters: {
      tenant_id: tenantID,
      runtime_ids: runtimeIDs.join(","),
      scenario_type: scenario,
      target_urn: targetURN,
    },
  },
});

export type AttackSimulationSnapshot = {
  findingCount: number;
  totalRiskScore: number;
  attackPathCount: number;
  totalAttackPathScore: number;
};

export type AttackSimulationPath = {
  pattern: string;
  score: number;
  findingID: string;
  steps: Array<{ from: string; relation: string; to: string }>;
};

export type AttackSimulationFindingImpact = {
  findingID: string;
  ruleID: string;
  before: number;
  after: number;
  reduction: number;
  addedReasons: string[];
  removedReasons: string[];
};

export type AttackSimulationResult = {
  runID: string;
  scenario: string;
  targetURN: string;
  graphEvidenceStatus: string;
  before: AttackSimulationSnapshot;
  after: AttackSimulationSnapshot;
  riskScoreChange: number;
  attackPathCountChange: number;
  attackPathScoreChange: number;
  affectedFindings: AttackSimulationFindingImpact[];
  removedPaths: AttackSimulationPath[];
  addedPaths: AttackSimulationPath[];
  remainingPaths: AttackSimulationPath[];
  reasons: string[];
};

type JSONRecord = Record<string, unknown>;

const record = (value: unknown): JSONRecord => (value && typeof value === "object" && !Array.isArray(value) ? value as JSONRecord : {});
const list = (value: unknown): unknown[] => (Array.isArray(value) ? value : []);
const text = (value: unknown) => (typeof value === "string" ? value.trim() : "");
const strings = (value: unknown) => list(value).map(text).filter(Boolean);
// The report travels as a protobuf Struct, so integers can arrive as JSON numbers or strings.
const count = (value: unknown) => {
  const parsed = typeof value === "number" ? value : Number(text(value));
  return Number.isFinite(parsed) ? Math.trunc(parsed) : 0;
};

const snapshot = (value: unknown): AttackSimulationSnapshot => {
  const source = record(value);
  return {
    findingCount: count(source.finding_count),
    totalRiskScore: count(source.total_risk_score),
    attackPathCount: count(source.attack_path_count),
    totalAttackPathScore: count(source.total_attack_path_score),
  };
};

const paths = (value: unknown): AttackSimulationPath[] =>
  list(value).map((entry) => {
    const path = record(entry);
    return {
      pattern: text(path.pattern),
      score: count(path.score),
      findingID: text(path.finding_id),
      steps: list(path.steps).map((step) => {
        const hop = record(step);
        return { from: text(hop.from_urn), relation: text(hop.relation), to: text(hop.to_urn) };
      }).filter((step) => step.from && step.to),
    };
  });

/** Normalizes a RunReport response for the risk-delta report into what the page renders. */
export const attackSimulationResult = (payload: unknown): AttackSimulationResult | null => {
  const run = record(record(payload).run);
  const result = record(run.result);
  const delta = record(result.risk_delta);
  if (Object.keys(delta).length === 0) return null;
  return {
    runID: text(run.id),
    scenario: text(delta.scenario_type) || text(result.scenario_type),
    targetURN: text(delta.target_urn) || text(result.target_urn),
    graphEvidenceStatus: text(result.graph_evidence_status),
    before: snapshot(delta.before),
    after: snapshot(delta.after),
    riskScoreChange: count(delta.risk_score_change),
    attackPathCountChange: count(delta.attack_path_count_change),
    attackPathScoreChange: count(delta.attack_path_score_change),
    affectedFindings: list(delta.affected_findings).map((entry) => {
      const impact = record(entry);
      return {
        findingID: text(impact.finding_id),
        ruleID: text(impact.rule_id),
        before: count(impact.before_risk_score),
        after: count(impact.after_risk_score),
        reduction: count(impact.reduction),
        addedReasons: strings(impact.added_reasons),
        removedReasons: strings(impact.removed_reasons),
      };
    }).filter((impact) => impact.findingID),
    removedPaths: paths(delta.removed_attack_paths),
    addedPaths: paths(delta.added_attack_paths),
    remainingPaths: paths(delta.remaining_attack_paths),
    reasons: strings(delta.reasons),
  };
};

export const signedChange = (value: number) => (value > 0 ? `+${value.toLocaleString()}` : value.toLocaleString());
