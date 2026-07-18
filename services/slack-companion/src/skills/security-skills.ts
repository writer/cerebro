export interface SecuritySkillStepTemplate {
  id: string;
  title: string;
  prompt: string;
  dependsOn?: string[];
}

export interface SecuritySkill {
  id: string;
  title: string;
  summary: string;
  aliases: string[];
  category: "posture" | "findings" | "runtime" | "slack" | "evidence" | "operations";
  prompt: string;
  steps?: SecuritySkillStepTemplate[];
}

export interface SecuritySkillStep {
  id: string;
  title: string;
  skillId?: string;
  prompt: string;
  dependsOn: string[];
}

export const SECURITY_SKILLS: SecuritySkill[] = [
  {
    id: "login-posture",
    title: "Login posture",
    summary: "Check identity runtime health, open identity findings, recent evidence, and owner path.",
    aliases: ["login", "identity", "okta", "mfa", "sso", "auth", "access"],
    category: "posture",
    prompt: [
      "Review current login security posture.",
      "Check relevant identity runtimes, open identity findings, recent evidence, prior notes, and graph context.",
      "Return the current status, highest-risk finding ids, missing evidence, likely owner, and the next safe check.",
    ].join("\n"),
  },
  {
    id: "runtime-health",
    title: "Runtime health",
    summary: "Check source runtime sync, graph ingest, and finding evaluation state.",
    aliases: ["runtime", "health", "source", "sync", "ingest", "evaluate", "pipeline"],
    category: "runtime",
    prompt: [
      "Check Cerebro source runtime health across configured security runtimes.",
      "Name unhealthy, stale, blocked, or missing runtimes. Include sync, graph ingest, and finding evaluation state when available.",
      "Return the affected runtime ids, likely blocker, and the next operator action.",
    ].join("\n"),
  },
  {
    id: "terminated-identity-access",
    title: "Terminated identity access",
    summary: "Verify terminated identities have no remaining Okta, GitHub, or AWS access and carry reviewed remediation through fresh closure evidence.",
    aliases: ["offboarding control", "offboarding-control canary", "terminated access", "deprovisioned access", "former employee access", "access after termination"],
    category: "operations",
    prompt: [
      "Run the terminated-identity access control against current source systems.",
      "For a broad read-only canary or when exact runtime IDs are not already known, call cerebro_offboarding_preflight with create_snapshot_when_ready=true. Use its explicit source identities, connector evidence, provider-sync validation, and precise setup blockers; do not reconstruct the same answer with repeated generic runtime calls.",
      "Resolve exact Okta, GitHub, and AWS runtime IDs, then call cerebro_offboarding_snapshot with all three provider sets. Do not infer provider coverage from configured names alone.",
      "For one exact open finding, call cerebro_offboarding_action without execute to obtain the stable target-bound proposal digest. Do not mutate a provider until the exact target, rollback, proposal digest, and reviewed approval are present.",
      "After approval, use operator_offboarding_control_start so provider execution, post-action source recollection, finding reevaluation, independent verification, and the durable completion receipt survive the current Slack turn.",
      "Report the decision-packet ID, source freshness, open exact finding, approval state, and blockers. Provider success is not closure; only fresh changed revisions and the independent close-loop receipt close the run.",
    ].join("\n"),
    steps: [
      {
        id: "collect-provider-evidence",
        title: "Collect Okta, GitHub, and AWS evidence",
        prompt: "Call cerebro_offboarding_preflight to resolve exact provider runtimes and conditionally create a read-only durable snapshot when all three providers pass.",
      },
      {
        id: "prepare-reviewed-action",
        title: "Prepare the exact provider action",
        prompt: "When an exact finding and target exist, run cerebro_offboarding_action as a dry run and return its proposal digest and rollback action.",
        dependsOn: ["collect-provider-evidence"],
      },
      {
        id: "start-durable-control-run",
        title: "Start the approval-gated control run",
        prompt: "After the proposal is reviewed, call operator_offboarding_control_start. Leave the run waiting when approval or fresh source evidence is missing.",
        dependsOn: ["prepare-reviewed-action"],
      },
    ],
  },
  {
    id: "scary-findings",
    title: "High-risk findings",
    summary: "Rank the newest high-risk open findings that need attention now.",
    aliases: ["scary", "risk", "top risk", "highest risk", "newest findings", "findings today", "critical", "high"],
    category: "findings",
    prompt: [
      "Find the newest high-risk open findings that need attention now.",
      "Use configured runtimes unless the request names a runtime. Include finding ids, runtimes, severity or risk score, last observed time, resource, and why each item matters.",
      "Return the top few items and the next concrete owner or review path.",
    ].join("\n"),
  },
  {
    id: "slack-app-review",
    title: "Slack app review",
    summary: "Review Slack app install context, scopes, prior discussion, and security follow-up.",
    aliases: ["slack app", "app install", "installed app", "oauth app", "slack audit", "workspace app"],
    category: "slack",
    prompt: [
      "Review Slack app installation and app-risk context.",
      "Check Slack audit or visible Slack history, installed-app discussion, relevant findings, and prior Cerebro notes.",
      "Return app name if known, installer or timestamp if available, scopes or missing scope coverage, risk, and next review action.",
    ].join("\n"),
  },
  {
    id: "stale-findings",
    title: "Stale findings",
    summary: "Find open findings that look old, unowned, missing evidence, or blocked.",
    aliases: ["stale", "old findings", "unowned", "overdue", "due", "blocked findings", "aging"],
    category: "findings",
    prompt: [
      "Find open findings that need queue cleanup.",
      "Look for old, unassigned, overdue, blocked, or evidence-poor findings across configured runtimes.",
      "Return finding ids, runtime ids, owner or missing owner, blocker, and the next action.",
    ].join("\n"),
  },
  {
    id: "evidence-integrity",
    title: "Evidence integrity",
    summary: "Check EvidenceCAS refs, manifests, verification status, and chain-of-custody gaps.",
    aliases: ["evidence", "cas", "manifest", "digest", "chain of custody", "verify"],
    category: "evidence",
    prompt: [
      "Review evidence integrity for the referenced finding, artifact, or evidence family.",
      "Resolve EvidenceCAS refs only when Cerebro evidence or the request gives a specific ref. Check manifest and verification status when available.",
      "Return verified refs, digest or manifest gaps, and the next evidence action.",
    ].join("\n"),
  },
  {
    id: "self-improvement",
    title: "Self improvement",
    summary: "Review recent failures, feedback, memories, skills, and runtime code paths; save the improvement.",
    aliases: ["self improve", "improve yourself", "learn", "skill improvement", "fix yourself", "runtime code", "write code"],
    category: "operations",
    prompt: [
      "Review Cerebro's recent behavior, user feedback, relevant skill prompt, memory, learning docs, and runtime code status.",
      "Identify the smallest durable improvement: one skill_improvement write when the correction is procedural, or one draft code PR when behavior requires implementation.",
      "When inspection or validation needs repeated reads or composition, select execution_style=code, discover the planned operations with cerebro_tool_search, and run them through cerebro_execute.",
      "A trusted-operator self-improvement turn may perform one side effect. For a behavior fix, inspect the companion source and tests at one immutable commit SHA, then pass that exact base_sha to cerebro_code_self_improvement_pr. For a later repair to the same candidate, inspect its current PR status and pass the returned head SHA as expected_head_sha. The host forces a draft on a stable candidate branch in the configured companion repository and excludes authority, dependency, credential, evaluator, release-gate, and Code Mode paths. Include the implementation, durable lesson, and regression test. Do not use general workspace, shell, or GitHub-write tools for self-improvement. Keep merge, deploy, promotion, infrastructure, and production control-plane actions outside the program.",
      "Return what changed, where it was saved, and the next review or deploy step.",
    ].join("\n"),
  },
  {
    id: "operator-investigation",
    title: "Operator investigation",
    summary: "Turn a broad security request into source-backed checks, checkpointed state, and a next action.",
    aliases: ["investigate", "figure out", "work through this", "get it healthy", "root cause", "proper", "loop"],
    category: "operations",
    prompt: [
      "Run an operator investigation from the current Slack request.",
      "Start with source-of-truth checks before synthesis: Cerebro runtime/source state, findings, graph, GitHub, Jira, Slack thread context, EvidenceCAS, Infisical metadata, or Panther context as relevant.",
      "If the work needs follow-up beyond this answer, create a durable goal with the current objective and save an operator_handoff record.",
      "Save durable non-secret state as separate operator facts, claims, decisions, risks, blockers, handoffs, or source-health notes. Do not flatten them into one prose memory.",
      "Return what changed, what is blocked, what needs attention, what evidence was checked, and the next executable action.",
    ].join("\n"),
  },
  {
    id: "change-review-health",
    title: "Change review health",
    summary: "Check PRs, checks, runtime status, tickets, and deploy readiness for a service change.",
    aliases: ["pr health", "checks", "ci", "merge", "rollout", "deploy health", "review state"],
    category: "operations",
    prompt: [
      "Review a code change or rollout from the user's repo, PR, branch, or service reference.",
      "Use GitHub PR/check tools for review and CI state, Jira tools for linked work, runtime/source tools for service health, and operator guardrails before any write or deploy action.",
      "Save source-health notes or blockers when checks are failed, missing, stale, or waiting on review.",
      "Return current state, failed or pending checks, owner or reviewer needs, deploy risk, and the next safe action.",
    ].join("\n"),
  },
  {
    id: "source-coverage-diff",
    title: "Source coverage diff",
    summary: "Compare expected security sources with registered Cerebro source/runtime coverage.",
    aliases: ["source coverage", "registered source", "hooked up", "connector diff", "source diff", "iru", "kandji"],
    category: "runtime",
    prompt: [
      "Check whether requested security sources, connectors, runtimes, or source claims are registered and healthy.",
      "Use Cerebro connector/source tools first for current tenant state. Use compliance/source docs only for expected semantics, then verify present-tense claims against live source/runtime evidence.",
      "Record source_health_note entries for missing, stale, unhealthy, or ambiguous sources.",
      "Return registered state, missing source or runtime ids, health blockers, evidence checked, and next registration or sync action.",
    ].join("\n"),
  },
  {
    id: "ticket-follow-up",
    title: "Ticket follow-up",
    summary: "Find duplicate tickets, current owner, stale state, and a safe comment or update path.",
    aliases: ["ticket follow-up", "jira follow-up", "stale ticket", "owner", "blocked ticket", "comment draft"],
    category: "operations",
    prompt: [
      "Check the source-of-truth ticket state before suggesting ticket action.",
      "Search for duplicates, read current status and owner, compare against GitHub/Cerebro evidence when useful, and use a ticket draft before a write unless the user explicitly requested a permitted update.",
      "Save operator_blocker or operator_handoff records when ticket state is missing owner, stale, contradictory, or blocked.",
      "Return current ticket state, duplicate risk, proposed comment or update, and the next owner action.",
    ].join("\n"),
  },
];

const skillLookup = new Map(SECURITY_SKILLS.flatMap((skill) => [
  [skill.id, skill],
  ...skill.aliases.map((alias) => [normalizeSkillText(alias), skill] as const),
] as const));

export function listSecuritySkills(): SecuritySkill[] {
  return SECURITY_SKILLS;
}

export function findSecuritySkill(idOrAlias: string | undefined): SecuritySkill | undefined {
  if (!idOrAlias?.trim()) return undefined;
  const normalized = normalizeSkillText(idOrAlias);
  return skillLookup.get(normalized) ?? SECURITY_SKILLS.find((skill) => normalizeSkillText(skill.title) === normalized);
}

export function findSecuritySkillsInText(textValue: string): SecuritySkill[] {
  const normalized = normalizeSkillText(textValue);
  const matches = SECURITY_SKILLS.filter((skill) => {
    if (normalized.includes(normalizeSkillText(skill.id)) || normalized.includes(normalizeSkillText(skill.title))) {
      return true;
    }
    return skill.aliases.some((alias) => normalized.includes(normalizeSkillText(alias)));
  });
  return uniqueBy(matches, (skill) => skill.id);
}

export function skillPrompt(skill: SecuritySkill, details = "", learnedGuidance: string[] = []): string {
  const trimmed = details.replace(/\s+/g, " ").trim();
  return [
    `Run security skill: ${skill.title}.`,
    skill.prompt,
    learnedGuidance.length > 0 ? [
      "Learned procedural guidance for this skill:",
      ...learnedGuidance.slice(0, 6).map((item) => `- ${item}`),
    ].join("\n") : "",
    trimmed ? `Request details: ${trimmed}` : "",
  ].filter(Boolean).join("\n");
}

export function skillSteps(skill: SecuritySkill, details = ""): SecuritySkillStep[] {
  const templates = skill.steps?.length ? skill.steps : [{ id: "check", title: skill.title, prompt: skill.prompt }];
  return templates.map((step) => ({
    id: step.id,
    title: step.title,
    skillId: skill.id,
    prompt: [
      `Run security skill step: ${skill.title} / ${step.title}.`,
      step.prompt,
      details.trim() ? `Request details: ${details.trim()}` : "",
    ].filter(Boolean).join("\n"),
    dependsOn: step.dependsOn ?? [],
  }));
}

export function normalizeSkillText(value: string): string {
  return value.toLowerCase().replace(/[^a-z0-9]+/g, " ").trim();
}

function uniqueBy<T>(values: T[], key: (value: T) => string): T[] {
  const seen = new Set<string>();
  const result: T[] = [];
  for (const value of values) {
    const id = key(value);
    if (seen.has(id)) continue;
    seen.add(id);
    result.push(value);
  }
  return result;
}
