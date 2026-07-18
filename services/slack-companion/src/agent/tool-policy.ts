import { securityAgentToolMetadata } from "./tools/tool-metadata.js";

export type SecurityAgentToolTier =
  | "read"
  | "memory_write"
  | "workspace_write"
  | "github_write"
  | "ticket_write"
  | "slack_write"
  | "bounded_shell"
  | "autonomy_write"
  | "approval";

export type SecurityAgentIntent =
  | "security_answer"
  | "self_improvement"
  | "code_change"
  | "response_action";

export interface SecurityAgentToolPolicy {
  name: string;
  tier: SecurityAgentToolTier;
  allowedIntents: SecurityAgentIntent[];
  approvalRequired: boolean;
  summary: string;
}

export interface SecurityAgentToolPolicyDecision {
  allowed: boolean;
  policy: SecurityAgentToolPolicy;
  intent: SecurityAgentIntent;
  reason?: string;
}

interface ToolPolicySummary {
  name: string;
  label?: string;
  description?: string;
}

const DEFAULT_READ_POLICY: Omit<SecurityAgentToolPolicy, "name"> = {
  tier: "read",
  allowedIntents: ["security_answer", "self_improvement", "code_change", "response_action"],
  approvalRequired: false,
  summary: "Read-only investigation tool.",
};

const TOOL_POLICIES = new Map<string, Omit<SecurityAgentToolPolicy, "name">>([
  ["security_working_memory_write", {
    tier: "memory_write",
    allowedIntents: ["security_answer", "self_improvement", "code_change", "response_action"],
    approvalRequired: false,
    summary: "Write tiny non-secret working-memory facts.",
  }],
  ["security_learning_docs_write", {
    tier: "memory_write",
    allowedIntents: ["security_answer", "self_improvement", "code_change", "response_action"],
    approvalRequired: false,
    summary: "Write stable non-secret learned procedures.",
  }],
  ["security_memory_write", {
    tier: "memory_write",
    allowedIntents: ["security_answer", "self_improvement", "code_change", "response_action"],
    approvalRequired: false,
    summary: "Store non-secret memory candidates or verified lessons.",
  }],
  ["security_memory_promote", {
    tier: "memory_write",
    allowedIntents: ["security_answer", "self_improvement", "code_change", "response_action"],
    approvalRequired: false,
    summary: "Promote verified non-secret memory into learning docs.",
  }],
  ["security_memory_hygiene", {
    tier: "memory_write",
    allowedIntents: ["self_improvement", "code_change"],
    approvalRequired: false,
    summary: "Clean up transient or duplicate memory records.",
  }],
  ["operator_memory_record", {
    tier: "memory_write",
    allowedIntents: ["security_answer", "self_improvement", "code_change", "response_action"],
    approvalRequired: false,
    summary: "Store one non-secret structured operator memory record.",
  }],
  ["cerebro_compliance_packet_store", {
    tier: "memory_write",
    allowedIntents: ["security_answer", "self_improvement", "code_change", "response_action"],
    approvalRequired: false,
    summary: "Store one bounded compliance packet for later review.",
  }],
  ["operator_goal_create", {
    tier: "autonomy_write",
    allowedIntents: ["security_answer", "self_improvement", "code_change", "response_action"],
    approvalRequired: false,
    summary: "Create a durable goal for broad work that should continue beyond the current Slack turn.",
  }],
  ["operator_agent_run_step_bind", {
    tier: "autonomy_write",
    allowedIntents: ["security_answer", "self_improvement", "code_change", "response_action"],
    approvalRequired: false,
    summary: "Bind one policy-checked tool to a waiting mission step without executing it.",
  }],
  ["operator_agent_run_step_decide", {
    tier: "autonomy_write",
    allowedIntents: ["security_answer", "self_improvement", "code_change", "response_action"],
    approvalRequired: false,
    summary: "Record one evidence-backed mission decision; reviewed action approval remains separate.",
  }],
  ["operator_security_case_start", {
    tier: "autonomy_write",
    allowedIntents: ["security_answer", "code_change", "response_action"],
    approvalRequired: false,
    summary: "Start one durable GitHub security-alert case after current evidence identifies its finding and repository.",
  }],
  ["operator_security_case_open_work_item", {
    tier: "autonomy_write",
    allowedIntents: ["security_answer", "code_change", "response_action"],
    approvalRequired: false,
    summary: "Open one durable operator case for an existing canonical Cerebro work item.",
  }],
  ["operator_security_case_attach_fix", {
    tier: "autonomy_write",
    allowedIntents: ["code_change", "response_action"],
    approvalRequired: false,
    summary: "Attach a bounded reviewable fix and verified-closure journey to one security case.",
  }],
  ["operator_security_case_command", {
    tier: "autonomy_write",
    allowedIntents: ["response_action"],
    approvalRequired: false,
    summary: "Attach one version-checked canonical work-item command to a durable approval flow.",
  }],
  ["operator_security_case_execute_command", {
    tier: "approval",
    allowedIntents: ["response_action"],
    approvalRequired: true,
    summary: "Apply one approved, version-checked command to a canonical Cerebro work item.",
  }],
  ["operator_task_artifact_record", {
    tier: "autonomy_write",
    allowedIntents: ["security_answer", "self_improvement", "code_change", "response_action"],
    approvalRequired: false,
    summary: "Attach an existing concrete artifact to one durable agent run.",
  }],
  ["operator_correction_record", {
    tier: "memory_write",
    allowedIntents: ["security_answer", "self_improvement", "code_change", "response_action"],
    approvalRequired: false,
    summary: "Store one source-verified replacement for a prior claim.",
  }],
  ["cerebro_code_workspace_write", {
    tier: "workspace_write",
    allowedIntents: ["code_change", "response_action"],
    approvalRequired: false,
    summary: "Write files inside the bounded runtime workspace.",
  }],
  ["cerebro_code_workspace_patch", {
    tier: "workspace_write",
    allowedIntents: ["code_change", "response_action"],
    approvalRequired: false,
    summary: "Patch files inside the bounded runtime workspace.",
  }],
  ["cerebro_code_shell_run", {
    tier: "bounded_shell",
    allowedIntents: ["code_change", "response_action"],
    approvalRequired: false,
    summary: "Run an exfil-gated shell command inside the bounded runtime workspace.",
  }],
  ["cerebro_code_github_pr", {
    tier: "github_write",
    allowedIntents: ["code_change", "response_action"],
    approvalRequired: false,
    summary: "Open a reviewable GitHub PR in a configured write org.",
  }],
  ["cerebro_code_self_improvement_pr", {
    tier: "github_write",
    allowedIntents: ["self_improvement"],
    approvalRequired: false,
    summary: "Open one operator-bound draft PR in the configured companion repository with protected paths excluded.",
  }],
  ["cerebro_compliance_monitor_create", {
    tier: "approval",
    allowedIntents: ["response_action"],
    approvalRequired: true,
    summary: "Create one approved continuous-compliance schedule from a review-ready packet.",
  }],
  ["cerebro_policy_candidate_create", {
    tier: "autonomy_write",
    allowedIntents: ["security_answer", "code_change", "response_action"],
    approvalRequired: false,
    summary: "Store one private, redacted policy hypothesis for source-backed authoring and testing; it cannot promote a rule.",
  }],
  ["cerebro_policy_candidate_prove", {
    tier: "autonomy_write",
    allowedIntents: ["security_answer", "code_change", "response_action"],
    approvalRequired: false,
    summary: "Ground, author, and prove one private policy candidate without creating findings or changing production policy.",
  }],
  ["cerebro_policy_candidate_shadow", {
    tier: "autonomy_write",
    allowedIntents: ["security_answer", "code_change", "response_action"],
    approvalRequired: false,
    summary: "Shadow one proved policy candidate without creating findings or changing production policy.",
  }],
  ["cerebro_policy_candidate_export", {
    tier: "read",
    allowedIntents: ["code_change", "response_action"],
    approvalRequired: false,
    summary: "Export the two bounded files from one operator-reviewed ready candidate for the existing GitHub PR path.",
  }],
  ["jira_issue_search", {
    tier: "read",
    allowedIntents: ["security_answer", "self_improvement", "code_change", "response_action"],
    approvalRequired: false,
    summary: "Read Jira issue summaries through bounded JQL search.",
  }],
  ["jira_issue_create", {
    tier: "ticket_write",
    allowedIntents: ["response_action"],
    approvalRequired: false,
    summary: "Create one external Jira issue from supplied issue fields.",
  }],
  ["jira_issue_update", {
    tier: "ticket_write",
    allowedIntents: ["response_action"],
    approvalRequired: false,
    summary: "Update one external Jira issue with an explicit comment, label, or transition request.",
  }],
  ["linear_issue_create", {
    tier: "ticket_write",
    allowedIntents: ["response_action"],
    approvalRequired: false,
    summary: "Create one external Linear issue from supplied issue fields.",
  }],
  ["slack_risk_attestation_request", {
    tier: "slack_write",
    allowedIntents: ["security_answer", "response_action"],
    approvalRequired: false,
    summary: "Ask one evidence-linked person to self-attest to bounded risk activity in a configured security channel.",
  }],
  ["source_run_trigger", {
    tier: "approval",
    allowedIntents: ["response_action"],
    approvalRequired: true,
    summary: "Start one Cerebro source run only when execute=true and reviewed approval are present.",
  }],
  ["cerebro_offboarding_refresh", {
    tier: "approval",
    allowedIntents: ["response_action"],
    approvalRequired: true,
    summary: "Refresh exact Okta, GitHub, and AWS source evidence only with reviewed approval.",
  }],
  ["cerebro_offboarding_action", {
    tier: "approval",
    allowedIntents: ["response_action"],
    approvalRequired: true,
    summary: "Execute a finding-scoped provider action only with a reviewed proposal and approval.",
  }],
  ["operator_offboarding_control_start", {
    tier: "autonomy_write",
    allowedIntents: ["response_action"],
    approvalRequired: false,
    summary: "Create one durable offboarding-control run from reviewed, digest-bound inputs.",
  }],
  ["finding_update", {
    tier: "approval",
    allowedIntents: ["response_action"],
    approvalRequired: true,
    summary: "Write one Cerebro finding update only when execute=true and reviewed approval are present.",
  }],
]);

export function inferSecurityAgentIntent(input: { question: string }): SecurityAgentIntent {
  const normalized = input.question.toLowerCase();
  if (/\b(handle|fix|patch|remediate)\w*\b.*\b(alert|finding|security case|vulnerabilit(?:y|ies))\b/.test(normalized)
    || /\b(remediate|resolve|suppress|assign|set due|due date|add note|disable|enable|delete|remove|revoke|suspend|unsuspend|deploy|rollout|apply|execute|close)\b/.test(normalized)
    || /\b(sync|ingest|evaluate|refresh|rerun|re-run)\b/.test(normalized)
    || /\b(open|create|file|make|update|comment|transition|label|link)\s+(a\s+)?(jira|linear|ticket|issue)\b/.test(normalized)
    || /\b(jira|linear)\s+(ticket|issue)\b/.test(normalized)) {
    return "response_action";
  }
  if (/\b(self[- ]?improv|improve yourself|fix yourself|debug yourself|repair yourself|agent behavior|tool behavior|skill|prompt|memory hygiene)\b/.test(normalized)) {
    return "self_improvement";
  }
  if (/\b(code|repo|repository|patch|pull request|pr|commit|branch|test|ci|build|typescript|refactor|implement|change the service|write file)\b/.test(normalized)) {
    return "code_change";
  }
  return "security_answer";
}

export function securityAgentToolPolicy(toolName: string): SecurityAgentToolPolicy {
  const metadata = securityAgentToolMetadata(toolName);
  const policy = TOOL_POLICIES.get(toolName) ?? (metadata.authority === "security_write" ? {
    tier: "approval" as const,
    allowedIntents: ["response_action" as const],
    approvalRequired: true,
    summary: "Change one external security control only through a reviewed mission step with rollback and independent verification.",
  } : DEFAULT_READ_POLICY);
  return {
    name: toolName,
    tier: policy.tier,
    allowedIntents: [...policy.allowedIntents],
    approvalRequired: policy.approvalRequired,
    summary: policy.summary,
  };
}

export function evaluateSecurityAgentToolCall(toolName: string, intent: SecurityAgentIntent): SecurityAgentToolPolicyDecision {
  const policy = securityAgentToolPolicy(toolName);
  const allowed = policy.allowedIntents.includes(intent);
  return {
    allowed,
    policy,
    intent,
    reason: allowed
      ? undefined
      : `${toolName} is ${policy.tier} and is only available for ${policy.allowedIntents.join(", ")} intents. Current intent: ${intent}.`,
  };
}

export function toolPolicyManifest(tools: ToolPolicySummary[]): Record<string, unknown> {
  const rows = tools.map((tool) => {
    const policy = securityAgentToolPolicy(tool.name);
    const metadata = securityAgentToolMetadata(tool.name);
    return {
      name: tool.name,
      label: tool.label,
      authority: metadata.authority,
      credential_scope: metadata.credentialScope,
      family: metadata.family,
      retry: metadata.retry,
      side_effect: metadata.sideEffect,
      target_source: metadata.targetSource,
      tier: policy.tier,
      allowed_intents: policy.allowedIntents,
      approval_required: policy.approvalRequired,
      summary: policy.summary,
      description: tool.description,
    };
  });
  return {
    default_policy: "Tools are read-only unless listed as memory, workspace, shell, GitHub, Slack message, or ticket write tools.",
    write_boundary: "Policy-candidate tools may store, prove, and shadow private redacted hypotheses, but cannot promote a rule, create findings, write the graph, open a pull request, or merge code. Self-improvement can submit one operator-bound draft PR to the configured companion repository. General workspace writes, bounded shell, and GitHub PR creation require a code-change or explicit security-case response-action intent. Jira and Linear ticket writes require an explicit response-action ticket request. A Slack risk check requires current identity and risk evidence in a configured security channel and remains self-attestation. Cerebro source refreshes, finding writes, canonical work-item writes, and provider actions require execute=true plus reviewed approval.",
    tools: rows,
  };
}

export function toolPolicyPrompt(tools: ToolPolicySummary[]): string {
  const rows = tools.map((tool) => {
    const policy = securityAgentToolPolicy(tool.name);
    return `- ${tool.name}: ${policy.tier}; allowed_intents=${policy.allowedIntents.join(",")}; ${policy.summary}`;
  });
  return [
    "Tool autonomy policy:",
    "Read-only investigation tools are allowed for security answers.",
    "Memory writes are allowed only for non-secret lessons, preferences, and verified investigation notes.",
    "Durable goals are allowed for broad work that needs checkpoints, follow-up, or approval-aware continuation.",
    "Self-improvement may submit one operator-bound draft PR to the configured companion repository through cerebro_code_self_improvement_pr. It cannot use general workspace writes, shell, or GitHub writes.",
    "General workspace writes, bounded shell, and GitHub PR creation are available only for code-change or explicit security-case response-action requests.",
    "Jira and Linear ticket write tools are available only for explicit ticket requests.",
    "The Slack risk-check tool may contact one evidence-linked person from a configured security channel. Treat every answer as unverified self-attestation and continue source verification.",
    "Policy-candidate tools may create, prove, and shadow a private host-derived hypothesis for a configured operator or configured security-triage channel. Cross-candidate reads require an operator. They cannot promote a policy, create findings, write the graph, open a pull request, or merge code.",
    "Cerebro source refreshes, finding writes, canonical work-item writes, and provider actions need execute=true and reviewed approval; do read-only checks, dry runs, and approval-ready plans first.",
    ...rows,
  ].join("\n");
}
