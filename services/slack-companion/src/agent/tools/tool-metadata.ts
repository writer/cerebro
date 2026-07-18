export type SecurityToolFamily =
  | "cerebro"
  | "compliance"
  | "evidence_cas"
  | "graph"
  | "infisical"
  | "learning_docs"
  | "memory"
  | "operator"
  | "panther_mcp"
  | "runtime_code"
  | "self_context"
  | "skills"
  | "slack"
  | "ticketing"
  | "other";

export type SecurityToolAuthority =
  | "autonomy_write"
  | "cerebro_write"
  | "security_write"
  | "read"
  | "memory_write"
  | "workspace_write"
  | "github_write"
  | "ticket_write"
  | "slack_write"
  | "bounded_shell";

export type SecurityToolTargetSource =
  | "bounded_workspace"
  | "host_configuration"
  | "model_arguments"
  | "runtime_context"
  | "slack_event_context";

export type SecurityToolCredentialScope =
  | "cerebro_read_key"
  | "cerebro_findings_key"
  | "cerebro_source_key"
  | "cerebro_graph_actions_key"
  | "compliance_context"
  | "evidence_cas_read_token"
  | "github_runtime_credentials"
  | "infisical_identity"
  | "panther_mcp_auth_token"
  | "ticketing_credentials"
  | "ticketing_defaults"
  | "none"
  | "runtime_workspace"
  | "slack_bot_token";

export type SecurityToolSideEffect =
  | "autonomy_goal"
  | "cerebro_finding_update"
  | "cerebro_policy_candidate"
  | "cerebro_source_run"
  | "cerebro_graph_action"
  | "none"
  | "external_ticket"
  | "github_pr"
  | "learning_docs"
  | "memory"
  | "process"
  | "schedule"
  | "slack_message"
  | "security_platform_change"
  | "workspace_file";

export type SecurityToolRetryModel =
  | "none"
  | "transient_retry"
  | "tool_owned";

export interface SecurityToolMetadata {
  authority: SecurityToolAuthority;
  credentialScope: SecurityToolCredentialScope;
  family: SecurityToolFamily;
  retry: SecurityToolRetryModel;
  sideEffect: SecurityToolSideEffect;
  targetSource: SecurityToolTargetSource;
}

type MetadataInput = Partial<SecurityToolMetadata> & Pick<SecurityToolMetadata, "family">;

const READ_DEFAULT: Omit<SecurityToolMetadata, "family"> = {
  authority: "read",
  credentialScope: "none",
  retry: "none",
  sideEffect: "none",
  targetSource: "model_arguments",
};

function exactMetadata(entries: Array<[string, MetadataInput]>): Map<string, MetadataInput> {
  const seen = new Set<string>();
  for (const [toolName] of entries) {
    if (seen.has(toolName)) throw new Error(`Duplicate exact security tool metadata: ${toolName}`);
    seen.add(toolName);
  }
  return new Map(entries);
}

const EXACT_METADATA = exactMetadata([
  ["cerebro_tool_search", {
    family: "runtime_code",
    targetSource: "runtime_context",
  }],
  ["cerebro_execute", {
    family: "runtime_code",
    targetSource: "runtime_context",
  }],
  ["cerebro_code_self_improvement_pr", {
    authority: "github_write",
    credentialScope: "github_runtime_credentials",
    family: "runtime_code",
    sideEffect: "github_pr",
    targetSource: "runtime_context",
  }],
  ["cerebro_compliance_monitor_create", {
    authority: "autonomy_write",
    family: "compliance",
    sideEffect: "schedule",
    targetSource: "model_arguments",
  }],
  ["cerebro_compliance_packet_store", {
    authority: "memory_write",
    credentialScope: "compliance_context",
    family: "compliance",
    sideEffect: "memory",
    targetSource: "model_arguments",
  }],
  ["evidence_cas_resolve", {
    credentialScope: "evidence_cas_read_token",
    family: "evidence_cas",
    targetSource: "model_arguments",
  }],
  ["owner_resolve", {
    credentialScope: "cerebro_read_key",
    family: "operator",
    retry: "transient_retry",
    targetSource: "model_arguments",
  }],
  ["source_run_status", {
    credentialScope: "cerebro_read_key",
    family: "cerebro",
    retry: "transient_retry",
    targetSource: "model_arguments",
  }],
  ["cerebro_companion_self_context", {
    family: "self_context",
    targetSource: "host_configuration",
  }],
  ["cerebro_code_status", {
    family: "runtime_code",
    targetSource: "host_configuration",
  }],
  ["cerebro_code_github_pr_status", {
    credentialScope: "github_runtime_credentials",
    family: "runtime_code",
    targetSource: "model_arguments",
  }],
  ["cerebro_code_github_checks", {
    credentialScope: "github_runtime_credentials",
    family: "runtime_code",
    targetSource: "model_arguments",
  }],
  ["cerebro_code_github_source_list", {
    credentialScope: "github_runtime_credentials",
    family: "runtime_code",
    targetSource: "model_arguments",
  }],
  ["cerebro_code_github_source_read", {
    credentialScope: "github_runtime_credentials",
    family: "runtime_code",
    targetSource: "model_arguments",
  }],
  ["security_working_memory_write", {
    authority: "memory_write",
    family: "memory",
    sideEffect: "memory",
    targetSource: "runtime_context",
  }],
  ["security_learning_docs_write", {
    authority: "memory_write",
    family: "learning_docs",
    sideEffect: "learning_docs",
    targetSource: "model_arguments",
  }],
  ["security_memory_write", {
    authority: "memory_write",
    family: "memory",
    sideEffect: "memory",
    targetSource: "model_arguments",
  }],
  ["security_memory_promote", {
    authority: "memory_write",
    family: "memory",
    sideEffect: "learning_docs",
    targetSource: "model_arguments",
  }],
  ["security_memory_hygiene", {
    authority: "memory_write",
    family: "memory",
    sideEffect: "memory",
    targetSource: "runtime_context",
  }],
  ["cerebro_code_workspace_write", {
    authority: "workspace_write",
    credentialScope: "runtime_workspace",
    family: "runtime_code",
    sideEffect: "workspace_file",
    targetSource: "bounded_workspace",
  }],
  ["cerebro_code_workspace_patch", {
    authority: "workspace_write",
    credentialScope: "runtime_workspace",
    family: "runtime_code",
    sideEffect: "workspace_file",
    targetSource: "bounded_workspace",
  }],
  ["cerebro_code_shell_run", {
    authority: "bounded_shell",
    credentialScope: "runtime_workspace",
    family: "runtime_code",
    sideEffect: "process",
    targetSource: "bounded_workspace",
  }],
  ["cerebro_code_github_pr", {
    authority: "github_write",
    credentialScope: "github_runtime_credentials",
    family: "runtime_code",
    sideEffect: "github_pr",
    targetSource: "model_arguments",
  }],
  ["jira_issue_create", {
    authority: "ticket_write",
    credentialScope: "ticketing_credentials",
    family: "ticketing",
    sideEffect: "external_ticket",
    targetSource: "model_arguments",
  }],
  ["jira_issue_search", {
    credentialScope: "ticketing_credentials",
    family: "ticketing",
    retry: "transient_retry",
    targetSource: "model_arguments",
  }],
  ["jira_issue_update", {
    authority: "ticket_write",
    credentialScope: "ticketing_credentials",
    family: "ticketing",
    sideEffect: "external_ticket",
    targetSource: "model_arguments",
  }],
  ["linear_issue_create", {
    authority: "ticket_write",
    credentialScope: "ticketing_credentials",
    family: "ticketing",
    sideEffect: "external_ticket",
    targetSource: "model_arguments",
  }],
  ["source_run_trigger", {
    authority: "cerebro_write",
    credentialScope: "cerebro_source_key",
    family: "cerebro",
    retry: "tool_owned",
    sideEffect: "cerebro_source_run",
    targetSource: "model_arguments",
  }],
  ["cerebro_offboarding_refresh", {
    authority: "cerebro_write",
    credentialScope: "cerebro_source_key",
    family: "cerebro",
    retry: "tool_owned",
    sideEffect: "cerebro_source_run",
    targetSource: "model_arguments",
  }],
  ["cerebro_offboarding_action", {
    authority: "cerebro_write",
    credentialScope: "cerebro_graph_actions_key",
    family: "cerebro",
    retry: "tool_owned",
    sideEffect: "cerebro_graph_action",
    targetSource: "model_arguments",
  }],
  ["cerebro_offboarding_snapshot", {
    credentialScope: "cerebro_read_key",
    family: "cerebro",
    retry: "transient_retry",
    targetSource: "model_arguments",
  }],
  ["cerebro_offboarding_preflight", {
    credentialScope: "cerebro_read_key",
    family: "cerebro",
    retry: "transient_retry",
    targetSource: "model_arguments",
  }],
  ["cerebro_offboarding_verify", {
    credentialScope: "cerebro_read_key",
    family: "cerebro",
    retry: "transient_retry",
    targetSource: "model_arguments",
  }],
  ["operator_offboarding_control_start", {
    authority: "autonomy_write",
    family: "operator",
    sideEffect: "autonomy_goal",
    targetSource: "model_arguments",
  }],
  ["finding_update", {
    authority: "cerebro_write",
    credentialScope: "cerebro_findings_key",
    family: "cerebro",
    retry: "tool_owned",
    sideEffect: "cerebro_finding_update",
    targetSource: "model_arguments",
  }],
  ["cerebro_panopticon_alerts", {
    credentialScope: "cerebro_read_key",
    family: "cerebro",
    retry: "transient_retry",
    targetSource: "model_arguments",
  }],
  ["cerebro_agent_control_plane", {
    credentialScope: "cerebro_read_key",
    family: "cerebro",
    retry: "transient_retry",
    targetSource: "host_configuration",
  }],
  ["cerebro_decision_packet", {
    credentialScope: "cerebro_read_key",
    family: "cerebro",
    retry: "transient_retry",
    targetSource: "model_arguments",
  }],
  ["cerebro_policy_candidate_create", {
    authority: "cerebro_write",
    credentialScope: "cerebro_findings_key",
    family: "cerebro",
    retry: "none",
    sideEffect: "cerebro_policy_candidate",
    targetSource: "runtime_context",
  }],
  ["cerebro_policy_candidate_get", {
    credentialScope: "cerebro_read_key",
    family: "cerebro",
    retry: "transient_retry",
    targetSource: "model_arguments",
  }],
  ["cerebro_policy_candidate_list", {
    credentialScope: "cerebro_read_key",
    family: "cerebro",
    retry: "transient_retry",
    targetSource: "model_arguments",
  }],
  ["cerebro_policy_candidate_export", {
    credentialScope: "cerebro_read_key",
    family: "cerebro",
    retry: "transient_retry",
    targetSource: "model_arguments",
  }],
  ["cerebro_policy_candidate_prove", {
    authority: "cerebro_write",
    credentialScope: "cerebro_findings_key",
    family: "cerebro",
    retry: "tool_owned",
    sideEffect: "cerebro_policy_candidate",
    targetSource: "model_arguments",
  }],
  ["cerebro_policy_candidate_shadow", {
    authority: "cerebro_write",
    credentialScope: "cerebro_findings_key",
    family: "cerebro",
    retry: "tool_owned",
    sideEffect: "cerebro_policy_candidate",
    targetSource: "model_arguments",
  }],
  ["cerebro_connector_preflight", {
    credentialScope: "cerebro_source_key",
    family: "cerebro",
    retry: "transient_retry",
    targetSource: "model_arguments",
  }],
  ["operator_goal_create", {
    authority: "autonomy_write",
    family: "operator",
    sideEffect: "autonomy_goal",
    targetSource: "model_arguments",
  }],
  ["operator_security_case_start", {
    authority: "autonomy_write",
    family: "operator",
    sideEffect: "autonomy_goal",
    targetSource: "model_arguments",
  }],
  ["operator_security_case_attach_fix", {
    authority: "autonomy_write",
    family: "operator",
    sideEffect: "autonomy_goal",
    targetSource: "model_arguments",
  }],
  ["operator_security_case_status", {
    family: "operator",
    targetSource: "model_arguments",
  }],
  ["operator_security_case_list", {
    family: "operator",
    targetSource: "runtime_context",
  }],
  ["operator_tool_catalog_search", {
    family: "operator",
    targetSource: "runtime_context",
  }],
  ["operator_context_resolve", {
    family: "operator",
    targetSource: "model_arguments",
  }],
  ["operator_agent_run_status", {
    family: "operator",
    targetSource: "model_arguments",
  }],
  ["operator_mission_compile", {
    family: "operator",
    targetSource: "runtime_context",
  }],
  ["operator_agent_run_step_bind", {
    authority: "autonomy_write",
    family: "operator",
    sideEffect: "autonomy_goal",
    targetSource: "model_arguments",
  }],
  ["operator_agent_run_step_decide", {
    authority: "autonomy_write",
    family: "operator",
    sideEffect: "autonomy_goal",
    targetSource: "model_arguments",
  }],
  ["operator_task_artifact_record", {
    authority: "autonomy_write",
    family: "operator",
    sideEffect: "autonomy_goal",
    targetSource: "model_arguments",
  }],
  ["operator_correction_record", {
    authority: "memory_write",
    family: "operator",
    sideEffect: "memory",
    targetSource: "model_arguments",
  }],
  ["operator_memory_record", {
    authority: "memory_write",
    family: "operator",
    sideEffect: "memory",
    targetSource: "model_arguments",
  }],
  ["operator_research_plan", {
    family: "operator",
    targetSource: "runtime_context",
  }],
  ["operator_claim_ledger", {
    family: "operator",
    targetSource: "runtime_context",
  }],
  ["operator_world_state", {
    family: "operator",
    targetSource: "runtime_context",
  }],
  ["operator_hypothesis_ledger", {
    family: "operator",
    targetSource: "runtime_context",
  }],
  ["operator_decision_ledger", {
    family: "operator",
    targetSource: "runtime_context",
  }],
  ["operator_workflow_compile", {
    family: "operator",
    targetSource: "runtime_context",
  }],
  ["operator_action_simulation", {
    family: "operator",
    targetSource: "runtime_context",
  }],
  ["operator_attention_decision", {
    family: "operator",
    targetSource: "runtime_context",
  }],
  ["slack_risk_attestation_request", {
    authority: "slack_write",
    credentialScope: "slack_bot_token",
    family: "slack",
    retry: "tool_owned",
    sideEffect: "slack_message",
    targetSource: "slack_event_context",
  }],
]);

const PREFIX_METADATA: Array<[string, MetadataInput]> = [
  ["operator_", {
    family: "operator",
  }],
  ["owner_", {
    credentialScope: "cerebro_read_key",
    family: "operator",
    retry: "transient_retry",
  }],
  ["source_run_status", {
    credentialScope: "cerebro_read_key",
    family: "cerebro",
    retry: "transient_retry",
  }],
  ["finding_lookup", {
    credentialScope: "cerebro_read_key",
    family: "cerebro",
    retry: "transient_retry",
  }],
  ["evidence_bundle_", {
    credentialScope: "cerebro_read_key",
    family: "cerebro",
    retry: "transient_retry",
  }],
  ["cerebro_graph_", {
    credentialScope: "cerebro_read_key",
    family: "graph",
    retry: "transient_retry",
  }],
  ["cerebro_code_", {
    credentialScope: "runtime_workspace",
    family: "runtime_code",
    targetSource: "bounded_workspace",
  }],
  ["cerebro_compliance_", {
    credentialScope: "compliance_context",
    family: "compliance",
  }],
  ["cerebro_", {
    credentialScope: "cerebro_read_key",
    family: "cerebro",
    retry: "transient_retry",
  }],
  ["evidence_cas_", {
    credentialScope: "evidence_cas_read_token",
    family: "evidence_cas",
  }],
  ["infisical_", {
    credentialScope: "infisical_identity",
    family: "infisical",
    targetSource: "host_configuration",
  }],
  ["panther_mcp_", {
    credentialScope: "panther_mcp_auth_token",
    family: "panther_mcp",
    retry: "transient_retry",
  }],
  ["ticketing_", {
    credentialScope: "ticketing_defaults",
    family: "ticketing",
    targetSource: "host_configuration",
  }],
  ["jira_", {
    credentialScope: "ticketing_defaults",
    family: "ticketing",
  }],
  ["linear_", {
    credentialScope: "ticketing_defaults",
    family: "ticketing",
  }],
  ["security_learning_", {
    family: "learning_docs",
  }],
  ["security_memory", {
    family: "memory",
    retry: "transient_retry",
  }],
  ["security_session", {
    family: "memory",
    retry: "transient_retry",
  }],
  ["security_working", {
    family: "memory",
    targetSource: "runtime_context",
  }],
  ["security_skill", {
    family: "skills",
    targetSource: "runtime_context",
  }],
  ["company_library_", {
    family: "memory",
    retry: "transient_retry",
  }],
  ["slack_", {
    credentialScope: "slack_bot_token",
    family: "slack",
    targetSource: "slack_event_context",
  }],
];

// Code Mode must never infer read authority for a newly registered tool from a
// name prefix. These existing read-only tools are enrolled by exact name; tools
// with side effects are enrolled through EXACT_METADATA above.
const EXPLICIT_CODE_MODE_READ_TOOLS = new Set([
  "cerebro_agent_claim_verify",
  "cerebro_code_workspace_list",
  "cerebro_code_workspace_read",
  "cerebro_code_workspace_read_many",
  "cerebro_code_workspace_search",
  "cerebro_compliance_context",
  "cerebro_compliance_context_status",
  "cerebro_compliance_gap_jira_draft",
  "cerebro_compliance_packet",
  "cerebro_compliance_packet_lookup",
  "cerebro_connector_activity",
  "cerebro_connector_catalog",
  "cerebro_connector_coverage",
  "cerebro_connector_credentials",
  "cerebro_connector_definition_plan",
  "cerebro_connector_definition_validate",
  "cerebro_connector_definitions",
  "cerebro_connector_detail",
  "cerebro_entity_neighborhood",
  "cerebro_evidence_packet",
  "cerebro_finding",
  "cerebro_finding_evidence",
  "cerebro_finding_investigation",
  "cerebro_finding_lifecycle_preflight",
  "cerebro_findings",
  "cerebro_graph_cypher_investigate",
  "cerebro_graph_cypher_schema",
  "cerebro_graph_reason",
  "cerebro_open_findings",
  "cerebro_offboarding_preflight",
  "cerebro_recent_scary_findings",
  "cerebro_runtime_health",
  "cerebro_security_posture",
  "cerebro_source_claims",
  "cerebro_source_invalid_events",
  "cerebro_source_runtimes",
  "company_library_read",
  "company_library_search",
  "evidence_bundle_get",
  "evidence_cas_status",
  "finding_lookup",
  "infisical_secret_fingerprint",
  "infisical_secret_metadata",
  "infisical_status",
  "jira_issue_draft",
  "linear_issue_draft",
  "operator_action_audit_log",
  "operator_handoff_packet",
  "operator_notification_plan",
  "operator_playbook_plan",
  "operator_policy_guardrail_check",
  "operator_tool_status",
  "panther_mcp_status",
  "security_learning_docs_read",
  "security_memory_intelligence",
  "security_memory_read",
  "security_memory_search",
  "security_session_recall",
  "security_skill_view",
  "security_skills_list",
  "security_working_memory_read",
  "slack_ai_search_context",
  "slack_app_install_audit",
  "slack_cerebro_recent_questions",
  "slack_channel_context",
  "slack_file_context",
  "slack_message_context",
  "slack_message_search",
  "slack_risk_attestation_status",
  "slack_scope_capabilities",
  "slack_thread_context",
  "slack_user_context",
  "ticketing_status",
]);

export function securityAgentToolMetadata(toolName: string): SecurityToolMetadata {
  const exact = EXACT_METADATA.get(toolName);
  if (exact) return buildMetadata(exact);
  if (isMutatingPantherAgentTool(toolName)) return buildMetadata({
    authority: "security_write",
    credentialScope: "panther_mcp_auth_token",
    family: "panther_mcp",
    retry: "tool_owned",
    sideEffect: "security_platform_change",
    targetSource: "model_arguments",
  });
  const prefix = PREFIX_METADATA.find(([candidate]) => toolName.startsWith(candidate));
  if (prefix) return buildMetadata(prefix[1]);
  return buildMetadata({ family: "other" });
}

function isMutatingPantherAgentTool(toolName: string): boolean {
  return toolName.startsWith("panther_mcp_")
    && /\b(create|update|delete|disable|enable|resolve|comment|assign|snooze|archive|trigger|write|set|patch|put|post)\b/i
      .test(toolName.slice("panther_mcp_".length).replace(/[^a-zA-Z0-9]+/g, " "));
}

export function securityAgentToolMetadataIsExplicit(toolName: string): boolean {
  return EXACT_METADATA.has(toolName) || EXPLICIT_CODE_MODE_READ_TOOLS.has(toolName);
}

export function securityAgentToolFamily(toolName: string): SecurityToolFamily {
  return securityAgentToolMetadata(toolName).family;
}

function buildMetadata(input: MetadataInput): SecurityToolMetadata {
  return {
    ...READ_DEFAULT,
    ...input,
  };
}
