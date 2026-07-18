import assert from "node:assert/strict";
import test from "node:test";
import {
  evaluateSecurityAgentToolCall,
  inferSecurityAgentIntent,
  toolPolicyManifest,
} from "../src/agent/tool-policy.js";
import { createSecurityAgentTools } from "../src/agent/tools/index.js";
import {
  securityAgentToolMetadata,
  securityAgentToolMetadataIsExplicit,
} from "../src/agent/tools/tool-metadata.js";
import { testConfig } from "./fixtures.js";

test("security agent tool policy blocks code writes in ordinary security answers", () => {
  const intent = inferSecurityAgentIntent({ question: "is finding f-1 real?" });
  const decision = evaluateSecurityAgentToolCall("cerebro_code_workspace_write", intent);
  const ticketDecision = evaluateSecurityAgentToolCall("jira_issue_create", intent);

  assert.equal(intent, "security_answer");
  assert.equal(decision.allowed, false);
  assert.equal(decision.policy.tier, "workspace_write");
  assert.match(decision.reason ?? "", /code_change, response_action/);
  assert.equal(ticketDecision.allowed, false);
  assert.equal(ticketDecision.policy.tier, "ticket_write");
});

test("policy discovery can prove a draft but cannot jump from a security answer to GitHub", () => {
  const intent = inferSecurityAgentIntent({ question: "Can Cerebro discover a missing multi-hop AWS exposure pattern?" });
  const create = evaluateSecurityAgentToolCall("cerebro_policy_candidate_create", intent);
  const prove = evaluateSecurityAgentToolCall("cerebro_policy_candidate_prove", intent);
  const shadow = evaluateSecurityAgentToolCall("cerebro_policy_candidate_shadow", intent);
  const exportFiles = evaluateSecurityAgentToolCall("cerebro_policy_candidate_export", intent);
  const github = evaluateSecurityAgentToolCall("cerebro_code_github_pr", intent);

  assert.equal(intent, "security_answer");
  assert.equal(create.allowed, true);
  assert.equal(prove.allowed, true);
  assert.equal(shadow.allowed, true);
  assert.equal(exportFiles.allowed, false);
  assert.equal(create.policy.approvalRequired, false);
  assert.equal(github.allowed, false);
  assert.equal(github.policy.tier, "github_write");
  assert.equal(securityAgentToolMetadata("cerebro_policy_candidate_create").sideEffect, "cerebro_policy_candidate");
  assert.equal(securityAgentToolMetadata("cerebro_policy_candidate_create").credentialScope, "cerebro_findings_key");
  assert.equal(securityAgentToolMetadata("cerebro_policy_candidate_create").retry, "none", "non-idempotent candidate creation must not be retried after an unknown outcome");
  assert.equal(securityAgentToolMetadata("cerebro_policy_candidate_export").authority, "read");
  assert.equal(securityAgentToolMetadata("cerebro_policy_candidate_export").credentialScope, "cerebro_read_key");
  assert.equal(evaluateSecurityAgentToolCall("cerebro_policy_candidate_export", "code_change").allowed, true);
  assert.equal(evaluateSecurityAgentToolCall("cerebro_policy_candidate_export", "response_action").allowed, true);
});

test("security agent tool policy gives self-improvement one protected candidate write", () => {
  const intent = inferSecurityAgentIntent({ question: "debug yourself and open a PR if the tool behavior is wrong" });

  assert.equal(intent, "self_improvement");
  assert.equal(evaluateSecurityAgentToolCall("cerebro_code_workspace_search", intent).allowed, true);
  assert.equal(evaluateSecurityAgentToolCall("cerebro_code_workspace_patch", intent).allowed, false);
  assert.equal(evaluateSecurityAgentToolCall("cerebro_code_shell_run", intent).allowed, false);
  assert.equal(evaluateSecurityAgentToolCall("cerebro_code_github_pr", intent).allowed, false);
  assert.equal(evaluateSecurityAgentToolCall("cerebro_code_self_improvement_pr", intent).allowed, true);
});

test("tool policy manifest marks unknown tools read-only by default", () => {
  const manifest = toolPolicyManifest([
    { name: "cerebro_finding_investigation", label: "Finding investigation" },
    { name: "cerebro_code_github_pr", label: "GitHub PR" },
    { name: "cerebro_code_self_improvement_pr", label: "Self-improvement PR" },
    { name: "jira_issue_search", label: "Search Jira issues" },
    { name: "jira_issue_create", label: "Create Jira issue" },
    { name: "jira_issue_update", label: "Update Jira issue" },
    { name: "source_run_trigger", label: "Source run trigger" },
    { name: "finding_update", label: "Finding update" },
  ]) as any;

  const finding = manifest.tools.find((tool: any) => tool.name === "cerebro_finding_investigation");
  const pr = manifest.tools.find((tool: any) => tool.name === "cerebro_code_github_pr");
  const selfImprovementPr = manifest.tools.find((tool: any) => tool.name === "cerebro_code_self_improvement_pr");
  const jiraSearch = manifest.tools.find((tool: any) => tool.name === "jira_issue_search");
  const jira = manifest.tools.find((tool: any) => tool.name === "jira_issue_create");
  const jiraUpdate = manifest.tools.find((tool: any) => tool.name === "jira_issue_update");
  const sourceRun = manifest.tools.find((tool: any) => tool.name === "source_run_trigger");
  const findingUpdate = manifest.tools.find((tool: any) => tool.name === "finding_update");
  assert.equal(finding.tier, "read");
  assert.equal(pr.tier, "github_write");
  assert.equal(pr.authority, "github_write");
  assert.equal(pr.side_effect, "github_pr");
  assert.equal(pr.credential_scope, "github_runtime_credentials");
  assert.deepEqual(pr.allowed_intents, ["code_change", "response_action"]);
  assert.equal(selfImprovementPr.tier, "github_write");
  assert.deepEqual(selfImprovementPr.allowed_intents, ["self_improvement"]);
  assert.equal(selfImprovementPr.target_source, "runtime_context");
  assert.equal(jiraSearch.tier, "read");
  assert.equal(jiraSearch.authority, "read");
  assert.equal(jiraSearch.side_effect, "none");
  assert.equal(jiraSearch.credential_scope, "ticketing_credentials");
  assert.equal(jira.tier, "ticket_write");
  assert.equal(jira.authority, "ticket_write");
  assert.equal(jira.side_effect, "external_ticket");
  assert.equal(jira.credential_scope, "ticketing_credentials");
  assert.deepEqual(jira.allowed_intents, ["response_action"]);
  assert.equal(jiraUpdate.tier, "ticket_write");
  assert.equal(jiraUpdate.side_effect, "external_ticket");
  assert.deepEqual(jiraUpdate.allowed_intents, ["response_action"]);
  assert.equal(sourceRun.tier, "approval");
  assert.equal(sourceRun.authority, "cerebro_write");
  assert.equal(sourceRun.side_effect, "cerebro_source_run");
  assert.equal(sourceRun.approval_required, true);
  assert.equal(findingUpdate.tier, "approval");
  assert.equal(findingUpdate.credential_scope, "cerebro_findings_key");
  assert.equal(findingUpdate.side_effect, "cerebro_finding_update");
});

test("security agent tool policy allows ticket tools for explicit ticket requests", () => {
  const intent = inferSecurityAgentIntent({ question: "open a Jira issue for finding f-1" });

  assert.equal(intent, "response_action");
  assert.equal(evaluateSecurityAgentToolCall("jira_issue_create", intent).allowed, true);
  assert.equal(evaluateSecurityAgentToolCall("jira_issue_update", intent).allowed, true);
  assert.equal(evaluateSecurityAgentToolCall("linear_issue_create", intent).allowed, true);
});

test("security agent tool policy allows a reviewable fix for an explicit security case request", () => {
  const intent = inferSecurityAgentIntent({ question: "handle this GitHub security alert" });

  assert.equal(intent, "response_action");
  assert.equal(evaluateSecurityAgentToolCall("operator_security_case_start", intent).allowed, true);
  assert.equal(evaluateSecurityAgentToolCall("operator_security_case_open_work_item", intent).allowed, true);
  assert.equal(evaluateSecurityAgentToolCall("operator_security_case_attach_fix", intent).allowed, true);
  assert.equal(evaluateSecurityAgentToolCall("cerebro_code_workspace_patch", intent).allowed, true);
  assert.equal(evaluateSecurityAgentToolCall("cerebro_code_github_pr", intent).allowed, true);
});

test("security agent tool policy approval-gates Cerebro response writes", () => {
  const sourceIntent = inferSecurityAgentIntent({ question: "sync the Okta source runtime now" });
  const findingIntent = inferSecurityAgentIntent({ question: "resolve finding finding-1 after approval" });

  assert.equal(sourceIntent, "response_action");
  assert.equal(findingIntent, "response_action");
  const sourceDecision = evaluateSecurityAgentToolCall("source_run_trigger", sourceIntent);
  const findingDecision = evaluateSecurityAgentToolCall("finding_update", findingIntent);
  const workItemPlanDecision = evaluateSecurityAgentToolCall("operator_security_case_command", findingIntent);
  const workItemDecision = evaluateSecurityAgentToolCall("operator_security_case_execute_command", findingIntent);
  assert.equal(sourceDecision.allowed, true);
  assert.equal(sourceDecision.policy.tier, "approval");
  assert.equal(sourceDecision.policy.approvalRequired, true);
  assert.equal(findingDecision.allowed, true);
  assert.equal(findingDecision.policy.tier, "approval");
  assert.equal(workItemPlanDecision.allowed, true);
  assert.equal(workItemPlanDecision.policy.tier, "autonomy_write");
  assert.equal(workItemPlanDecision.policy.approvalRequired, false);
  assert.equal(workItemDecision.allowed, true);
  assert.equal(workItemDecision.policy.tier, "approval");
  assert.equal(workItemDecision.policy.approvalRequired, true);
  assert.equal(evaluateSecurityAgentToolCall("operator_security_case_execute_command", "security_answer").allowed, false);
  assert.equal(evaluateSecurityAgentToolCall("finding_update", "security_answer").allowed, false);
});

test("security agent tool policy classifies a scoped risk check as a Slack write", () => {
  const decision = evaluateSecurityAgentToolCall("slack_risk_attestation_request", "security_answer");
  const metadata = securityAgentToolMetadata("slack_risk_attestation_request");
  const statusMetadata = securityAgentToolMetadata("slack_risk_attestation_status");

  assert.equal(decision.allowed, true);
  assert.equal(decision.policy.tier, "slack_write");
  assert.equal(decision.policy.approvalRequired, false);
  assert.equal(metadata.authority, "slack_write");
  assert.equal(metadata.credentialScope, "slack_bot_token");
  assert.equal(metadata.sideEffect, "slack_message");
  assert.equal(metadata.targetSource, "slack_event_context");
  assert.equal(statusMetadata.authority, "read");
  assert.equal(statusMetadata.sideEffect, "none");
});

test("registered agent tools expose authority metadata", () => {
  const tools = createSecurityAgentTools({
    config: testConfig(),
    memory: {
      readWorkingMemory: () => [],
      writeWorkingMemory: () => ({ success: true }),
      search: async () => [],
    } as any,
    cerebro: {} as any,
  });

  const unclassified = tools
    .map((tool) => ({ name: tool.name, metadata: securityAgentToolMetadata(tool.name) }))
    .filter((tool) => tool.metadata.family === "other")
    .map((tool) => tool.name);

  assert.deepEqual(unclassified, []);
  const implicitCodeModeAuthority = tools
    .map((tool) => tool.name)
    .filter((name) => !securityAgentToolMetadataIsExplicit(name));
  assert.deepEqual(implicitCodeModeAuthority, []);
  assert.equal(securityAgentToolMetadata("cerebro_code_shell_run").authority, "bounded_shell");
  assert.equal(securityAgentToolMetadata("cerebro_code_github_source_list").credentialScope, "github_runtime_credentials");
  assert.equal(securityAgentToolMetadata("cerebro_code_github_source_read").targetSource, "model_arguments");
  assert.equal(securityAgentToolMetadata("slack_thread_context").credentialScope, "slack_bot_token");
  assert.equal(securityAgentToolMetadata("cerebro_graph_cypher_investigate").retry, "transient_retry");
  assert.equal(securityAgentToolMetadata("jira_issue_search").sideEffect, "none");
  assert.equal(securityAgentToolMetadata("jira_issue_search").credentialScope, "ticketing_credentials");
  assert.equal(securityAgentToolMetadata("linear_issue_create").sideEffect, "external_ticket");
  assert.equal(securityAgentToolMetadata("operator_policy_guardrail_check").family, "operator");
  assert.equal(securityAgentToolMetadata("source_run_trigger").authority, "cerebro_write");
  assert.equal(securityAgentToolMetadata("finding_update").credentialScope, "cerebro_findings_key");
  assert.equal(securityAgentToolMetadata("cerebro_panopticon_alerts").retry, "transient_retry");
  assert.deepEqual(securityAgentToolMetadata("cerebro_tool_search"), {
    authority: "read",
    credentialScope: "none",
    family: "runtime_code",
    retry: "none",
    sideEffect: "none",
    targetSource: "runtime_context",
  });
  assert.deepEqual(securityAgentToolMetadata("cerebro_execute"), {
    authority: "read",
    credentialScope: "none",
    family: "runtime_code",
    retry: "none",
    sideEffect: "none",
    targetSource: "runtime_context",
  });
  assert.equal(securityAgentToolMetadata("cerebro_code_self_improvement_pr").sideEffect, "github_pr");
  assert.equal(securityAgentToolMetadata("cerebro_compliance_monitor_create").sideEffect, "schedule");
  assert.equal(securityAgentToolMetadata("cerebro_compliance_packet_store").sideEffect, "memory");
  assert.equal(evaluateSecurityAgentToolCall("cerebro_compliance_packet_store", "self_improvement").policy.tier, "memory_write");
});
