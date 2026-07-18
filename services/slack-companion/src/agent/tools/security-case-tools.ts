import type { AgentTool } from "@earendil-works/pi-agent-core";
import { Type } from "@earendil-works/pi-ai";
import {
  attachGithubSecurityCaseFix,
  createGithubSecurityCase,
  securityCaseView,
} from "../../security-cases/security-case.js";
import type { AutonomousGoalRecord } from "../../autonomy/goals.js";
import { safeToolResult } from "./tool-result.js";
import type { SecurityToolDeps } from "./types.js";

export function createSecurityCaseTools(deps: SecurityToolDeps): AgentTool[] {
  return [
    {
      name: "operator_security_case_start",
      label: "Start security case",
      description: "Start one durable GitHub security-alert case after Cerebro identifies the runtime, finding, repository, and alert reference. The case begins with current finding investigation and keeps existing commands and goals unchanged.",
      parameters: Type.Object({
        title: Type.String(),
        alert_ref: Type.String(),
        repository: Type.String(),
        runtime_id: Type.String(),
        finding_id: Type.String(),
        owner: Type.Optional(Type.String()),
        channel_id: Type.Optional(Type.String()),
        thread_ts: Type.Optional(Type.String()),
        requested_by_slack_user_id: Type.Optional(Type.String()),
        requested_by_display_name: Type.Optional(Type.String()),
      }),
      execute: async (_toolCallId, params) => safeToolResult(async () => startSecurityCase(deps, params as StartCaseArgs)),
    },
    {
      name: "operator_security_case_attach_fix",
      label: "Attach security case fix",
      description: "Attach a bounded reviewable code fix to an existing security case. The durable run opens a draft pull request, waits for merge, requests approval for fresh finding evaluation, and verifies the finding is resolved.",
      parameters: Type.Object({
        case_id: Type.String(),
        title: Type.String(),
        body: Type.Optional(Type.String()),
        files: Type.Array(Type.Object({ path: Type.String(), content: Type.String() }), { minItems: 1, maxItems: 12 }),
        branch: Type.Optional(Type.String()),
        base: Type.Optional(Type.String()),
        draft: Type.Optional(Type.Boolean()),
      }),
      execute: async (_toolCallId, params) => safeToolResult(async () => attachSecurityCaseFix(deps, params as AttachFixArgs)),
    },
    {
      name: "operator_security_case_status",
      label: "Security case status",
      description: "Read one security case with its current state, owner, next action, blockers, artifacts, approvals, and fresh-verification receipt.",
      parameters: Type.Object({ case_id: Type.String() }),
      execute: async (_toolCallId, params) => safeToolResult(async () => readSecurityCase(deps, String((params as Record<string, unknown>).case_id))),
    },
    {
      name: "operator_security_case_list",
      label: "Security case list",
      description: "List durable security cases as one work queue. Optional state values: investigating, needs_evidence, needs_decision, ready_to_act, waiting_on_owner, verifying, closed, blocked.",
      parameters: Type.Object({ state: Type.Optional(Type.String()) }),
      execute: async (_toolCallId, params) => safeToolResult(async () => listSecurityCases(deps, stringValue((params as Record<string, unknown>).state))),
    },
  ];
}

interface StartCaseArgs {
  title: string;
  alert_ref: string;
  repository: string;
  runtime_id: string;
  finding_id: string;
  owner?: string;
  channel_id?: string;
  thread_ts?: string;
  requested_by_slack_user_id?: string;
  requested_by_display_name?: string;
}

interface AttachFixArgs {
  case_id: string;
  title: string;
  body?: string;
  files: Array<{ path: string; content: string }>;
  branch?: string;
  base?: string;
  draft?: boolean;
}

async function startSecurityCase(deps: SecurityToolDeps, args: StartCaseArgs): Promise<Record<string, unknown>> {
  const goals = deps.autonomyGoals;
  if (!goals?.createFromPlan) return { created: false, error: "security_case_store_unavailable" };
  const prepared = createGithubSecurityCase({
    title: args.title,
    alertRef: args.alert_ref,
    repository: args.repository,
    runtimeId: args.runtime_id,
    findingId: args.finding_id,
    owner: args.owner,
  });
  const slackUserId = stringValue(args.requested_by_slack_user_id) ?? "unknown";
  const goal = await goals.createFromPlan({
    objective: `Handle GitHub security alert ${args.alert_ref} for ${args.repository}; verify Cerebro finding ${args.finding_id} is resolved.`,
    actor: {
      slackUserId,
      actorId: slackUserId === "unknown" ? "slack:unknown" : `slack:${slackUserId}`,
      displayName: stringValue(args.requested_by_display_name),
    },
    channelId: stringValue(args.channel_id),
    threadTs: stringValue(args.thread_ts),
    capabilityId: "remediation",
    plan: prepared.plan,
    resourceRefs: prepared.resourceRefs,
    acceptanceCriteria: prepared.acceptanceCriteria,
    securityCase: prepared.context,
  });
  deps.researchState?.recordCreatedGoal(goal.id);
  return { created: true, case: securityCaseView(goal) };
}

async function attachSecurityCaseFix(deps: SecurityToolDeps, args: AttachFixArgs): Promise<Record<string, unknown>> {
  const goals = deps.autonomyGoals;
  if (!goals?.replacePlan || !goals.update) return { attached: false, error: "security_case_update_unavailable" };
  const goal = await findSecurityCase(deps, args.case_id);
  if (!goal) return { attached: false, error: "security_case_not_found" };
  const plan = attachGithubSecurityCaseFix(goal, {
    title: args.title,
    body: args.body,
    files: args.files,
    branch: args.branch,
    base: args.base,
    draft: args.draft,
  });
  await goals.replacePlan(goal.id, plan);
  const updated = await goals.update(goal.id, {
    status: "active",
    activeStepId: null,
    nextWakeAt: new Date().toISOString(),
  });
  return { attached: true, case: securityCaseView(updated) };
}

async function readSecurityCase(deps: SecurityToolDeps, caseId: string): Promise<Record<string, unknown>> {
  const goal = await findSecurityCase(deps, caseId);
  return goal ? { found: true, case: securityCaseView(goal) } : { found: false, error: "security_case_not_found" };
}

async function listSecurityCases(deps: SecurityToolDeps, state?: string): Promise<Record<string, unknown>> {
  if (!deps.autonomyGoals?.list) return { cases: [], error: "security_case_store_unavailable" };
  const cases = (await deps.autonomyGoals.list())
    .map(securityCaseView)
    .filter((item): item is NonNullable<typeof item> => Boolean(item))
    .filter((item) => !state || item.state === state)
    .slice(0, 50);
  return { cases, count: cases.length };
}

async function findSecurityCase(deps: SecurityToolDeps, caseId: string): Promise<AutonomousGoalRecord | undefined> {
  const direct = await deps.autonomyGoals?.get?.(caseId);
  if (direct?.securityCase) return direct;
  const goals = await deps.autonomyGoals?.list?.();
  return goals?.find((goal) => goal.securityCase?.id === caseId);
}

function stringValue(value: unknown): string | undefined {
  return typeof value === "string" && value.trim() ? value.trim() : undefined;
}
