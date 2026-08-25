import fs from "node:fs";
import path from "node:path";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import { PracticeRegistry } from "./registry.js";
import { registryOptionsFromEnv } from "./config.js";
import { formatMcpResult, registerMcpUx } from "./mcpUx.js";
import { packageRoot } from "./paths.js";
import { approvalMethods, enforcementLevels, practiceStatuses } from "./schema.js";

const filesSchema = z.array(z.string()).default([]);
const dependenciesSchema = z.array(z.string()).default([]);
const decisionSchema = z.enum(["allowed", "follow_guidance", "revise_or_justify", "change_code", "ask_owner", "needs_review"]);
const statusSchema = z.enum(practiceStatuses);
const enforcementSchema = z.enum(enforcementLevels);
const approvalMethod = () => z.enum(approvalMethods);
const approvalSource = () =>
  z.object({
    title: z.string(),
    publisher: z.string(),
    url: z.string().url(),
    direct_support: z.string(),
  });
const pathScopeSchema = z.object({
  include: z.array(z.string()),
  exclude: z.array(z.string()),
});
const scopeSchema = z.object({
  languages: z.array(z.string()),
  frameworks: z.array(z.string()),
  paths: pathScopeSchema,
});
const practiceMatchSchema = z.object({
  id: z.string(),
  title: z.string(),
  status: statusSchema,
  enforcement: enforcementSchema,
  summary: z.string(),
  rationale: z.string(),
  owner: z.string(),
  source_file: z.string(),
  use_instead: z.array(z.string()),
  avoid: z.array(z.string()),
  confidence: z.enum(["low", "medium", "high"]),
  score: z.number(),
  reasons: z.array(z.string()),
});
const guardrailSchema = z.object({
  id: z.string(),
  title: z.string(),
  status: statusSchema,
  enforcement: enforcementSchema,
  relevance: z.enum(["high", "medium", "low"]),
  summary: z.string(),
  owner: z.string(),
  source_file: z.string(),
  scope: scopeSchema,
  avoid: z.array(z.string()),
  use_instead: z.array(z.string()),
  reasons: z.array(z.string()),
});
const findingSchema = z.object({
  rule_id: z.string(),
  practice_id: z.string(),
  title: z.string(),
  status: statusSchema,
  enforcement: enforcementSchema,
  blocking: z.boolean(),
  severity: z.enum(["ERROR", "WARNING", "INFO"]),
  message: z.string(),
  path: z.string(),
  line: z.number().int().nullable(),
  code: z.string(),
  engine: z.enum(["semgrep", "semgrep-rule-fallback"]),
  source_file: z.string(),
  owner: z.string(),
  use_instead: z.array(z.string()),
});
const checkResultSchema = z.object({
  observation_id: z.number().int().optional(),
  decision: decisionSchema,
  blocking: z.boolean(),
  passed: z.boolean(),
  action_required: z.boolean(),
  rerun_required: z.boolean(),
  summary: z.string(),
  next_steps: z.array(z.string()),
  matched_practices: z.array(practiceMatchSchema),
});
const scanResultSchema = z.object({
  observation_id: z.number().int().optional(),
  decision: decisionSchema,
  blocking: z.boolean(),
  passed: z.boolean(),
  action_required: z.boolean(),
  rerun_required: z.boolean(),
  summary: z.string(),
  next_steps: z.array(z.string()),
  findings: z.array(findingSchema),
  engine: z.object({
    semgrep_available: z.boolean(),
    semgrep_used: z.boolean(),
    fallback_used: z.boolean(),
    rules_path: z.string(),
  }),
});
const observationSchema = z.object({
  id: z.number().int(),
  kind: z.string(),
  decision: decisionSchema.nullable(),
  blocking: z.boolean(),
  passed: z.boolean(),
  action_required: z.boolean(),
  rerun_required: z.boolean(),
  practice_ids: z.array(z.string()),
  summary: z.string().nullable(),
  created_at: z.string(),
});
const observationStatsSchema = z.object({
  total: z.number().int(),
  passed: z.number().int(),
  action_required: z.number().int(),
  rerun_required: z.number().int(),
  by_decision: z.record(z.string(), z.number().int()),
  by_kind: z.record(z.string(), z.number().int()),
  top_practices: z.array(z.object({ practice_id: z.string(), count: z.number().int() })),
});
const planCheckReferenceSchema = z.object({
  required: z.boolean(),
  provided_observation_id: z.number().int().nullable(),
  matched_observation_id: z.number().int().nullable(),
  match_type: z.enum(["provided", "recent_context", "missing"]),
  passed: z.boolean(),
  reason: z.string(),
  final_files: z.array(z.string()),
  final_language: z.string().nullable(),
  plan_files: z.array(z.string()),
  plan_language: z.string().nullable(),
});
const finalizeResultSchema = z.object({
  observation_id: z.number().int().optional(),
  decision: decisionSchema,
  blocking: z.boolean(),
  passed: z.boolean(),
  action_required: z.boolean(),
  rerun_required: z.boolean(),
  summary: z.string(),
  next_steps: z.array(z.string()),
  scan_diff: scanResultSchema,
  observations: z.object({
    required_plan_check: z.boolean(),
    passing_plan_found: z.boolean(),
    plan_check: planCheckReferenceSchema,
    recent: z.array(observationSchema),
    stats: observationStatsSchema,
  }),
});
const guardrailResultSchema = z.object({
  summary: z.string(),
  next_steps: z.array(z.string()),
  agent_contract: z.array(z.string()),
  practices: z.array(guardrailSchema),
});
const preflightResultSchema = z.object({
  observation_id: z.number().int().optional(),
  decision: decisionSchema,
  blocking: z.boolean(),
  passed: z.boolean(),
  action_required: z.boolean(),
  rerun_required: z.boolean(),
  summary: z.string(),
  next_steps: z.array(z.string()),
  required_calls: z.array(z.string()),
  guardrails: guardrailResultSchema,
  plan_check: checkResultSchema.nullable(),
});
const serverInfoSchema = z.object({
  name: z.string(),
  package_version: z.string(),
  plugin_version: z.string().nullable(),
  contract_version: z.string(),
  supported_languages: z.array(z.string()),
  features: z.array(z.string()),
  package_root: z.string(),
});
const practiceRecordSchema = z.object({
  id: z.string(),
  title: z.string(),
  status: statusSchema,
  enforcement: enforcementSchema,
  summary: z.string(),
  rationale: z.string(),
  scope: scopeSchema,
  applies_when: z.object({
    intents: z.array(z.string()),
    keywords: z.array(z.string()),
  }),
  avoid: z.array(z.string()),
  use_instead: z.array(z.string()),
  good_examples: z.array(z.string()),
  bad_examples: z.array(z.string()),
  semgrep: z
    .object({
      rule_id: z.string().optional(),
      severity: z.enum(["ERROR", "WARNING", "INFO"]).optional(),
      pattern: z.string().optional(),
      pattern_regex: z.string().optional(),
      languages: z.array(z.string()).optional(),
    })
    .optional(),
  owner: z.string(),
  last_reviewed: z.string(),
  approval: z
    .object({
      method: approvalMethod(),
      approved_by: z.string(),
      approved_at: z.string(),
      conclusion: z.string(),
      sources: z.array(approvalSource()),
    })
    .optional(),
  source_file: z.string(),
});
const proposalResultSchema = z.object({
  observation_id: z.number().int().optional(),
  decision: decisionSchema,
  blocking: z.boolean(),
  passed: z.boolean(),
  action_required: z.boolean(),
  rerun_required: z.boolean(),
  summary: z.string(),
  next_steps: z.array(z.string()),
  proposal: z.object({
    title: z.string(),
    owner: z.string(),
    language: z.string().nullable(),
    framework: z.string().nullable(),
    files: z.array(z.string()),
    suggested_status: statusSchema,
    suggested_enforcement: enforcementSchema,
    evidence: z.string().nullable(),
  }),
});
const exceptionResultSchema = z.object({
  observation_id: z.number().int().optional(),
  decision: decisionSchema,
  blocking: z.boolean(),
  passed: z.boolean(),
  action_required: z.boolean(),
  rerun_required: z.boolean(),
  summary: z.string(),
  next_steps: z.array(z.string()),
  exception: z.object({
    practice_id: z.string(),
    owner: z.string(),
    accepted_context: z.string(),
    expires_at: z.string().nullable(),
    files: z.array(z.string()),
    evidence: z.string().nullable(),
    replacement_plan: z.string().nullable(),
  }),
});
const approvalResultSchema = z.object({
  observation_id: z.number().int().optional(),
  decision: decisionSchema,
  blocking: z.literal(false),
  passed: z.boolean(),
  action_required: z.boolean(),
  rerun_required: z.boolean(),
  summary: z.string(),
  next_steps: z.array(z.string()),
  approval: z.object({
    practice_id: z.string(),
    owner: z.string().nullable(),
    method: approvalMethod(),
    approved_by: z.string(),
    conclusion: z.string(),
    related_observation_ids: z.array(z.number().int()),
    sources: z.array(approvalSource()),
  }),
});
const reviewQueueItemSchema = z.object({
  key: z.string(),
  kind: z.enum(["needs_review_observation", "practice_proposal", "practice_exception", "owner_decision"]),
  title: z.string(),
  summary: z.string(),
  owner: z.string().nullable(),
  practice_ids: z.array(z.string()),
  files: z.array(z.string()),
  language: z.string().nullable(),
  count: z.number().int(),
  latest_observation_id: z.number().int(),
  observation_ids: z.array(z.number().int()),
  created_at: z.string(),
  evidence: z.string().nullable(),
  expires_at: z.string().nullable(),
  next_step: z.string(),
});
const reviewQueueResultSchema = z.object({
  observation_id: z.number().int().optional(),
  decision: decisionSchema,
  blocking: z.boolean(),
  passed: z.boolean(),
  action_required: z.boolean(),
  rerun_required: z.boolean(),
  summary: z.string(),
  next_steps: z.array(z.string()),
  stats: z.object({
    total: z.number().int(),
    needs_review: z.number().int(),
    proposals: z.number().int(),
    exceptions: z.number().int(),
    owner_decisions: z.number().int(),
  }),
  items: z.array(reviewQueueItemSchema),
});
const readOnlyTool = {
  readOnlyHint: true,
  destructiveHint: false,
  idempotentHint: true,
  openWorldHint: false,
};
const writeTool = {
  readOnlyHint: false,
  destructiveHint: false,
  idempotentHint: false,
  openWorldHint: false,
};

export function createMcpServer(): McpServer {
  const registry = new PracticeRegistry(registryOptionsFromEnv());
  registry.rebuild();

  const server = new McpServer(
    {
      name: "practice-registry",
      version: "0.1.0",
    },
    {
      instructions:
        [
          "Use Practice Registry before and after non-trivial Scala, Python, TypeScript, JavaScript, or Rust edits.",
          "Call preflight or get_guardrails when you need the relevant company practices for a task.",
          "Call check_plan before generating code. Trust the passed field. Only allowed and follow_guidance are pass decisions.",
          "Call finalize_change on the final diff before summarizing work. Pass plan_observation_id from check_plan when available. Use scan_diff or check_diff when a narrower review is needed.",
          "For change_code, revise_or_justify, ask_owner, or needs_review, take the listed next_steps and rerun the check before finalizing.",
          "Treat banned or blocking findings as blockers. Prefer recorded alternatives and cite practice ids.",
          "Do not treat an unlisted pattern as approved. Ask the owner, propose a practice, or add a researched practice record with independent direct support.",
          "Use record_approval only after the approved practice record exists. Research approval requires two directly supporting HTTPS sources from independent publishers and domains and does not approve exceptions.",
        ].join(" "),
    },
  );

  registerMcpUx(server, registry);

  server.registerTool(
    "server_info",
    {
      title: "Get server info",
      description: "Return Practice Registry version, contract version, supported languages, and feature flags.",
      inputSchema: {},
      outputSchema: serverInfoSchema,
      annotations: readOnlyTool,
    },
    async () => jsonResult(serverInfo()),
  );

  server.registerTool(
    "preflight",
    {
      title: "Preflight code generation",
      description:
        "Return the compact before-coding bundle for a Scala, Python, TypeScript, JavaScript, or Rust task: matching practices, required calls, and optional plan check.",
      inputSchema: {
        repo: z.string().optional(),
        topic: z.string().optional(),
        intent: z.string().optional(),
        language: z.string().optional(),
        framework: z.string().optional(),
        files: filesSchema,
        dependencies: dependenciesSchema,
        planned_approach: z.string().optional(),
        proposed_code: z.string().optional(),
        max_practices: z.number().int().min(1).max(25).optional(),
      },
      outputSchema: preflightResultSchema,
      annotations: readOnlyTool,
    },
    async (input) => jsonResult(registry.preflight(input)),
  );

  server.registerTool(
    "get_guardrails",
    {
      title: "Get relevant practices",
      description:
        "Return the company practices that apply to a Scala, Python, TypeScript, JavaScript, or Rust task. Use this when a user asks what practices apply or before planning when the approach is still rough.",
      inputSchema: {
        repo: z.string().optional(),
        topic: z.string().optional(),
        intent: z.string().optional(),
        language: z.string().optional(),
        framework: z.string().optional(),
        files: filesSchema,
        dependencies: dependenciesSchema,
        max_practices: z.number().int().min(1).max(25).optional(),
      },
      outputSchema: guardrailResultSchema,
      annotations: readOnlyTool,
    },
    async (input) => jsonResult(registry.getGuardrails(input)),
  );

  server.registerTool(
    "check_plan",
    {
      title: "Check plan before code",
      description:
        "Decision gate for a planned Scala, Python, TypeScript, JavaScript, or Rust change. Call before generating code and revise the approach when the result blocks.",
      inputSchema: {
        repo: z.string().optional(),
        intent: z.string().optional(),
        language: z.string().optional(),
        framework: z.string().optional(),
        files: filesSchema,
        planned_approach: z.string().optional(),
        proposed_code: z.string().optional(),
        dependencies: dependenciesSchema,
      },
      outputSchema: checkResultSchema,
      annotations: readOnlyTool,
    },
    async (input) => jsonResult(registry.check("plan", input)),
  );

  server.registerTool(
    "check_diff",
    {
      title: "Review final diff",
      description:
        "Semantic review for a completed diff against company practices. Use after edits when the agent needs advisory guidance beyond changed-line scanning.",
      inputSchema: {
        repo: z.string().optional(),
        language: z.string().optional(),
        framework: z.string().optional(),
        files: filesSchema,
        diff: z.string(),
        dependencies: dependenciesSchema,
      },
      outputSchema: checkResultSchema,
      annotations: readOnlyTool,
    },
    async (input) => jsonResult(registry.check("diff", input)),
  );

  server.registerTool(
    "scan_diff",
    {
      title: "Scan changed lines",
      description:
        "Changed-line scan for concrete Scala, Python, TypeScript, JavaScript, and Rust findings. Use after edits and before the final response.",
      inputSchema: {
        diff: z.string(),
        rules_path: z.string().optional(),
        use_semgrep: z.boolean().optional(),
      },
      outputSchema: scanResultSchema,
      annotations: readOnlyTool,
    },
    async (input) =>
      jsonResult(
        registry.scanDiff(input.diff, {
          rulesPath: input.rules_path,
          useSemgrep: input.use_semgrep,
        }),
      ),
  );

  server.registerTool(
    "finalize_change",
    {
      title: "Finalize code change",
      description:
        "Final Practice Registry gate for generated Scala, Python, TypeScript, JavaScript, and Rust code. Call before the final response and trust passed, action_required, and rerun_required.",
      inputSchema: {
        diff: z.string(),
        repo: z.string().optional(),
        language: z.string().optional(),
        framework: z.string().optional(),
        files: filesSchema,
        dependencies: dependenciesSchema,
        rules_path: z.string().optional(),
        use_semgrep: z.boolean().optional(),
        require_plan_check: z.boolean().optional(),
        plan_observation_id: z.number().int().optional(),
      },
      outputSchema: finalizeResultSchema,
      annotations: readOnlyTool,
    },
    async (input) => jsonResult(registry.finalizeChange(input)),
  );

  server.registerTool(
    "search_practices",
    {
      title: "Search practices",
      description: "Search indexed company practices by topic, language, framework, or file path.",
      inputSchema: {
        query: z.string(),
        language: z.string().optional(),
        framework: z.string().optional(),
        files: filesSchema,
      },
      outputSchema: z.object({
        matched_practices: z.array(practiceMatchSchema),
      }),
      annotations: readOnlyTool,
    },
    async (input) => jsonResult({ matched_practices: registry.search(input.query, input) }),
  );

  server.registerTool(
    "explain_practice",
    {
      title: "Explain practice",
      description: "Return the full record for one indexed company practice.",
      inputSchema: {
        id: z.string(),
      },
      outputSchema: practiceRecordSchema.or(z.object({ error: z.string() })),
      annotations: readOnlyTool,
    },
    async (input) => {
      const practice = registry.explain(input.id);
      return jsonResult(practice ?? { error: `No practice found for id ${input.id}` });
    },
  );

  server.registerTool(
    "propose_practice",
    {
      title: "Propose practice",
      description:
        "Record a reusable practice proposal when no indexed practice covers a repeated pattern, false positive, or team decision.",
      inputSchema: {
        title: z.string(),
        summary: z.string(),
        owner: z.string().optional(),
        language: z.string().optional(),
        framework: z.string().optional(),
        files: filesSchema,
        evidence: z.string().optional(),
        suggested_status: statusSchema.optional(),
        suggested_enforcement: enforcementSchema.optional(),
        avoid: z.array(z.string()).default([]),
        use_instead: z.array(z.string()).default([]),
      },
      outputSchema: proposalResultSchema,
      annotations: writeTool,
    },
    async (input) => jsonResult(registry.proposePractice(input)),
  );

  server.registerTool(
    "record_exception",
    {
      title: "Record exception request",
      description:
        "Record a scoped exception request for a discouraged, legacy, needs_review, or blocking practice. This does not approve the exception.",
      inputSchema: {
        practice_id: z.string(),
        reason: z.string(),
        accepted_context: z.string(),
        owner: z.string().optional(),
        expires_at: z.string().optional(),
        language: z.string().optional(),
        files: filesSchema,
        evidence: z.string().optional(),
        replacement_plan: z.string().optional(),
      },
      outputSchema: exceptionResultSchema,
      annotations: writeTool,
    },
    async (input) => jsonResult(registry.recordException(input)),
  );

  server.registerTool(
    "record_approval",
    {
      title: "Record practice approval",
      description:
        "Resolve practice review observations through the recorded owner or through research supported by independent primary sources.",
      inputSchema: {
        practice_id: z.string(),
        method: approvalMethod(),
        approved_by: z.string(),
        conclusion: z.string(),
        related_observation_ids: z.array(z.number().int().positive()).default([]),
        sources: z.array(approvalSource()).default([]),
      },
      outputSchema: approvalResultSchema,
      annotations: writeTool,
    },
    async (input) => jsonResult(registry.recordApproval(input)),
  );

  server.registerTool(
    "review_queue",
    {
      title: "Review practice queue",
      description:
        "Return repeated needs_review observations, practice proposals, owner decisions, and exception requests that need follow-up.",
      inputSchema: {
        limit: z.number().int().min(1).max(100).optional(),
      },
      outputSchema: reviewQueueResultSchema,
      annotations: readOnlyTool,
    },
    async (input) => jsonResult(registry.reviewQueue(input)),
  );

  server.registerTool(
    "observation_summary",
    {
      title: "Summarize practice checks",
      description:
        "Return recent Practice Registry observations, pass counts, action-required counts, and recurring practice ids.",
      inputSchema: {
        limit: z.number().int().min(1).max(200).optional(),
        action_required_only: z.boolean().optional(),
        kind: z.string().optional(),
      },
      outputSchema: z.object({
        stats: observationStatsSchema,
        recent: z.array(observationSchema),
      }),
      annotations: readOnlyTool,
    },
    async (input) =>
      jsonResult({
        stats: registry.observationStats(input.limit ?? 100),
        recent: registry.recentObservations({
          kind: input.kind,
          limit: input.limit ?? 20,
          actionRequiredOnly: input.action_required_only,
        }),
      }),
  );

  return server;
}

function serverInfo(): Record<string, unknown> {
  const root = packageRoot();
  return {
    name: "practice-registry",
    package_version: readJsonString(path.join(root, "package.json"), "version") ?? "unknown",
    plugin_version: readJsonString(path.join(root, ".codex-plugin", "plugin.json"), "version"),
    contract_version: "2026-07-16.rust-practices",
    supported_languages: ["python", "scala", "typescript", "javascript", "rust"],
    features: [
      "passed_action_required_rerun_required",
      "finalize_change",
      "plan_observation_id",
      "observation_summary",
      "practice_lint",
      "coverage_report",
      "explicit_mcp_schemas",
      "preflight",
      "practice_feedback",
      "review_queue",
      "precise_preflight_matching",
      "research_backed_approvals",
      "typescript_practices",
      "everyday_typescript_practices",
      "rust_practices",
      "everyday_rust_practices",
    ],
    package_root: root,
  };
}

function readJsonString(filePath: string, field: string): string | null {
  try {
    const parsed = JSON.parse(fs.readFileSync(filePath, "utf8")) as Record<string, unknown>;
    return typeof parsed[field] === "string" ? parsed[field] : null;
  } catch {
    return null;
  }
}

function jsonResult(value: Record<string, unknown>) {
  return {
    structuredContent: value,
    content: [
      {
        type: "text" as const,
        text: formatMcpResult(value),
      },
    ],
  };
}
