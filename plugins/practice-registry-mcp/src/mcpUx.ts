import { McpServer, ResourceTemplate } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import { buildCoverageReport, formatCoverageReport } from "./coverageReport.js";
import { PracticeRegistry } from "./registry.js";
import type {
  PracticeCheckResult,
  PracticeFinalizeResult,
  PracticeFinding,
  PracticeGuardrail,
  PracticeObservation,
  PracticeObservationStats,
  PracticePlanCheckReference,
  PracticePreflightResult,
  PracticeRecord,
  PracticeReviewQueueResult,
  PracticeScanResult,
} from "./schema.js";

type DisplayPractice = Pick<PracticeGuardrail, "id" | "title" | "status" | "enforcement" | "use_instead"> & {
  relevance?: PracticeGuardrail["relevance"];
};

export function registerMcpUx(server: McpServer, registry: PracticeRegistry): void {
  registerResources(server, registry);
  registerPrompts(server);
}

export function formatMcpResult(value: Record<string, unknown>): string {
  if (isPreflightResult(value)) {
    return [
      value.observation_id ? `Observation: #${value.observation_id}` : undefined,
      `Decision: ${value.decision}`,
      `Passed: ${value.passed ? "yes" : "no"}`,
      `Summary: ${value.summary}`,
      "",
      "Required calls:",
      ...numbered(value.required_calls),
      "",
      "Next steps:",
      ...numbered(value.next_steps),
      "",
      "Practices:",
      ...formatGuardrails(value.guardrails.practices),
      value.plan_check ? "" : undefined,
      value.plan_check ? `Plan check: ${value.plan_check.decision}` : undefined,
    ]
      .filter(Boolean)
      .join("\n");
  }

  if (isGuardrailResult(value)) {
    return [
      `Summary: ${value.summary}`,
      "",
      "Next steps:",
      ...numbered(value.next_steps),
      "",
      "Agent contract:",
      ...numbered(value.agent_contract),
      "",
      "Practices:",
      ...formatGuardrails(value.practices),
    ].join("\n");
  }

  if (isCheckResult(value)) {
    return [
      value.observation_id ? `Observation: #${value.observation_id}` : undefined,
      `Decision: ${value.decision}`,
      `Blocking: ${value.blocking ? "yes" : "no"}`,
      `Passed: ${value.passed ? "yes" : "no"}`,
      `Action required: ${value.action_required ? "yes" : "no"}`,
      `Rerun required: ${value.rerun_required ? "yes" : "no"}`,
      `Summary: ${value.summary}`,
      "",
      "Next steps:",
      ...numbered(value.next_steps),
      "",
      "Matched practices:",
      ...formatGuardrails(value.matched_practices),
    ]
      .filter(Boolean)
      .join("\n");
  }

  if (isScanResult(value)) {
    return [
      value.observation_id ? `Observation: #${value.observation_id}` : undefined,
      `Decision: ${value.decision}`,
      `Blocking: ${value.blocking ? "yes" : "no"}`,
      `Passed: ${value.passed ? "yes" : "no"}`,
      `Action required: ${value.action_required ? "yes" : "no"}`,
      `Rerun required: ${value.rerun_required ? "yes" : "no"}`,
      `Summary: ${value.summary}`,
      "",
      "Next steps:",
      ...numbered(value.next_steps),
      "",
      "Findings:",
      ...formatFindings(value.findings),
    ]
      .filter(Boolean)
      .join("\n");
  }

  if (isFinalizeResult(value)) {
    return [
      value.observation_id ? `Observation: #${value.observation_id}` : undefined,
      `Decision: ${value.decision}`,
      `Blocking: ${value.blocking ? "yes" : "no"}`,
      `Passed: ${value.passed ? "yes" : "no"}`,
      `Action required: ${value.action_required ? "yes" : "no"}`,
      `Rerun required: ${value.rerun_required ? "yes" : "no"}`,
      `Summary: ${value.summary}`,
      "",
      "Next steps:",
      ...numbered(value.next_steps),
      "",
      "Final scan:",
      `Decision: ${value.scan_diff.decision}`,
      `Findings: ${value.scan_diff.findings.length}`,
      "",
      "Observations:",
      `Passing plan found: ${value.observations.passing_plan_found ? "yes" : "no"}`,
      `Plan check: ${formatPlanCheck(value.observations.plan_check)}`,
      ...formatObservationStats(value.observations.stats),
    ]
      .filter(Boolean)
      .join("\n");
  }

  if (isObservationSummary(value)) {
    return [
      "Observation summary:",
      ...formatObservationStats(value.stats),
      "",
      "Recent:",
      ...formatObservations(value.recent),
    ].join("\n");
  }

  if (isReviewQueueResult(value)) {
    return renderReviewQueue(value);
  }

  if (isFeedbackResult(value)) {
    return [
      value.observation_id ? `Observation: #${value.observation_id}` : undefined,
      `Decision: ${value.decision}`,
      `Passed: ${value.passed ? "yes" : "no"}`,
      `Summary: ${value.summary}`,
      "",
      "Next steps:",
      ...numbered(value.next_steps),
    ]
      .filter(Boolean)
      .join("\n");
  }

  if (Array.isArray(value.matched_practices)) {
    return ["Matched practices:", ...formatGuardrails(value.matched_practices as DisplayPractice[])].join("\n");
  }

  if (typeof value.id === "string" && typeof value.title === "string") {
    return renderPractice(value as unknown as PracticeRecord);
  }

  return JSON.stringify(value, null, 2);
}

function registerResources(server: McpServer, registry: PracticeRegistry): void {
  server.registerResource(
    "agent-contract",
    "practice://agent-contract",
    {
      title: "Agent contract",
      description: "When agents should call Practice Registry and how to act on results.",
      mimeType: "text/markdown",
      annotations: { audience: ["assistant"], priority: 1 },
    },
    async (uri) => textResource(uri.toString(), renderAgentContract()),
  );

  server.registerResource(
    "registry-summary",
    "practice://registry-summary",
    {
      title: "Registry summary",
      description: "Counts, owners, languages, and blocking records in the indexed practice set.",
      mimeType: "text/markdown",
      annotations: { audience: ["assistant", "user"], priority: 0.8 },
    },
    async (uri) => textResource(uri.toString(), renderRegistrySummary(registry.all())),
  );

  server.registerResource(
    "observation-summary",
    "practice://observation-summary",
    {
      title: "Observation summary",
      description: "Recent Practice Registry pass counts, action-required counts, and recurring practice ids.",
      mimeType: "text/markdown",
      annotations: { audience: ["assistant", "user"], priority: 0.8 },
    },
    async (uri) => textResource(uri.toString(), renderObservationSummary(registry.observationStats(), registry.recentObservations({ limit: 10 }))),
  );

  server.registerResource(
    "coverage-report",
    "practice://coverage-report",
    {
      title: "Coverage report",
      description: "Practice coverage by language, framework, owner, and recent needs_review observations.",
      mimeType: "text/markdown",
      annotations: { audience: ["assistant", "user"], priority: 0.8 },
    },
    async (uri) =>
      textResource(
        uri.toString(),
        formatCoverageReport(buildCoverageReport(registry.all(), registry.recentObservations({ limit: 100 }))),
      ),
  );

  server.registerResource(
    "review-queue",
    "practice://review-queue",
    {
      title: "Review queue",
      description: "Practice proposals, exception requests, and repeated needs_review observations.",
      mimeType: "text/markdown",
      annotations: { audience: ["assistant", "user"], priority: 0.9 },
    },
    async (uri) => textResource(uri.toString(), renderReviewQueue(registry.reviewQueue({ limit: 50, record: false }))),
  );

  server.registerResource(
    "practice-record",
    new ResourceTemplate("practice://practices/{id}", {
      list: async () => ({
        resources: registry.all().map((practice) => ({
          uri: practiceUri(practice.id),
          name: practice.id,
          title: practice.title,
          description: `${practice.status} / ${practice.enforcement} / ${practice.owner}`,
          mimeType: "text/markdown",
        })),
      }),
      complete: {
        id: async (value) =>
          registry
            .all()
            .map((practice) => practice.id)
            .filter((id) => id.includes(value))
            .slice(0, 20),
      },
    }),
    {
      title: "Practice record",
      description: "One indexed company practice record.",
      mimeType: "text/markdown",
      annotations: { audience: ["assistant", "user"], priority: 0.7 },
    },
    async (uri, variables) => {
      const id = decodeURIComponent(String(variables.id ?? ""));
      const practice = registry.explain(id);
      return textResource(uri.toString(), practice ? renderPractice(practice) : `# Practice not found\n\nNo practice is indexed for \`${id}\`.`);
    },
  );
}

function registerPrompts(server: McpServer): void {
  server.registerPrompt(
    "plan_with_practices",
    {
      title: "Plan with practices",
      description: "Prepare a code generation plan that calls Practice Registry before writing code.",
      argsSchema: {
        intent: z.string().describe("What the user wants changed."),
        language: z.string().optional().describe("Primary language, such as python, scala, typescript, javascript, or rust."),
        files: z.string().optional().describe("Comma-separated file paths when known."),
        planned_approach: z.string().optional().describe("Initial implementation approach when known."),
      },
    },
    async ({ intent, language, files, planned_approach }) => ({
      messages: [
        {
          role: "user" as const,
          content: {
            type: "text" as const,
            text: [
              "Before writing code, call Practice Registry.",
              "",
              `Intent: ${intent}`,
              language ? `Language: ${language}` : undefined,
              files ? `Files: ${files}` : undefined,
              planned_approach ? `Planned approach: ${planned_approach}` : undefined,
              "",
              "Call server_info if you need to confirm the active contract version.",
              "First call preflight or get_guardrails if the applicable practices are unclear.",
              "Then call check_plan with the planned approach.",
              "Trust the passed field. Only allowed and follow_guidance are pass decisions.",
              "For change_code, revise_or_justify, ask_owner, or needs_review, take the listed next_steps before writing code.",
              "Use propose_practice when no durable practice covers the decision, record_approval after an approved record exists, or record_exception for a scoped exception request.",
            ]
              .filter(Boolean)
              .join("\n"),
          },
        },
      ],
    }),
  );

  server.registerPrompt(
    "review_final_diff",
    {
      title: "Review final diff",
      description: "Run the final Practice Registry checks before summarizing code changes.",
      argsSchema: {
        language: z.string().optional().describe("Primary language, such as python, scala, typescript, javascript, or rust."),
        files: z.string().optional().describe("Comma-separated file paths when known."),
      },
    },
    async ({ language, files }) => ({
      messages: [
        {
          role: "user" as const,
          content: {
            type: "text" as const,
            text: [
              "Before the final response, inspect the final diff and call Practice Registry.",
              language ? `Language: ${language}` : undefined,
              files ? `Files: ${files}` : undefined,
              "",
              "Call finalize_change with the final diff.",
              "Pass plan_observation_id from the matching check_plan result when it is available.",
              "Trust the passed field. Only allowed and follow_guidance are pass decisions.",
              "For change_code, revise_or_justify, ask_owner, or needs_review, take the listed next_steps and rerun finalize_change.",
              "Use check_diff when you need semantic practice guidance beyond concrete changed-line findings.",
            ]
              .filter(Boolean)
              .join("\n"),
          },
        },
      ],
    }),
  );
}

function textResource(uri: string, text: string) {
  return {
    contents: [
      {
        uri,
        mimeType: "text/markdown",
        text,
      },
    ],
  };
}

function renderAgentContract(): string {
  return [
    "# Agent Contract",
    "",
    "Use Practice Registry as the code-generation gate for Scala, Python, TypeScript, JavaScript, and Rust changes.",
    "",
    "1. Call `server_info` when you need to confirm the active contract version.",
    "2. Read `practice://registry-summary` or call `get_guardrails` when the task is broad.",
    "3. Call `preflight` when files or intent are known.",
    "4. Call `check_plan` before generating non-trivial code.",
    "5. Trust the `passed` field. Treat only `allowed` and `follow_guidance` as pass decisions.",
    "6. Take the listed `next_steps` for `change_code`, `revise_or_justify`, `ask_owner`, or `needs_review`.",
    "7. Run `finalize_change` on the final diff before the final response. Pass the matching `check_plan` observation id when available.",
    "8. Use `check_diff` when concrete scanning is clean but the change still needs practice guidance.",
    "9. Use `propose_practice` when no durable practice covers the decision. Use `record_approval` after an approved record exists; research approval requires two directly supporting HTTPS sources from independent publishers and domains.",
    "10. Use `record_exception` for scoped exception requests. Research approval does not approve an exception.",
  ].join("\n");
}

function renderRegistrySummary(records: PracticeRecord[]): string {
  const byLanguage = countBy(records.flatMap((record) => record.scope.languages));
  const byStatus = countBy(records.map((record) => record.status));
  const byOwner = countBy(records.map((record) => record.owner));
  const blocking = records.filter((record) => record.status === "banned" || record.enforcement === "blocking");

  return [
    "# Registry Summary",
    "",
    `Practices: ${records.length}`,
    `Blocking practices: ${blocking.length}`,
    "",
    "## Languages",
    ...formatCounts(byLanguage),
    "",
    "## Status",
    ...formatCounts(byStatus),
    "",
    "## Owners",
    ...formatCounts(byOwner),
    "",
    "## Blocking Records",
    ...blocking.map((record) => `- ${record.id}: ${record.title} (${record.owner})`),
  ].join("\n");
}

function renderObservationSummary(stats: PracticeObservationStats, recent: PracticeObservation[]): string {
  return [
    "# Observation Summary",
    "",
    ...formatObservationStats(stats),
    "",
    "## Recent Checks",
    ...formatObservations(recent),
  ].join("\n");
}

function renderReviewQueue(queue: PracticeReviewQueueResult): string {
  return [
    "# Review Queue",
    "",
    `Items: ${queue.stats.total}`,
    `Needs review: ${queue.stats.needs_review}`,
    `Proposals: ${queue.stats.proposals}`,
    `Exceptions: ${queue.stats.exceptions}`,
    `Owner decisions: ${queue.stats.owner_decisions}`,
    "",
    "## Next Steps",
    ...queue.next_steps.map((step) => `- ${step}`),
    "",
    "## Items",
    ...formatReviewQueueItems(queue.items),
  ].join("\n");
}

function formatReviewQueueItems(items: PracticeReviewQueueResult["items"]): string[] {
  if (items.length === 0) {
    return ["- None."];
  }
  return items.map((item) => {
    const owner = item.owner ? ` Owner: ${item.owner}.` : "";
    const practices = item.practice_ids.length > 0 ? ` Practices: ${item.practice_ids.join(", ")}.` : "";
    const files = item.files.length > 0 ? ` Files: ${item.files.slice(0, 3).join(", ")}.` : "";
    return `- #${item.latest_observation_id} ${item.title} (${item.kind}, ${item.count}). ${item.summary}${owner}${practices}${files} Next: ${item.next_step}`;
  });
}

function renderPractice(practice: PracticeRecord): string {
  return [
    `# ${practice.title}`,
    "",
    `ID: ${practice.id}`,
    `Status: ${practice.status}`,
    `Enforcement: ${practice.enforcement}`,
    `Owner: ${practice.owner}`,
    `Last reviewed: ${practice.last_reviewed}`,
    practice.approval ? `Approval: ${practice.approval.method} by ${practice.approval.approved_by} on ${practice.approval.approved_at}` : undefined,
    "",
    "## Summary",
    practice.summary,
    "",
    "## Rationale",
    practice.rationale,
    "",
    "## Avoid",
    ...listOrNone(practice.avoid),
    "",
    "## Use Instead",
    ...listOrNone(practice.use_instead),
    "",
    "## Scope",
    `Languages: ${practice.scope.languages.join(", ") || "any"}`,
    `Frameworks: ${practice.scope.frameworks.join(", ") || "any"}`,
    `Include: ${practice.scope.paths.include.join(", ") || "any"}`,
    `Exclude: ${practice.scope.paths.exclude.join(", ") || "none"}`,
    "",
    "## Examples",
    ...practice.good_examples.map((example) => `- Good: ${example}`),
    ...practice.bad_examples.map((example) => `- Bad: ${example}`),
  ].filter((line) => line !== undefined).join("\n");
}

function numbered(values: string[]): string[] {
  return values.length > 0 ? values.map((value, index) => `${index + 1}. ${value}`) : ["1. None."];
}

function listOrNone(values: string[]): string[] {
  return values.length > 0 ? values.map((value) => `- ${value}`) : ["- None."];
}

function formatGuardrails(practices: DisplayPractice[]): string[] {
  if (practices.length === 0) {
    return ["- None."];
  }
  return practices.map((practice) => {
    const replacement = practice.use_instead?.[0] ? ` Use instead: ${practice.use_instead[0]}` : "";
    const relevance = practice.relevance ? `, ${practice.relevance} relevance` : "";
    return `- ${practice.id}: ${practice.title} (${practice.status}, ${practice.enforcement}${relevance}).${replacement}`;
  });
}

function formatFindings(findings: PracticeFinding[]): string[] {
  if (findings.length === 0) {
    return ["- None."];
  }
  return findings.map((finding) => {
    const location = finding.line ? `${finding.path}:${finding.line}` : finding.path;
    return `- ${location}: ${finding.practice_id} (${finding.status}, ${finding.enforcement}). ${finding.message}`;
  });
}

function formatObservationStats(stats: PracticeObservationStats): string[] {
  return [
    `Checks: ${stats.total}`,
    `Passed: ${stats.passed}`,
    `Action required: ${stats.action_required}`,
    `Rerun required: ${stats.rerun_required}`,
    `Decisions: ${formatInlineCounts(stats.by_decision)}`,
    `Kinds: ${formatInlineCounts(stats.by_kind)}`,
    `Top practices: ${
      stats.top_practices.length > 0
        ? stats.top_practices.map((practice) => `${practice.practice_id} (${practice.count})`).join(", ")
        : "none"
    }`,
  ];
}

function formatObservations(observations: PracticeObservation[]): string[] {
  if (observations.length === 0) {
    return ["- None."];
  }
  return observations.map((observation) => {
    const decision = observation.decision ?? "none";
    const practices = observation.practice_ids.length > 0 ? ` Practices: ${observation.practice_ids.join(", ")}.` : "";
    return `- #${observation.id} ${observation.kind}: ${decision}. Passed: ${observation.passed ? "yes" : "no"}.${practices}`;
  });
}

function formatPlanCheck(planCheck: PracticePlanCheckReference): string {
  const matched = planCheck.matched_observation_id ? `#${planCheck.matched_observation_id}` : "none";
  return `${planCheck.match_type}, matched ${matched}. ${planCheck.reason}`;
}

function formatInlineCounts(counts: Record<string, number>): string {
  const entries = Object.entries(counts).sort((left, right) => right[1] - left[1] || left[0].localeCompare(right[0]));
  return entries.length > 0 ? entries.map(([key, count]) => `${key} ${count}`).join(", ") : "none";
}

function formatCounts(counts: Map<string, number>): string[] {
  if (counts.size === 0) {
    return ["- None."];
  }
  return [...counts.entries()]
    .sort((left, right) => right[1] - left[1] || left[0].localeCompare(right[0]))
    .map(([key, count]) => `- ${key}: ${count}`);
}

function countBy(values: string[]): Map<string, number> {
  const counts = new Map<string, number>();
  for (const value of values.filter(Boolean)) {
    counts.set(value, (counts.get(value) ?? 0) + 1);
  }
  return counts;
}

function practiceUri(id: string): string {
  return `practice://practices/${encodeURIComponent(id)}`;
}

function isCheckResult(value: Record<string, unknown>): value is PracticeCheckResult {
  return typeof value.decision === "string" && Array.isArray(value.matched_practices);
}

function isScanResult(value: Record<string, unknown>): value is PracticeScanResult {
  return typeof value.decision === "string" && Array.isArray(value.findings);
}

function isFinalizeResult(value: Record<string, unknown>): value is PracticeFinalizeResult {
  return typeof value.decision === "string" && Boolean(value.scan_diff) && Boolean(value.observations);
}

function isPreflightResult(value: Record<string, unknown>): value is PracticePreflightResult {
  return typeof value.decision === "string" && Boolean(value.guardrails) && Array.isArray(value.required_calls);
}

function isReviewQueueResult(value: Record<string, unknown>): value is PracticeReviewQueueResult {
  return typeof value.decision === "string" && Boolean(value.stats) && Array.isArray(value.items);
}

function isFeedbackResult(value: Record<string, unknown>): value is {
  observation_id?: number;
  decision: string;
  passed: boolean;
  summary: string;
  next_steps: string[];
} {
  return (
    typeof value.decision === "string" &&
    (Boolean(value.proposal) || Boolean(value.exception) || Boolean(value.approval)) &&
    Array.isArray(value.next_steps)
  );
}

function isObservationSummary(value: Record<string, unknown>): value is {
  stats: PracticeObservationStats;
  recent: PracticeObservation[];
} {
  return Boolean(value.stats) && Array.isArray(value.recent);
}

function isGuardrailResult(value: Record<string, unknown>): value is {
  summary: string;
  next_steps: string[];
  agent_contract: string[];
  practices: PracticeGuardrail[];
} {
  return Array.isArray(value.practices) && Array.isArray(value.agent_contract) && Array.isArray(value.next_steps);
}
