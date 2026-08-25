#!/usr/bin/env node
import path from "node:path";
import process from "node:process";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StdioClientTransport } from "@modelcontextprotocol/sdk/client/stdio.js";

const root = process.cwd();
const env = Object.fromEntries(
  Object.entries(process.env).filter((entry) => typeof entry[1] === "string"),
);
env.PRACTICE_REGISTRY_ROOT = path.join(root, "practices");
env.PRACTICE_REGISTRY_DB = path.join(root, ".practice-registry", "smoke.db");
env.PRACTICE_SEMGREP_RULES = path.join(root, "semgrep", "practice-rules.yml");

const transport = new StdioClientTransport({
  command: process.execPath,
  args: [path.join(root, "dist", "index.js")],
  cwd: root,
  env,
  stderr: "pipe",
});

const client = new Client({ name: "practice-registry-smoke", version: "0.1.0" });

try {
  await client.connect(transport);

  const tools = await client.listTools();
  assertTool(tools, "check_plan");
  assertTool(tools, "preflight");
  assertTool(tools, "check_diff");
  assertTool(tools, "scan_diff");
  assertTool(tools, "finalize_change");
  assertTool(tools, "server_info");
  assertTool(tools, "get_guardrails");
  assertTool(tools, "observation_summary");
  assertTool(tools, "propose_practice");
  assertTool(tools, "record_exception");
  assertTool(tools, "record_approval");
  assertTool(tools, "review_queue");
  assertTool(tools, "search_practices");
  assertTool(tools, "explain_practice");

  const instructions = client.getInstructions();
  if (!instructions?.includes("check_plan") || !instructions.includes("finalize_change")) {
    throw new Error(`Server instructions do not describe the generation-time contract: ${instructions}`);
  }

  const info = await callJson("server_info", {});
  assertEqual(info.contract_version, "2026-07-16.rust-practices", "server_info should report contract version");
  for (const language of ["typescript", "javascript", "rust"]) {
    if (!info.supported_languages?.includes(language)) {
      throw new Error(`server_info did not report ${language} support: ${JSON.stringify(info)}`);
    }
  }
  for (const feature of ["typescript_practices", "everyday_typescript_practices", "rust_practices", "everyday_rust_practices", "coverage_report", "explicit_mcp_schemas", "preflight", "practice_feedback", "review_queue", "precise_preflight_matching", "research_backed_approvals"]) {
    if (!info.features?.includes(feature)) {
      throw new Error(`server_info did not report ${feature}: ${JSON.stringify(info)}`);
    }
  }
  if (!instructions.includes("Trust the passed field") || !instructions.includes("Only allowed and follow_guidance are pass decisions")) {
    throw new Error(`Server instructions do not name pass decisions: ${instructions}`);
  }

  const resources = await client.listResources();
  assertResource(resources, "practice://agent-contract");
  assertResource(resources, "practice://registry-summary");
  assertResource(resources, "practice://observation-summary");
  assertResource(resources, "practice://coverage-report");
  assertResource(resources, "practice://review-queue");
  assertResource(resources, "practice://practices/python.subprocess.no-shell-true");

  const templates = await client.listResourceTemplates();
  if (!templates.resourceTemplates.some((template) => template.uriTemplate === "practice://practices/{id}")) {
    throw new Error(`Missing practice resource template. Got ${JSON.stringify(templates)}`);
  }

  const contract = await client.readResource({ uri: "practice://agent-contract" });
  assertResourceText(contract, "Call `check_plan` before generating non-trivial code.");
  assertResourceText(contract, "Treat only `allowed` and `follow_guidance` as pass decisions.");
  assertResourceText(contract, "Run `finalize_change` on the final diff before the final response.");

  const summary = await client.readResource({ uri: "practice://registry-summary" });
  assertResourceText(summary, "Blocking Records");

  const observationSummary = await client.readResource({ uri: "practice://observation-summary" });
  assertResourceText(observationSummary, "Observation Summary");

  const coverageReport = await client.readResource({ uri: "practice://coverage-report" });
  assertResourceText(coverageReport, "Practice Coverage Report");
  assertResourceText(coverageReport, "typescript");
  assertResourceText(coverageReport, "rust");

  const reviewQueueResource = await client.readResource({ uri: "practice://review-queue" });
  assertResourceText(reviewQueueResource, "Review Queue");

  const practiceRecord = await client.readResource({ uri: "practice://practices/python.subprocess.no-shell-true" });
  assertResourceText(practiceRecord, "Avoid shell=True for subprocess calls");

  const researchedPractice = await client.readResource({ uri: "practice://practices/typescript.react.bounded-list-projections" });
  assertResourceText(researchedPractice, "Approval: research by cerebro-web");

  const prompts = await client.listPrompts();
  assertPrompt(prompts, "plan_with_practices");
  assertPrompt(prompts, "review_final_diff");

  const planPrompt = await client.getPrompt({
    name: "plan_with_practices",
    arguments: {
      intent: "run a command in a worker",
      language: "python",
      files: "services/sync/git_worker.py",
      planned_approach: "Use subprocess.run(command, shell=True)",
    },
  });
  const planPromptText = planPrompt.messages?.[0]?.content?.text ?? "";
  if (!planPromptText.includes("check_plan") || !planPromptText.includes("get_guardrails")) {
    throw new Error(`Plan prompt does not describe MCP tool use: ${JSON.stringify(planPrompt)}`);
  }
  if (!planPromptText.includes("Trust the passed field") || !planPromptText.includes("Only allowed and follow_guidance are pass decisions")) {
    throw new Error(`Plan prompt does not name pass decisions: ${JSON.stringify(planPrompt)}`);
  }

  const guardrails = await callJson("get_guardrails", {
    language: "python",
    files: ["services/sync/git_worker.py"],
    topic: "run a command",
  });
  assertGuardrail(guardrails, "python.subprocess.no-shell-true");

  const preflight = await callJson("preflight", {
    language: "typescript",
    framework: "express",
    files: ["src/routes/users.ts"],
    intent: "add an endpoint that reads user id and queries postgres",
    planned_approach: "Build SQL with a template string and pass it to the db client.",
  });
  assertEqual(preflight.decision, "change_code", "Preflight should check risky planned approaches");
  assertMatch(preflight.plan_check, "typescript.db.parameterized-sql");

  const pythonPlan = await callJson("check_plan", {
    language: "python",
    files: ["services/sync/git_worker.py"],
    intent: "run a command in a worker",
    planned_approach: "Use subprocess.run(command, shell=True)",
  });
  assertEqual(pythonPlan.decision, "change_code", "Python shell plan should be blocked");
  assertEqual(pythonPlan.passed, false, "Python shell plan should not pass");
  assertMatch(pythonPlan, "python.subprocess.no-shell-true");

  const eventUnitPlan = await callJson("check_plan", {
    language: "scala",
    framework: "cats-effect",
    files: ["server/src/com/writer/reporting/SessionInternalService.scala"],
    intent: "publish an audit log event",
    planned_approach: "Create an EventUnit in the application loader and inject it into the service.",
  });
  assertEqual(eventUnitPlan.decision, "follow_guidance", "EventUnit plan should pass with guidance");
  assertEqual(eventUnitPlan.passed, true, "EventUnit plan should expose passed true");
  if (!Number.isInteger(eventUnitPlan.observation_id)) {
    throw new Error(`EventUnit plan did not return an observation_id: ${JSON.stringify(eventUnitPlan)}`);
  }
  assertMatch(eventUnitPlan, "scala.writer.eventunit-startup-injection");

  const scalaDiff = await callJson("check_diff", {
    language: "scala",
    diff: [
      "diff --git a/services/users/UserService.scala b/services/users/UserService.scala",
      "+++ b/services/users/UserService.scala",
      "+val user = Await.result(userRepo.fetch(id), 5.seconds)",
    ].join("\n"),
  });
  assertEqual(scalaDiff.decision, "change_code", "Scala blocking diff should be blocked");
  assertMatch(scalaDiff, "scala.effects.no-await-result-in-services");

  const generatedScala = await callJson("check_plan", {
    language: "scala",
    files: ["modules/proto/generated/UserProto.scala"],
    intent: "generated protobuf null interop",
    planned_approach: "Keep generated null handling contained at the service boundary",
  });
  assertEqual(generatedScala.blocking, false, "Generated Scala legacy practice should not block");
  assertMatch(generatedScala, "scala.generated.null-legacy-accepted");

  const pythonScan = await callJson("scan_diff", {
    diff: [
      "diff --git a/services/sync/git_worker.py b/services/sync/git_worker.py",
      "+++ b/services/sync/git_worker.py",
      "@@ -1,1 +1,2 @@",
      " import subprocess",
      "+subprocess.run(command, shell=True)",
    ].join("\n"),
    use_semgrep: false,
  });
  assertEqual(pythonScan.decision, "change_code", "Python shell diff should be blocked by scan_diff");
  assertEqual(pythonScan.action_required, true, "Python shell diff should require action");
  assertFinding(pythonScan, "python.subprocess.no-shell-true");

  const rustPlan = await callJson("check_plan", {
    language: "rust",
    files: ["src/release.rs"],
    intent: "run a release command",
    planned_approach: 'Use Command::new("sh").arg("-c").arg(command).',
  });
  assertEqual(rustPlan.decision, "change_code", "Rust shell plan should be blocked");
  assertMatch(rustPlan, "rust.process.no-shell-command");

  const rustScan = await callJson("scan_diff", {
    diff: [
      "diff --git a/src/release.rs b/src/release.rs",
      "+++ b/src/release.rs",
      "@@ -1,1 +1,2 @@",
      " use std::process::Command;",
      '+Command::new("sh").arg("-c").arg(command).status()?;',
    ].join("\n"),
    use_semgrep: false,
  });
  assertEqual(rustScan.decision, "change_code", "Rust shell diff should be blocked by scan_diff");
  assertFinding(rustScan, "rust.process.no-shell-command");

  const finalized = await callJson("finalize_change", {
    diff: [
      "diff --git a/server/src/com/writer/reporting/SessionInternalService.scala b/server/src/com/writer/reporting/SessionInternalService.scala",
      "+++ b/server/src/com/writer/reporting/SessionInternalService.scala",
      "@@ -1,1 +1,2 @@",
      " final class SessionInternalService",
      "+def publishAuditLog(): Unit = ()",
    ].join("\n"),
    language: "scala",
    use_semgrep: false,
  });
  assertEqual(finalized.passed, true, "finalize_change should pass after a passing plan and clean scan");
  assertEqual(finalized.observations.passing_plan_found, true, "finalize_change should see the passing plan observation");
  assertEqual(
    finalized.observations.plan_check.matched_observation_id,
    eventUnitPlan.observation_id,
    "finalize_change should match the EventUnit plan observation",
  );

  const observations = await callJson("observation_summary", { limit: 20 });
  if (!observations.stats || observations.stats.total < 1) {
    throw new Error(`observation_summary did not return stats: ${JSON.stringify(observations)}`);
  }

  const proposal = await callJson("propose_practice", {
    title: "Use repository helpers for analytics reads",
    summary: "Analytics reads should go through the package repository helper instead of ad hoc SQL.",
    owner: "data-platform",
    language: "typescript",
    files: ["src/analytics/report.ts"],
    evidence: "Repeated needs_review observations in analytics routes.",
  });
  assertEqual(proposal.decision, "needs_review", "Practice proposal should require owner review");

  const approval = await callJson("record_approval", {
    practice_id: "typescript.react.bounded-list-projections",
    method: "research",
    approved_by: "cerebro-web",
    conclusion: "Independent specifications support sparse fields and bounded pagination.",
    related_observation_ids: [proposal.observation_id],
    sources: [
      {
        title: "JSON:API Sparse Fieldsets",
        publisher: "JSON:API",
        url: "https://jsonapi.org/format/#fetching-sparse-fieldsets",
        direct_support: "Restricted fieldsets omit additional response fields.",
      },
      {
        title: "GraphQL Pagination",
        publisher: "GraphQL Foundation",
        url: "https://graphql.org/learn/pagination/",
        direct_support: "Large list fields should use bounded pagination.",
      },
    ],
  });
  assertEqual(approval.passed, true, "Independent research approval should pass");

  const exception = await callJson("record_exception", {
    practice_id: "typescript.db.parameterized-sql",
    reason: "Legacy migration script has static seed data.",
    accepted_context: "Only the one-time migration script may keep static SQL text.",
    owner: "data-platform",
    expires_at: "2026-12-31",
    files: ["scripts/migrate-seed.ts"],
  });
  assertEqual(exception.exception.practice_id, "typescript.db.parameterized-sql", "Exception should retain practice id");

  const reviewQueue = await callJson("review_queue", { limit: 10 });
  if (reviewQueue.items?.some((item) => item.observation_ids.includes(proposal.observation_id)) || !reviewQueue.items?.some((item) => item.kind === "practice_exception")) {
    throw new Error(`review_queue did not resolve the approved proposal: ${JSON.stringify(reviewQueue)}`);
  }

  console.log(
    JSON.stringify(
      {
        tools: tools.tools.map((tool) => tool.name).sort(),
        resources: resources.resources.length,
        prompts: prompts.prompts.map((prompt) => prompt.name).sort(),
        checks: [
          info.contract_version,
          preflight.plan_check.matched_practices[0].id,
          guardrails.practices[0].id,
          pythonPlan.matched_practices[0].id,
          eventUnitPlan.matched_practices[0].id,
          scalaDiff.matched_practices[0].id,
          generatedScala.matched_practices[0].id,
          pythonScan.findings[0].practice_id,
          rustPlan.matched_practices[0].id,
          rustScan.findings[0].practice_id,
          finalized.decision,
          reviewQueue.items[0]?.kind,
        ],
      },
      null,
      2,
    ),
  );
} finally {
  await client.close();
}

async function callJson(name, args) {
  const result = await client.callTool({ name, arguments: args });
  const text = result.content?.find((item) => item.type === "text")?.text;
  if (!text) {
    throw new Error(`${name} did not return text content`);
  }
  if (
    !text.includes("Summary:") &&
    !text.includes("Decision:") &&
    !text.includes("Matched practices:") &&
    !text.includes("Observation summary:") &&
    !text.includes("Review Queue") &&
    !text.includes("contract_version")
  ) {
    throw new Error(`${name} did not return readable MCP text: ${text}`);
  }
  return result.structuredContent ?? JSON.parse(text);
}

function assertTool(tools, name) {
  if (!tools.tools.some((tool) => tool.name === name)) {
    throw new Error(`Missing MCP tool: ${name}`);
  }
}

function assertResource(resources, uri) {
  if (!resources.resources.some((resource) => resource.uri === uri)) {
    throw new Error(`Missing MCP resource: ${uri}. Got ${JSON.stringify(resources)}`);
  }
}

function assertPrompt(prompts, name) {
  if (!prompts.prompts.some((prompt) => prompt.name === name)) {
    throw new Error(`Missing MCP prompt: ${name}. Got ${JSON.stringify(prompts)}`);
  }
}

function assertResourceText(result, text) {
  const body = result.contents?.find((item) => item.text)?.text ?? "";
  if (!body.includes(text)) {
    throw new Error(`Expected resource text ${text}. Got ${JSON.stringify(result)}`);
  }
}

function assertMatch(result, id) {
  const matched = result.matched_practices?.some((practice) => practice.id === id);
  if (!matched) {
    throw new Error(`Expected practice match ${id}. Got ${JSON.stringify(result)}`);
  }
}

function assertGuardrail(result, id) {
  const matched = result.practices?.some((practice) => practice.id === id);
  if (!matched) {
    throw new Error(`Expected guardrail ${id}. Got ${JSON.stringify(result)}`);
  }
}

function assertFinding(result, id) {
  const matched = result.findings?.some((finding) => finding.practice_id === id);
  if (!matched) {
    throw new Error(`Expected practice finding ${id}. Got ${JSON.stringify(result)}`);
  }
}

function assertEqual(actual, expected, message) {
  if (actual !== expected) {
    throw new Error(`${message}. Expected ${expected}, got ${actual}`);
  }
}
