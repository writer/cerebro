#!/usr/bin/env node
import { spawnSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import process from "node:process";

const root = process.cwd();
const tempRoot = fs.mkdtempSync(path.join(os.tmpdir(), "practice-registry-cli-ux-"));
const cli = path.join(root, "dist", "cli.js");

try {
  const help = run(["generate-editor-config", "--help"], tempRoot);
  if (help.status !== 0) {
    throw new Error(`Expected help to exit 0, got ${help.status}: ${help.stderr}`);
  }
  if (fs.existsSync(path.join(tempRoot, ".cursor", "mcp.json"))) {
    throw new Error("Help wrote .cursor/mcp.json.");
  }

  const setup = run(["setup", "--client", "cursor", "--repo", tempRoot, "--registry-root", root], tempRoot);
  if (setup.status !== 0) {
    throw new Error(`setup failed with exit ${setup.status}: ${setup.stderr}`);
  }
  if (!setup.stdout.includes("Practice Registry setup") || !setup.stdout.includes("Next steps:")) {
    throw new Error(`setup output did not include operator guidance: ${setup.stdout}`);
  }

  const configPath = path.join(tempRoot, ".cursor", "mcp.json");
  const rulePath = path.join(tempRoot, ".cursor", "rules", "practice-registry.mdc");
  const launcherPath = path.join(tempRoot, ".practice-registry", "run-mcp");
  const config = JSON.parse(fs.readFileSync(configPath, "utf8"));
  if (config.mcpServers?.["practice-registry"]?.type !== "stdio") {
    throw new Error("setup did not write a stdio MCP server.");
  }
  if (config.mcpServers?.["practice-registry"]?.command !== ".practice-registry/run-mcp") {
    throw new Error("setup did not write the repo-local launcher command.");
  }
  if (config.mcpServers?.["practice-registry"]?.env) {
    throw new Error("setup wrote inline env paths into mcp.json.");
  }
  fs.accessSync(launcherPath, fs.constants.X_OK);
  const rule = fs.readFileSync(rulePath, "utf8");
  if (!rule.includes("practice-registry.check_plan") || !rule.includes("practice-registry.finalize_change")) {
    throw new Error("setup did not write the expected editor rule.");
  }
  if (!rule.includes("TypeScript") || !rule.includes("**/*.ts") || !rule.includes("JavaScript") || !rule.includes("**/*.jsx") || !rule.includes("Rust") || !rule.includes("**/*.rs") || !rule.includes("**/Cargo.toml")) {
    throw new Error("setup did not write TypeScript, JavaScript, and Rust editor coverage.");
  }
  if (!rule.includes("Trust the passed field") || !rule.includes("Do not treat blocking: false as a pass") || !rule.includes("revise_or_justify")) {
    throw new Error("setup did not write non-blocking decision guidance.");
  }
  if (fs.existsSync(path.join(tempRoot, ".practice-registry", "practices.db"))) {
    throw new Error("setup or doctor created a repo-local practice database.");
  }

  const init = run(["init-repo", "--client", "cursor", "--repo", tempRoot, "--registry-root", root, "--overwrite"], tempRoot);
  if (init.status !== 0) {
    throw new Error(`init-repo failed with exit ${init.status}: ${init.stdout}\n${init.stderr}`);
  }
  const agents = fs.readFileSync(path.join(tempRoot, "AGENTS.md"), "utf8");
  const ciSnippet = fs.readFileSync(path.join(tempRoot, ".practice-registry", "ci.md"), "utf8");
  if (!agents.includes("practice-registry.preflight") || !agents.includes("practice-registry.propose_practice")) {
    throw new Error(`init-repo did not write preflight-aware AGENTS.md: ${agents}`);
  }
  if (!ciSnippet.includes("scan-diff --fail-on-actionable")) {
    throw new Error(`init-repo did not write CI scan guidance: ${ciSnippet}`);
  }

  const actionableDiff = [
    "diff --git a/src/api/users.py b/src/api/users.py",
    "+++ b/src/api/users.py",
    "@@ -1,1 +1,2 @@",
    " import os",
    '+feature_flag = os.environ.get("FEATURE_FLAG", "")',
  ].join("\n");
  const advisorySoft = run(["scan-diff", "--no-semgrep", "--fail-on-blocking"], tempRoot, actionableDiff);
  if (advisorySoft.status !== 0) {
    throw new Error(`Expected fail-on-blocking to allow advisory findings, got ${advisorySoft.status}: ${advisorySoft.stdout}`);
  }
  const advisoryStrict = run(["scan-diff", "--no-semgrep", "--fail-on-actionable"], tempRoot, actionableDiff);
  if (advisoryStrict.status !== 2) {
    throw new Error(`Expected fail-on-actionable to stop on advisory findings, got ${advisoryStrict.status}: ${advisoryStrict.stdout}`);
  }
  const advisoryResult = JSON.parse(advisoryStrict.stdout);
  if (advisoryResult.decision !== "revise_or_justify") {
    throw new Error(`Expected revise_or_justify from strict advisory scan, got ${advisoryResult.decision}`);
  }
  if (advisoryResult.passed !== false || advisoryResult.action_required !== true) {
    throw new Error(`Expected explicit actionable outcome fields, got ${advisoryStrict.stdout}`);
  }

  const lint = run(["lint-practices", "--fail-on-actionable"], tempRoot);
  if (lint.status !== 0) {
    throw new Error(`lint-practices failed with exit ${lint.status}: ${lint.stdout}\n${lint.stderr}`);
  }

  const coverage = run(["coverage-report", "--observations", "10"], tempRoot);
  if (coverage.status !== 0) {
    throw new Error(`coverage-report failed with exit ${coverage.status}: ${coverage.stdout}\n${coverage.stderr}`);
  }
  const coverageResult = JSON.parse(coverage.stdout);
  if (!coverageResult.language_coverage.some((item) => item.language === "typescript" && item.dedicated_practices >= 10)) {
    throw new Error(`coverage-report did not expose TypeScript coverage: ${coverage.stdout}`);
  }
  if (!coverageResult.language_coverage.some((item) => item.language === "javascript" && item.total_practices >= 10)) {
    throw new Error(`coverage-report did not expose JavaScript coverage: ${coverage.stdout}`);
  }
  if (!coverageResult.language_coverage.some((item) => item.language === "rust" && item.dedicated_practices >= 10)) {
    throw new Error(`coverage-report did not expose Rust coverage: ${coverage.stdout}`);
  }

  const preflight = run(
    [
      "preflight",
      "--language",
      "typescript",
      "--framework",
      "express",
      "--file",
      "src/routes/users.ts",
      "--intent",
      "add a user endpoint",
      "--approach",
      "Build SQL with a template string and pass it to the db client.",
    ],
    tempRoot,
  );
  if (preflight.status !== 0) {
    throw new Error(`preflight failed with exit ${preflight.status}: ${preflight.stdout}\n${preflight.stderr}`);
  }
  const preflightResult = JSON.parse(preflight.stdout);
  if (preflightResult.decision !== "change_code" || preflightResult.plan_check?.matched_practices?.[0]?.id !== "typescript.db.parameterized-sql") {
    throw new Error(`preflight did not check the risky plan: ${preflight.stdout}`);
  }

  const proposal = run(
    [
      "propose-practice",
      "--title",
      "Use repository helpers for analytics reads",
      "--summary",
      "Analytics reads should go through repository helpers instead of ad hoc SQL.",
      "--owner",
      "data-platform",
      "--language",
      "typescript",
    ],
    tempRoot,
  );
  if (proposal.status !== 0) {
    throw new Error(`propose-practice failed with exit ${proposal.status}: ${proposal.stdout}\n${proposal.stderr}`);
  }
  const proposalResult = JSON.parse(proposal.stdout);
  const approval = run(
    [
      "record-approval",
      "--practice-id",
      "typescript.react.bounded-list-projections",
      "--method",
      "research",
      "--approved-by",
      "cerebro-web",
      "--conclusion",
      "Independent specifications support sparse fields and bounded pagination.",
      "--observation-id",
      String(proposalResult.observation_id),
      "--source-json",
      JSON.stringify({
        title: "JSON:API Sparse Fieldsets",
        publisher: "JSON:API",
        url: "https://jsonapi.org/format/#fetching-sparse-fieldsets",
        direct_support: "Restricted fieldsets omit additional response fields.",
      }),
      "--source-json",
      JSON.stringify({
        title: "GraphQL Pagination",
        publisher: "GraphQL Foundation",
        url: "https://graphql.org/learn/pagination/",
        direct_support: "Large list fields should use bounded pagination.",
      }),
    ],
    tempRoot,
  );
  if (approval.status !== 0 || JSON.parse(approval.stdout).passed !== true) {
    throw new Error(`record-approval failed with exit ${approval.status}: ${approval.stdout}\n${approval.stderr}`);
  }
  const exception = run(
    [
      "record-exception",
      "--practice-id",
      "typescript.db.parameterized-sql",
      "--reason",
      "Legacy migration script has static seed data.",
      "--context",
      "Only the one-time migration script may keep static SQL text.",
      "--owner",
      "data-platform",
      "--expires-at",
      "2026-12-31",
    ],
    tempRoot,
  );
  if (exception.status !== 0) {
    throw new Error(`record-exception failed with exit ${exception.status}: ${exception.stdout}\n${exception.stderr}`);
  }
  const reviewQueue = run(["review-queue", "--limit", "10"], tempRoot);
  if (reviewQueue.status !== 0) {
    throw new Error(`review-queue failed with exit ${reviewQueue.status}: ${reviewQueue.stdout}\n${reviewQueue.stderr}`);
  }
  const reviewQueueResult = JSON.parse(reviewQueue.stdout);
  if (reviewQueueResult.items.some((item) => item.observation_ids.includes(proposalResult.observation_id)) || !reviewQueueResult.items.some((item) => item.kind === "practice_exception")) {
    throw new Error(`review-queue did not resolve the approved proposal: ${reviewQueue.stdout}`);
  }

  const doctor = run(["doctor", "--client", "cursor", "--repo", tempRoot, "--registry-root", root, "--json"], tempRoot);
  if (doctor.status !== 0) {
    throw new Error(`doctor failed with exit ${doctor.status}: ${doctor.stderr}`);
  }
  const doctorResult = JSON.parse(doctor.stdout);
  if (!["ok", "warn"].includes(doctorResult.status)) {
    throw new Error(`Expected doctor status ok or warn, got ${doctorResult.status}`);
  }
  if (!doctorResult.checks.some((check) => check.label === "Cursor MCP config" && check.status === "ok")) {
    throw new Error("doctor did not confirm the Cursor MCP config.");
  }
  if (!doctorResult.checks.some((check) => check.label === "Cursor MCP launcher" && check.status === "ok")) {
    throw new Error("doctor did not confirm the Cursor MCP launcher.");
  }
  if (!doctorResult.checks.some((check) => check.label === "Codex plugin" && ["ok", "warn"].includes(check.status))) {
    throw new Error("doctor did not report the Codex plugin state.");
  }

  console.log(
    JSON.stringify(
      {
        help: "side-effect-free",
        setup: {
          config: path.relative(tempRoot, configPath),
          launcher: path.relative(tempRoot, launcherPath),
          rule: path.relative(tempRoot, rulePath),
          agents: "AGENTS.md",
        },
        actionable_exit: advisoryStrict.status,
        coverage_languages: coverageResult.language_coverage.map((item) => item.language),
        preflight: preflightResult.decision,
        review_queue: reviewQueueResult.stats.total,
        doctor: doctorResult.status,
      },
      null,
      2,
    ),
  );
} finally {
  fs.rmSync(tempRoot, { recursive: true, force: true });
}

function run(args, cwd, input = "") {
  return spawnSync(process.execPath, [cli, ...args], {
    cwd,
    input,
    encoding: "utf8",
    maxBuffer: 20 * 1024 * 1024,
  });
}
