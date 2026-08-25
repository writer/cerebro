#!/usr/bin/env node
import fs from "node:fs";
import path from "node:path";
import { PracticeRegistry } from "./registry.js";
import { registryOptionsFromEnv } from "./config.js";
import { buildCoverageReport } from "./coverageReport.js";
import { formatDoctor, runDoctor } from "./doctor.js";
import { isActionableDecision } from "./outcome.js";
import { packageRoot } from "./paths.js";
import { lintPractices } from "./practiceLint.js";
import {
  approvalMethods,
  enforcementLevels,
  practiceStatuses,
  type ApprovalMethod,
  type ApprovalSource,
  type EnforcementLevel,
  type PracticeStatus,
} from "./schema.js";
import {
  defaultEditorConfigPath,
  defaultEditorLauncherPath,
  defaultEditorRulePath,
  normalizeEditorClient,
  writeEditorMcpConfig,
  writeEditorRule,
  writeMcpLauncher,
} from "./editorConfig.js";

type Args = Record<string, string | string[] | boolean>;

const [command, ...rest] = process.argv.slice(2);
const args = parseArgs(rest);

try {
  run(command, args);
} catch (error) {
  process.stderr.write(`Error: ${error instanceof Error ? error.message : String(error)}\n`);
  process.exitCode = 1;
}

function run(command: string | undefined, args: Args): void {
  if (!command || command === "help" || args.help === true || args.h === true) {
    usage(command === "help" ? positional(args)[0] : command);
    process.exitCode = 0;
    return;
  }

  if (command === "setup") {
    setupEditor(args);
    return;
  }

  if (command === "init-repo") {
    initRepo(args);
    return;
  }

  if (command === "doctor") {
    const result = runDoctor({
      registryRoot: path.resolve(stringArg(args, "registry-root") ?? defaultRegistryRoot()),
      repoRoot: path.resolve(stringArg(args, "repo") ?? stringArg(args, "repo-root") ?? process.cwd()),
      client: stringArg(args, "client") ? normalizeEditorClient(stringArg(args, "client")) : undefined,
      serverName: stringArg(args, "server-name") ?? "practice-registry",
    });
    if (args.json === true) {
      print(result);
    } else {
      process.stdout.write(formatDoctor(result));
    }
    if (result.status === "fail") {
      process.exitCode = 1;
    }
    return;
  }

  if (command === "generate-editor-config") {
    generateEditorConfig(args);
    return;
  }

  withRegistry((registry) => {
    if (command === "index") {
      const records = registry.rebuild();
      print({ indexed: records.length });
    } else if (command === "generate-semgrep") {
      registry.rebuild();
      const outputPath = path.resolve(stringArg(args, "output") ?? "semgrep/practice-rules.yml");
      const result = registry.writeSemgrepConfig(outputPath);
      print({ output: outputPath, rules: result.rules.length });
    } else if (command === "lint-practices") {
      const records = registry.rebuild();
      const result = lintPractices(records);
      print(result);
      setPracticeExitCode(args, result);
    } else if (command === "coverage-report") {
      const records = registry.rebuild();
      const result = buildCoverageReport(records, registry.recentObservations({ limit: numberArg(args, "observations") ?? 100 }));
      print(result);
    } else if (command === "preflight") {
      registry.rebuild();
      const result = registry.preflight({
        repo: stringArg(args, "repo-name"),
        topic: stringArg(args, "topic"),
        intent: stringArg(args, "intent"),
        language: stringArg(args, "language"),
        framework: stringArg(args, "framework"),
        files: listArg(args, "file"),
        dependencies: listArg(args, "dependency"),
        planned_approach: stringArg(args, "approach"),
        proposed_code: stringArg(args, "code"),
        max_practices: numberArg(args, "max-practices"),
      });
      print(result);
      setPracticeExitCode(args, result);
    } else if (command === "propose-practice") {
      registry.rebuild();
      const title = stringArg(args, "title");
      const summary = stringArg(args, "summary");
      requireValue(title, "Provide --title.");
      requireValue(summary, "Provide --summary.");
      const result = registry.proposePractice({
        title,
        summary,
        owner: stringArg(args, "owner"),
        language: stringArg(args, "language"),
        framework: stringArg(args, "framework"),
        files: listArg(args, "file"),
        evidence: stringArg(args, "evidence"),
        suggested_status: practiceStatusArg(args, "status"),
        suggested_enforcement: enforcementArg(args, "enforcement"),
        avoid: listArg(args, "avoid"),
        use_instead: listArg(args, "use-instead"),
      });
      print(result);
      setPracticeExitCode(args, result);
    } else if (command === "record-exception") {
      registry.rebuild();
      const practiceId = stringArg(args, "practice-id");
      const reason = stringArg(args, "reason");
      const acceptedContext = stringArg(args, "context") ?? stringArg(args, "accepted-context");
      requireValue(practiceId, "Provide --practice-id.");
      requireValue(reason, "Provide --reason.");
      requireValue(acceptedContext, "Provide --context.");
      const result = registry.recordException({
        practice_id: practiceId,
        reason,
        accepted_context: acceptedContext,
        owner: stringArg(args, "owner"),
        expires_at: stringArg(args, "expires-at"),
        language: stringArg(args, "language"),
        files: listArg(args, "file"),
        evidence: stringArg(args, "evidence"),
        replacement_plan: stringArg(args, "replacement-plan"),
      });
      print(result);
      setPracticeExitCode(args, result);
    } else if (command === "record-approval") {
      registry.rebuild();
      const practiceId = stringArg(args, "practice-id");
      const method = approvalMethodArg(args, "method");
      const approvedBy = stringArg(args, "approved-by");
      const conclusion = stringArg(args, "conclusion");
      requireValue(practiceId, "Provide --practice-id.");
      requireValue(method, "Provide --method owner|research.");
      requireValue(approvedBy, "Provide --approved-by.");
      requireValue(conclusion, "Provide --conclusion.");
      const result = registry.recordApproval({
        practice_id: practiceId,
        method,
        approved_by: approvedBy,
        conclusion,
        related_observation_ids: integerListArg(args, "observation-id"),
        sources: approvalSourceArgs(args),
      });
      print(result);
      setPracticeExitCode(args, result);
    } else if (command === "review-queue") {
      registry.rebuild();
      const result = registry.reviewQueue({ limit: numberArg(args, "limit") });
      print(result);
      setPracticeExitCode(args, result);
    } else if (command === "search") {
      registry.rebuild();
      const query = positional(args).join(" ") || stringArg(args, "query");
      requireValue(query, "Provide a search query.");
      print({ matched_practices: registry.search(query, filters(args)) });
    } else if (command === "explain") {
      registry.rebuild();
      const id = positional(args)[0] ?? stringArg(args, "id");
      requireValue(id, "Provide a practice id.");
      print(registry.explain(id) ?? { error: `No practice found for id ${id}` });
    } else if (command === "check-plan") {
      registry.rebuild();
      const result = registry.check("plan", {
        intent: stringArg(args, "intent"),
        language: stringArg(args, "language"),
        framework: stringArg(args, "framework"),
        files: listArg(args, "file"),
        planned_approach: stringArg(args, "approach"),
        dependencies: listArg(args, "dependency"),
      });
      print(result);
      setPracticeExitCode(args, result);
    } else if (command === "check-diff") {
      registry.rebuild();
      const diff = readDiff(args);
      const result = registry.check("diff", {
        language: stringArg(args, "language"),
        framework: stringArg(args, "framework"),
        files: listArg(args, "file"),
        diff,
        dependencies: listArg(args, "dependency"),
      });
      print(result);
      setPracticeExitCode(args, result);
    } else if (command === "scan-diff") {
      registry.rebuild();
      const diff = readDiff(args);
      const result = registry.scanDiff(diff, {
        cwd: process.cwd(),
        rulesPath: stringArg(args, "rules"),
        useSemgrep: args["no-semgrep"] === true ? false : undefined,
      });
      print(result);
      setPracticeExitCode(args, result);
    } else if (command === "finalize-change") {
      registry.rebuild();
      const diff = readDiff(args);
      const result = registry.finalizeChange(
        {
          language: stringArg(args, "language"),
          framework: stringArg(args, "framework"),
          files: listArg(args, "file"),
          diff,
          dependencies: listArg(args, "dependency"),
          rules_path: stringArg(args, "rules"),
          use_semgrep: args["no-semgrep"] === true ? false : undefined,
          require_plan_check: args["skip-plan-check"] === true ? false : undefined,
          plan_observation_id: numberArg(args, "plan-observation-id"),
        },
        { cwd: process.cwd() },
      );
      print(result);
      setPracticeExitCode(args, result);
    } else {
      usage();
      process.exitCode = 1;
    }
  });
}

function initRepo(args: Args): void {
  const client = normalizeEditorClient(stringArg(args, "client"));
  const repoRoot = path.resolve(stringArg(args, "repo") ?? stringArg(args, "repo-root") ?? process.cwd());
  const registryRoot = path.resolve(stringArg(args, "registry-root") ?? defaultRegistryRoot());
  const serverName = stringArg(args, "server-name") ?? "practice-registry";
  const overwrite = args.overwrite === true;

  const outputPath = path.resolve(repoRoot, stringArg(args, "output") ?? defaultEditorConfigPath(client));
  const rulePath = path.resolve(repoRoot, stringArg(args, "rules-output") ?? defaultEditorRulePath(client));
  const launcherPath = path.resolve(repoRoot, stringArg(args, "launcher-output") ?? defaultEditorLauncherPath(client));
  const dbPath = path.resolve(repoRoot, stringArg(args, "db-path") ?? ".practice-registry/practices.db");

  writeMcpLauncher({ outputPath: launcherPath, registryRoot, overwrite });
  writeEditorMcpConfig({
    client,
    outputPath,
    registryRoot,
    dbPath,
    inlineEnv: false,
    launcherPath: path.relative(repoRoot, launcherPath),
    serverName,
    overwrite,
  });
  writeEditorRule({ outputPath: rulePath, serverName });

  const agentsPath = path.join(repoRoot, "AGENTS.md");
  writeTextFile(agentsPath, downstreamAgentsText(serverName), overwrite);
  const ciSnippetPath = path.join(repoRoot, ".practice-registry", "ci.md");
  writeTextFile(ciSnippetPath, ciSnippetText(), overwrite);

  const doctor = runDoctor({ registryRoot, repoRoot, client, serverName });
  const result = {
    repo: repoRoot,
    client,
    server: serverName,
    config: outputPath,
    launcher: launcherPath,
    rule: rulePath,
    agents: agentsPath,
    ci_snippet: ciSnippetPath,
    doctor_status: doctor.status,
    next_steps: [
      "Open the repo in Cursor.",
      `Enable ${serverName} in Settings > Tools & MCPs for this workspace.`,
      "Run practice preflight before the first non-trivial edit.",
      "Wire the CI snippet into the repo's existing CI job when the registry package is available there.",
    ],
  };

  if (args.json === true) {
    print({ ...result, doctor });
  } else {
    process.stdout.write(formatSetup(result));
    process.stdout.write("\n");
    process.stdout.write(formatDoctor(doctor));
  }
}

function setupEditor(args: Args): void {
  const client = normalizeEditorClient(stringArg(args, "client"));
  const repoRoot = path.resolve(stringArg(args, "repo") ?? stringArg(args, "repo-root") ?? process.cwd());
  const registryRoot = path.resolve(stringArg(args, "registry-root") ?? defaultRegistryRoot());
  const serverName = stringArg(args, "server-name") ?? "practice-registry";
  const outputPath = path.resolve(repoRoot, stringArg(args, "output") ?? defaultEditorConfigPath(client));
  const rulePath = path.resolve(repoRoot, stringArg(args, "rules-output") ?? defaultEditorRulePath(client));
  const dbPath = path.resolve(repoRoot, stringArg(args, "db-path") ?? ".practice-registry/practices.db");
  const launcherPath = path.resolve(repoRoot, stringArg(args, "launcher-output") ?? defaultEditorLauncherPath(client));
  const launcherCommand = path.relative(repoRoot, launcherPath);
  const inlineEnv = args["inline-env"] === true;

  if (!inlineEnv) {
    writeMcpLauncher({
      outputPath: launcherPath,
      registryRoot,
      overwrite: args.overwrite === true,
    });
  }

  writeEditorMcpConfig({
    client,
    outputPath,
    registryRoot,
    dbPath,
    inlineEnv,
    launcherPath: launcherCommand,
    serverName,
    nodePath: stringArg(args, "node-path"),
    overwrite: args.overwrite === true,
  });
  writeEditorRule({ outputPath: rulePath, serverName });

  const doctor = runDoctor({ registryRoot, repoRoot, client, serverName });
  const result = {
    client,
    repo: repoRoot,
    server: serverName,
    config: outputPath,
    launcher: inlineEnv ? undefined : launcherPath,
    rule: rulePath,
    doctor_status: doctor.status,
    next_steps: [
      "Open the repo in Cursor.",
      `Enable ${serverName} in Settings > Tools & MCPs for this workspace.`,
      `Start a Scala, Python, TypeScript, JavaScript, or Rust edit and confirm the agent calls ${serverName}.check_plan before edits and ${serverName}.finalize_change before the final response.`,
    ],
  };

  if (args.json === true) {
    print({ ...result, doctor });
  } else {
    process.stdout.write(formatSetup(result));
    process.stdout.write("\n");
    process.stdout.write(formatDoctor(doctor));
  }
}

function generateEditorConfig(args: Args): void {
  const client = normalizeEditorClient(stringArg(args, "client"));
  const outputArg = stringArg(args, "output");
  const repoRoot = path.resolve(
    stringArg(args, "repo") ?? stringArg(args, "repo-root") ?? (outputArg ? inferRepoRootFromOutput(client, path.resolve(outputArg)) : process.cwd()),
  );
  const outputPath = outputArg ? path.resolve(outputArg) : path.resolve(repoRoot, defaultEditorConfigPath(client));
  const rulePath =
    args["with-rule"] === true
      ? path.resolve(repoRoot, stringArg(args, "rules-output") ?? defaultEditorRulePath(client))
      : stringArg(args, "rules-output")
        ? path.resolve(stringArg(args, "rules-output")!)
        : undefined;
  const serverName = stringArg(args, "server-name") ?? "practice-registry";
  const registryRoot = path.resolve(stringArg(args, "registry-root") ?? defaultRegistryRoot());
  const dbPath = path.resolve(repoRoot, stringArg(args, "db-path") ?? ".practice-registry/practices.db");
  const launcherPath = path.resolve(repoRoot, stringArg(args, "launcher-output") ?? defaultEditorLauncherPath(client));
  const launcherCommand = path.relative(repoRoot, launcherPath);
  const inlineEnv = args["inline-env"] === true;

  if (!inlineEnv) {
    writeMcpLauncher({
      outputPath: launcherPath,
      registryRoot,
      overwrite: args.overwrite === true,
    });
  }

  writeEditorMcpConfig({
    client,
    outputPath,
    registryRoot,
    dbPath,
    inlineEnv,
    launcherPath: launcherCommand,
    serverName,
    nodePath: stringArg(args, "node-path"),
    overwrite: args.overwrite === true,
  });
  if (rulePath) {
    writeEditorRule({ outputPath: rulePath, serverName });
  }
  print({ client, output: outputPath, server: serverName, launcher: inlineEnv ? undefined : launcherPath, rule: rulePath });
}

function withRegistry(callback: (registry: PracticeRegistry) => void): void {
  const registry = new PracticeRegistry(registryOptionsFromEnv());
  try {
    callback(registry);
  } finally {
    registry.close();
  }
}

function parseArgs(values: string[]): Args {
  const parsed: Args = { _: [] };
  for (let index = 0; index < values.length; index += 1) {
    const value = values[index];
    if (value === "-h") {
      addArg(parsed, "help", true);
      continue;
    }
    if (!value.startsWith("--")) {
      (parsed._ as string[]).push(value);
      continue;
    }

    const inline = value.match(/^--([^=]+)=(.*)$/);
    if (inline) {
      addArg(parsed, inline[1], inline[2]);
      continue;
    }

    const key = value.slice(2);
    const next = values[index + 1];
    if (!next || next.startsWith("--")) {
      addArg(parsed, key, true);
      continue;
    }

    index += 1;
    addArg(parsed, key, next);
  }
  return parsed;
}

function addArg(parsed: Args, key: string, value: string | boolean): void {
  const current = parsed[key];
  if (Array.isArray(current)) {
    current.push(String(value));
  } else if (typeof current === "string") {
    parsed[key] = [current, String(value)];
  } else {
    parsed[key] = value;
  }
}

function filters(args: Args) {
  return {
    language: stringArg(args, "language"),
    framework: stringArg(args, "framework"),
    files: listArg(args, "file"),
  };
}

function readDiff(args: Args): string {
  const diffFile = stringArg(args, "diff-file");
  if (diffFile) {
    return fs.readFileSync(diffFile, "utf8");
  }
  return fs.readFileSync(0, "utf8");
}

function stringArg(args: Args, name: string): string | undefined {
  const value = args[name];
  if (Array.isArray(value)) return value.at(-1);
  return typeof value === "string" ? value : undefined;
}

function listArg(args: Args, name: string): string[] {
  const value = args[name];
  if (Array.isArray(value)) return value;
  return typeof value === "string" ? [value] : [];
}

function numberArg(args: Args, name: string): number | undefined {
  const value = stringArg(args, name);
  if (!value) return undefined;
  const parsed = Number(value);
  if (!Number.isInteger(parsed)) {
    throw new Error(`--${name} must be an integer.`);
  }
  return parsed;
}

function practiceStatusArg(args: Args, name: string): PracticeStatus | undefined {
  const value = stringArg(args, name);
  if (!value) return undefined;
  if ((practiceStatuses as readonly string[]).includes(value)) {
    return value as PracticeStatus;
  }
  throw new Error(`--${name} must be one of ${practiceStatuses.join(", ")}.`);
}

function enforcementArg(args: Args, name: string): EnforcementLevel | undefined {
  const value = stringArg(args, name);
  if (!value) return undefined;
  if ((enforcementLevels as readonly string[]).includes(value)) {
    return value as EnforcementLevel;
  }
  throw new Error(`--${name} must be one of ${enforcementLevels.join(", ")}.`);
}

function approvalMethodArg(args: Args, name: string): ApprovalMethod | undefined {
  const value = stringArg(args, name);
  if (!value) return undefined;
  if ((approvalMethods as readonly string[]).includes(value)) {
    return value as ApprovalMethod;
  }
  throw new Error(`--${name} must be one of ${approvalMethods.join(", ")}.`);
}

function integerListArg(args: Args, name: string): number[] {
  return listArg(args, name).map((value) => {
    const parsed = Number(value);
    if (!Number.isInteger(parsed) || parsed < 1) {
      throw new Error(`--${name} must be a positive integer.`);
    }
    return parsed;
  });
}

function approvalSourceArgs(args: Args): ApprovalSource[] {
  return listArg(args, "source-json").map((value) => {
    const parsed = JSON.parse(value) as Record<string, unknown>;
    for (const field of ["title", "publisher", "url", "direct_support"] as const) {
      if (typeof parsed[field] !== "string" || !parsed[field]) {
        throw new Error(`--source-json must include ${field}.`);
      }
    }
    return parsed as ApprovalSource;
  });
}

function positional(args: Args): string[] {
  return Array.isArray(args._) ? args._ : [];
}

function requireValue(value: string | undefined, message: string): asserts value is string {
  if (!value) {
    throw new Error(message);
  }
}

function print(value: unknown): void {
  process.stdout.write(`${JSON.stringify(value, null, 2)}\n`);
}

function setPracticeExitCode(args: Args, result: { blocking?: boolean; decision: string }): void {
  if (args["fail-on-actionable"] === true && isActionableDecision(result.decision)) {
    process.exitCode = 2;
    return;
  }
  if (args["fail-on-blocking"] === true && result.blocking === true) {
    process.exitCode = 2;
  }
}

function defaultRegistryRoot(): string {
  return packageRoot();
}

function inferRepoRootFromOutput(client: "cursor", outputPath: string): string {
  const normalizedOutput = path.normalize(outputPath);
  const defaultConfigPath = path.normalize(defaultEditorConfigPath(client));
  if (normalizedOutput.endsWith(defaultConfigPath)) {
    return path.dirname(path.dirname(normalizedOutput));
  }
  return process.cwd();
}

function formatSetup(value: {
  client: string;
  repo: string;
  server: string;
  config: string;
  launcher?: string;
  rule: string;
  agents?: string;
  ci_snippet?: string;
  doctor_status: string;
  next_steps: string[];
}): string {
  return [
    "Practice Registry setup",
    `Client: ${value.client}`,
    `Repo: ${value.repo}`,
    `MCP config: ${value.config}`,
    ...(value.launcher ? [`Launcher: ${value.launcher}`] : []),
    `Rule: ${value.rule}`,
    ...(value.agents ? [`Agents: ${value.agents}`] : []),
    ...(value.ci_snippet ? [`CI snippet: ${value.ci_snippet}`] : []),
    `Doctor: ${value.doctor_status}`,
    "Next steps:",
    ...value.next_steps.map((step, index) => `${index + 1}. ${step}`),
  ].join("\n");
}

function writeTextFile(filePath: string, text: string, overwrite: boolean): void {
  fs.mkdirSync(path.dirname(filePath), { recursive: true });
  try {
    fs.writeFileSync(filePath, text, { flag: overwrite ? "w" : "wx" });
  } catch (error) {
    if (!overwrite && isNodeError(error, "EEXIST")) {
      throw new Error(`${filePath} exists. Pass --overwrite to replace it.`);
    }
    throw error;
  }
}

function isNodeError(error: unknown, code: string): error is NodeJS.ErrnoException {
  return error instanceof Error && "code" in error && error.code === code;
}

function downstreamAgentsText(serverName: string): string {
  return `# Practice Registry

Before generating or editing non-trivial Scala, Python, TypeScript, JavaScript, or Rust code, call \`${serverName}.preflight\` when intent or files are known.

Before writing code, call \`${serverName}.check_plan\` with the intended approach, affected files, language, framework, and dependencies.

Before the final response, call \`${serverName}.finalize_change\` with the final diff. Pass \`plan_observation_id\` from the matching \`check_plan\` result when it is available.

Trust the \`passed\` field. Treat only \`allowed\` and \`follow_guidance\` as pass decisions. Treat \`banned\` results as blockers. Treat \`discouraged\` and \`legacy_accepted\` results as changes to make unless a recorded context applies. Resolve \`needs_review\` through the named owner or a research approval for an indexed practice with at least two directly supporting HTTPS sources from independent publishers and domains. Research approval does not approve an exception.

When no durable practice covers a repeated decision, use \`${serverName}.propose_practice\`. When an exception is needed, use \`${serverName}.record_exception\`; this records the request but does not approve it. After an approved practice record exists, use \`${serverName}.record_approval\` to resolve related review observations.
`;
}

function ciSnippetText(): string {
  return `# Practice Registry CI

Run this after the Practice Registry package is available in CI:

\`\`\`bash
npm ci
npm run build
npm run generate-semgrep
git diff origin/main...HEAD | node dist/cli.js scan-diff --fail-on-actionable
\`\`\`

Use --fail-on-blocking for an initial advisory rollout.
`;
}

function usage(command?: string): void {
  if (command === "setup") {
    process.stdout.write(`practice setup

Configure an editor workspace for Practice Registry.

Usage:
  practice setup --client cursor --repo /path/to/code-repo

Options:
  --registry-root PATH   Practice Registry checkout or package root.
  --launcher-output PATH Repo-local MCP launcher path.
  --server-name NAME     MCP server name. Defaults to practice-registry.
  --overwrite            Replace existing mcpServers entries in the output file.
  --json                 Print setup result and doctor checks as JSON.
`);
    return;
  }

  if (command === "init-repo") {
    process.stdout.write(`practice init-repo

Initialize a code repo for Practice Registry.

Usage:
  practice init-repo --client cursor --repo /path/to/code-repo

Writes:
  AGENTS.md
  .cursor/mcp.json
  .cursor/rules/practice-registry.mdc
  .practice-registry/run-mcp
  .practice-registry/ci.md

Options:
  --registry-root PATH   Practice Registry checkout or package root.
  --server-name NAME     MCP server name. Defaults to practice-registry.
  --overwrite            Replace generated files.
  --json                 Print init result and doctor checks as JSON.
`);
    return;
  }

  if (command === "doctor") {
    process.stdout.write(`practice doctor

Check whether Practice Registry is ready for a repo.

Usage:
  practice doctor --client cursor --repo /path/to/code-repo

Options:
  --registry-root PATH   Practice Registry checkout or package root.
  --server-name NAME     MCP server name. Defaults to practice-registry.
  --json                 Print checks as JSON.
`);
    return;
  }

  if (command === "generate-editor-config") {
    process.stdout.write(`practice generate-editor-config

Write an MCP config file for an editor client.

Usage:
  practice generate-editor-config --client cursor --repo /path/to/code-repo --with-rule

Options:
  --repo PATH            Code repo that should receive the launcher.
  --registry-root PATH   Practice Registry checkout or package root.
  --launcher-output PATH Repo-local MCP launcher path.
  --rules-output PATH    Rule file path. Written when passed or with --with-rule.
  --inline-env           Write direct paths into mcp.json for one-off debugging.
  --db-path PATH         SQLite index path for --inline-env.
  --server-name NAME     MCP server name. Defaults to practice-registry.
  --overwrite            Replace existing mcpServers entries in the output file.
`);
    return;
  }

  process.stdout.write(`practice registry

Commands:
  practice setup --client cursor --repo /path/to/code-repo
  practice init-repo --client cursor --repo /path/to/code-repo
  practice doctor [--client cursor] [--repo /path/to/code-repo]
  practice index
  practice lint-practices [--fail-on-actionable]
  practice coverage-report [--observations 100]
  practice preflight --intent text --language python --file service/foo.py [--approach text]
  practice review-queue [--limit 25]
  practice propose-practice --title text --summary text [--owner team]
  practice record-exception --practice-id id --reason text --context text [--expires-at YYYY-MM-DD]
  practice record-approval --practice-id id --method owner|research --approved-by team --conclusion text [--observation-id id] [--source-json json]
  practice search <query> [--language python|scala|typescript|javascript|rust] [--file path]
  practice explain <practice-id>
  practice generate-semgrep [--output semgrep/practice-rules.yml]
  practice generate-editor-config --client cursor --repo /path/to/code-repo [--with-rule]
  practice check-plan --intent text --language python --file service/foo.py --approach text
  practice check-diff --diff-file patch.diff [--fail-on-blocking|--fail-on-actionable]
  practice scan-diff --diff-file patch.diff [--fail-on-blocking|--fail-on-actionable] [--no-semgrep]
  practice finalize-change --diff-file patch.diff [--plan-observation-id id] [--fail-on-actionable] [--skip-plan-check]
  git diff | practice check-diff --language scala --fail-on-actionable
  git diff | practice scan-diff --fail-on-actionable
`);
}
