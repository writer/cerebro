#!/usr/bin/env node
import { spawnSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import process from "node:process";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StdioClientTransport } from "@modelcontextprotocol/sdk/client/stdio.js";

const root = process.cwd();
const tempRoot = fs.mkdtempSync(path.join(os.tmpdir(), "practice-registry-plugin-"));

try {
  const gitInit = spawnSync("git", ["init"], {
    cwd: tempRoot,
    encoding: "utf8",
    stdio: ["ignore", "pipe", "pipe"],
  });
  if (gitInit.status !== 0) {
    throw new Error(`git init failed: ${gitInit.stderr}`);
  }

  const pluginManifest = JSON.parse(fs.readFileSync(path.join(root, ".codex-plugin", "plugin.json"), "utf8"));
  const defaultPrompts = pluginManifest.interface?.defaultPrompt;
  if (
    !Array.isArray(defaultPrompts) ||
    defaultPrompts.length === 0 ||
    defaultPrompts.length > 3 ||
    defaultPrompts.some((prompt) => typeof prompt !== "string" || prompt.trim().length === 0)
  ) {
    throw new Error(`Plugin defaultPrompt must contain one to three concrete prompts: ${JSON.stringify(defaultPrompts)}`);
  }

  const env = {
    ...Object.fromEntries(Object.entries(process.env).filter(([, value]) => typeof value === "string")),
    PRACTICE_REGISTRY_PLUGIN_ROOT: root,
    PRACTICE_REGISTRY_DB: path.join(tempRoot, ".practice-registry", "practices.db"),
  };

  const hookConfig = JSON.parse(fs.readFileSync(path.join(root, "hooks", "hooks.json"), "utf8"));
  const command = hookConfig.hooks.PreToolUse[0].hooks[0].command;
  const input = JSON.stringify({
    tool: "apply_patch",
    tool_input: {
      patch: [
        "*** Begin Patch",
        "*** Update File: services/sync/git_worker.py",
        "@@",
        "+subprocess.run(command, shell=True)",
        "*** End Patch",
      ].join("\n"),
    },
  });

  const hook = spawnHook(command, env, tempRoot, input);
  if (hook.status !== 2) {
    process.stderr.write(hook.stdout);
    process.stderr.write(hook.stderr);
    throw new Error(`Expected plugin hook config to block with exit 2, got ${hook.status}`);
  }
  const hookResult = JSON.parse(hook.stderr.trim());
  if (hookResult.findings[0]?.practice_id !== "python.subprocess.no-shell-true") {
    throw new Error(`Unexpected hook finding: ${hook.stderr}`);
  }

  const advisoryInput = JSON.stringify({
    tool: "apply_patch",
    tool_input: {
      patch: [
        "*** Begin Patch",
        "*** Update File: src/api/users.py",
        "@@",
        "+import os",
        '+feature_flag = os.environ.get("FEATURE_FLAG", "")',
        "*** End Patch",
      ].join("\n"),
    },
  });
  const advisoryHook = spawnHook(command, env, tempRoot, advisoryInput);
  if (advisoryHook.status !== 2) {
    process.stderr.write(advisoryHook.stdout);
    process.stderr.write(advisoryHook.stderr);
    throw new Error(`Expected plugin hook config to stop on actionable advisory with exit 2, got ${advisoryHook.status}`);
  }
  const advisoryHookResult = JSON.parse(advisoryHook.stderr.trim());
  if (advisoryHookResult.decision !== "revise_or_justify") {
    throw new Error(`Unexpected advisory hook decision: ${advisoryHook.stderr}`);
  }

  const typescriptInput = JSON.stringify({
    tool: "apply_patch",
    tool_input: {
      patch: [
        "*** Begin Patch",
        "*** Update File: src/routes/users.ts",
        "@@",
        "+const rows = db.query(`SELECT * FROM users WHERE id = ${userId}`);",
        "*** End Patch",
      ].join("\n"),
    },
  });
  const typescriptHook = spawnHook(command, env, tempRoot, typescriptInput);
  if (typescriptHook.status !== 2) {
    process.stderr.write(typescriptHook.stdout);
    process.stderr.write(typescriptHook.stderr);
    throw new Error(`Expected plugin hook config to stop on TypeScript SQL interpolation with exit 2, got ${typescriptHook.status}`);
  }
  const typescriptHookResult = JSON.parse(typescriptHook.stderr.trim());
  if (typescriptHookResult.findings[0]?.practice_id !== "typescript.db.parameterized-sql") {
    throw new Error(`Unexpected TypeScript hook finding: ${typescriptHook.stderr}`);
  }

  const rustInput = JSON.stringify({
    tool: "apply_patch",
    tool_input: {
      patch: [
        "*** Begin Patch",
        "*** Update File: src/release.rs",
        "@@",
        '+Command::new("sh").arg("-c").arg(command).status()?;',
        "*** End Patch",
      ].join("\n"),
    },
  });
  const rustHook = spawnHook(command, env, tempRoot, rustInput);
  if (rustHook.status !== 2) {
    process.stderr.write(rustHook.stdout);
    process.stderr.write(rustHook.stderr);
    throw new Error(`Expected plugin hook config to stop on Rust shell execution with exit 2, got ${rustHook.status}`);
  }
  const rustHookResult = JSON.parse(rustHook.stderr.trim());
  if (rustHookResult.findings[0]?.practice_id !== "rust.process.no-shell-command") {
    throw new Error(`Unexpected Rust hook finding: ${rustHook.stderr}`);
  }

  const mcpConfig = JSON.parse(fs.readFileSync(path.join(root, ".mcp.json"), "utf8")).mcpServers[
    "practice-registry"
  ];
  if (
    mcpConfig.command !== "node" ||
    JSON.stringify(mcpConfig.args) !== JSON.stringify(["./dist/index.js"]) ||
    mcpConfig.cwd !== "."
  ) {
    throw new Error(`Plugin MCP server must launch from the installed bundle: ${JSON.stringify(mcpConfig)}`);
  }
  const transport = new StdioClientTransport({
    command: mcpConfig.command,
    args: mcpConfig.args,
    cwd: path.resolve(root, mcpConfig.cwd),
    env,
    stderr: "pipe",
  });
  const client = new Client({ name: "practice-registry-plugin-config-smoke", version: "0.1.0" });

  try {
    await client.connect(transport);
    const tools = await client.listTools();
    const toolNames = tools.tools.map((tool) => tool.name);
    for (const requiredTool of [
      "get_guardrails",
      "preflight",
      "check_plan",
      "scan_diff",
      "finalize_change",
      "server_info",
      "observation_summary",
      "propose_practice",
      "record_exception",
      "record_approval",
      "review_queue",
      "search_practices",
      "explain_practice",
    ]) {
      if (!toolNames.includes(requiredTool)) {
        throw new Error(`Missing MCP tool through plugin config: ${requiredTool}`);
      }
    }

    const info = await client.callTool({ name: "server_info", arguments: {} });
    const infoResult = info.structuredContent;
    if (
      !infoResult.features?.includes("typescript_practices") ||
      !infoResult.features?.includes("rust_practices") ||
      !infoResult.features?.includes("everyday_rust_practices") ||
      !infoResult.features?.includes("coverage_report") ||
      !infoResult.features?.includes("preflight") ||
      !infoResult.features?.includes("precise_preflight_matching") ||
      !infoResult.features?.includes("research_backed_approvals") ||
      !infoResult.supported_languages?.includes("javascript") ||
      !infoResult.supported_languages?.includes("rust")
    ) {
      throw new Error(`server_info did not expose TypeScript, JavaScript, and Rust feature support: ${JSON.stringify(infoResult)}`);
    }

    const scan = await client.callTool({
      name: "scan_diff",
      arguments: {
        diff: [
          "diff --git a/services/sync/git_worker.py b/services/sync/git_worker.py",
          "+++ b/services/sync/git_worker.py",
          "@@ -1,1 +1,2 @@",
          " import subprocess",
          "+subprocess.run(command, shell=True)",
        ].join("\n"),
        use_semgrep: false,
      },
    });
    const text = scan.content?.find((item) => item.type === "text")?.text;
    const scanResult = scan.structuredContent;
    if (scanResult.findings[0]?.practice_id !== "python.subprocess.no-shell-true") {
      throw new Error(`Unexpected MCP scan finding: ${text}`);
    }
    if (scanResult.passed !== false || scanResult.action_required !== true) {
      throw new Error(`MCP scan did not expose outcome fields: ${JSON.stringify(scanResult)}`);
    }

    console.log(
      JSON.stringify(
        {
          hook: {
            decision: hookResult.decision,
            finding: hookResult.findings[0]?.practice_id,
            advisory_decision: advisoryHookResult.decision,
            typescript_finding: typescriptHookResult.findings[0]?.practice_id,
            rust_finding: rustHookResult.findings[0]?.practice_id,
          },
          mcp: {
            tools: toolNames.sort(),
            contract: infoResult.contract_version,
            decision: scanResult.decision,
            finding: scanResult.findings[0]?.practice_id,
          },
        },
        null,
        2,
      ),
    );
  } finally {
    await client.close();
  }
} finally {
  fs.rmSync(tempRoot, { recursive: true, force: true });
}

function spawnHook(command, env, cwd, input) {
  return spawnSync("sh", ["-c", command], {
    cwd,
    env,
    input,
    encoding: "utf8",
    maxBuffer: 20 * 1024 * 1024,
  });
}
