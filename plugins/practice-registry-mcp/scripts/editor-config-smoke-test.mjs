#!/usr/bin/env node
import { spawnSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import process from "node:process";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StdioClientTransport } from "@modelcontextprotocol/sdk/client/stdio.js";

const root = process.cwd();
const tempRoot = fs.mkdtempSync(path.join(os.tmpdir(), "practice-registry-editor-"));

try {
  const generate = spawnSync(
    process.execPath,
    [
      path.join(root, "dist", "cli.js"),
      "generate-editor-config",
      "--client",
      "cursor",
      "--registry-root",
      root,
      "--output",
      path.join(tempRoot, ".cursor", "mcp.json"),
      "--rules-output",
      path.join(tempRoot, ".cursor", "rules", "practice-registry.mdc"),
    ],
    {
      cwd: tempRoot,
      encoding: "utf8",
      maxBuffer: 20 * 1024 * 1024,
    },
  );
  if (generate.status !== 0) {
    process.stderr.write(generate.stdout);
    process.stderr.write(generate.stderr);
    throw new Error(`generate-editor-config failed with exit ${generate.status}`);
  }

  const configPath = path.join(tempRoot, ".cursor", "mcp.json");
  const rulePath = path.join(tempRoot, ".cursor", "rules", "practice-registry.mdc");
  const launcherPath = path.join(tempRoot, ".practice-registry", "run-mcp");
  const config = JSON.parse(fs.readFileSync(configPath, "utf8"));
  const server = config.mcpServers?.["practice-registry"];
  if (!server) {
    throw new Error("Generated editor config is missing mcpServers.practice-registry");
  }
  if (server.type !== "stdio") {
    throw new Error(`Expected stdio server type, got ${server.type}`);
  }
  if (server.command !== ".practice-registry/run-mcp") {
    throw new Error(`Expected launcher command .practice-registry/run-mcp, got ${server.command}`);
  }
  if (server.args.length !== 0) {
    throw new Error(`Expected launcher args to be empty, got ${JSON.stringify(server.args)}`);
  }
  if (server.env) {
    throw new Error(`Expected generated config to omit inline env paths, got ${JSON.stringify(server.env)}`);
  }
  fs.accessSync(launcherPath, fs.constants.X_OK);
  const launcherText = fs.readFileSync(launcherPath, "utf8");
  if (!launcherText.includes("PRACTICE_REGISTRY_DB") || !launcherText.includes(`REGISTRY_ROOT='${root}'`)) {
    throw new Error("Generated launcher does not set repo database and registry entry point.");
  }
  const rule = fs.readFileSync(rulePath, "utf8");
  if (!rule.includes("preflight") || !rule.includes("check_plan") || !rule.includes("finalize_change")) {
    throw new Error("Generated editor rule does not mention required practice checks.");
  }
  if (!rule.includes("TypeScript") || !rule.includes("**/*.ts") || !rule.includes("JavaScript") || !rule.includes("**/*.jsx") || !rule.includes("Rust") || !rule.includes("**/*.rs") || !rule.includes("**/Cargo.toml")) {
    throw new Error("Generated editor rule does not include TypeScript, JavaScript, and Rust coverage.");
  }
  if (
    !rule.includes("Trust the passed field") ||
    !rule.includes("Do not treat blocking: false as a pass") ||
    !rule.includes("revise_or_justify") ||
    !rule.includes("rerun the check")
  ) {
    throw new Error("Generated editor rule does not explain non-blocking practice decisions.");
  }

  const env = Object.fromEntries(Object.entries(process.env).filter(([, value]) => typeof value === "string"));
  const transport = new StdioClientTransport({
    command: server.command,
    args: server.args,
    cwd: tempRoot,
    env: { ...env, ...server.env },
    stderr: "pipe",
  });
  const client = new Client({ name: "practice-registry-editor-config-smoke", version: "0.1.0" });

  try {
    await client.connect(transport);
    const tools = await client.listTools();
    if (!tools.tools.some((tool) => tool.name === "get_guardrails")) {
      throw new Error(`Generated editor config server is missing get_guardrails: ${JSON.stringify(tools)}`);
    }
    if (!tools.tools.some((tool) => tool.name === "server_info")) {
      throw new Error(`Generated editor config server is missing server_info: ${JSON.stringify(tools)}`);
    }
    const info = await client.callTool({ name: "server_info", arguments: {} });
    if (
      !info.structuredContent?.features?.includes("typescript_practices") ||
      !info.structuredContent?.features?.includes("rust_practices") ||
      !info.structuredContent?.features?.includes("coverage_report") ||
      !info.structuredContent?.features?.includes("preflight") ||
      !info.structuredContent?.supported_languages?.includes("javascript") ||
      !info.structuredContent?.supported_languages?.includes("rust")
    ) {
      throw new Error(`server_info did not report TypeScript, JavaScript, and Rust practice support: ${JSON.stringify(info.structuredContent)}`);
    }
    const plan = await client.callTool({
      name: "check_plan",
      arguments: {
        language: "python",
        files: ["bad.py"],
        intent: "run a command",
        planned_approach: "Use subprocess.run(command, shell=True)",
      },
    });
    const text = plan.content?.find((item) => item.type === "text")?.text;
    const result = plan.structuredContent;
    if (result.decision !== "change_code") {
      throw new Error(`Expected change_code decision, got ${result.decision}`);
    }
    if (result.passed !== false || result.action_required !== true) {
      throw new Error(`Expected explicit outcome fields, got ${JSON.stringify(result)}`);
    }
    if (result.matched_practices[0]?.id !== "python.subprocess.no-shell-true") {
      throw new Error(`Unexpected matching practice: ${text}`);
    }

    console.log(
      JSON.stringify(
        {
          config: path.relative(tempRoot, configPath),
          launcher: path.relative(tempRoot, launcherPath),
          rule: path.relative(tempRoot, rulePath),
          tools: tools.tools.map((tool) => tool.name).sort(),
          contract: info.structuredContent.contract_version,
          decision: result.decision,
          match: result.matched_practices[0]?.id,
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
