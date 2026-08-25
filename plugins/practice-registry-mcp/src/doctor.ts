import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import process from "node:process";
import { spawnSync } from "node:child_process";
import { semgrepBinFromEnv } from "./config.js";
import { loadPractices } from "./loader.js";
import { PracticeRegistry } from "./registry.js";
import type { EditorClient } from "./editorConfig.js";
import { defaultEditorConfigPath, defaultEditorRulePath } from "./editorConfig.js";

export type DoctorStatus = "ok" | "warn" | "fail";

export type DoctorCheck = {
  status: DoctorStatus;
  label: string;
  detail: string;
};

export type DoctorResult = {
  status: DoctorStatus;
  checks: DoctorCheck[];
};

export type DoctorOptions = {
  registryRoot: string;
  repoRoot: string;
  client?: EditorClient;
  serverName?: string;
};

export function runDoctor(options: DoctorOptions): DoctorResult {
  const registryRoot = path.resolve(options.registryRoot);
  const repoRoot = path.resolve(options.repoRoot);
  const practicesRoot = path.join(registryRoot, "practices");
  const checks: DoctorCheck[] = [];

  checks.push(checkNodeVersion());
  checks.push(checkFile("Built MCP server", path.join(registryRoot, "dist", "index.js")));

  try {
    const records = loadPractices(practicesRoot);
    checks.push({ status: "ok", label: "Practice records", detail: `${records.length} records loaded from ${practicesRoot}` });
  } catch (error) {
    checks.push({ status: "fail", label: "Practice records", detail: errorMessage(error) });
  }

  checks.push(checkFile("Semgrep rules", path.join(registryRoot, "semgrep", "practice-rules.yml")));
  checks.push(checkCommand("Semgrep CLI", semgrepBinFromEnv(), "Fallback changed-line scanning remains available."));
  checks.push(checkRegistryDecision(practicesRoot));
  checks.push(checkCodexPluginInstall(registryRoot));

  if (options.client === "cursor") {
    checks.push(...checkCursorWorkspace(repoRoot, options.serverName ?? "practice-registry"));
  }

  return {
    status: overallStatus(checks),
    checks,
  };
}

function checkCodexPluginInstall(registryRoot: string): DoctorCheck {
  const result = spawnSync("codex", ["plugin", "list"], { encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] });
  if (result.error && "code" in result.error && result.error.code === "ENOENT") {
    return { status: "warn", label: "Codex plugin", detail: "codex was not found. Skip this check outside Codex environments." };
  }
  if (result.status !== 0) {
    return { status: "warn", label: "Codex plugin", detail: "codex plugin list did not complete." };
  }

  const line = result.stdout
    .split("\n")
    .find((entry) => entry.includes("practice-registry-mcp@") && entry.includes("installed, enabled"));
  if (!line) {
    return { status: "warn", label: "Codex plugin", detail: "practice-registry-mcp is not installed and enabled." };
  }

  const columns = line.trim().split(/\s+/);
  const listedVersion = columns.length >= 4 ? columns.at(-2) : undefined;
  const installedPath = columns.at(-1);
  if (!installedPath) {
    return { status: "warn", label: "Codex plugin", detail: "Installed plugin path was not listed." };
  }

  const installedReal = realPathOrSelf(installedPath);
  const registryReal = realPathOrSelf(registryRoot);
  const version = readPluginVersion(installedReal);
  if (installedReal !== registryReal) {
    return {
      status: "warn",
      label: "Codex plugin",
      detail: `Codex uses ${installedPath}${version ? ` (${version})` : ""}; this checkout is ${registryRoot}. Reinstall or point the plugin at this checkout before testing active tools.`,
    };
  }
  if (version && listedVersion && version !== listedVersion) {
    return {
      status: "warn",
      label: "Codex plugin",
      detail: `installed path points at this checkout, but marketplace lists ${listedVersion} while plugin.json is ${version}. Refresh the marketplace entry before relying on displayed plugin metadata.`,
    };
  }
  return {
    status: "ok",
    label: "Codex plugin",
    detail: `installed, enabled, and pointing at this checkout${version ? ` (${version})` : ""}.`,
  };
}

export function formatDoctor(result: DoctorResult): string {
  const lines = ["Practice Registry doctor"];
  for (const check of result.checks) {
    lines.push(`${statusLabel(check.status)} ${check.label}: ${check.detail}`);
  }
  lines.push(`Status: ${result.status}`);
  return `${lines.join("\n")}\n`;
}

function checkNodeVersion(): DoctorCheck {
  const major = Number(process.versions.node.split(".")[0]);
  return major >= 22
    ? { status: "ok", label: "Node.js", detail: process.version }
    : { status: "fail", label: "Node.js", detail: `${process.version}; Node 22 or newer is required.` };
}

function checkFile(label: string, filePath: string): DoctorCheck {
  return fs.existsSync(filePath)
    ? { status: "ok", label, detail: filePath }
    : { status: "fail", label, detail: `${filePath} is missing.` };
}

function checkCommand(label: string, command: string, fallback: string): DoctorCheck {
  const result = spawnSync(command, ["--version"], { encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] });
  if (result.error && "code" in result.error && result.error.code === "ENOENT") {
    return { status: "warn", label, detail: `${command} was not found. ${fallback}` };
  }
  if (result.status === 0) {
    return { status: "ok", label, detail: firstLine(result.stdout) || command };
  }
  return { status: "warn", label, detail: `${command} did not return a version. ${fallback}` };
}

function checkRegistryDecision(practicesRoot: string): DoctorCheck {
  const tempRoot = fs.mkdtempSync(path.join(os.tmpdir(), "practice-registry-doctor-"));
  const dbPath = path.join(tempRoot, "doctor.db");
  const registry = new PracticeRegistry({ practicesRoot, dbPath });
  try {
    registry.rebuild();
    const result = registry.check("plan", {
      language: "python",
      files: ["bad.py"],
      intent: "run a command",
      planned_approach: "Use subprocess.run(command, shell=True)",
    });
    if (result.decision === "change_code" && result.matched_practices[0]?.id === "python.subprocess.no-shell-true") {
      return { status: "ok", label: "Sample check", detail: "shell=True returns change_code." };
    }
    return { status: "fail", label: "Sample check", detail: `Expected shell=True to return change_code, got ${result.decision}.` };
  } catch (error) {
    return { status: "fail", label: "Sample check", detail: errorMessage(error) };
  } finally {
    registry.close();
    fs.rmSync(tempRoot, { recursive: true, force: true });
  }
}

function checkCursorWorkspace(repoRoot: string, serverName: string): DoctorCheck[] {
  const checks: DoctorCheck[] = [];
  const configPath = path.join(repoRoot, defaultEditorConfigPath("cursor"));
  const rulePath = path.join(repoRoot, defaultEditorRulePath("cursor"));

  try {
    const config = JSON.parse(fs.readFileSync(configPath, "utf8")) as {
      mcpServers?: Record<string, { type?: string; command?: string; args?: string[]; env?: Record<string, string> }>;
    };
    const server = config.mcpServers?.[serverName];
    if (!server) {
      checks.push({ status: "fail", label: "Cursor MCP config", detail: `${configPath} does not define ${serverName}.` });
    } else if (server.type !== "stdio") {
      checks.push({ status: "fail", label: "Cursor MCP config", detail: `${serverName} is not a stdio server.` });
    } else if (server.env && Object.keys(server.env).some((key) => key.startsWith("PRACTICE_"))) {
      checks.push({ status: "warn", label: "Cursor MCP config", detail: `${serverName} uses inline paths. Run setup to install the repo launcher.` });
    } else {
      checks.push({ status: "ok", label: "Cursor MCP config", detail: `${configPath} defines ${serverName}.` });
      checks.push(checkCursorLauncher(repoRoot, server.command));
    }
  } catch (error) {
    checks.push({ status: "fail", label: "Cursor MCP config", detail: `${configPath}: ${errorMessage(error)}` });
  }

  if (!fs.existsSync(rulePath)) {
    checks.push({ status: "warn", label: "Cursor rule", detail: `${rulePath} is missing.` });
  } else {
    const text = fs.readFileSync(rulePath, "utf8");
    const hasTools = text.includes("check_plan") && text.includes("finalize_change");
    checks.push(
      hasTools
        ? { status: "ok", label: "Cursor rule", detail: `${rulePath} names check_plan and finalize_change.` }
        : { status: "warn", label: "Cursor rule", detail: `${rulePath} does not name check_plan and finalize_change.` },
    );
  }

  return checks;
}

function checkCursorLauncher(repoRoot: string, command: string | undefined): DoctorCheck {
  if (!command) {
    return { status: "fail", label: "Cursor MCP launcher", detail: "The MCP server command is missing." };
  }

  const launcherPath = path.resolve(repoRoot, command);
  if (!fs.existsSync(launcherPath)) {
    return { status: "fail", label: "Cursor MCP launcher", detail: `${launcherPath} is missing.` };
  }

  try {
    fs.accessSync(launcherPath, fs.constants.X_OK);
    return { status: "ok", label: "Cursor MCP launcher", detail: `${launcherPath} is executable.` };
  } catch {
    return { status: "warn", label: "Cursor MCP launcher", detail: `${launcherPath} exists but is not executable.` };
  }
}

function overallStatus(checks: DoctorCheck[]): DoctorStatus {
  if (checks.some((check) => check.status === "fail")) {
    return "fail";
  }
  if (checks.some((check) => check.status === "warn")) {
    return "warn";
  }
  return "ok";
}

function statusLabel(status: DoctorStatus): string {
  if (status === "ok") return "OK";
  if (status === "warn") return "WARN";
  return "FAIL";
}

function firstLine(value: string): string {
  return value.trim().split("\n")[0] ?? "";
}

function realPathOrSelf(filePath: string): string {
  try {
    return fs.realpathSync(filePath);
  } catch {
    return path.resolve(filePath);
  }
}

function readPluginVersion(pluginRoot: string): string | undefined {
  try {
    const parsed = JSON.parse(fs.readFileSync(path.join(pluginRoot, ".codex-plugin", "plugin.json"), "utf8")) as {
      version?: unknown;
    };
    return typeof parsed.version === "string" ? parsed.version : undefined;
  } catch {
    return undefined;
  }
}

function errorMessage(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}
