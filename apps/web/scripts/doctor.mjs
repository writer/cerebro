#!/usr/bin/env node

import { execFileSync, spawnSync } from "node:child_process";
import { access } from "node:fs/promises";
import net from "node:net";
import path from "node:path";
import { pathToFileURL } from "node:url";

export const parseNodeMajor = (version) => {
  const match = /^v?(\d+)\./.exec(version.trim());
  return match ? Number.parseInt(match[1], 10) : 0;
};

export const truthyEnv = (value) =>
  ["1", "true", "yes", "on"].includes((value ?? "").trim().toLowerCase());

const check = (status, label, detail = "") => ({ status, label, detail });

const commandVersion = (command, args) => {
  const result = spawnSync(command, args, { encoding: "utf8" });
  if (result.error) {
    return { ok: false, detail: result.error.message };
  }
  if (result.status !== 0) {
    return { ok: false, detail: (result.stderr || result.stdout).trim() };
  }
  return { ok: true, detail: (result.stdout || result.stderr).trim().split(/\r?\n/)[0] ?? "" };
};

const pathExists = async (candidate) => {
  try {
    await access(candidate);
    return true;
  } catch {
    return false;
  }
};

const portFree = (port) =>
  new Promise((resolve) => {
    const server = net.createServer();
    server.once("error", () => resolve(false));
    server.once("listening", () => server.close(() => resolve(true)));
    server.listen(port, "127.0.0.1");
  });

const git = (args) => {
  try {
    return execFileSync("git", args, { encoding: "utf8", stdio: ["ignore", "pipe", "ignore"] }).trim();
  } catch {
    return "";
  }
};

async function probeApiBase(apiBase) {
  if (!apiBase || apiBase === "fixture://local") {
    return check("ok", "Cerebro API", "using fixture mode");
  }
  try {
    const url = new URL("/health", apiBase).toString();
    const response = await fetch(url, { cache: "no-store", signal: AbortSignal.timeout(1_500) });
    if (response.ok) {
      return check("ok", "Cerebro API", `${url} returned ${response.status}`);
    }
    return check("warn", "Cerebro API", `${url} returned ${response.status}`);
  } catch (error) {
    return check("warn", "Cerebro API", `${apiBase} is not reachable: ${error.message}`);
  }
}

export async function collectDoctorChecks(options = {}) {
  const root = options.root ?? process.cwd();
  const checks = [];
  const nodeMajor = parseNodeMajor(process.version);
  checks.push(nodeMajor >= 22
    ? check("ok", "Node.js", process.version)
    : check("fail", "Node.js", `${process.version}; Node 22+ is required`));

  const npm = commandVersion("npm", ["--version"]);
  checks.push(npm.ok ? check("ok", "npm", npm.detail) : check("fail", "npm", npm.detail || "npm is required"));

  checks.push(await pathExists(path.join(root, "node_modules"))
    ? check("ok", "Dependencies", "node_modules is present")
    : check("warn", "Dependencies", "node_modules missing; run npm install or npm ci"));

  checks.push(await pathExists(path.join(root, ".next", "standalone", "apps", "web", "server.js"))
    ? check("ok", "Standalone build", ".next/standalone/apps/web/server.js is present")
    : check("warn", "Standalone build", "not built yet; run npm run build"));

  if (!options.ci) {
    for (const port of [3000, 13000]) {
      checks.push(await portFree(port)
        ? check("ok", `Port ${port}`, "available")
        : check("warn", `Port ${port}`, "already in use"));
    }
  }

  const fixtureMode = truthyEnv(process.env.CEREBRO_WEB_FIXTURE_MODE) || process.env.CEREBRO_API_BASE === "fixture://local";
  checks.push(fixtureMode
    ? check("ok", "Fixture mode", "enabled")
    : check("warn", "Fixture mode", "disabled; use npm run dev:fixtures for backend-free UI work"));

  if (!options.ci) {
    const apiBase = process.env.CEREBRO_API_BASE || process.env.NEXT_PUBLIC_CEREBRO_API_BASE || "http://localhost:8080";
    checks.push(await probeApiBase(fixtureMode ? "fixture://local" : apiBase));
  }

  const branch = git(["branch", "--show-current"]);
  checks.push(branch ? check("ok", "Git branch", branch) : check("warn", "Git branch", "not in a git checkout or detached HEAD"));
  const status = git(["status", "--short"]);
  checks.push(status ? check("warn", "Git worktree", "has local changes") : check("ok", "Git worktree", "clean"));
  return checks;
}

export const doctorExitCode = (checks) =>
  checks.some((item) => item.status === "fail") ? 1 : 0;

const formatCheck = (item) => {
  const marker = item.status === "ok" ? "[ok]" : item.status === "warn" ? "[warn]" : "[fail]";
  return `${marker} ${item.label}${item.detail ? `: ${item.detail}` : ""}`;
};

async function runCli() {
  const ci = process.argv.includes("--ci") || truthyEnv(process.env.CI);
  const checks = await collectDoctorChecks({ ci });
  checks.forEach((item) => console.log(formatCheck(item)));
  process.exitCode = doctorExitCode(checks);
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  runCli().catch((error) => {
    console.error(`[doctor] failed: ${error.stack || error.message}`);
    process.exitCode = 1;
  });
}
