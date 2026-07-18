#!/usr/bin/env node

import { spawn } from "node:child_process";
import { createWriteStream } from "node:fs";
import { mkdir, mkdtemp, rm } from "node:fs/promises";
import net from "node:net";
import os from "node:os";
import path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

import { grcBrowserRouteContracts } from "./grc-route-contract.mjs";
import { fetchText, smokeBaseUrl, waitForHttp } from "./smoke-http.mjs";

const scriptDir = path.dirname(fileURLToPath(import.meta.url));
const defaultWebRoot = path.resolve(scriptDir, "..");
const fixtureRootURN = "urn:cerebro:local-e2e:entity:root";
const renderedErrorPattern = /Application error|Unhandled Runtime Error|Cerebro request failed \([45][0-9][0-9]\)/i;

export function parseArgs(argv) {
  const options = { browser: false, port: 0, readyTimeoutMs: 90_000 };
  for (let index = 0; index < argv.length; index += 1) {
    const arg = argv[index];
    if (arg === "--browser") {
      options.browser = true;
    } else if (arg === "--port") {
      options.port = parseIntegerOption("--port", argv[index + 1], { minimum: 0, maximum: 65_535 });
      index += 1;
    } else if (arg.startsWith("--port=")) {
      options.port = parseIntegerOption("--port", arg.slice("--port=".length), { minimum: 0, maximum: 65_535 });
    } else if (arg === "--ready-timeout-ms") {
      options.readyTimeoutMs = parseIntegerOption("--ready-timeout-ms", argv[index + 1], { minimum: 1 });
      index += 1;
    } else if (arg.startsWith("--ready-timeout-ms=")) {
      options.readyTimeoutMs = parseIntegerOption("--ready-timeout-ms", arg.slice("--ready-timeout-ms=".length), { minimum: 1 });
    } else {
      throw new Error(`Unknown option: ${arg}`);
    }
  }
  return options;
}

function parseIntegerOption(name, value, { minimum, maximum = Number.MAX_SAFE_INTEGER }) {
  if (!/^\d+$/.test(value ?? "")) {
    throw new Error(`${name} requires an integer`);
  }
  const parsed = Number.parseInt(value, 10);
  if (!Number.isSafeInteger(parsed) || parsed < minimum || parsed > maximum) {
    throw new Error(`${name} must be between ${minimum} and ${maximum}`);
  }
  return parsed;
}

export async function findFreePort(requestedPort = 0) {
  return new Promise((resolve, reject) => {
    const server = net.createServer();
    server.once("error", reject);
    server.once("listening", () => {
      const address = server.address();
      const port = typeof address === "object" && address ? address.port : requestedPort;
      server.close((error) => error ? reject(error) : resolve(port));
    });
    server.listen(requestedPort, "127.0.0.1");
  });
}

export function assertPublicConfig(response) {
  if (response.status !== 200) {
    throw new Error(`Expected public config to return 200, got ${response.status}`);
  }
  const cacheControl = response.headers.get("cache-control") ?? "";
  if (!cacheControl.includes("private") || !cacheControl.includes("no-store")) {
    throw new Error("Expected public config to be private and uncached");
  }
  let payload;
  try {
    payload = JSON.parse(response.body);
  } catch {
    throw new Error("Expected public config to return JSON");
  }
  if (payload.apiBase !== "/api/cerebro") {
    throw new Error("Expected public config to use the same-origin API path");
  }
  if (JSON.stringify(payload).includes("://")) {
    throw new Error("Public config exposed an absolute service address");
  }
}

export function assertPageContract(contract, response) {
  if (response.status !== 200) {
    throw new Error(`Expected ${contract.route} to return 200, got ${response.status}`);
  }
  if (renderedErrorPattern.test(response.body)) {
    throw new Error(`${contract.route} rendered an application error`);
  }
  const marker = `data-grc-page="${contract.pageId}"`;
  if (!response.body.includes(marker)) {
    throw new Error(`${contract.route} is missing page contract ${contract.pageId}`);
  }
}

export async function validateHttpContracts(baseUrl, options = {}) {
  const timeoutMs = options.timeoutMs ?? 15_000;
  const fetchPage = options.fetchPage ?? fetchText;
  const contracts = options.contracts ?? grcBrowserRouteContracts({ adminURN: fixtureRootURN });
  const config = await fetchPage(new URL("/api/config", baseUrl).toString(), { timeoutMs });
  assertPublicConfig(config);
  for (const contract of contracts) {
    const response = await fetchPage(new URL(contract.route, baseUrl).toString(), { timeoutMs });
    assertPageContract(contract, response);
  }
  return contracts;
}

async function validateBrowserContracts(baseUrl, contracts, timeoutMs) {
  const { chromium } = await import("@playwright/test");
  const browser = await chromium.launch({ headless: true });
  try {
    const page = await browser.newPage({ viewport: { width: 1440, height: 1000 } });
    for (const contract of contracts) {
      await page.goto(new URL(contract.route, baseUrl).toString(), {
        timeout: timeoutMs,
        waitUntil: "domcontentloaded",
      });
      await page.locator(`[data-grc-page="${contract.pageId}"]`).waitFor({
        state: "visible",
        timeout: timeoutMs,
      });
      const body = await page.locator("body").innerText();
      if (renderedErrorPattern.test(body)) {
        throw new Error(`${contract.route} rendered an application error in the browser`);
      }
    }
  } finally {
    await browser.close();
  }
}

function fixtureAppExit(child) {
  return new Promise((_, reject) => {
    child.once("error", reject);
    child.once("exit", (code, signal) => {
      const status = signal ? `signal ${signal}` : `exit ${code ?? "unknown"}`;
      reject(new Error(`Fixture app stopped before validation completed (${status})`));
    });
  });
}

function interruptedRun() {
  const handlers = new Map();
  const promise = new Promise((_, reject) => {
    for (const [signal, exitCode] of [["SIGINT", 130], ["SIGTERM", 143]]) {
      const handler = () => {
        const error = new Error(`Local E2E interrupted by ${signal}`);
        error.exitCode = exitCode;
        reject(error);
      };
      handlers.set(signal, handler);
      process.once(signal, handler);
    }
  });
  return {
    promise,
    remove: () => {
      for (const [signal, handler] of handlers) process.removeListener(signal, handler);
    },
  };
}

export async function stopProcessTree(child, graceMs = 5_000) {
  if (!child || !child.pid || child.exitCode !== null || child.signalCode !== null) return;
  const exited = new Promise((resolve) => child.once("exit", resolve));
  const signal = (name) => {
    try {
      if (process.platform === "win32") child.kill(name);
      else process.kill(-child.pid, name);
    } catch (error) {
      if (error?.code !== "ESRCH") throw error;
    }
  };
  signal("SIGTERM");
  let killTimer;
  const stopped = await Promise.race([
    exited.then(() => true),
    new Promise((resolve) => {
      killTimer = setTimeout(() => resolve(false), graceMs);
    }),
  ]);
  clearTimeout(killTimer);
  if (!stopped) {
    signal("SIGKILL");
    await exited;
  }
}

export async function runLocalGrcE2E(options = {}) {
  const webRoot = options.webRoot ?? defaultWebRoot;
  const port = await findFreePort(options.port ?? 0);
  const readyTimeoutMs = options.readyTimeoutMs ?? 90_000;
  const workDir = await mkdtemp(path.join(os.tmpdir(), "cerebro-web-local-e2e-"));
  const logDir = path.join(workDir, "logs");
  const logPath = path.join(logDir, "web.log");
  await mkdir(logDir, { recursive: true });
  const logStream = createWriteStream(logPath, { flags: "a" });
  const npmCommand = process.platform === "win32" ? "npm.cmd" : "npm";
  const child = spawn(npmCommand, ["run", "dev:fixtures", "--", "--port", String(port)], {
    cwd: webRoot,
    detached: process.platform !== "win32",
    env: { ...process.env },
    stdio: ["ignore", "pipe", "pipe"],
  });
  child.stdout.pipe(logStream);
  child.stderr.pipe(logStream);
  const baseUrl = `http://127.0.0.1:${port}`;
  const interruption = interruptedRun();
  let passed = false;
  try {
    const validation = async () => {
      await waitForHttp(`${baseUrl}/api/health`, { timeoutMs: readyTimeoutMs });
      const smoke = await smokeBaseUrl(baseUrl);
      const contracts = await validateHttpContracts(baseUrl);
      if (options.browser) {
        await validateBrowserContracts(baseUrl, contracts, readyTimeoutMs);
      }
      return {
        browserChecked: Boolean(options.browser),
        routeCount: contracts.length,
        scriptChunkCount: smoke.chunkResponses.length,
      };
    };
    const result = await Promise.race([
      validation(),
      fixtureAppExit(child),
      interruption.promise,
    ]);
    passed = true;
    return result;
  } catch (error) {
    error.message = `${error.message}\nLocal E2E log: ${logPath}`;
    throw error;
  } finally {
    interruption.remove();
    await stopProcessTree(child);
    await new Promise((resolve) => logStream.end(resolve));
    if (passed) await rm(workDir, { recursive: true, force: true });
  }
}

async function runCli() {
  const result = await runLocalGrcE2E(parseArgs(process.argv.slice(2)));
  const browser = result.browserChecked ? " with browser checks" : "";
  console.log(`[e2e:grc:local] passed ${result.routeCount} route contracts${browser}`);
  console.log(`[e2e:grc:local] checked ${result.scriptChunkCount} application chunks`);
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  runCli().catch((error) => {
    console.error(`[e2e:grc:local] failed: ${error.stack || error.message}`);
    process.exitCode = error.exitCode ?? 1;
  });
}
