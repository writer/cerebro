#!/usr/bin/env node

import { execFile, spawn } from "node:child_process";
import { randomUUID } from "node:crypto";
import { createWriteStream } from "node:fs";
import { mkdir, mkdtemp, rm } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

import { createFixtureEnvironment, fixtureReadyPrefix } from "./dev-fixtures.mjs";
import { grcBrowserRouteContracts } from "./grc-route-contract.mjs";
import { fetchText, smokeBaseUrl, waitForHttp } from "./smoke-http.mjs";

const scriptDir = path.dirname(fileURLToPath(import.meta.url));
const defaultWebRoot = path.resolve(scriptDir, "..");
const fixtureDevScript = path.join(scriptDir, "dev-fixtures.mjs");
const fixtureRootURN = "urn:cerebro:local-e2e:entity:root";
const renderedErrorPattern = /Application error|Unhandled Runtime Error|Cerebro request failed \([45][0-9][0-9]\)/i;
const defaultTimeoutMs = 180_000;
const perRequestTimeoutMs = 15_000;

export function parseArgs(argv) {
  const options = { browser: true, port: 0, timeoutMs: defaultTimeoutMs };
  for (let index = 0; index < argv.length; index += 1) {
    const arg = argv[index];
    if (arg === "--browser") {
      options.browser = true;
    } else if (arg === "--no-browser") {
      options.browser = false;
    } else if (arg === "--port") {
      options.port = parseIntegerOption("--port", argv[index + 1], { minimum: 0, maximum: 65_535 });
      index += 1;
    } else if (arg.startsWith("--port=")) {
      options.port = parseIntegerOption("--port", arg.slice("--port=".length), { minimum: 0, maximum: 65_535 });
    } else if (arg === "--timeout-ms" || arg === "--ready-timeout-ms") {
      options.timeoutMs = parseIntegerOption(arg, argv[index + 1], { minimum: 1 });
      index += 1;
    } else if (arg.startsWith("--timeout-ms=")) {
      options.timeoutMs = parseIntegerOption("--timeout-ms", arg.slice("--timeout-ms=".length), { minimum: 1 });
    } else if (arg.startsWith("--ready-timeout-ms=")) {
      options.timeoutMs = parseIntegerOption("--ready-timeout-ms", arg.slice("--ready-timeout-ms=".length), { minimum: 1 });
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

function timeoutError(label) {
  const error = new Error(`Timed out during ${label}`);
  error.code = "ETIMEDOUT";
  return error;
}

export function createDeadlineAt(expiresAt) {
  const remaining = () => Math.max(0, expiresAt - Date.now());
  const run = async (promise, label) => {
    const timeoutMs = remaining();
    if (timeoutMs === 0) throw timeoutError(label);
    let timer;
    try {
      return await Promise.race([
        Promise.resolve(promise),
        new Promise((_, reject) => {
          timer = setTimeout(() => reject(timeoutError(label)), timeoutMs);
          timer.unref?.();
        }),
      ]);
    } finally {
      clearTimeout(timer);
    }
  };
  return { expiresAt, remaining, run };
}

export function createDeadline(timeoutMs) {
  return createDeadlineAt(Date.now() + timeoutMs);
}

export function parseFixtureReadyLine(line, expectedNonce) {
  const markerIndex = line.indexOf(fixtureReadyPrefix);
  if (markerIndex === -1) return null;
  let record;
  try {
    record = JSON.parse(line.slice(markerIndex + fixtureReadyPrefix.length));
  } catch {
    throw new Error("Fixture readiness record was not valid JSON");
  }
  if (record?.nonce !== expectedNonce) {
    throw new Error("Fixture readiness record did not match this run");
  }
  if (!Number.isSafeInteger(record.port) || record.port < 1 || record.port > 65_535) {
    throw new Error("Fixture readiness record contained an invalid port");
  }
  return record.port;
}

export async function waitForFixtureEndpoint(stream, expectedNonce, deadline) {
  let buffer = "";
  let settled = false;
  let resolveRecord;
  let rejectRecord;
  const record = new Promise((resolve, reject) => {
    resolveRecord = resolve;
    rejectRecord = reject;
  });
  const cleanup = () => {
    stream.off("data", onData);
    stream.off("error", onError);
    stream.off("end", onEnd);
  };
  const finish = (callback, value) => {
    if (settled) return;
    settled = true;
    cleanup();
    callback(value);
  };
  const inspectLine = (line) => {
    try {
      const port = parseFixtureReadyLine(line, expectedNonce);
      if (port !== null) finish(resolveRecord, port);
    } catch (error) {
      finish(rejectRecord, error);
    }
  };
  const onData = (chunk) => {
    buffer += chunk.toString();
    const lines = buffer.split(/\r?\n/);
    buffer = lines.pop() ?? "";
    for (const line of lines) inspectLine(line);
  };
  const onError = (error) => finish(rejectRecord, error);
  const onEnd = () => {
    if (buffer) inspectLine(buffer);
    if (!settled) finish(rejectRecord, new Error("Fixture process ended before publishing its endpoint"));
  };
  stream.on("data", onData);
  stream.once("error", onError);
  stream.once("end", onEnd);
  try {
    return await deadline.run(record, "fixture endpoint discovery");
  } finally {
    cleanup();
  }
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
  const timeoutMs = options.timeoutMs ?? perRequestTimeoutMs;
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

export async function validateBrowserContracts(baseUrl, contracts, deadline) {
  const { chromium } = await deadline.run(import("@playwright/test"), "Playwright import");
  const browser = await deadline.run(chromium.launch({ headless: true }), "Chromium launch");
  try {
    const page = await deadline.run(browser.newPage({ viewport: { width: 1440, height: 1000 } }), "browser page creation");
    const pageErrors = [];
    page.on("pageerror", (error) => pageErrors.push(error));
    for (const contract of contracts) {
      pageErrors.length = 0;
      const operationTimeout = Math.max(1, Math.min(perRequestTimeoutMs, deadline.remaining()));
      const response = await page.goto(new URL(contract.route, baseUrl).toString(), {
        timeout: operationTimeout,
        waitUntil: "domcontentloaded",
      });
      if (!response || response.status() !== 200) {
        throw new Error(`${contract.route} did not return 200 in Chromium`);
      }
      const pageContract = page.locator(`[data-grc-page="${contract.pageId}"]:visible`);
      await pageContract.waitFor({
        state: "visible",
        timeout: Math.max(1, Math.min(perRequestTimeoutMs, deadline.remaining())),
      });
      await pageContract.getByRole("heading", { name: contract.heading, exact: true }).waitFor({
        state: "visible",
        timeout: Math.max(1, Math.min(perRequestTimeoutMs, deadline.remaining())),
      });
      const body = await deadline.run(page.locator("body").innerText(), `${contract.route} body read`);
      if (renderedErrorPattern.test(body)) {
        throw new Error(`${contract.route} rendered an application error in Chromium`);
      }
      if (pageErrors.length > 0) {
        throw new Error(`${contract.route} raised a client error: ${pageErrors[0].message}`);
      }
    }
  } finally {
    await deadline.run(browser.close(), "Chromium shutdown");
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

export function windowsTaskkillArgs(pid, force) {
  const args = ["/PID", String(pid), "/T"];
  if (force) args.push("/F");
  return args;
}

function taskkill(pid, force, timeoutMs) {
  return new Promise((resolve, reject) => {
    execFile("taskkill", windowsTaskkillArgs(pid, force), { timeout: Math.max(1, timeoutMs), windowsHide: true }, (error) => {
      if (error) reject(error);
      else resolve();
    });
  });
}

async function waitForExitUntil(exited, expiresAt) {
  try {
    await createDeadlineAt(expiresAt).run(exited, "fixture process exit");
    return true;
  } catch (error) {
    if (error.code === "ETIMEDOUT") return false;
    throw error;
  }
}

export async function stopProcessTree(child, options = {}) {
  if (typeof options === "number") options = { graceMs: options };
  if (!child || !child.pid || child.exitCode !== null || child.signalCode !== null) return;
  const graceMs = options.graceMs ?? 5_000;
  const deadlineAt = options.deadlineAt ?? Date.now() + graceMs + 5_000;
  const platform = options.platform ?? process.platform;
  const taskkillProcess = options.taskkillProcess ?? taskkill;
  const signalProcessGroup = options.signalProcessGroup ?? ((pid, signal) => process.kill(-pid, signal));
  const exited = new Promise((resolve) => child.once("exit", resolve));
  const signal = async (force) => {
    if (platform === "win32") {
      try {
        await createDeadlineAt(deadlineAt).run(
          taskkillProcess(child.pid, force, Math.max(1, deadlineAt - Date.now())),
          force ? "forced Windows process-tree termination" : "Windows process-tree termination",
        );
      } catch (error) {
        if (error.code === "ETIMEDOUT") throw error;
      }
      return;
    }
    try {
      signalProcessGroup(child.pid, force ? "SIGKILL" : "SIGTERM");
    } catch (error) {
      if (error?.code !== "ESRCH") throw error;
    }
  };
  await signal(false);
  const graceDeadline = Math.min(deadlineAt, Date.now() + graceMs);
  if (await waitForExitUntil(exited, graceDeadline)) return;
  await signal(true);
  if (!await waitForExitUntil(exited, deadlineAt)) {
    throw timeoutError("forced fixture process-tree termination");
  }
}

export async function closeLogStream(stream, deadlineAt) {
  if (!stream || stream.closed || stream.destroyed) return;
  const closed = new Promise((resolve, reject) => {
    stream.once("close", resolve);
    stream.once("error", reject);
  });
  stream.end();
  try {
    await createDeadlineAt(deadlineAt).run(closed, "E2E log closure");
  } catch (error) {
    stream.destroy();
    throw error;
  }
}

export async function runLocalGrcE2E(options = {}) {
  const timeoutMs = options.timeoutMs ?? options.readyTimeoutMs ?? defaultTimeoutMs;
  const overallDeadline = createDeadline(timeoutMs);
  const cleanupReserveMs = Math.min(10_000, Math.max(25, Math.floor(timeoutMs / 10)), Math.floor(timeoutMs / 2));
  const validationDeadline = createDeadlineAt(overallDeadline.expiresAt - cleanupReserveMs);
  const webRoot = options.webRoot ?? defaultWebRoot;
  const runNonce = randomUUID();
  const workDir = await overallDeadline.run(mkdtemp(path.join(os.tmpdir(), "cerebro-web-local-e2e-")), "temporary directory creation");
  const logDir = path.join(workDir, "logs");
  const logPath = path.join(logDir, "web.log");
  await overallDeadline.run(mkdir(logDir, { recursive: true }), "log directory creation");
  const logStream = createWriteStream(logPath, { flags: "a" });
  const child = spawn(process.execPath, [fixtureDevScript, "--port", String(options.port ?? 0)], {
    cwd: webRoot,
    detached: process.platform !== "win32",
    env: createFixtureEnvironment(process.env, runNonce),
    stdio: ["ignore", "pipe", "pipe"],
  });
  child.stdout.pipe(logStream, { end: false });
  child.stderr.pipe(logStream, { end: false });
  const interruption = interruptedRun();
  let result;
  let primaryError;
  let passed = false;
  try {
    const validation = async () => {
      const port = await waitForFixtureEndpoint(child.stdout, runNonce, validationDeadline);
      const baseUrl = `http://127.0.0.1:${port}`;
      await validationDeadline.run(waitForHttp(`${baseUrl}/api/health`, {
        requestTimeoutMs: Math.max(1, Math.min(5_000, validationDeadline.remaining())),
        timeoutMs: validationDeadline.remaining(),
      }), "fixture readiness");
      const smoke = await validationDeadline.run(smokeBaseUrl(baseUrl, {
        timeoutMs: Math.max(1, Math.min(perRequestTimeoutMs, validationDeadline.remaining())),
      }), "HTTP smoke validation");
      const contracts = await validationDeadline.run(validateHttpContracts(baseUrl, {
        timeoutMs: Math.max(1, Math.min(perRequestTimeoutMs, validationDeadline.remaining())),
      }), "route contract validation");
      if (options.browser ?? true) {
        await validateBrowserContracts(baseUrl, contracts, validationDeadline);
      }
      return {
        browserChecked: options.browser ?? true,
        routeCount: contracts.length,
        scriptChunkCount: smoke.chunkResponses.length,
      };
    };
    result = await Promise.race([
      validationDeadline.run(validation(), "local E2E validation"),
      fixtureAppExit(child),
      interruption.promise,
    ]);
    passed = true;
  } catch (error) {
    error.message = `${error.message}\nLocal E2E log: ${logPath}`;
    primaryError = error;
  } finally {
    interruption.remove();
    const cleanupErrors = [];
    try {
      await stopProcessTree(child, { deadlineAt: overallDeadline.expiresAt });
    } catch (error) {
      cleanupErrors.push(error);
    }
    try {
      await closeLogStream(logStream, overallDeadline.expiresAt);
    } catch (error) {
      cleanupErrors.push(error);
    }
    if (passed && cleanupErrors.length === 0) {
      try {
        await overallDeadline.run(rm(workDir, { recursive: true, force: true }), "temporary directory cleanup");
      } catch (error) {
        cleanupErrors.push(error);
      }
    }
    if (cleanupErrors.length > 0) {
      primaryError = new AggregateError(
        primaryError ? [primaryError, ...cleanupErrors] : cleanupErrors,
        primaryError?.message ?? "Local E2E cleanup failed",
      );
    }
  }
  if (primaryError) throw primaryError;
  return result;
}

async function runCli() {
  const result = await runLocalGrcE2E(parseArgs(process.argv.slice(2)));
  const browser = result.browserChecked ? " with Chromium checks" : " without Chromium checks";
  console.log(`[e2e:grc:local] passed ${result.routeCount} route contracts${browser}`);
  console.log(`[e2e:grc:local] checked ${result.scriptChunkCount} application chunks`);
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  runCli().catch((error) => {
    console.error(`[e2e:grc:local] failed: ${error.stack || error.message}`);
    process.exitCode = error.exitCode ?? 1;
  });
}
