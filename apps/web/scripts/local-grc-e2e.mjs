#!/usr/bin/env node

import { execFile, spawn } from "node:child_process";
import { randomBytes, randomUUID } from "node:crypto";
import { createWriteStream } from "node:fs";
import { access, mkdir, mkdtemp, rm } from "node:fs/promises";
import net from "node:net";
import os from "node:os";
import path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

import { grcBrowserRouteContracts } from "./grc-route-contract.mjs";

const scriptDir = path.dirname(fileURLToPath(import.meta.url));
const webRoot = path.resolve(scriptDir, "..");
const backendRoot = path.resolve(webRoot, "..", "..");
const defaultTimeoutMs = 15 * 60_000;
const cleanupReserveMs = 30_000;
const proxyCacheTtlMs = 1_000;
const proxyCacheStaleMs = 60_000;
const perfFirstMs = 5_000;
const perfCachedMs = 1_000;
const tenantID = "e2e-local";
const postgresImage = "postgres:16-alpine";
const neo4jImage = "neo4j:5";
const runID = randomUUID();
const postgresContainer = `cerebro-grc-e2e-postgres-${process.pid}-${runID}`;
const neo4jContainer = `cerebro-grc-e2e-neo4j-${process.pid}-${runID}`;
let pgPort;
let neo4jPort;
let apiPort;
let webPort;
let postgresDSN;
let neo4jURI;
const neo4jUser = "neo4j";
const neo4jCredential = randomBytes(24).toString("base64url");
let apiBase;
let webBase;
const proxyCacheProbeOptions = { cache: "default" };
const adminURN = `urn:cerebro:${tenantID}:identity:privileged`;
let workDir;
let logDir;
let failed = false;
let backendProcess = null;
let webProcess = null;
let neo4jStopped = false;
let postgresStarted = false;
let neo4jStarted = false;
let overallDeadlineAt = 0;
let validationDeadlineAt = 0;

export function parseArgs(argv) {
  const options = { artifactRoot: undefined, browser: true, timeoutMs: defaultTimeoutMs };
  for (let index = 0; index < argv.length; index += 1) {
    const arg = argv[index];
    if (arg === "--browser") {
      options.browser = true;
    } else if (arg === "--no-browser") {
      options.browser = false;
    } else if (arg === "--timeout-ms") {
      options.timeoutMs = parsePositiveInteger(arg, argv[++index]);
    } else if (arg.startsWith("--timeout-ms=")) {
      options.timeoutMs = parsePositiveInteger("--timeout-ms", arg.slice("--timeout-ms=".length));
    } else if (arg === "--artifact-dir") {
      options.artifactRoot = requireOptionValue(arg, argv[++index]);
    } else if (arg.startsWith("--artifact-dir=")) {
      options.artifactRoot = requireOptionValue("--artifact-dir", arg.slice("--artifact-dir=".length));
    } else {
      throw new Error(`Unknown option: ${arg}`);
    }
  }
  return options;
}

function requireOptionValue(name, value) {
  if (!value || value.startsWith("--")) throw new Error(`${name} requires a value`);
  return value;
}

function parsePositiveInteger(name, value) {
  if (!/^\d+$/.test(value ?? "")) throw new Error(`${name} requires an integer`);
  const parsed = Number.parseInt(value, 10);
  if (!Number.isSafeInteger(parsed) || parsed < 1) throw new Error(`${name} must be a positive integer`);
  return parsed;
}

export function portableChildEnvironment(source = process.env, additions = {}) {
  const allowed = [
    "PATH", "HOME", "USERPROFILE", "TMPDIR", "TEMP", "TMP", "SYSTEMROOT", "WINDIR",
    "PATHEXT", "COMSPEC", "LOCALAPPDATA", "APPDATA", "CI", "NO_COLOR", "TERM",
    "DOCKER_HOST", "DOCKER_CONTEXT",
  ];
  const environment = Object.fromEntries(allowed.flatMap((key) => source[key] === undefined ? [] : [[key, source[key]]]));
  return { ...environment, ...additions };
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

export function parseDockerLoopbackPort(output) {
  const lines = output.trim().split(/\r?\n/).filter(Boolean);
  if (lines.length !== 1) throw new Error("Expected one Docker port mapping");
  const match = /^127\.0\.0\.1:(\d+)$/.exec(lines[0]);
  if (!match) throw new Error("Docker published a non-loopback or invalid endpoint");
  const port = Number.parseInt(match[1], 10);
  if (!Number.isSafeInteger(port) || port < 1 || port > 65_535) throw new Error("Docker published an invalid port");
  return port;
}

const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));
const step = (message) => console.log(`\n[grc-e2e] ${message}`);
const expect = (condition, message) => {
  if (!condition) {
    throw new Error(message);
  }
};

async function main(options) {
  await access(backendRoot);
  apiPort = await allocateLoopbackPort();
  webPort = await allocateLoopbackPort();
  apiBase = `http://127.0.0.1:${apiPort}`;
  webBase = `http://127.0.0.1:${webPort}`;
  await requireCommand("docker", ["--version"]);
  await requireCommand("go", ["version"]);
  await requireCommand("npm", ["--version"]);

  step("starting disposable stores");
  await startPostgres();
  await startNeo4j();

  step("seeding GRC fixture data");
  await seedStores();

  step("starting local Cerebro API");
  const apiBinary = path.join(workDir, process.platform === "win32" ? "cerebro.exe" : "cerebro");
  await run("go", ["-C", backendRoot, "build", "-o", apiBinary, "./cmd/cerebro"], {
    env: portableChildEnvironment(),
    quiet: true,
  });
  backendProcess = spawnLogged("cerebro-api", apiBinary, ["serve"], {
    env: portableChildEnvironment(process.env, {
      CEREBRO_HTTP_ADDR: `127.0.0.1:${apiPort}`,
      CEREBRO_STATE_STORE_DRIVER: "postgres",
      CEREBRO_POSTGRES_DSN: postgresDSN,
      CEREBRO_GRAPH_STORE_DRIVER: "neo4j",
      CEREBRO_NEO4J_URI: neo4jURI,
      CEREBRO_NEO4J_USERNAME: neo4jUser,
      CEREBRO_NEO4J_PASSWORD: neo4jCredential,
      CEREBRO_API_AUTH_ENABLED: "false",
      CEREBRO_DEV_MODE: "1",
      CEREBRO_DEV_MODE_ACK: "1",
    }),
  });
  await waitFor("Cerebro API readiness", async () => {
    const health = await requestJSON(`${apiBase}/health`);
    expect(health.status === 200, `health status ${health.status}`);
    expect(componentReady(health.json, "state_store"), "state_store not ready");
    expect(componentReady(health.json, "graph_store"), "graph_store not ready");
  }, Math.min(360_000, remainingValidationMs()), backendProcess);

  step("validating backend GRC endpoints");
  assertChildHealthy(backendProcess, "Cerebro API");
  await validateBackend();
  assertChildHealthy(backendProcess, "Cerebro API");

  step("starting cerebro-web");
  webProcess = spawnLogged("cerebro-web", "npm", ["run", "dev", "--", "--hostname", "127.0.0.1", "--port", String(webPort)], {
    cwd: webRoot,
    env: portableChildEnvironment(process.env, {
      CEREBRO_API_BASE: apiBase,
      NEXT_PUBLIC_CEREBRO_API_BASE: "/api/cerebro",
      CEREBRO_PROXY_TIMEOUT_MS: "5000",
      CEREBRO_PROXY_CACHE_TTL_MS: String(proxyCacheTtlMs),
      CEREBRO_PROXY_CACHE_STALE_MS: String(proxyCacheStaleMs),
      CEREBRO_IDENTITY_PROFILE: "local",
      CEREBRO_LOCAL_IDENTITY_FALLBACK: "1",
    }),
  });
  await waitFor("cerebro-web readiness", async () => {
    const config = await requestJSON(`${webBase}/api/config`);
    expect(config.status === 200, `config status ${config.status}`);
    expect(config.json.apiBase === "/api/cerebro", `public apiBase ${config.json.apiBase}`);
    expect(!JSON.stringify(config.json).includes("://"), "public config exposed an absolute service address");
    const cacheControl = config.headers.get("cache-control") ?? "";
    expect(cacheControl.includes("private") && cacheControl.includes("no-store"), "public config was cacheable");
  }, Math.min(90_000, remainingValidationMs()), webProcess);

  step("validating proxy cache, dedupe, and perf");
  assertChildHealthy(backendProcess, "Cerebro API");
  assertChildHealthy(webProcess, "cerebro-web");
  await validateProxyCache();
  await validateConcurrentProxyRequests();

  step("validating app routes");
  assertChildHealthy(backendProcess, "Cerebro API");
  assertChildHealthy(webProcess, "cerebro-web");
  await validateRoutes();

  if (options.browser) {
    step("validating browser UI");
    assertChildHealthy(backendProcess, "Cerebro API");
    assertChildHealthy(webProcess, "cerebro-web");
    await validateBrowser();
  }

  step("validating failure modes");
  assertChildHealthy(backendProcess, "Cerebro API");
  assertChildHealthy(webProcess, "cerebro-web");
  await validateFailureModes();
  assertChildHealthy(webProcess, "cerebro-web");

  console.log("\n[grc-e2e] local GRC E2E passed");
}

async function startPostgres() {
  postgresStarted = true;
  await run("docker", [
    "run",
    "--rm",
    "--name",
    postgresContainer,
    "-e",
    "POSTGRES_HOST_AUTH_METHOD=trust",
    "-e",
    "POSTGRES_DB=cerebro",
    "-p",
    "127.0.0.1::5432",
    "-d",
    postgresImage,
  ]);
  pgPort = parseDockerLoopbackPort((await run("docker", ["port", postgresContainer, "5432/tcp"], { quiet: true })).stdout);
  postgresDSN = `postgres://postgres@127.0.0.1:${pgPort}/cerebro?sslmode=disable`;
  await waitFor("Postgres readiness", async () => {
    await run("docker", ["exec", postgresContainer, "pg_isready", "-U", "postgres", "-d", "cerebro"], { quiet: true });
  });
}

async function startNeo4j() {
  neo4jStarted = true;
  await run("docker", [
    "run",
    "--rm",
    "--name",
    neo4jContainer,
    "-e",
    "NEO4J_AUTH=none",
    "-p",
    "127.0.0.1::7687",
    "-d",
    neo4jImage,
  ]);
  neo4jPort = parseDockerLoopbackPort((await run("docker", ["port", neo4jContainer, "7687/tcp"], { quiet: true })).stdout);
  neo4jURI = `bolt://127.0.0.1:${neo4jPort}`;
  await waitFor("Neo4j readiness", async () => {
    await run("docker", ["exec", neo4jContainer, "cypher-shell", "-a", "bolt://127.0.0.1:7687", "RETURN 1"], { quiet: true });
  }, 120_000);
}

export async function allocateLoopbackPort() {
  return new Promise((resolve, reject) => {
    const server = net.createServer();
    server.once("error", reject);
    server.once("listening", () => {
      const address = server.address();
      const port = typeof address === "object" && address ? address.port : 0;
      server.close((error) => error ? reject(error) : resolve(port));
    });
    server.listen(0, "127.0.0.1");
  });
}

async function requireCommand(command, commandArgs) {
  try {
    await run(command, commandArgs, { quiet: true });
  } catch (error) {
    throw new Error(`${command} is required for local GRC E2E: ${error.message}`);
  }
}

function spawnLogged(name, command, commandArgs, options = {}) {
  const logPath = path.join(logDir, `${name}.log`);
  const stream = createWriteStream(logPath, { flags: "a" });
  const child = spawn(command, commandArgs, {
    cwd: options.cwd,
    env: options.env ?? portableChildEnvironment(),
    detached: process.platform !== "win32",
    stdio: ["ignore", "pipe", "pipe"],
  });
  child.spawnError = null;
  child.logError = null;
  child.once("error", (error) => {
    child.spawnError = error;
  });
  stream.on("error", (error) => {
    child.logError = error;
  });
  child.stdout.pipe(stream);
  child.stderr.pipe(stream);
  child.logPath = logPath;
  child.logStream = stream;
  return child;
}

async function run(command, commandArgs, options = {}) {
  const child = spawn(command, commandArgs, {
    cwd: options.cwd,
    env: options.env ?? portableChildEnvironment(),
    detached: process.platform !== "win32",
    stdio: ["ignore", "pipe", "pipe"],
  });
  const completion = new Promise((resolve, reject) => {
    let stdout = "";
    let stderr = "";
    child.stdout.on("data", (chunk) => {
      stdout = appendBounded(stdout, chunk);
      if (!options.quiet) {
        process.stdout.write(chunk);
      }
    });
    child.stderr.on("data", (chunk) => {
      stderr = appendBounded(stderr, chunk);
      if (!options.quiet) {
        process.stderr.write(chunk);
      }
    });
    child.on("error", reject);
    child.on("close", (code) => {
      if (code === 0) {
        resolve({ stdout, stderr });
      } else {
        reject(new Error(`${command} ${commandArgs.join(" ")} exited ${code}: ${stderr || stdout}`.trim()));
      }
    });
  });
  const deadlineAt = options.deadlineAt ?? validationDeadlineAt;
  try {
    return await createDeadlineAt(deadlineAt).run(completion, `${command} command`);
  } catch (error) {
    await stopProcessTree(child, { deadlineAt: Math.min(overallDeadlineAt, Date.now() + 10_000) }).catch(() => undefined);
    throw error;
  }
}

function appendBounded(current, chunk) {
  const maximum = 1024 * 1024;
  const combined = current + chunk.toString();
  return combined.length > maximum ? combined.slice(-maximum) : combined;
}

function remainingValidationMs() {
  return Math.max(0, validationDeadlineAt - Date.now());
}

export async function waitFor(label, action, timeoutMs = 60_000, child) {
  const deadline = Math.min(validationDeadlineAt, Date.now() + timeoutMs);
  let lastError;
  while (Date.now() < deadline) {
    assertChildHealthy(child, label);
    try {
      await createDeadlineAt(deadline).run(action(), label);
      return;
    } catch (error) {
      lastError = error;
      await createDeadlineAt(deadline).run(sleep(Math.min(1_000, Math.max(1, deadline - Date.now()))), `${label} retry delay`);
    }
  }
  throw new Error(`${label} timed out: ${lastError?.message ?? "unknown error"}`);
}

export function assertChildHealthy(child, label) {
  if (!child) return;
  if (child.spawnError) throw new Error(`${label} failed to start: ${child.spawnError.message}`);
  if (child.logError) throw new Error(`${label} log stream failed: ${child.logError.message}`);
  if (child.exitCode !== null || child.signalCode !== null) {
    throw new Error(`${label} stopped before validation completed; inspect its retained log`);
  }
}

async function request(url, options = {}) {
  const startedAt = performance.now();
  const {
    timeoutMs = 10_000,
    cache = "no-store",
    signal,
    ...fetchOptions
  } = options;
  const boundedTimeoutMs = Math.max(1, Math.min(timeoutMs, remainingValidationMs()));
  const response = await fetch(url, {
    ...fetchOptions,
    cache,
    signal: signal ?? AbortSignal.timeout(boundedTimeoutMs),
  });
  const body = await response.text();
  return { status: response.status, headers: response.headers, body, durationMs: Math.round(performance.now() - startedAt) };
}

async function requestJSON(url, options = {}) {
  const response = await request(url, options);
  try {
    return { ...response, json: JSON.parse(response.body) };
  } catch {
    throw new Error(`expected JSON from ${url}, got status ${response.status}: ${response.body.slice(0, 200)}`);
  }
}

export function componentReady(health, name) {
  return Array.isArray(health?.components)
    && health.components.some((component) => component.name === name && component.status === "ready");
}

async function validateBackend() {
  const dashboard = await requestJSON(`${apiBase}/grc/dashboard?tenant_id=${tenantID}&limit=100`);
  expect(dashboard.status === 200, `dashboard status ${dashboard.status}`);
  expect(dashboard.json.summary.open_findings === 3, "dashboard open_findings mismatch");
  expect(dashboard.json.summary.critical_findings === 1, "dashboard critical_findings mismatch");
  expect(dashboard.json.summary.high_findings === 1, "dashboard high_findings mismatch");
  expect(dashboard.json.summary.overdue_findings === 1, "dashboard overdue_findings mismatch");
  expect(dashboard.json.summary.evidence_items === 3, "dashboard evidence_items mismatch");
  expect(dashboard.json.summary.connectors === 3, "dashboard connectors mismatch");
  expect(dashboard.json.findings.length === 3, "dashboard finding row mismatch");

  const findings = await requestJSON(`${apiBase}/grc/findings?tenant_id=${tenantID}&severity=high&limit=10`);
  expect(findings.status === 200, `findings status ${findings.status}`);
  expect(findings.json.findings.map((finding) => finding.id).join(",") === "e2e-finding-high", "high finding filter mismatch");

  const controls = await requestJSON(`${apiBase}/grc/controls?tenant_id=${tenantID}&limit=10`);
  expect(controls.status === 200, `controls status ${controls.status}`);
  expect(controls.json.controls.length === 3, "controls count mismatch");

  const evidence = await requestJSON(`${apiBase}/grc/evidence?tenant_id=${tenantID}&limit=10`);
  expect(evidence.status === 200, `evidence status ${evidence.status}`);
  expect(evidence.json.evidence.length === 3, "evidence count mismatch");

  const impact = await requestJSON(`${apiBase}/grc/entities/${encodeURIComponent(adminURN)}/impact?tenant_id=${tenantID}&limit=10`);
  expect(impact.status === 200, `impact status ${impact.status}`);
  expect(impact.json.graph.root.urn === adminURN, "impact root mismatch");
  expect(impact.json.graph.neighbors.length >= 2, "impact neighbors missing");
  expect(impact.json.graph.relations.length >= 2, "impact relations missing");
  expect(impact.json.findings.some((finding) => finding.id === "e2e-finding-critical"), "impact finding missing");

  const missingImpact = await request(`${apiBase}/grc/entities/${encodeURIComponent(`urn:cerebro:${tenantID}:missing:node`)}/impact?tenant_id=${tenantID}&limit=10`);
  expect(missingImpact.status === 404, `missing impact status ${missingImpact.status}`);

  const invalidLimit = await request(`${apiBase}/grc/dashboard?tenant_id=${tenantID}&limit=1000`);
  expect(invalidLimit.status === 400, `invalid limit status ${invalidLimit.status}`);
}

async function validateProxyCache() {
  const dashboardUrl = `${webBase}/api/cerebro/grc/dashboard?tenant_id=${tenantID}&limit=100&cache_probe=${Date.now()}`;
  const firstDashboard = await requestJSON(dashboardUrl, proxyCacheProbeOptions);
  expect(firstDashboard.status === 200, `proxy dashboard first status ${firstDashboard.status}`);
  expect(firstDashboard.headers.get("x-cerebro-cache") === "miss", `proxy dashboard first cache ${firstDashboard.headers.get("x-cerebro-cache")}`);
  expect(firstDashboard.json.summary.open_findings === 3, "proxy dashboard payload mismatch");
  expect(firstDashboard.durationMs < perfFirstMs, `dashboard first request took ${firstDashboard.durationMs}ms`);

  const secondDashboard = await requestJSON(dashboardUrl, proxyCacheProbeOptions);
  expect(secondDashboard.status === 200, `proxy dashboard second status ${secondDashboard.status}`);
  expect(secondDashboard.headers.get("x-cerebro-cache") === "hit", `proxy dashboard second cache ${secondDashboard.headers.get("x-cerebro-cache")}`);
  expect(secondDashboard.json.summary.evidence_items === 3, "proxy dashboard cached payload mismatch");
  expect(secondDashboard.durationMs < perfCachedMs, `dashboard cached request took ${secondDashboard.durationMs}ms`);

  const impactUrl = `${webBase}/api/cerebro/grc/entities/${encodeURIComponent(adminURN)}/impact?tenant_id=${tenantID}&limit=10&cache_probe=${Date.now()}`;
  const firstImpact = await requestJSON(impactUrl, proxyCacheProbeOptions);
  expect(firstImpact.status === 200, `proxy impact first status ${firstImpact.status}`);
  expect(firstImpact.headers.get("x-cerebro-cache") === "miss", `proxy impact first cache ${firstImpact.headers.get("x-cerebro-cache")}`);
  expect(firstImpact.json.graph.root.urn === adminURN, "proxy impact root mismatch");
  expect(firstImpact.durationMs < perfFirstMs, `impact first request took ${firstImpact.durationMs}ms`);

  const secondImpact = await requestJSON(impactUrl, proxyCacheProbeOptions);
  expect(secondImpact.status === 200, `proxy impact second status ${secondImpact.status}`);
  expect(secondImpact.headers.get("x-cerebro-cache") === "hit", `proxy impact second cache ${secondImpact.headers.get("x-cerebro-cache")}`);
  expect(secondImpact.durationMs < perfCachedMs, `impact cached request took ${secondImpact.durationMs}ms`);
}

async function validateConcurrentProxyRequests() {
  const url = `${webBase}/api/cerebro/grc/dashboard?tenant_id=${tenantID}&limit=100&cache_probe=dedupe-${Date.now()}`;
  const responses = await Promise.all(Array.from({ length: 12 }, () => requestJSON(url, proxyCacheProbeOptions)));
  assertConcurrentProxyResponses(responses);
}

export function assertConcurrentProxyResponses(responses) {
  const bodies = new Set(responses.map((response) => JSON.stringify(response.json.summary)));
  const states = responses.map((response) => response.headers.get("x-cerebro-cache"));
  const missCount = states.filter((state) => state === "miss").length;
  expect(responses.every((response) => response.status === 200), `concurrent statuses ${responses.map((response) => response.status).join(",")}`);
  expect(bodies.size === 1, "concurrent responses diverged");
  expect(missCount <= 1, `expected at most one upstream miss under concurrency, got states ${states.join(",")}`);
  expect(states.every((state) => ["miss", "dedupe", "hit"].includes(state)), `unexpected cache states ${states.join(",")}`);
}

async function validateRoutes() {
  for (const { route } of grcBrowserRouteContracts({ adminURN })) {
    const page = await request(`${webBase}${route}`);
    expect(page.status === 200, `${route} status ${page.status}`);
    expect(page.body.includes("Cerebro"), `${route} missing app shell`);
  }
}

async function validateBrowser() {
  await validatePlaywrightBrowser();
}

async function validatePlaywrightBrowser() {
  const { chromium } = await import("@playwright/test");
  const browser = await createDeadlineAt(validationDeadlineAt).run(chromium.launch({ headless: true }), "Chromium launch");
  try {
    const page = await browser.newPage({ viewport: { width: 1440, height: 1000 } });
    const pageErrors = [];
    page.on("pageerror", (error) => pageErrors.push(error));
    for (const { route, pageId, heading } of grcBrowserRouteContracts({ adminURN })) {
      pageErrors.length = 0;
      const response = await page.goto(`${webBase}${route}`, {
        timeout: Math.max(1, Math.min(15_000, remainingValidationMs())),
        waitUntil: "domcontentloaded",
      });
      expect(response?.status() === 200, `${route} browser status ${response?.status() ?? "missing"}`);
      const pageContract = page.locator(`[data-grc-page="${pageId}"]:visible`);
      try {
        await pageContract.waitFor({ state: "visible", timeout: Math.max(1, Math.min(15_000, remainingValidationMs())) });
        await pageContract.getByRole("heading", { name: heading, exact: true }).waitFor({
          state: "visible",
          timeout: Math.max(1, Math.min(15_000, remainingValidationMs())),
        });
      } catch (error) {
        const body = await page.locator("body").innerText().catch(() => "");
        throw new Error(`${route} missing browser page contract ${pageId}: ${body.slice(0, 500)}`, { cause: error });
      }
      const body = await page.locator("body").innerText();
      expect(!/Application error|Unhandled Runtime Error|Cerebro request failed \([45][0-9][0-9]\)/i.test(body), `${route} contains error text`);
      expect(pageErrors.length === 0, `${route} raised a client error: ${pageErrors[0]?.message ?? "unknown"}`);
      await page.screenshot({ path: path.join(workDir, `${safeRouteName(route)}.png`), fullPage: true });
    }
  } finally {
    await createDeadlineAt(overallDeadlineAt).run(browser.close(), "Chromium shutdown");
  }
}

function safeRouteName(route) {
  if (route === "/") {
    return "home";
  }
  return route.replace(/^\/+/, "").replace(/[^a-z0-9-]+/gi, "-").replace(/-+$/g, "");
}

async function validateFailureModes() {
  const invalidLimit = await request(`${webBase}/api/cerebro/grc/dashboard?tenant_id=${tenantID}&limit=1000`);
  expect(invalidLimit.status === 400, `proxy invalid limit status ${invalidLimit.status}`);

  const missingImpact = await request(`${webBase}/api/cerebro/grc/entities/${encodeURIComponent(`urn:cerebro:${tenantID}:missing:node`)}/impact?tenant_id=${tenantID}&limit=10`);
  expect(missingImpact.status === 404, `proxy missing impact status ${missingImpact.status}`);

  const staleImpactUrl = `${webBase}/api/cerebro/grc/entities/${encodeURIComponent(adminURN)}/impact?tenant_id=${tenantID}&limit=10&cache_probe=graph-stale-${Date.now()}`;
  const staleDashboardUrl = `${webBase}/api/cerebro/grc/dashboard?tenant_id=${tenantID}&limit=100&cache_probe=api-stale-${Date.now()}`;
  const warmImpact = await requestJSON(staleImpactUrl, proxyCacheProbeOptions);
  expect(warmImpact.status === 200, `warm impact status ${warmImpact.status}`);
  expect(warmImpact.headers.get("x-cerebro-cache") === "miss", `warm impact cache ${warmImpact.headers.get("x-cerebro-cache")}`);
  const warmDashboard = await requestJSON(staleDashboardUrl, proxyCacheProbeOptions);
  expect(warmDashboard.status === 200, `warm dashboard status ${warmDashboard.status}`);
  await sleep(proxyCacheTtlMs + 500);
  await stopNeo4j();
  const staleImpact = await requestJSON(staleImpactUrl, proxyCacheProbeOptions);
  expect(staleImpact.status === 200, `stale impact status ${staleImpact.status}`);
  expect(staleImpact.headers.get("x-cerebro-cache") === "stale", `stale impact cache ${staleImpact.headers.get("x-cerebro-cache")}`);
  expect(staleImpact.headers.get("warning")?.includes("stale"), "stale impact missing warning header");
  expect(staleImpact.json.graph.root.urn === adminURN, "stale impact payload mismatch");

  await stopChild(backendProcess);
  backendProcess = null;
  const staleDashboard = await requestJSON(staleDashboardUrl, proxyCacheProbeOptions);
  expect(staleDashboard.status === 200, `stale dashboard status ${staleDashboard.status}`);
  expect(staleDashboard.headers.get("x-cerebro-cache") === "stale", `stale dashboard cache ${staleDashboard.headers.get("x-cerebro-cache")}`);
  expect(staleDashboard.json.summary.open_findings === 3, "stale dashboard payload mismatch");

  const nonCacheableDown = await request(`${webBase}/api/cerebro/health`);
  expect(nonCacheableDown.status === 502, `non-cacheable backend-down status ${nonCacheableDown.status}`);
}

async function stopNeo4j() {
  if (neo4jStopped || !neo4jStarted) return;
  neo4jStopped = true;
  await run("docker", ["stop", "--time", "5", neo4jContainer], {
    deadlineAt: Math.min(overallDeadlineAt, Date.now() + 10_000),
    quiet: true,
  });
  neo4jStarted = false;
}

async function stopChild(child) {
  if (!child) return;
  await stopProcessTree(child, { deadlineAt: overallDeadlineAt });
  await closeLogStream(child.logStream, overallDeadlineAt);
}

export function windowsTaskkillArgs(pid, force) {
  const args = ["/PID", String(pid), "/T"];
  if (force) args.push("/F");
  return args;
}

function taskkill(pid, force, timeoutMs) {
  return new Promise((resolve, reject) => {
    execFile("taskkill", windowsTaskkillArgs(pid, force), {
      timeout: Math.max(1, timeoutMs),
      windowsHide: true,
    }, (error) => error ? reject(error) : resolve());
  });
}

async function waitForExit(exited, expiresAt) {
  try {
    await createDeadlineAt(expiresAt).run(exited, "process exit");
    return true;
  } catch (error) {
    if (error.code === "ETIMEDOUT") return false;
    throw error;
  }
}

export async function stopProcessTree(child, options = {}) {
  if (!child?.pid || child.exitCode !== null || child.signalCode !== null) return;
  const deadlineAt = options.deadlineAt ?? Date.now() + 10_000;
  const graceDeadlineAt = Math.min(deadlineAt, Date.now() + (options.graceMs ?? 5_000));
  const platform = options.platform ?? process.platform;
  const taskkillProcess = options.taskkillProcess ?? taskkill;
  const signalProcessGroup = options.signalProcessGroup ?? ((pid, signal) => process.kill(-pid, signal));
  const exited = new Promise((resolve) => child.once("exit", resolve));
  const signal = async (force, signalDeadlineAt) => {
    if (platform === "win32") {
      try {
        await createDeadlineAt(signalDeadlineAt).run(
          taskkillProcess(child.pid, force, Math.max(1, signalDeadlineAt - Date.now())),
          force ? "forced Windows descendant termination" : "Windows descendant termination",
        );
      } catch (error) {
        if (force && error.code === "ETIMEDOUT") throw error;
      }
      return;
    }
    try {
      signalProcessGroup(child.pid, force ? "SIGKILL" : "SIGTERM");
    } catch (error) {
      if (error?.code !== "ESRCH") throw error;
    }
  };
  await signal(false, graceDeadlineAt);
  if (await waitForExit(exited, graceDeadlineAt)) return;
  await signal(true, deadlineAt);
  if (!await waitForExit(exited, deadlineAt)) throw timeoutError("forced descendant termination");
}

export async function closeLogStream(stream, deadlineAt) {
  if (!stream || stream.closed || stream.destroyed) return;
  const closed = new Promise((resolve, reject) => {
    stream.once("close", resolve);
    stream.once("error", reject);
  });
  stream.end();
  try {
    await createDeadlineAt(deadlineAt).run(closed, "integration log closure");
  } catch (error) {
    stream.destroy();
    throw error;
  }
}

async function cleanup() {
  const errors = [];
  for (const child of [webProcess, backendProcess]) {
    try {
      await stopChild(child);
    } catch (error) {
      errors.push(error);
    }
  }
  if (neo4jStarted) {
    try {
      await run("docker", ["rm", "-f", neo4jContainer], { deadlineAt: overallDeadlineAt, quiet: true });
      neo4jStarted = false;
    } catch (error) {
      if (!error.message.includes("No such container")) errors.push(error);
      neo4jStarted = false;
    }
  }
  if (postgresStarted) {
    try {
      await run("docker", ["rm", "-f", postgresContainer], { deadlineAt: overallDeadlineAt, quiet: true });
      postgresStarted = false;
    } catch (error) {
      if (!error.message.includes("No such container")) errors.push(error);
      postgresStarted = false;
    }
  }
  if (!failed && errors.length === 0 && workDir) {
    try {
      await createDeadlineAt(overallDeadlineAt).run(rm(workDir, { recursive: true, force: true }), "artifact cleanup");
    } catch (error) {
      errors.push(error);
    }
  } else if (workDir) {
    console.log(`[grc-e2e] retained artifacts: ${workDir}`);
  }
  return errors;
}

async function seedStores() {
  await run("go", ["-C", backendRoot, "run", "./apps/web/scripts/testdata/grc-e2e-seed"], {
    env: portableChildEnvironment(process.env, {
      CEREBRO_POSTGRES_DSN: postgresDSN,
      CEREBRO_NEO4J_URI: neo4jURI,
      CEREBRO_NEO4J_USERNAME: neo4jUser,
      CEREBRO_NEO4J_PASSWORD: neo4jCredential,
    }),
    quiet: true,
  });
}

function interruptedRun() {
  const handlers = new Map();
  const promise = new Promise((_, reject) => {
    for (const [signal, exitCode] of [["SIGINT", 130], ["SIGTERM", 143]]) {
      const handler = () => {
        const error = new Error(`Full-stack integration interrupted by ${signal}`);
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

export async function runLocalGrcE2E(options = {}) {
  const effectiveOptions = { browser: true, ...options };
  const timeoutMs = effectiveOptions.timeoutMs ?? defaultTimeoutMs;
  const reserveMs = Math.min(cleanupReserveMs, Math.max(25, Math.floor(timeoutMs / 2)));
  overallDeadlineAt = Date.now() + timeoutMs;
  validationDeadlineAt = overallDeadlineAt - reserveMs;
  failed = false;
  backendProcess = null;
  webProcess = null;
  neo4jStopped = false;
  postgresStarted = false;
  neo4jStarted = false;

  const artifactRoot = effectiveOptions.artifactRoot ? path.resolve(effectiveOptions.artifactRoot) : os.tmpdir();
  await createDeadlineAt(validationDeadlineAt).run(mkdir(artifactRoot, { recursive: true }), "artifact root creation");
  workDir = await createDeadlineAt(validationDeadlineAt).run(
    mkdtemp(path.join(artifactRoot, effectiveOptions.artifactRoot ? "run-" : "cerebro-grc-e2e-")),
    "artifact directory creation",
  );
  logDir = path.join(workDir, "logs");
  await createDeadlineAt(validationDeadlineAt).run(mkdir(logDir, { recursive: true }), "log directory creation");

  const interruption = interruptedRun();
  let primaryError;
  try {
    await Promise.race([
      createDeadlineAt(validationDeadlineAt).run(main(effectiveOptions), "full-stack web integration"),
      interruption.promise,
    ]);
  } catch (error) {
    failed = true;
    error.message = `${error.message}\nFull-stack integration artifacts: ${workDir}`;
    primaryError = error;
  } finally {
    interruption.remove();
    const cleanupErrors = await cleanup();
    if (cleanupErrors.length > 0) {
      primaryError = new AggregateError(
        primaryError ? [primaryError, ...cleanupErrors] : cleanupErrors,
        primaryError?.message ?? "Full-stack integration cleanup failed",
      );
    }
  }
  if (primaryError) throw primaryError;
  return { browserChecked: effectiveOptions.browser };
}

async function runCli() {
  const options = parseArgs(process.argv.slice(2));
  await runLocalGrcE2E(options);
  const browser = options.browser ? " with Chromium evidence" : " without Chromium evidence";
  console.log(`[e2e:grc:local] passed real-service integration${browser}`);
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  runCli().catch((error) => {
    console.error(`[e2e:grc:local] failed: ${error.stack || error.message}`);
    process.exitCode = error.exitCode ?? 1;
  });
}
