#!/usr/bin/env node

import { execFile, spawn } from "node:child_process";
import { randomBytes, randomUUID } from "node:crypto";
import { createWriteStream } from "node:fs";
import { access, mkdir, mkdtemp, rm } from "node:fs/promises";
import http from "node:http";
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
let delayRelay = null;
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
let activeRunControl = null;

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

function abortReason(signal, label) {
  return signal?.reason instanceof Error
    ? signal.reason
    : new Error(`${label} aborted`);
}

export function throwIfAborted(signal, label) {
  if (signal?.aborted) throw abortReason(signal, label);
}

export function createRunControl(expiresAt, options = {}) {
  const controller = new AbortController();
  const pendingSettlements = new Set();
  const timeout = options.setTimeoutFn ?? setTimeout;
  const clear = options.clearTimeoutFn ?? clearTimeout;
  const timer = timeout(() => controller.abort(timeoutError("full-stack web integration")), Math.max(0, expiresAt - Date.now()));
  timer?.unref?.();
  const control = {
    signal: controller.signal,
    abort(reason = new Error("Full-stack web integration aborted")) {
      if (!controller.signal.aborted) controller.abort(reason);
    },
    assertActive(label) {
      throwIfAborted(controller.signal, label);
    },
    trackSettlement(promise) {
      const settlement = Promise.resolve(promise).then(() => undefined, () => undefined);
      pendingSettlements.add(settlement);
      void settlement.then(() => pendingSettlements.delete(settlement));
      return promise;
    },
    async quiesce() {
      while (pendingSettlements.size > 0) {
        await Promise.allSettled([...pendingSettlements]);
      }
    },
    disposeDeadline() {
      clear(timer);
    },
  };
  return control;
}

export async function startAfterPrerequisite(prerequisite, start, control, label) {
  await prerequisite;
  control.assertActive(label);
  return start();
}

export async function acquireAbortableResource(create, dispose, control, label) {
  control.assertActive(label);
  const creation = Promise.resolve().then(() => {
    control.assertActive(label);
    return create();
  });
  const interrupted = new Promise((_, reject) => {
    const onAbort = () => reject(abortReason(control.signal, label));
    control.signal.addEventListener("abort", onAbort, { once: true });
    void creation.finally(() => control.signal.removeEventListener("abort", onAbort)).catch(() => undefined);
  });
  try {
    const resource = await Promise.race([creation, interrupted]);
    control.assertActive(label);
    return resource;
  } catch (error) {
    control.trackSettlement(creation.then((resource) => dispose(resource), () => undefined));
    throw error;
  }
}

function abortableSleep(ms, signal, label = "retry delay") {
  throwIfAborted(signal, label);
  return new Promise((resolve, reject) => {
    const timer = setTimeout(() => {
      signal?.removeEventListener("abort", onAbort);
      resolve();
    }, ms);
    const onAbort = () => {
      clearTimeout(timer);
      reject(abortReason(signal, label));
    };
    signal?.addEventListener("abort", onAbort, { once: true });
  });
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
const step = (message) => {
  activeRunControl?.assertActive(message);
  console.log(`\n[grc-e2e] ${message}`);
};
const expect = (condition, message) => {
  if (!condition) {
    throw new Error(message);
  }
};

async function main(options) {
  const usedPorts = new Set();
  activeRunControl.assertActive("integration startup");
  await access(backendRoot);
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
  const apiBuild = run("go", ["-C", backendRoot, "build", "-o", apiBinary, "./cmd/cerebro"], {
    env: portableChildEnvironment(),
    quiet: true,
  });
  backendProcess = await startAfterPrerequisite(apiBuild, async () => {
    const reservation = await reserveDistinctLoopbackPort(usedPorts, { control: activeRunControl });
    apiPort = reservation.port;
    usedPorts.add(apiPort);
    apiBase = `http://127.0.0.1:${apiPort}`;
    return handoffLoopbackReservation(reservation, () => spawnLogged("cerebro-api", apiBinary, ["serve"], {
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
    }), activeRunControl, "Cerebro API spawn");
  }, activeRunControl, "Cerebro API port reservation");
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
  delayRelay = await startDelayRelay(apiPort, activeRunControl);
  usedPorts.add(delayRelay.port);
  const webReservation = await reserveDistinctLoopbackPort(usedPorts, { control: activeRunControl });
  webPort = webReservation.port;
  expect(webPort !== apiPort, "web and API ports must be distinct");
  webBase = `http://127.0.0.1:${webPort}`;
  webProcess = await handoffLoopbackReservation(webReservation, () => spawnLogged("cerebro-web", "npm", ["run", "dev", "--", "--hostname", "127.0.0.1", "--port", String(webPort)], {
      cwd: webRoot,
      env: portableChildEnvironment(process.env, {
        CEREBRO_API_BASE: delayRelay.base,
        NEXT_PUBLIC_CEREBRO_API_BASE: "/api/cerebro",
        CEREBRO_PROXY_TIMEOUT_MS: "5000",
        CEREBRO_PROXY_CACHE_TTL_MS: String(proxyCacheTtlMs),
        CEREBRO_PROXY_CACHE_STALE_MS: String(proxyCacheStaleMs),
        CEREBRO_IDENTITY_PROFILE: "local",
        CEREBRO_LOCAL_IDENTITY_FALLBACK: "1",
      }),
    }), activeRunControl, "cerebro-web spawn");
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
  activeRunControl.assertActive("integration completion");

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

async function reserveLoopbackPort(signal = activeRunControl?.signal, control = activeRunControl) {
  throwIfAborted(signal, "loopback port reservation");
  const server = net.createServer();
  let released = false;
  const release = () => new Promise((resolve, reject) => {
    if (released) {
      resolve();
      return;
    }
    released = true;
    signal?.removeEventListener("abort", onAbort);
    server.close((error) => error ? reject(error) : resolve());
  });
  const onAbort = () => {
    control?.trackSettlement(release());
  };
  const listening = new Promise((resolve, reject) => {
    server.once("error", reject);
    server.once("listening", resolve);
    server.listen(0, "127.0.0.1");
  });
  signal?.addEventListener("abort", onAbort, { once: true });
  try {
    await listening;
    throwIfAborted(signal, "loopback port reservation");
    const address = server.address();
    const port = typeof address === "object" && address ? address.port : 0;
    expect(Number.isSafeInteger(port) && port > 0 && port <= 65_535, "loopback reservation returned an invalid port");
    return { port, release };
  } catch (error) {
    await release().catch(() => undefined);
    throw error;
  }
}

export async function reserveDistinctLoopbackPort(excludedPorts = new Set(), options = {}) {
  const control = options.control ?? activeRunControl;
  const reserve = options.reserve ?? (() => reserveLoopbackPort(control?.signal, control));
  const maximumAttempts = options.maximumAttempts ?? 10;
  for (let attempt = 1; attempt <= maximumAttempts; attempt += 1) {
    control?.assertActive("loopback port reservation");
    const reservation = await reserve();
    if (!excludedPorts.has(reservation.port)) return reservation;
    await reservation.release();
  }
  throw new Error(`Unable to reserve a distinct loopback port after ${maximumAttempts} attempts`);
}

export async function handoffLoopbackReservation(reservation, start, control, label) {
  await reservation.release();
  control?.assertActive(label);
  return start(reservation.port);
}

async function requireCommand(command, commandArgs) {
  try {
    await run(command, commandArgs, { quiet: true });
  } catch (error) {
    throw new Error(`${command} is required for local GRC E2E: ${error.message}`);
  }
}

function spawnLogged(name, command, commandArgs, options = {}) {
  const control = activeRunControl;
  control?.assertActive(`${name} spawn`);
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
  child.processGroupId = child.pid;
  child.stopPromise = null;
  const onAbort = () => {
    control?.trackSettlement(stopChild(child));
  };
  control?.signal.addEventListener("abort", onAbort, { once: true });
  child.removeAbortListener = () => control?.signal.removeEventListener("abort", onAbort);
  return child;
}

async function run(command, commandArgs, options = {}) {
  const control = activeRunControl;
  const signal = Object.hasOwn(options, "signal") ? options.signal : control?.signal;
  throwIfAborted(signal, `${command} command`);
  const child = spawn(command, commandArgs, {
    cwd: options.cwd,
    env: options.env ?? portableChildEnvironment(),
    detached: process.platform !== "win32",
    stdio: ["ignore", "pipe", "pipe"],
  });
  child.processGroupId = child.pid;
  const completion = new Promise((resolve, reject) => {
    let stdout = "";
    let stderr = "";
    let abortError = null;
    let abortStop = null;
    const removeAbortListener = () => signal?.removeEventListener("abort", onAbort);
    const onAbort = () => {
      if (abortStop) return;
      abortError = abortReason(signal, `${command} command`);
      abortStop = stopProcessTree(child, { deadlineAt: Math.min(overallDeadlineAt, Date.now() + 10_000) });
      control?.trackSettlement(abortStop);
      void abortStop.then(
        () => {
          removeAbortListener();
          reject(abortError);
        },
        (error) => {
          removeAbortListener();
          reject(error);
        },
      );
    };
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
    child.on("error", (error) => {
      if (!abortError) {
        removeAbortListener();
        reject(error);
      }
    });
    child.on("close", (code) => {
      if (abortError) return;
      removeAbortListener();
      if (code === 0) {
        resolve({ stdout, stderr });
      } else {
        reject(new Error(`${command} ${commandArgs.join(" ")} exited ${code}: ${stderr || stdout}`.trim()));
      }
    });
    signal?.addEventListener("abort", onAbort, { once: true });
    if (signal?.aborted) onAbort();
  });
  const deadlineAt = options.deadlineAt ?? overallDeadlineAt;
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
  const signal = activeRunControl?.signal;
  let lastError;
  while (Date.now() < deadline) {
    throwIfAborted(signal, label);
    assertChildHealthy(child, label);
    try {
      await action();
      return;
    } catch (error) {
      throwIfAborted(signal, label);
      lastError = error;
      await abortableSleep(Math.min(1_000, Math.max(1, deadline - Date.now())), signal, `${label} retry delay`);
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
  const signals = [AbortSignal.timeout(boundedTimeoutMs)];
  if (activeRunControl?.signal) signals.push(activeRunControl.signal);
  if (signal) signals.push(signal);
  const requestSignal = signals.length === 1 ? signals[0] : AbortSignal.any(signals);
  throwIfAborted(requestSignal, `request ${url}`);
  const response = await fetch(url, {
    ...fetchOptions,
    cache,
    signal: requestSignal,
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

export function localRelayPath(rawTarget) {
  if (typeof rawTarget !== "string" || !rawTarget.startsWith("/") || rawTarget.startsWith("//")) {
    throw new Error("delay relay requires a relative request target");
  }
  const sentinel = new URL("http://local-relay.invalid");
  const parsed = new URL(rawTarget, sentinel);
  if (parsed.origin !== sentinel.origin || parsed.username || parsed.password) {
    throw new Error("delay relay rejected an absolute request target");
  }
  return `${parsed.pathname}${parsed.search}`;
}

export function internalLoopbackPort(port) {
  if (!Number.isSafeInteger(port) || port < 1 || port > 65_535) throw new Error("delay relay upstream port is invalid");
  return port;
}

async function requestLoopbackUpstream(upstreamPort, requestPath, headers, signal) {
  const port = internalLoopbackPort(upstreamPort);
  throwIfAborted(signal, "delay relay upstream request");
  return await new Promise((resolve, reject) => {
    let removeAbortListener = () => undefined;
    const request = http.request({
      headers,
      hostname: "127.0.0.1",
      method: "GET",
      path: requestPath,
      port,
      protocol: "http:",
    }, (response) => {
      const chunks = [];
      response.on("data", (chunk) => chunks.push(Buffer.from(chunk)));
      response.once("error", (error) => {
        removeAbortListener();
        reject(error);
      });
      response.once("end", () => {
        removeAbortListener();
        resolve({
          body: Buffer.concat(chunks),
          headers: response.headers,
          status: response.statusCode ?? 502,
        });
      });
    });
    const onAbort = () => request.destroy(abortReason(signal, "delay relay upstream request"));
    removeAbortListener = () => signal.removeEventListener("abort", onAbort);
    signal.addEventListener("abort", onAbort, { once: true });
    request.once("error", (error) => {
      removeAbortListener();
      reject(error);
    });
    request.end();
  });
}

async function startDelayRelay(upstreamPort, control) {
  control.assertActive("delay relay startup");
  const fixedUpstreamPort = internalLoopbackPort(upstreamPort);
  const delayedRequests = new Map();
  const server = http.createServer(async (incoming, outgoing) => {
    try {
      if (incoming.method !== "GET") {
        outgoing.writeHead(405, { allow: "GET", "content-type": "application/json" });
        outgoing.end(JSON.stringify({ error: "local upstream relay only accepts GET" }));
        return;
      }
      const relayTarget = new URL(localRelayPath(incoming.url ?? "/"), "http://local-relay.invalid");
      const delayKey = relayTarget.searchParams.get("e2e_delay_key") ?? "";
      const parsedDelay = Number.parseInt(relayTarget.searchParams.get("e2e_delay_ms") ?? "0", 10);
      const delayMs = Number.isSafeInteger(parsedDelay) ? Math.max(0, Math.min(parsedDelay, 2_000)) : 0;
      relayTarget.searchParams.delete("e2e_delay_key");
      relayTarget.searchParams.delete("e2e_delay_ms");
      if (delayKey) delayedRequests.set(delayKey, (delayedRequests.get(delayKey) ?? 0) + 1);

      const headers = {};
      for (const [name, value] of Object.entries(incoming.headers)) {
        if (value === undefined || ["accept-encoding", "connection", "content-length", "host", "transfer-encoding"].includes(name.toLowerCase())) continue;
        headers[name] = Array.isArray(value) ? value.join(",") : value;
      }
      const upstream = await requestLoopbackUpstream(
        fixedUpstreamPort,
        `${relayTarget.pathname}${relayTarget.search}`,
        headers,
        control.signal,
      );
      if (delayMs > 0) await abortableSleep(delayMs, control.signal, "delayed upstream response");
      const responseHeaders = {};
      for (const [name, value] of Object.entries(upstream.headers)) {
        if (value !== undefined && !["connection", "content-length", "transfer-encoding"].includes(name.toLowerCase())) responseHeaders[name] = value;
      }
      outgoing.writeHead(upstream.status, responseHeaders);
      outgoing.end(upstream.body);
    } catch {
      if (control.signal.aborted) {
        outgoing.destroy();
        return;
      }
      if (!outgoing.headersSent) outgoing.writeHead(502, { "content-type": "application/json" });
      outgoing.end(JSON.stringify({ error: "local upstream relay failed" }));
    }
  });

  let closePromise = null;
  let removeAbortListener = () => undefined;
  const close = () => {
    if (closePromise) return closePromise;
    removeAbortListener();
    closePromise = new Promise((resolve, reject) => {
      server.close((error) => error ? reject(error) : resolve());
      server.closeAllConnections?.();
    });
    return closePromise;
  };
  let rejectStartup = () => undefined;
  const listening = new Promise((resolve, reject) => {
    rejectStartup = reject;
    server.once("error", reject);
    server.listen(0, "127.0.0.1", resolve);
  });
  const onAbort = () => {
    control.trackSettlement(close());
    rejectStartup(abortReason(control.signal, "delay relay startup"));
  };
  control.signal.addEventListener("abort", onAbort, { once: true });
  removeAbortListener = () => control.signal.removeEventListener("abort", onAbort);
  try {
    await listening;
    control.assertActive("delay relay startup");
    const address = server.address();
    const port = typeof address === "object" && address ? address.port : 0;
    expect(Number.isSafeInteger(port) && port > 0, "delay relay returned an invalid port");
    return {
      base: `http://127.0.0.1:${port}`,
      close,
      delayedRequestCount: (key) => delayedRequests.get(key) ?? 0,
      port,
    };
  } catch (error) {
    await close().catch(() => undefined);
    throw error;
  }
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
  const delayKey = `dedupe-${Date.now()}`;
  const url = `${webBase}/api/cerebro/grc/dashboard?tenant_id=${tenantID}&limit=100&cache_probe=${delayKey}&e2e_delay_key=${delayKey}&e2e_delay_ms=300`;
  const responses = await Promise.all(Array.from({ length: 12 }, () => requestJSON(url, proxyCacheProbeOptions)));
  assertConcurrentProxyResponses(responses);
  expect(delayRelay?.delayedRequestCount(delayKey) === 1, `expected one delayed upstream request, got ${delayRelay?.delayedRequestCount(delayKey) ?? 0}`);
}

export function assertConcurrentProxyResponses(responses) {
  const bodies = new Set(responses.map((response) => JSON.stringify(response.json.summary)));
  const states = responses.map((response) => response.headers.get("x-cerebro-cache"));
  const missCount = states.filter((state) => state === "miss").length;
  const dedupeCount = states.filter((state) => state === "dedupe").length;
  expect(responses.every((response) => response.status === 200), `concurrent statuses ${responses.map((response) => response.status).join(",")}`);
  expect(bodies.size === 1, "concurrent responses diverged");
  expect(states.every((state) => ["miss", "dedupe", "hit"].includes(state)), `unexpected cache states ${states.join(",")}`);
  expect(missCount === 1, `expected exactly one upstream miss under concurrency, got states ${states.join(",")}`);
  expect(dedupeCount >= 1, `expected at least one deduplicated response, got states ${states.join(",")}`);
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

export function browserDataContract(route) {
  return route === "/risk-inbox"
    ? {
        apiPath: "/api/cerebro/grc/findings",
        findingID: "e2e-finding-critical",
        navigationPath: `/risk-inbox?tenant_id=${encodeURIComponent(tenantID)}`,
        tenantID,
        visibleText: "Privileged identity missing verification",
      }
    : null;
}

async function validatePlaywrightBrowser() {
  const { chromium } = await import("@playwright/test");
  const control = activeRunControl;
  const browser = await acquireAbortableResource(
    () => chromium.launch({ headless: true }),
    (resource) => createDeadlineAt(overallDeadlineAt).run(resource.close(), "aborted Chromium shutdown"),
    control,
    "Chromium launch",
  );
  try {
    const page = await browser.newPage({ viewport: { width: 1440, height: 1000 } });
    const pageErrors = [];
    page.on("pageerror", (error) => pageErrors.push(error));
    for (const { route, pageId, heading } of grcBrowserRouteContracts({ adminURN })) {
      control.assertActive(`${route} browser validation`);
      pageErrors.length = 0;
      const dataContract = browserDataContract(route);
      const apiResponse = dataContract
          ? page.waitForResponse((candidate) => {
            const url = new URL(candidate.url());
            return url.pathname === dataContract.apiPath
              && url.searchParams.get("tenant_id") === dataContract.tenantID
              && candidate.status() === 200;
          }, { timeout: Math.max(1, Math.min(15_000, remainingValidationMs())) })
            .then((candidate) => ({ candidate }), (error) => ({ error }))
        : null;
      const response = await page.goto(`${webBase}${dataContract?.navigationPath ?? route}`, {
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
        if (dataContract) {
          const result = await apiResponse;
          if (result.error) throw result.error;
          const payload = await result.candidate.json();
          expect(payload.findings?.some((finding) => finding.id === dataContract.findingID), `${route} API payload missing seeded finding`);
          await page.getByText(dataContract.visibleText, { exact: true }).first().waitFor({
            state: "visible",
            timeout: Math.max(1, Math.min(15_000, remainingValidationMs())),
          });
        }
      } catch (error) {
        const body = await page.locator("body").innerText().catch(() => "");
        throw new Error(`${route} missing browser page contract ${pageId}: ${body.slice(0, 500)}`, { cause: error });
      }
      const body = await page.locator("body").innerText();
      expect(!/Application error|Unhandled Runtime Error|Cerebro request failed \([45][0-9][0-9]\)/i.test(body), `${route} contains error text`);
      expect(pageErrors.length === 0, `${route} raised a client error: ${pageErrors[0]?.message ?? "unknown"}`);
      await page.screenshot({ path: path.join(workDir, `${safeRouteName(route)}.png`), fullPage: true });
      control.assertActive(`${route} browser evidence`);
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
  await abortableSleep(proxyCacheTtlMs + 500, activeRunControl?.signal, "proxy cache expiry");
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
  if (child.stopPromise) return child.stopPromise;
  child.stopPromise = (async () => {
    try {
      await stopProcessTree(child, { deadlineAt: overallDeadlineAt });
    } finally {
      child.removeAbortListener?.();
      await closeLogStream(child.logStream, overallDeadlineAt);
    }
  })();
  return child.stopPromise;
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

function defaultProcessGroupAlive(processGroupId) {
  try {
    process.kill(-processGroupId, 0);
    return true;
  } catch (error) {
    if (error?.code === "ESRCH") return false;
    if (error?.code === "EPERM") return true;
    throw error;
  }
}

async function waitForProcessGroupGone(processGroupId, deadlineAt, processGroupAlive, pollMs) {
  while (Date.now() < deadlineAt) {
    if (!processGroupAlive(processGroupId)) return true;
    await sleep(Math.min(pollMs, Math.max(1, deadlineAt - Date.now())));
  }
  return !processGroupAlive(processGroupId);
}

async function stopProcessTreeOnce(child, options) {
  if (!child?.pid) return;
  const deadlineAt = options.deadlineAt ?? Date.now() + 10_000;
  const graceDeadlineAt = Math.min(deadlineAt, Date.now() + (options.graceMs ?? 5_000));
  const platform = options.platform ?? process.platform;
  const taskkillProcess = options.taskkillProcess ?? taskkill;
  if (platform === "win32") {
    try {
      await createDeadlineAt(graceDeadlineAt).run(
        taskkillProcess(child.pid, false, Math.max(1, graceDeadlineAt - Date.now())),
        "Windows descendant termination",
      );
      return;
    } catch {
      await createDeadlineAt(deadlineAt).run(
        taskkillProcess(child.pid, true, Math.max(1, deadlineAt - Date.now())),
        "forced Windows descendant termination",
      );
      return;
    }
  }

  const processGroupId = child.processGroupId ?? child.pid;
  const processGroupAlive = options.processGroupAlive ?? defaultProcessGroupAlive;
  const signalProcessGroup = options.signalProcessGroup ?? ((pid, signal) => process.kill(-pid, signal));
  const pollMs = options.pollMs ?? 25;
  if (!processGroupAlive(processGroupId)) return;
  try {
    signalProcessGroup(processGroupId, "SIGTERM");
  } catch (error) {
    if (error?.code !== "ESRCH") throw error;
  }
  if (await waitForProcessGroupGone(processGroupId, graceDeadlineAt, processGroupAlive, pollMs)) return;
  try {
    signalProcessGroup(processGroupId, "SIGKILL");
  } catch (error) {
    if (error?.code !== "ESRCH") throw error;
  }
  if (!await waitForProcessGroupGone(processGroupId, deadlineAt, processGroupAlive, pollMs)) {
    throw timeoutError("forced descendant termination");
  }
}

export async function stopProcessTree(child, options = {}) {
  if (!child?.pid) return;
  if (child.processTreeStopPromise) return child.processTreeStopPromise;
  child.processTreeStopPromise = stopProcessTreeOnce(child, options);
  return child.processTreeStopPromise;
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
  try {
    await stopChild(webProcess);
  } catch (error) {
    errors.push(error);
  }
  if (delayRelay) {
    try {
      await delayRelay.close();
    } catch (error) {
      errors.push(error);
    }
    delayRelay = null;
  }
  try {
    await stopChild(backendProcess);
  } catch (error) {
    errors.push(error);
  }
  if (neo4jStarted) {
    try {
      await run("docker", ["rm", "-f", neo4jContainer], { deadlineAt: overallDeadlineAt, quiet: true, signal: null });
      neo4jStarted = false;
    } catch (error) {
      if (!error.message.includes("No such container")) errors.push(error);
      neo4jStarted = false;
    }
  }
  if (postgresStarted) {
    try {
      await run("docker", ["rm", "-f", postgresContainer], { deadlineAt: overallDeadlineAt, quiet: true, signal: null });
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

function interruptedRun(control) {
  const handlers = new Map();
  for (const [signal, exitCode] of [["SIGINT", 130], ["SIGTERM", 143]]) {
    const handler = () => {
      const error = new Error(`Full-stack integration interrupted by ${signal}`);
      error.exitCode = exitCode;
      control.abort(error);
    };
    handlers.set(signal, handler);
    process.once(signal, handler);
  }
  return {
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
  activeRunControl = createRunControl(validationDeadlineAt);
  failed = false;
  backendProcess = null;
  webProcess = null;
  delayRelay = null;
  workDir = undefined;
  logDir = undefined;
  apiBase = undefined;
  webBase = undefined;
  neo4jStopped = false;
  postgresStarted = false;
  neo4jStarted = false;

  const control = activeRunControl;
  const interruption = interruptedRun(control);
  let primaryError;
  let mainPromise;
  try {
    const artifactRoot = effectiveOptions.artifactRoot ? path.resolve(effectiveOptions.artifactRoot) : os.tmpdir();
    control.assertActive("artifact root creation");
    await mkdir(artifactRoot, { recursive: true });
    control.assertActive("artifact directory creation");
    workDir = await mkdtemp(path.join(artifactRoot, effectiveOptions.artifactRoot ? "run-" : "cerebro-grc-e2e-"));
    control.assertActive("integration log directory creation");
    logDir = path.join(workDir, "logs");
    await mkdir(logDir, { recursive: true });
    control.assertActive("integration execution");
    mainPromise = main(effectiveOptions);
    await mainPromise;
  } catch (error) {
    failed = true;
    control.abort(error);
    if (mainPromise) await Promise.allSettled([mainPromise]);
    await control.quiesce();
    if (workDir) error.message = `${error.message}\nFull-stack integration artifacts: ${workDir}`;
    primaryError = error;
  } finally {
    interruption.remove();
    control.disposeDeadline();
    if (primaryError) control.abort(primaryError);
    if (mainPromise) await Promise.allSettled([mainPromise]);
    await control.quiesce();
    const cleanupErrors = await cleanup();
    if (cleanupErrors.length > 0) {
      primaryError = new AggregateError(
        primaryError ? [primaryError, ...cleanupErrors] : cleanupErrors,
        primaryError?.message ?? "Full-stack integration cleanup failed",
      );
    }
    activeRunControl = null;
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
