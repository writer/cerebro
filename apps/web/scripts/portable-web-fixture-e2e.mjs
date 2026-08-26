#!/usr/bin/env node

import { execFile, spawn } from "node:child_process";
import { randomUUID } from "node:crypto";
import { createWriteStream } from "node:fs";
import { mkdir, mkdtemp, readdir, rm } from "node:fs/promises";
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
const frameworkErrorPattern = /This page could not be found|Next\.js.*error|ChunkLoadError|Minified React error/i;
const defaultTimeoutMs = 180_000;
const perRequestTimeoutMs = 15_000;
const apiRouteTimeoutMs = 5_000;
const routeBugbashTimeoutMs = 420_000;
const maxBugbashRoutes = 500;
const defaultHomeSamples = 5;
const defaultHomeP95Ms = 1_000;
const fixtureTenantID = "demo-tenant";
const fixtureWorkspaceID = "fixture-workspace";
const fixtureUserEmail = "local-bugbash@example.org";
const routeScopeMatrix = Object.freeze([
  { tenantID: "tenant-a", workspaceID: "workspace-a" },
  { tenantID: "tenant-a", workspaceID: "workspace-b" },
  { tenantID: "tenant-b", workspaceID: "workspace-a" },
  { tenantID: "tenant-b", workspaceID: "workspace-b" },
]);
const homepageAPIPaths = Object.freeze({
  coverage: "/api/cerebro/connectors/coverage",
  dashboard: "/api/cerebro/grc/dashboard",
  readiness: "/api/cerebro/grc/program-readiness",
});
const routeParameterSamples = Object.freeze({
  dashboardID: "fixture-program-overview",
  frameworkID: "soc2",
  id: "demo-finding-critical",
  operationID: "fixture-operation",
  slug: "grc",
  snapshotID: "fixture-snapshot-1",
  sourceID: "okta",
});
const expectedRouteRedirects = new Map([
  ["/connectors/source-cdk", { pathname: "/connectors/activation", preserveScope: true }],
  ["/developer/codegen", { pathname: "/developer", preserveScope: false }],
  ["/mission-control", { pathname: "/connectors", preserveScope: false }],
  ["/vision", { pathname: "/", preserveScope: false }],
]);

const routeURNParameterSample = (pageFile) => pageFile === path.join("vendors", "[urn]", "page.tsx")
  ? "urn:cerebro:demo-tenant:vendor:core-sso"
  : "urn:cerebro:demo-tenant:identity:platform-admin";

export function parseArgs(argv) {
  const options = {
    allRoutes: false,
    browser: true,
    homeSamples: defaultHomeSamples,
    maxHomeP95Ms: defaultHomeP95Ms,
    port: 0,
    timeoutMs: defaultTimeoutMs,
  };
  for (let index = 0; index < argv.length; index += 1) {
    const arg = argv[index];
    if (arg === "--browser") {
      options.browser = true;
    } else if (arg === "--all-routes") {
      options.allRoutes = true;
      if (options.timeoutMs === defaultTimeoutMs) options.timeoutMs = routeBugbashTimeoutMs;
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
    } else if (arg === "--home-samples") {
      options.homeSamples = parseIntegerOption(arg, argv[index + 1], { minimum: 1, maximum: 100 });
      index += 1;
    } else if (arg.startsWith("--home-samples=")) {
      options.homeSamples = parseIntegerOption("--home-samples", arg.slice("--home-samples=".length), { minimum: 1, maximum: 100 });
    } else if (arg === "--max-home-p95-ms") {
      options.maxHomeP95Ms = parseIntegerOption(arg, argv[index + 1], { minimum: 1, maximum: 60_000 });
      index += 1;
    } else if (arg.startsWith("--max-home-p95-ms=")) {
      options.maxHomeP95Ms = parseIntegerOption("--max-home-p95-ms", arg.slice("--max-home-p95-ms=".length), { minimum: 1, maximum: 60_000 });
    } else {
      throw new Error(`Unknown option: ${arg}`);
    }
  }
  return options;
}

function pageRouteSegment(segment, pageFile) {
  if (segment.startsWith("(") && segment.endsWith(")")) return "";
  if (segment.startsWith("@")) return "";
  const dynamic = segment.match(/^\[(?:\.\.\.)?([^\]]+)\]$/);
  if (!dynamic) return segment;
  const sample = dynamic[1] === "urn"
    ? routeURNParameterSample(pageFile)
    : routeParameterSamples[dynamic[1]];
  if (!sample) {
    throw new Error(`No local route sample is registered for [${dynamic[1]}]`);
  }
  return encodeURIComponent(sample);
}

async function pageFilesBelow(directory, relativeDirectory = "") {
  const entries = await readdir(directory, { withFileTypes: true });
  const files = [];
  for (const entry of entries) {
    const relativePath = path.join(relativeDirectory, entry.name);
    if (entry.isDirectory()) {
      files.push(...await pageFilesBelow(path.join(directory, entry.name), relativePath));
    } else if (entry.isFile() && entry.name === "page.tsx") {
      files.push(relativePath);
    }
  }
  return files;
}

export async function discoverPageRoutes(webRoot = defaultWebRoot) {
  const appRoot = path.join(webRoot, "src", "app");
  const pageFiles = await pageFilesBelow(appRoot);
  return pageFiles
    .map((pageFile) => {
      const segments = path.dirname(pageFile)
        .split(path.sep)
        .filter((segment) => segment !== ".")
        .map((segment) => pageRouteSegment(segment, pageFile))
        .filter(Boolean);
      return `/${segments.join("/")}`;
    })
    .sort((left, right) => left.localeCompare(right));
}

export function routeWithScope(route, tenantID = fixtureTenantID, workspaceID = fixtureWorkspaceID) {
  const url = new URL(route, "http://cerebro.local");
  url.searchParams.set("tenant_id", tenantID);
  url.searchParams.set("workspace_id", workspaceID);
  return `${url.pathname}${url.search}`;
}

export function sameOriginApplicationRoute(href, baseUrl) {
  let url;
  try {
    url = new URL(href, baseUrl);
  } catch {
    return null;
  }
  const base = new URL(baseUrl);
  if (url.origin !== base.origin) return null;
  if (url.pathname.startsWith("/api/") || url.pathname.startsWith("/_next/")) return null;
  if (url.pathname !== "/" && /\.[a-z0-9]{2,8}$/i.test(url.pathname)) return null;
  if ([...url.searchParams.values()].some((value) => /\[[^\]]+\]/.test(value))) return null;
  url.hash = "";
  return `${url.pathname}${url.search}`;
}

export function isExpectedLocal404(pathname, status) {
  return status === 404 && [
    "/evals/ask/latest.json",
    "/evals/security-agent/latest.json",
  ].includes(pathname);
}

export function isExpectedRouteRedirect(route, finalURL) {
  const requested = new URL(route, finalURL);
  const final = new URL(finalURL);
  return expectedRouteRedirects.get(requested.pathname)?.pathname === final.pathname;
}

export function routeBugbashFindings({ body, consoleErrors, documentStatus, finalURL, pageErrors, requestFailures = [], response404s = [], responseFailures = [], route }) {
  const findings = [];
  if (documentStatus !== 200) findings.push(`${route} returned document status ${documentStatus ?? "none"}`);
  if (finalURL) {
    const requested = new URL(route, finalURL);
    const final = new URL(finalURL);
    const expectedRedirect = expectedRouteRedirects.get(requested.pathname);
    const expectedPathname = expectedRedirect?.pathname ?? requested.pathname;
    if (expectedPathname !== final.pathname) {
      findings.push(`${route} navigated to unexpected path ${final.pathname}`);
    }
    if (!expectedRedirect || expectedRedirect.preserveScope) {
      for (const key of ["tenant_id", "workspace_id"]) {
        const expected = requested.searchParams.get(key);
        if (expected && final.searchParams.get(key) !== expected) {
          findings.push(`${route} dropped ${key} during navigation`);
        }
      }
    }
  }
  if (renderedErrorPattern.test(body) || frameworkErrorPattern.test(body)) {
    findings.push(`${route} rendered an application or framework error`);
  }
  for (const error of pageErrors) findings.push(`${route} raised a page error: ${error}`);
  for (const failure of requestFailures) findings.push(`${route} had a network failure at ${failure.url}: ${failure.error}`);
  for (const error of consoleErrors) findings.push(`${route} logged a console error: ${error}`);
  for (const pathname of response404s) findings.push(`${route} requested missing backend path ${pathname}`);
  for (const failure of responseFailures) {
    findings.push(`${route} requested ${failure.status} response at ${failure.pathname}`);
  }
  return findings;
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

async function waitForRouteSettled(page, deadline, route) {
  const waitMs = Math.max(1, Math.min(apiRouteTimeoutMs, deadline.remaining()));
  try {
    await page.waitForLoadState("networkidle", { timeout: waitMs });
  } catch (error) {
    if (error?.name !== "TimeoutError") throw error;
  }
  await deadline.run(page.waitForTimeout(50), `${route} render settlement`);
}

function observeAPIRequest(request) {
  const url = new URL(request.url());
  const requestURL = `${url.pathname}${url.search}`;
  return new Promise((resolve) => {
    const timeout = setTimeout(() => resolve({ timedOut: true, url: requestURL }), apiRouteTimeoutMs);
    request.response().then((response) => {
      clearTimeout(timeout);
      resolve({ response, timedOut: false, url: requestURL });
    }, (error) => {
      clearTimeout(timeout);
      resolve({ error, timedOut: false, url: requestURL });
    });
  });
}

export function nearestRankPercentile(values, percentile) {
  if (values.length === 0) return null;
  const sorted = [...values].sort((left, right) => left - right);
  const rank = Math.max(1, Math.ceil((percentile / 100) * sorted.length));
  return sorted[Math.min(rank - 1, sorted.length - 1)];
}

export function assertHomepageAPIScope(api, requestURL, scope) {
  const url = new URL(requestURL);
  const expectedPath = homepageAPIPaths[api];
  if (!expectedPath) {
    throw new Error(`Unknown homepage API ${api}`);
  }
  if (url.pathname !== expectedPath) {
    throw new Error(`Expected homepage ${api} request at ${expectedPath}, got ${url.pathname}`);
  }
  if (url.searchParams.get("tenant_id") !== scope.tenantID) {
    throw new Error(`Homepage ${api} tenant scope mismatch for ${scope.tenantID}`);
  }
  if (url.searchParams.get("workspace_id") !== scope.workspaceID) {
    throw new Error(`Homepage ${api} workspace scope mismatch for ${scope.workspaceID}`);
  }
}

export function assertDashboardScope(requestURL, scope) {
  assertHomepageAPIScope("dashboard", requestURL, scope);
}

export function assertHomepageP95(durations, maxP95Ms) {
  const p95Ms = nearestRankPercentile(durations, 95);
  if (p95Ms === null || p95Ms >= maxP95Ms) {
    throw new Error(`Homepage data-ready p95 ${p95Ms ?? "missing"}ms must be below ${maxP95Ms}ms`);
  }
  return p95Ms;
}

async function validateAuthenticatedIdentity(context, baseUrl, deadline) {
  const response = await deadline.run(
    context.request.get(new URL("/api/me", baseUrl).toString()),
    "local authenticated identity probe",
  );
  const payload = await deadline.run(response.json(), "local authenticated identity payload");
  if (response.status() !== 200 || !payload.authenticated || payload.fallback || payload.user?.email !== fixtureUserEmail) {
    throw new Error("Local route bug bash did not establish the trusted test identity");
  }
}

async function measureHomepageDataReady(context, baseUrl, deadline, options) {
  const samples = options.homeSamples ?? defaultHomeSamples;
  const durations = [];
  const endpointDurations = Object.fromEntries(
    Object.keys(homepageAPIPaths).map((api) => [api, []]),
  );
  for (let index = 0; index < samples; index += 1) {
    const scope = routeScopeMatrix[index % routeScopeMatrix.length];
    const page = await deadline.run(context.newPage(), "homepage performance page creation");
    try {
      const route = new URL(routeWithScope("/", scope.tenantID, scope.workspaceID), baseUrl);
      let startedAt = 0;
      const apiResponses = Object.entries(homepageAPIPaths).map(([api, pathname]) =>
        page.waitForResponse((response) => new URL(response.url()).pathname === pathname, {
          timeout: Math.max(1, Math.min(perRequestTimeoutMs, deadline.remaining())),
        }).then(async (response) => {
          await response.finished();
          return {
            api,
            durationMs: Math.round(performance.now() - startedAt),
            response,
          };
        }, (error) => ({ api, error })));
      startedAt = performance.now();
      const response = await page.goto(route.toString(), {
        timeout: Math.max(1, Math.min(perRequestTimeoutMs, deadline.remaining())),
        waitUntil: "domcontentloaded",
      });
      if (!response || response.status() !== 200) {
        throw new Error(`Homepage returned ${response?.status() ?? "no response"}`);
      }
      await page.getByText("Open work queue", { exact: true }).waitFor({
        state: "visible",
        timeout: Math.max(1, Math.min(perRequestTimeoutMs, deadline.remaining())),
      });
      const apiResults = await deadline.run(Promise.all(apiResponses), "homepage API responses");
      for (const result of apiResults) {
        if (result.error) throw result.error;
        if (result.response.status() !== 200) {
          throw new Error(`Homepage ${result.api} returned ${result.response.status()}`);
        }
        assertHomepageAPIScope(result.api, result.response.url(), scope);
        endpointDurations[result.api].push(result.durationMs);
      }
      durations.push(Math.round(performance.now() - startedAt));
    } finally {
      await deadline.run(page.close(), "homepage performance page close");
    }
  }
  return {
    durations,
    endpointDurations,
    endpointP95Ms: Object.fromEntries(
      Object.entries(endpointDurations).map(([api, values]) => [
        api,
        assertHomepageP95(values, options.maxHomeP95Ms ?? defaultHomeP95Ms),
      ]),
    ),
    p95Ms: assertHomepageP95(durations, options.maxHomeP95Ms ?? defaultHomeP95Ms),
  };
}

export async function validateBrowserRouteBugbash(baseUrl, options) {
  const { deadline, webRoot = defaultWebRoot } = options;
  const { chromium } = await deadline.run(import("@playwright/test"), "Playwright import");
  const browser = await deadline.run(chromium.launch({ headless: true }), "Chromium launch");
  const routeQueue = [];
  const queuedRoutes = new Set();
  const auditedRoutes = new Set();
  const enqueue = (route, { preserveSearch = true } = {}) => {
    const normalized = sameOriginApplicationRoute(route, baseUrl);
    if (!normalized) return;
    const crawlRoute = preserveSearch
      ? normalized
      : new URL(normalized, baseUrl).pathname;
    if (queuedRoutes.has(crawlRoute)) return;
    if (queuedRoutes.size >= maxBugbashRoutes) {
      throw new Error(`Local route bug bash exceeded its ${maxBugbashRoutes}-route bound`);
    }
    queuedRoutes.add(crawlRoute);
    routeQueue.push(crawlRoute);
  };
  try {
    const discoveredRoutes = await deadline.run(discoverPageRoutes(webRoot), "application route discovery");
    for (const route of discoveredRoutes) {
      enqueue(route);
      for (const scope of routeScopeMatrix) {
        enqueue(routeWithScope(route, scope.tenantID, scope.workspaceID));
      }
    }

    const context = await deadline.run(browser.newContext({
      extraHTTPHeaders: { "x-user-email": fixtureUserEmail },
      viewport: { width: 1440, height: 1000 },
    }), "authenticated bug-bash context creation");
    await validateAuthenticatedIdentity(context, baseUrl, deadline);
    const page = await deadline.run(context.newPage(), "bug-bash page creation");
    let currentConsoleErrors = [];
    let currentPageErrors = [];
    let currentAPIRequests = [];
    let currentRequestFailures = [];
    let currentResponseFailures = [];
    const observedAPIRoutes = new Set();
    const scopedAPIRequests = new Set();
    const observedScopes = new Set();
    let redirectLifecycleAbortCount = 0;
    page.on("console", (message) => {
      if (message.type() !== "error") return;
      if (/^Failed to load resource: the server responded with a status of/i.test(message.text())) return;
      currentConsoleErrors.push(message.text());
    });
    page.on("pageerror", (error) => currentPageErrors.push(error.message));
    page.on("request", (request) => {
      const url = new URL(request.url());
      if (url.origin !== new URL(baseUrl).origin || !url.pathname.startsWith("/api/")) return;
      observedAPIRoutes.add(`${request.method()} ${url.pathname}`);
      currentAPIRequests.push(observeAPIRequest(request));
      if (!url.pathname.startsWith("/api/cerebro/")) return;
      const tenantID = url.searchParams.get("tenant_id");
      const workspaceID = url.searchParams.get("workspace_id");
      if (tenantID && workspaceID) {
        scopedAPIRequests.add(`${url.pathname}${url.search}`);
        observedScopes.add(`${tenantID}:${workspaceID}`);
      }
    });
    page.on("requestfailed", (request) => {
      const url = new URL(request.url());
      const error = request.failure()?.errorText ?? "unknown browser failure";
      if (url.origin !== new URL(baseUrl).origin || error === "net::ERR_ABORTED") return;
      currentRequestFailures.push({ error, url: `${url.pathname}${url.search}` });
    });
    page.on("response", (response) => {
      const url = new URL(response.url());
      if (url.origin !== new URL(baseUrl).origin || response.status() < 400) return;
      if (url.pathname.startsWith("/_next/") || isExpectedLocal404(url.pathname, response.status())) return;
      currentResponseFailures.push({ pathname: url.pathname, status: response.status() });
    });

    const findings = [];
    while (routeQueue.length > 0) {
      const route = routeQueue.shift();
      if (!route || auditedRoutes.has(route)) continue;
      auditedRoutes.add(route);
      currentConsoleErrors = [];
      currentPageErrors = [];
      currentAPIRequests = [];
      currentRequestFailures = [];
      currentResponseFailures = [];
      const response = await page.goto(new URL(route, baseUrl).toString(), {
        timeout: Math.max(1, Math.min(perRequestTimeoutMs, deadline.remaining())),
        waitUntil: "domcontentloaded",
      });
      await waitForRouteSettled(page, deadline, route);
      const expectedRedirect = isExpectedRouteRedirect(route, page.url());
      for (let index = 0; index < currentAPIRequests.length; index += 1) {
        const request = await deadline.run(currentAPIRequests[index], `${route} API response`);
        if (!request.timedOut) continue;
        if (expectedRedirect) {
          redirectLifecycleAbortCount += 1;
          continue;
        }
        currentRequestFailures.push({
          error: `timed out after ${apiRouteTimeoutMs}ms`,
          url: request.url,
        });
      }
      const body = await deadline.run(page.locator("body").innerText(), `${route} body read`);
      findings.push(...routeBugbashFindings({
        body,
        consoleErrors: [...new Set(currentConsoleErrors)],
        documentStatus: response?.status(),
        finalURL: page.url(),
        pageErrors: [...new Set(currentPageErrors)],
        requestFailures: [...new Map(currentRequestFailures.map((failure) => [
          `${failure.error}:${failure.url}`,
          failure,
        ])).values()],
        responseFailures: [...new Map(currentResponseFailures.map((failure) => [
          `${failure.status}:${failure.pathname}`,
          failure,
        ])).values()],
        route,
      }));
      const hrefs = await deadline.run(page.locator("a[href]").evaluateAll((anchors) =>
        anchors.map((anchor) => anchor.href).filter(Boolean)), `${route} link discovery`);
      for (const href of hrefs) enqueue(href, { preserveSearch: false });
    }
    if (findings.length > 0) {
      throw new Error(`Local route bug bash found ${findings.length} failure(s):\n- ${findings.join("\n- ")}`);
    }
    const missingScopes = routeScopeMatrix.filter((scope) =>
      !observedScopes.has(`${scope.tenantID}:${scope.workspaceID}`));
    if (missingScopes.length > 0) {
      throw new Error(`Local route bug bash did not observe scoped API requests for ${missingScopes.map((scope) => `${scope.tenantID}/${scope.workspaceID}`).join(", ")}`);
    }
    const homepagePerformance = await measureHomepageDataReady(context, baseUrl, deadline, options);
    return {
      apiRouteCount: observedAPIRoutes.size,
      discoveredRouteCount: auditedRoutes.size,
      homepageDataReadyDurationsMs: homepagePerformance.durations,
      homepageDataReadyP95Ms: homepagePerformance.p95Ms,
      homepageEndpointDurationsMs: homepagePerformance.endpointDurations,
      homepageEndpointP95Ms: homepagePerformance.endpointP95Ms,
      redirectLifecycleAbortCount,
      routeTemplateCount: discoveredRoutes.length,
      scopedRouteCount: [...auditedRoutes].filter((route) => route.includes("workspace_id=")).length,
      scopedAPIRequestCount: scopedAPIRequests.size,
      tenantWorkspaceScopeCount: observedScopes.size,
    };
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
        const error = new Error(`Portable fixture E2E interrupted by ${signal}`);
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
  const signal = async (force, signalDeadlineAt) => {
    if (platform === "win32") {
      try {
        await createDeadlineAt(signalDeadlineAt).run(
          taskkillProcess(child.pid, force, Math.max(1, signalDeadlineAt - Date.now())),
          force ? "forced Windows process-tree termination" : "Windows process-tree termination",
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
  const graceDeadline = Math.min(deadlineAt, Date.now() + graceMs);
  await signal(false, graceDeadline);
  if (await waitForExitUntil(exited, graceDeadline)) return;
  await signal(true, deadlineAt);
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

export async function runPortableWebFixtureE2E(options = {}) {
  const timeoutMs = options.timeoutMs ?? options.readyTimeoutMs ?? defaultTimeoutMs;
  const overallDeadline = createDeadline(timeoutMs);
  const cleanupReserveMs = Math.min(10_000, Math.max(25, Math.floor(timeoutMs / 10)), Math.floor(timeoutMs / 2));
  const validationDeadline = createDeadlineAt(overallDeadline.expiresAt - cleanupReserveMs);
  const webRoot = options.webRoot ?? defaultWebRoot;
  const runNonce = randomUUID();
  const workDir = await overallDeadline.run(mkdtemp(path.join(os.tmpdir(), "cerebro-web-local-e2e-")), "temporary directory creation");
  const logDir = path.join(workDir, "logs");
  const logPath = path.join(logDir, "web.log");
  let logStream;
  let child;
  let interruption;
  let result;
  let primaryError;
  let passed = false;
  try {
    await overallDeadline.run(mkdir(logDir, { recursive: true }), "log directory creation");
    const createLog = options.createLogStream ?? ((filePath) => createWriteStream(filePath, { flags: "a" }));
    logStream = createLog(logPath);
    const logStreamFailure = new Promise((_, reject) => {
      logStream.once("error", (error) => reject(new Error(`Portable fixture E2E log stream failed: ${error.message}`, { cause: error })));
    });
    logStreamFailure.catch(() => {});
    const spawnFixture = options.spawnFixture ?? spawn;
    child = spawnFixture(process.execPath, [fixtureDevScript, "--port", String(options.port ?? 0)], {
      cwd: webRoot,
      detached: process.platform !== "win32",
      env: createFixtureEnvironment(process.env, runNonce),
      stdio: ["ignore", "pipe", "pipe"],
    });
    child.stdout.pipe(logStream, { end: false });
    child.stderr.pipe(logStream, { end: false });
    interruption = interruptedRun();
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
      const routeBugbash = options.allRoutes
        ? await validateBrowserRouteBugbash(baseUrl, { ...options, deadline: validationDeadline, webRoot })
        : null;
      return {
        browserChecked: options.browser ?? true,
        routeCount: contracts.length,
        routeBugbash,
        scriptChunkCount: smoke.chunkResponses.length,
      };
    };
    result = await Promise.race([
      validationDeadline.run(validation(), "portable fixture E2E validation"),
      fixtureAppExit(child),
      logStreamFailure,
      interruption.promise,
    ]);
    passed = true;
  } catch (error) {
    error.message = `${error.message}\nPortable fixture E2E log: ${logPath}`;
    primaryError = error;
  } finally {
    interruption?.remove();
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
        primaryError?.message ?? "Portable fixture E2E cleanup failed",
      );
    }
  }
  if (primaryError) throw primaryError;
  return result;
}

async function runCli() {
  const result = await runPortableWebFixtureE2E(parseArgs(process.argv.slice(2)));
  const browser = result.browserChecked ? " with Chromium checks" : " without Chromium checks";
  console.log(`[e2e:web:fixtures] passed ${result.routeCount} route contracts${browser}`);
  if (result.routeBugbash) {
    console.log(`[e2e:web:fixtures] bug-bashed ${result.routeBugbash.discoveredRouteCount} local routes from ${result.routeBugbash.routeTemplateCount} page templates`);
    console.log(`[e2e:web:fixtures] checked ${result.routeBugbash.scopedRouteCount} tenant and workspace route variants`);
    console.log(`[e2e:web:fixtures] observed ${result.routeBugbash.scopedAPIRequestCount} tenant and workspace scoped API requests`);
    console.log(`[e2e:web:fixtures] observed ${result.routeBugbash.apiRouteCount} same-origin API routes`);
    console.log(`[e2e:web:fixtures] observed ${result.routeBugbash.tenantWorkspaceScopeCount} tenant and workspace scope pairs`);
    console.log(`[e2e:web:fixtures] classified ${result.routeBugbash.redirectLifecycleAbortCount} redirect lifecycle-aborted API requests`);
    console.log(`[e2e:web:fixtures] homepage data-ready samples ${result.routeBugbash.homepageDataReadyDurationsMs.join(",")}ms; p95 ${result.routeBugbash.homepageDataReadyP95Ms}ms`);
    for (const [api, durations] of Object.entries(result.routeBugbash.homepageEndpointDurationsMs)) {
      console.log(`[e2e:web:fixtures] homepage ${api} samples ${durations.join(",")}ms; p95 ${result.routeBugbash.homepageEndpointP95Ms[api]}ms`);
    }
  }
  console.log(`[e2e:web:fixtures] checked ${result.scriptChunkCount} application chunks`);
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  runCli().catch((error) => {
    console.error(`[e2e:web:fixtures] failed: ${error.stack || error.message}`);
    process.exitCode = error.exitCode ?? 1;
  });
}
