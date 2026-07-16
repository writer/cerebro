#!/usr/bin/env node

import { spawn } from "node:child_process";
import { createServer } from "node:http";
import { mkdir, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import net from "node:net";
import os from "node:os";
import path from "node:path";
import { performance } from "node:perf_hooks";
import { fileURLToPath } from "node:url";

const scriptDir = path.dirname(fileURLToPath(import.meta.url));
const webRoot = path.resolve(scriptDir, "..");
const args = process.argv.slice(2);
const argSet = new Set(args);
const quick = argSet.has("--quick");
const includeStress = argSet.has("--stress") || process.env.CEREBRO_GRC_SCALE_STRESS === "1";
const failOnStress = argSet.has("--fail-on-stress") || process.env.CEREBRO_GRC_SCALE_FAIL_ON_STRESS === "1";
const keepServices = argSet.has("--keep") || process.env.CEREBRO_GRC_SCALE_KEEP === "1";
const retainArtifacts = argSet.has("--artifacts") || process.env.CEREBRO_GRC_SCALE_RETAIN_ARTIFACTS === "1";
const defaultRecordCount = quick ? 600 : 3000;
const recordCount = positiveInteger(process.env.CEREBRO_GRC_SCALE_RECORDS, defaultRecordCount);
const tenantID = "scale-tenant";
const impactRootURN = `urn:cerebro:${tenantID}:service:service-root`;
const generatedAt = "2026-06-28T12:00:00.000Z";
const routeTimeoutMs = positiveInteger(process.env.CEREBRO_GRC_SCALE_ROUTE_TIMEOUT_MS, quick ? 30_000 : 60_000);
const webReadyTimeoutMs = positiveInteger(process.env.CEREBRO_GRC_SCALE_WEB_READY_MS, 90_000);
const hardThresholds = {
  usableMs: positiveInteger(process.env.CEREBRO_GRC_SCALE_USABLE_MS, quick ? 6000 : 8000),
  domNodes: positiveInteger(process.env.CEREBRO_GRC_SCALE_DOM_NODES, 6500),
  filterMs: positiveInteger(process.env.CEREBRO_GRC_SCALE_FILTER_MS, 750),
};

let workDir;
let currentWebProcess = null;
let currentApiServer = null;

const routeSpecs = [
  {
    route: "/vendors",
    label: "Vendors",
    readySelector: 'input[placeholder="Search loaded vendors"]',
    filterSelector: 'input[placeholder="Search loaded vendors"]',
    filterText: "vendor 12",
  },
  {
    route: "/connectors?tab=attention",
    label: "Connectors",
    readySelector: 'a[href*="/connectors/source-"]:visible',
    filterSelector: 'input[placeholder="Provider, source, capability"]:visible',
    filterText: "source 12",
  },
  {
    route: "/connectors/activation",
    label: "Source Activation",
    readySelector: "text=Runtime activation plan",
  },
  {
    route: "/connectors/source-0?tab=connections",
    label: "Connector Detail",
    readySelector: "table.data-table",
    interactions: [
      {
        label: "open activity",
        action: async (page) => page.getByRole("button", { name: "Activity" }).click(),
        readySelector: "text=Diagnostic timeline",
      },
      {
        label: "open data",
        action: async (page) => page.getByRole("button", { name: "Data" }).click(),
        readySelector: "text=Data and graph",
      },
    ],
  },
  {
    route: "/risk-inbox",
    label: "Risk Inbox",
    readySelector: "table.data-table",
    filterSelector: 'input[placeholder="Filter loaded findings"]',
    filterText: "finding 12",
  },
  {
    route: "/findings/finding-0",
    label: "Finding Detail",
    readySelector: "text=Risk Score",
    interactions: [
      {
        label: "open evidence",
        action: async (page) => page.getByRole("button", { name: /Evidence/ }).click(),
        readySelector: "#finding-evidence table",
      },
      {
        label: "open timeline",
        action: async (page) => page.getByRole("button", { name: "Timeline" }).click(),
        readySelector: "text=Finding Lifecycle",
      },
    ],
  },
  {
    route: "/evidence",
    label: "Evidence",
    readySelector: 'input[placeholder="Filter loaded evidence"]',
    filterSelector: 'input[placeholder="Filter loaded evidence"]',
    filterText: "evidence 12",
  },
  {
    route: "/controls",
    label: "Controls",
    readySelector: 'input[placeholder="Filter loaded controls"]',
    filterSelector: 'input[placeholder="Filter loaded controls"]',
    filterText: "control 12",
  },
  {
    route: "/frameworks/soc2",
    label: "Framework detail",
    readySelector: "table",
  },
  {
    route: "/inventory",
    label: "Inventory",
    readySelector: "table.data-table",
    filterSelector: 'input[placeholder="Search..."]',
    filterText: "asset 12",
  },
  {
    route: `/impact?root_urn=${encodeURIComponent(impactRootURN)}`,
    label: "Impact Map",
    readySelector: 'input[placeholder="Search graph"]',
    filterSelector: 'input[placeholder="Search graph"]',
    filterText: "asset 12",
  },
  {
    route: `/explore?root_urn=${encodeURIComponent(impactRootURN)}`,
    label: "Graph Explore",
    readySelector: 'input[placeholder="Search graph"]',
    filterSelector: 'input[placeholder="Search graph"]',
    filterText: "asset 12",
  },
  {
    route: "/identity",
    label: "Identity",
    readySelector: 'input[placeholder="User, email, organization, provider"]',
    filterSelector: 'input[placeholder="User, email, organization, provider"]',
    filterText: "user 12",
    interactions: [
      {
        label: "open users",
        action: async (page) => page.getByRole("button", { name: /Users/ }).click(),
        readySelector: "table",
      },
    ],
  },
  {
    route: "/policies",
    label: "Policies",
    readySelector: 'input[placeholder="Filter loaded work"]',
    filterSelector: 'input[placeholder="Filter loaded work"]',
    filterText: "policy 12",
    interactions: [
      {
        label: "open register",
        action: async (page) => page.getByRole("button", { name: "Policy register" }).click(),
        readySelector: 'input[placeholder="Filter loaded policies"]',
      },
    ],
  },
  {
    route: "/reports?report_type=control",
    label: "Reports control",
    readySelector: 'input[placeholder="Filter context"]',
    filterSelector: 'input[placeholder="Filter context"]',
    filterText: "soc 2",
  },
];

const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));
const step = (message) => console.log(`\n[grc-scale] ${message}`);

async function main() {
  workDir = await mkdtemp(path.join(os.tmpdir(), "cerebro-grc-scale-"));
  await mkdir(path.join(workDir, "logs"), { recursive: true });
  process.on("SIGINT", () => void shutdown(130));
  process.on("SIGTERM", () => void shutdown(143));

  await requireCommand("npm", ["--version"]);
  const scenarios = [
    { name: "bounded", bounded: true, failOnThreshold: true },
    ...(includeStress ? [{ name: "stress", bounded: false, failOnThreshold: failOnStress }] : []),
  ];

  const results = [];
  for (const scenario of scenarios) {
    results.push(await runScenario(scenario));
  }

  const reportPath = path.join(workDir, "grc-scale-benchmark.json");
  await writeFile(reportPath, JSON.stringify({ generated_at: new Date().toISOString(), record_count: recordCount, thresholds: hardThresholds, results }, null, 2));
  printSummary(results);
  console.log(`\n[grc-scale] artifact ${reportPath}`);
  if (!retainArtifacts && !keepServices) {
    await rm(workDir, { recursive: true, force: true });
  }
}

async function runScenario(scenario) {
  step(`${scenario.name}: starting mock graph with ${recordCount.toLocaleString()} source records`);
  const apiPort = await freePort();
  const webPort = await freePort();
  const apiBase = `http://127.0.0.1:${apiPort}`;
  const webBase = `http://127.0.0.1:${webPort}`;
  const apiStats = new Map();
  currentApiServer = createMockApi({ bounded: scenario.bounded, recordCount, stats: apiStats });
  await listen(currentApiServer, apiPort);

  currentWebProcess = spawnLogged(`${scenario.name}-web`, "npm", ["run", "dev", "--", "--hostname", "127.0.0.1", "--port", String(webPort)], {
    cwd: webRoot,
    env: {
      ...process.env,
      CEREBRO_API_BASE: apiBase,
      NEXT_PUBLIC_CEREBRO_API_BASE: apiBase,
      CEREBRO_FORWARD_AUTH_HEADERS: "false",
      CEREBRO_IDENTITY_PROFILE: "local",
      CEREBRO_IDENTITY_REQUIRED: "false",
      CEREBRO_LOCAL_IDENTITY_FALLBACK: "1",
      CEREBRO_PROXY_CACHE_TTL_MS: "0",
      CEREBRO_PROXY_TIMEOUT_MS: "30000",
    },
  });

  try {
    await waitFor(`${scenario.name} web readiness`, async () => {
      const response = await fetch(`${webBase}/api/config`);
      if (!response.ok) throw new Error(`config status ${response.status}`);
    }, webReadyTimeoutMs);

    const browserResults = await benchmarkRoutes({ scenario, webBase });
    return {
      name: scenario.name,
      bounded: scenario.bounded,
      record_count: recordCount,
      web_base: webBase,
      api_bytes: apiStatsSnapshot(apiStats),
      routes: browserResults,
    };
  } finally {
    if (!keepServices) {
      await stopChild(currentWebProcess);
      currentWebProcess = null;
      await closeServer(currentApiServer);
      currentApiServer = null;
    }
  }
}

async function benchmarkRoutes({ scenario, webBase }) {
  const { chromium } = await import("@playwright/test");
  const browser = await chromium.launch({ headless: true });
  try {
    const context = await browser.newContext({ viewport: { width: 1440, height: 1000 } });
    const page = await context.newPage();
    const results = [];
    for (const spec of routeSpecs) {
      const pageErrors = [];
      page.on("pageerror", (error) => pageErrors.push(error.message));
      page.on("console", (message) => {
        if (message.type() === "error") pageErrors.push(message.text());
      });

      const started = performance.now();
      await page.goto(`${webBase}${spec.route}`, { waitUntil: "domcontentloaded", timeout: routeTimeoutMs });
      await page.waitForSelector(spec.readySelector, { state: "visible", timeout: routeTimeoutMs });
      await page.waitForLoadState("networkidle", { timeout: 10_000 }).catch(() => undefined);
      const usableMs = Math.round(performance.now() - started);
      const body = await page.locator("body").innerText({ timeout: 5000 }).catch(() => "");
      if (/Application error|Unhandled Runtime Error|Cerebro request failed \([45][0-9][0-9]\)/i.test(body)) {
        throw new Error(`${scenario.name} ${spec.route} rendered error text: ${body.slice(0, 500)}`);
      }
      if (pageErrors.length > 0) {
        throw new Error(`${scenario.name} ${spec.route} browser errors: ${pageErrors.slice(0, 3).join(" | ")}`);
      }

      const domNodes = await page.evaluate(() => document.querySelectorAll("*").length);
      const filterMs = await benchmarkFilter(page, spec);
      const interactions = [];
      for (const interaction of spec.interactions ?? []) {
        const interactionStarted = performance.now();
        await interaction.action(page);
        await page.waitForSelector(interaction.readySelector, { state: "visible", timeout: routeTimeoutMs });
        interactions.push({
          label: interaction.label,
          usable_ms: Math.round(performance.now() - interactionStarted),
          dom_nodes: await page.evaluate(() => document.querySelectorAll("*").length),
        });
      }
      const routeResult = {
        route: spec.route,
        label: spec.label,
        usable_ms: usableMs,
        dom_nodes: domNodes,
        filter_ms: filterMs,
        interactions,
        passed: routePasses({ usableMs, domNodes, filterMs, interactions }),
      };
      results.push(routeResult);
      console.log(
        `[grc-scale] ${scenario.name} ${spec.label}: usable ${usableMs}ms, dom ${domNodes}, filter ${formatDurationMs(filterMs)}`,
      );
    }
    return results;
  } finally {
    await browser.close();
  }
}

async function benchmarkFilter(page, spec) {
  if (!spec.filterSelector) return null;
  const locator = page.locator(spec.filterSelector).first();
  const started = performance.now();
  await locator.fill(spec.filterText);
  await page.waitForTimeout(100);
  return Math.round(performance.now() - started);
}

function routePasses({ usableMs, domNodes, filterMs, interactions }) {
  return usableMs <= hardThresholds.usableMs
    && domNodes <= hardThresholds.domNodes
    && (filterMs === null || filterMs <= hardThresholds.filterMs)
    && interactions.every((interaction) => interaction.usable_ms <= hardThresholds.usableMs && interaction.dom_nodes <= hardThresholds.domNodes);
}

function printSummary(results) {
  step("summary");
  const failed = [];
  for (const result of results) {
    for (const route of result.routes) {
      const status = route.passed ? "pass" : result.name === "stress" && !failOnStress ? "advisory" : "fail";
      console.log(
        `[grc-scale] ${result.name.padEnd(7)} ${status.padEnd(8)} ${route.label.padEnd(16)} usable=${route.usable_ms}ms dom=${route.dom_nodes} filter=${formatDurationMs(route.filter_ms)}`,
      );
      if (!route.passed && (result.name !== "stress" || failOnStress)) {
        failed.push(`${result.name} ${route.label}`);
      }
      for (const interaction of route.interactions ?? []) {
        const interactionPassed = interaction.usable_ms <= hardThresholds.usableMs && interaction.dom_nodes <= hardThresholds.domNodes;
        const interactionStatus = interactionPassed ? "pass" : result.name === "stress" && !failOnStress ? "advisory" : "fail";
        console.log(
          `[grc-scale] ${result.name.padEnd(7)} ${interactionStatus.padEnd(8)} ${route.label} ${interaction.label}: usable=${interaction.usable_ms}ms dom=${interaction.dom_nodes}`,
        );
        if (!interactionPassed && (result.name !== "stress" || failOnStress)) {
          failed.push(`${result.name} ${route.label} ${interaction.label}`);
        }
      }
    }
    const topPayloads = result.api_bytes
      .slice()
      .sort((left, right) => right.bytes - left.bytes)
      .slice(0, 5)
      .map((entry) => `${entry.path} ${(entry.bytes / 1024 / 1024).toFixed(2)} MB`)
      .join(", ");
    console.log(`[grc-scale] ${result.name} largest payloads: ${topPayloads || "none"}`);
  }
  if (failed.length > 0) {
    throw new Error(`Scale thresholds failed: ${failed.join(", ")}`);
  }
}

function formatDurationMs(value) {
  return typeof value === "number" ? `${value}ms` : "n/a";
}

function createMockApi({ bounded, recordCount: count, stats }) {
  const data = makeScaleData(count);
  return createServer((request, response) => {
    try {
      const url = new URL(request.url ?? "/", "http://127.0.0.1");
      const normalizedPath = url.pathname.replace(/^\/+|\/+$/g, "");
      if (request.method !== "GET") {
        return sendJSON(response, stats, normalizedPath, { ok: true, generated_at: generatedAt }, 201);
      }
      if (normalizedPath === "health" || normalizedPath === "healthz") {
        return sendJSON(response, stats, normalizedPath, { status: "ready", generated_at: generatedAt });
      }
      if (normalizedPath === "user/preferences") {
        return sendJSON(response, stats, normalizedPath, { tenant_id: tenantID, user_id: "scale-benchmark", preferences: {}, generated_at: generatedAt });
      }
      if (normalizedPath === "identity/orgs") {
        const organizations = boundedList(filterIdentityOrganizations(data.identityOrganizations, url.searchParams), url.searchParams, bounded);
        return sendJSON(response, stats, normalizedPath, {
          tenant_id: tenantID,
          organizations,
          meta: identityMeta(organizations, data.identityOrganizations, url.searchParams),
          generated_at: generatedAt,
        });
      }
      if (normalizedPath === "identity/users") {
        const users = boundedList(filterIdentityUsers(data.identityUsers, url.searchParams), url.searchParams, bounded);
        return sendJSON(response, stats, normalizedPath, {
          tenant_id: tenantID,
          users,
          meta: identityMeta(users, data.identityUsers, url.searchParams),
          generated_at: generatedAt,
        });
      }
      if (normalizedPath === "connectors") {
        const view = url.searchParams.get("view") === "summary" ? "summary" : "full";
        return sendJSON(response, stats, `${normalizedPath}?view=${view}`, connectorLibraryFixture(data, url.searchParams, bounded));
      }
      const connectorDetailMatch = /^connectors\/([^/]+)$/.exec(normalizedPath);
      if (connectorDetailMatch) {
        return sendJSON(response, stats, normalizedPath, connectorDetailFixture(data, decodeURIComponent(connectorDetailMatch[1]), url.searchParams, bounded));
      }
      if (normalizedPath === "connector-definitions") {
        const definitionRows = data.connectorDefinitions.map(connectorDefinitionListItem);
        const definitions = boundedList(definitionRows, url.searchParams, bounded);
        return sendJSON(response, stats, normalizedPath, {
          definitions,
          tenant_id: tenantID,
          runtime_store: "scale",
          generated_at: generatedAt,
        });
      }
      const connectorPlanMatch = /^connector-definitions\/([^/]+)\/promotion-plan$/.exec(normalizedPath);
      if (connectorPlanMatch) {
        return sendJSON(response, stats, normalizedPath, connectorPromotionPlanFixture(data, decodeURIComponent(connectorPlanMatch[1])));
      }
      if (normalizedPath === "grc/vendors") {
        const vendors = boundedList(data.vendors, url.searchParams, bounded);
        return sendJSON(response, stats, normalizedPath, {
          vendors,
          summary: vendorSummary(data.vendors),
          meta: listMeta(vendors, data.vendors, url.searchParams, bounded),
          generated_at: generatedAt,
        });
      }
      const vendorDetailMatch = /^grc\/vendors\/(.+)$/.exec(normalizedPath);
      if (vendorDetailMatch) {
        const vendor = data.vendors.find((item) => item.urn === decodeURIComponent(vendorDetailMatch[1])) ?? data.vendors[0];
        return sendJSON(response, stats, normalizedPath, vendorDetail(vendor));
      }
      if (normalizedPath === "grc/vendor-discoveries") {
        const discoveries = boundedList(data.vendorDiscoveries, url.searchParams, bounded);
        return sendJSON(response, stats, normalizedPath, {
          discoveries,
          summary: discoverySummary(data.vendorDiscoveries),
          source_summaries: sourceSummaries(data.vendorDiscoveries),
          decisions: [],
          decision_events: [],
          meta: listMeta(discoveries, data.vendorDiscoveries, url.searchParams, bounded),
          generated_at: generatedAt,
        });
      }
      if (normalizedPath === "grc/policy-lifecycle") {
        return sendJSON(response, stats, normalizedPath, policyLifecycleFixture(data, url.searchParams, bounded));
      }
      if (normalizedPath === "grc/evidence") {
        const evidence = boundedList(data.evidence, url.searchParams, bounded);
        return sendJSON(response, stats, normalizedPath, {
          evidence,
          meta: listMeta(evidence, data.evidence, url.searchParams, bounded),
          generated_at: generatedAt,
        });
      }
      if (normalizedPath === "grc/evidence-packets") {
        return sendJSON(response, stats, normalizedPath, evidencePacketsFixture(data, url.searchParams, bounded));
      }
      if (normalizedPath === "grc/findings") {
        const findings = boundedList(data.findings, url.searchParams, bounded);
        return sendJSON(response, stats, normalizedPath, {
          findings,
          meta: listMeta(findings, data.findings, url.searchParams, bounded),
          generated_at: generatedAt,
        });
      }
      const auditPacketMatch = /^grc\/audit-packets\/([^/]+)$/.exec(normalizedPath);
      if (auditPacketMatch) {
        const finding = data.findings.find((item) => item.id === decodeURIComponent(auditPacketMatch[1])) ?? data.findings[0];
        const evidence = boundedList(data.evidence, url.searchParams, bounded);
        const resourceURNs = Array.from({ length: recordCount }, (_, index) => `urn:cerebro:${tenantID}:asset:asset-${index}`);
        const sourceCoverageRefs = Array.from({ length: recordCount }, (_, index) => ({
          source_id: `source-${index % 32}`,
          dimension_id: `dimension-${index}`,
          dimension_type: index % 2 === 0 ? "resource" : "identity",
          support_level: index % 5 === 0 ? "partial" : "supported",
        }));
        return sendJSON(response, stats, normalizedPath, {
          id: `packet-${finding.id}`,
          finding: { ...finding, evidence_count: data.evidence.length, resource_urns: resourceURNs, source_coverage_refs: sourceCoverageRefs },
          evidence,
          controls: finding.controls,
          recommended_action: "Review owner, evidence freshness, and remediation due date.",
          metadata: reportMetadata("ready"),
          generated_at: generatedAt,
        });
      }
      if (normalizedPath === "grc/control-packets") {
        return sendJSON(response, stats, normalizedPath, controlPacketsFixture(data, url.searchParams, bounded));
      }
      if (normalizedPath === "grc/inventory/categories") {
        const assets = filterInventoryAssets(data.inventoryAssets, url.searchParams, { includeCategory: false, includeQuery: false });
        return sendJSON(response, stats, normalizedPath, {
          categories: inventoryCategories(assets),
          generated_at: generatedAt,
        });
      }
      if (normalizedPath === "grc/inventory/assets") {
        const allAssets = filterInventoryAssets(data.inventoryAssets, url.searchParams);
        const assets = boundedList(allAssets, url.searchParams, bounded);
        return sendJSON(response, stats, normalizedPath, {
          assets,
          summary: inventorySummary(allAssets),
          generated_at: generatedAt,
        });
      }
      if (/^grc\/entities\/[^/]+\/impact$/.test(normalizedPath)) {
        return sendJSON(response, stats, normalizedPath, entityImpactFixture(data, url.searchParams, bounded));
      }
      if (normalizedPath === "grc/frameworks") {
        return sendJSON(response, stats, normalizedPath, {
          version: "scale-v1",
          frameworks: [{ id: "soc2", name: "SOC 2", lifecycle: "active", family_count: 5, control_count: 64 }],
          generated_at: generatedAt,
        });
      }
      return sendJSON(response, stats, normalizedPath, { ok: true, path: normalizedPath, generated_at: generatedAt });
    } catch (error) {
      const body = JSON.stringify({ error: error instanceof Error ? error.message : String(error), generated_at: generatedAt });
      response.writeHead(500, { "content-type": "application/json; charset=utf-8" });
      response.end(body);
    }
  });
}

function makeScaleData(count) {
  const vendors = Array.from({ length: count }, (_, index) => makeVendor(index));
  const vendorDiscoveries = Array.from({ length: count }, (_, index) => makeVendorDiscovery(index));
  const evidence = Array.from({ length: count }, (_, index) => makeEvidence(index));
  const findings = Array.from({ length: Math.min(count, 500) }, (_, index) => makeFinding(index));
  const policies = Array.from({ length: count }, (_, index) => makePolicy(index));
  const documents = Array.from({ length: count }, (_, index) => makePolicyDocument(index));
  const riskRegister = Array.from({ length: count }, (_, index) => makeRisk(index));
  const governanceGaps = Array.from({ length: count }, (_, index) => makeGovernanceGap(index));
  const workQueue = Array.from({ length: count }, (_, index) => makePolicyWork(index));
  const documentWorkQueue = Array.from({ length: count }, (_, index) => makeDocumentWork(index));
  const inventoryAssets = Array.from({ length: count }, (_, index) => makeInventoryAsset(index));
  const connectors = Array.from({ length: count }, (_, index) => makeConnector(index));
  const connectorRuntimes = Array.from({ length: count }, (_, index) => makeConnectorRuntime(index));
  const connectorDefinitions = Array.from({ length: count }, (_, index) => makeConnectorDefinition(index, count));
  const identityOrganizations = Array.from({ length: count }, (_, index) => makeIdentityOrganization(index));
  const identityUsers = Array.from({ length: count }, (_, index) => makeIdentityUser(index));
  return { vendors, vendorDiscoveries, evidence, findings, policies, documents, riskRegister, governanceGaps, workQueue, documentWorkQueue, inventoryAssets, connectors, connectorRuntimes, connectorDefinitions, identityOrganizations, identityUsers };
}

function makeIdentityOrganization(index) {
  return {
    org_id: `org-${index}`,
    tenant_id: tenantID,
    name: `Organization ${String(index).padStart(5, "0")}`,
    slug: `organization-${index}`,
    domain: `org-${index}.example.com`,
    provider: index % 3 === 0 ? "okta" : "oidc",
    source: index % 2 === 0 ? "mcp_oauth" : "auth_config",
    external_id: `external-org-${index}`,
    user_count: 10 + (index % 500),
    last_synced_at: isoDay(-1 * (index % 20)),
    created_at: isoDay(-60),
    updated_at: isoDay(-1 * (index % 10)),
  };
}

function makeIdentityUser(index) {
  return {
    user_id: `user-${index}`,
    tenant_id: tenantID,
    org_id: `org-${index % Math.max(1, recordCount)}`,
    subject: `subject-${index}`,
    email: `user-${index}@example.com`,
    display_name: `User ${String(index).padStart(5, "0")}`,
    status: index % 11 === 0 ? "suspended" : "active",
    provider: index % 3 === 0 ? "okta" : "oidc",
    source: index % 2 === 0 ? "mcp_oauth" : "auth_config",
    roles: [`role-${index % 12}`, `role-${(index + 3) % 12}`],
    groups: [`group-${index % 20}`, `group-${(index + 5) % 20}`],
    last_seen_at: isoDay(-1 * (index % 30)),
    last_synced_at: isoDay(-1 * (index % 20)),
    created_at: isoDay(-90),
    updated_at: isoDay(-1 * (index % 10)),
  };
}

function identityMeta(rows, allRows, searchParams) {
  return {
    limit: positiveInteger(searchParams.get("limit"), rows.length || 100),
    loaded: rows.length,
    configured: allRows.length,
    persisted: allRows.length,
  };
}

function filterIdentityOrganizations(organizations, searchParams) {
  const tenant = searchParams.get("tenant_id")?.trim().toLowerCase() || "";
  const org = searchParams.get("org_id")?.trim().toLowerCase() || "";
  const query = searchParams.get("q")?.trim().toLowerCase() || "";
  return organizations.filter((item) => {
    if (tenant && item.tenant_id.toLowerCase() !== tenant) return false;
    if (org && item.org_id.toLowerCase() !== org) return false;
    if (!query) return true;
    return [item.org_id, item.name, item.slug, item.domain, item.provider, item.source]
      .filter(Boolean)
      .some((value) => String(value).toLowerCase().includes(query));
  });
}

function filterIdentityUsers(users, searchParams) {
  const tenant = searchParams.get("tenant_id")?.trim().toLowerCase() || "";
  const org = searchParams.get("org_id")?.trim().toLowerCase() || "";
  const query = searchParams.get("q")?.trim().toLowerCase() || "";
  return users.filter((item) => {
    if (tenant && item.tenant_id.toLowerCase() !== tenant) return false;
    if (org && item.org_id?.toLowerCase() !== org) return false;
    if (!query) return true;
    return [item.user_id, item.display_name, item.email, item.subject, item.org_id, item.provider, item.source, ...(item.roles ?? []), ...(item.groups ?? [])]
      .filter(Boolean)
      .some((value) => String(value).toLowerCase().includes(query));
  });
}

function makeVendor(index) {
  const riskLevels = ["critical", "high", "medium", "low"];
  const reviewStates = ["overdue", "due_soon", "current", "not_scheduled"];
  const lifecycleStates = ["approved", "in_review", "conditionally_approved", "restricted"];
  const riskLevel = riskLevels[index % riskLevels.length];
  const ownerMissing = index % 9 === 0;
  return {
    urn: `urn:cerebro:${tenantID}:vendor:vendor-${index}`,
    vendor_id: `vendor-${index}`,
    name: `Vendor ${String(index).padStart(5, "0")}`,
    source_id: `source-${index % 8}`,
    runtime_id: `runtime-${index % 32}`,
    provider: `Provider ${index % 12}`,
    status: index % 17 === 0 ? "inactive" : "active",
    category: ["identity", "payments", "data", "developer", "marketing"][index % 5],
    website_url: `https://scale.example.com/vendors/vendor-${index}`,
    services_provided: `Service group ${index % 20}`,
    source_status: "active",
    lifecycle_state: lifecycleStates[index % lifecycleStates.length],
    lifecycle_reason: "Observed in connected graph sources.",
    owner: ownerMissing ? undefined : `owner-${index % 50}@example.com`,
    security_owner_user_id: ownerMissing ? undefined : `security-${index % 30}@example.com`,
    business_owner_user_id: `business-${index % 40}@example.com`,
    owner_state: ownerMissing ? "missing" : "assigned",
    inherent_risk_level: riskLevel,
    residual_risk_level: riskLevels[(index + 1) % riskLevels.length],
    risk_level: riskLevel,
    risk_score: 40 + (index % 60),
    risk_score_level: riskLevel,
    risk_score_source: "graph",
    risk_tier: index % 4 === 0 ? "tier_1" : "tier_2",
    review_state: reviewStates[index % reviewStates.length],
    review_due_at: isoDay(index % 90),
    last_review_completed_at: isoDay(-1 * (index % 60)),
    assessment_state: index % 4 === 0 ? "overdue" : "current",
    assessment_progress: index % 101,
    open_assessments: index % 3,
    completed_assessments: index % 7,
    assessment_types: ["security_review", "privacy_review"],
    questionnaire_state: index % 5 === 0 ? "needs_review" : "complete",
    questionnaire_progress: 50 + (index % 51),
    evidence_freshness_state: index % 6 === 0 ? "stale" : "current",
    monitoring_state: index % 8 === 0 ? "alert" : "quiet",
    monitoring_signals: index % 8 === 0 ? [{ id: `signal-${index}`, label: "New external rating", severity: "medium" }] : [],
    renewal_state: index % 10 === 0 ? "due_soon" : "not_due",
    primary_contact: `contact-${index % 60}@example.com`,
    business_unit: `Unit ${index % 7}`,
    cost_center: `CC-${1000 + (index % 50)}`,
    exposure_level: riskLevel,
    exposure_reasons: [`Data access ${index % 4}`, `Region ${index % 5}`],
    packet_state: index % 11 === 0 ? "needs_work" : "ready",
    packet_ready_items: ["contract", "security review"],
    packet_missing_items: index % 11 === 0 ? ["owner attestation"] : [],
    remediation_state: index % 13 === 0 ? "overdue" : "not_due",
    open_remediation_items: index % 4,
    overdue_remediation_items: index % 13 === 0 ? 1 : 0,
    offboarding_state: index % 23 === 0 ? "due_soon" : "not_due",
    data_deletion_state: "not_due",
    contract_count: index % 4,
    security_review_count: index % 3,
    questionnaire_count: index % 5,
    assurance_document_count: index % 6,
    open_findings: index % 5,
    critical_findings: riskLevel === "critical" ? 1 : 0,
    high_findings: riskLevel === "high" ? 1 : 0,
    evidence_items: index % 9,
    queue_reasons: ownerMissing ? ["owner_missing"] : index % 6 === 0 ? ["stale_evidence"] : [],
    next_actions: ownerMissing ? [{ id: `assign-owner-${index}`, label: "Assign owner", action_type: "assign_owner", priority: 80 }] : [],
    close_actions: [],
    attributes: { source_system: `source-${index % 8}`, graph_size: String(recordCount) },
  };
}

function makeVendorDiscovery(index) {
  const decisionStates = ["discovered", "approved", "rejected", "ignored", "linked"];
  return {
    urn: `urn:cerebro:${tenantID}:vendor_discovery:discovery-${index}`,
    discovery_id: `discovery-${index}`,
    name: `Vendor ${String(index).padStart(5, "0")}`,
    normalized_name: `vendor ${index}`,
    source_id: `source-${index % 8}`,
    source_ids: [`source-${index % 8}`, `source-${(index + 1) % 8}`],
    runtime_id: `runtime-${index % 32}`,
    provider: `Provider ${index % 12}`,
    source_status: "observed",
    decision_state: decisionStates[index % decisionStates.length],
    category: ["identity", "payments", "data", "developer", "marketing"][index % 5],
    website_url: `https://scale.example.com/vendors/vendor-${index}`,
    confidence_score: 0.45 + ((index % 55) / 100),
    discovery_reason: "Observed through graph relationships and source usage.",
    first_observed_at: isoDay(-30 - (index % 90)),
    last_observed_at: isoDay(-1 * (index % 15)),
    linked_vendor_urn: index % 5 === 0 ? `urn:cerebro:${tenantID}:vendor:vendor-${index}` : undefined,
    signals: [
      { id: `signal-${index}-usage`, label: "Application usage", source_id: `source-${index % 8}`, confidence_score: 0.8, observed_at: isoDay(-1 * (index % 10)) },
      { id: `signal-${index}-expense`, label: "Spend record", source_id: `source-${(index + 1) % 8}`, confidence_score: 0.7, observed_at: isoDay(-1 * (index % 20)) },
    ],
    attributes: { discovered_from: "scale benchmark" },
  };
}

function makeEvidence(index) {
  return {
    id: `evidence-${index}`,
    finding_id: `finding-${index % 500}`,
    finding_title: `Finding ${index % 500}`,
    runtime_id: `runtime-${index % 32}`,
    run_id: `run-${index % 120}`,
    rule_id: `rule-${index % 80}`,
    claim_ids: [`claim-${index}`, `claim-${index + 1}`],
    event_ids: [`event-${index}`, `event-${index + 1}`],
    graph_root_urns: [`urn:cerebro:${tenantID}:service:service-${index % 200}`],
    created_at: isoDay(-1 * (index % 120)),
  };
}

function makeFinding(index) {
  const severities = ["critical", "high", "medium", "low"];
  return {
    id: `finding-${index}`,
    title: `Finding ${index}`,
    summary: "Synthetic finding for scale benchmark.",
    status: "open",
    severity: severities[index % severities.length],
    owner: `owner-${index % 50}@example.com`,
    entity: `urn:cerebro:${tenantID}:service:service-${index % 200}`,
    runtime_id: `runtime-${index % 32}`,
    source_id: `source-${index % 8}`,
    rule_id: `rule-${index % 80}`,
    risk_score: 40 + (index % 60),
    likelihood_score: 2,
    impact_score: 3,
    confidence_score: 4,
    risk_reasons: ["Synthetic scale risk"],
    sla_status: index % 4 === 0 ? "overdue" : "within_sla",
    controls: [{ framework_name: "SOC 2", control_id: `CC${index % 9}.${index % 4}`, title: "Logical access" }],
  };
}

function makePolicy(index) {
  return {
    id: `policy-${index}`,
    urn: `urn:cerebro:${tenantID}:policy:policy-${index}`,
    title: `Policy ${index}`,
    status: index % 5 === 0 ? "draft" : "approved",
    category: ["access", "incident", "data", "vendor"][index % 4],
    owner: `owner-${index % 40}@example.com`,
    reviewer: `reviewer-${index % 30}@example.com`,
    latest_version: `${1 + (index % 3)}.${index % 10}`,
    approval_status: index % 4 === 0 ? "pending" : "approved",
    review_due_at: isoDay(index % 120),
    acceptance_summary: { total: 100, accepted: 80 + (index % 20), pending: index % 8, overdue: index % 5 },
    exception_summary: { active: index % 4, expiring: index % 3 },
    versions: [],
    approvals: [],
    attestations: [],
    reviews: [],
    exceptions: [],
    events: [],
    actions: [],
    version_diffs: [],
    reminder_plan: [],
    assignments: [],
    controls: [{ urn: `urn:cerebro:${tenantID}:control:${index}`, control_id: `CC${index % 9}.${index % 4}`, framework: "SOC 2", title: "Logical access" }],
    evidence: [{ urn: `evidence-${index}`, title: `Evidence ${index}`, evidence_type: "policy_document" }],
  };
}

function makePolicyDocument(index) {
  return {
    id: `document-${index}`,
    urn: `urn:cerebro:${tenantID}:policy_document:document-${index}`,
    title: `Policy document ${index}`,
    document_type: "policy",
    document_class: "standard",
    status: index % 5 === 0 ? "draft" : "approved",
    owner: `owner-${index % 40}@example.com`,
    version: `${1 + (index % 3)}.${index % 10}`,
    review_due_at: isoDay(index % 120),
    policies: [{ id: `policy-${index}`, title: `Policy ${index}` }],
    risks: [],
    controls: [],
    evidence: [],
  };
}

function makeInventoryAsset(index) {
  const entityTypes = ["aws.ec2.instance", "aws.s3.bucket", "github.repository", "okta.application", "snowflake.database", "aws.iam.role"];
  const entityType = entityTypes[index % entityTypes.length];
  const riskLevels = ["critical", "high", "medium", "low"];
  const riskLevel = riskLevels[index % riskLevels.length];
  const ownerMissing = index % 7 === 0;
  const scopedOut = index % 19 === 0;
  const reportedIssue = index % 13 === 0;
  const publicAsset = entityType === "aws.s3.bucket" || (entityType === "github.repository" && index % 3 === 0);
  const owner = ownerMissing ? "" : `owner-${index % 40}@example.com`;
  const accountabilityState = scopedOut ? "not_required" : ownerMissing ? "required_missing" : "known";
  const reviewState = scopedOut ? "out_of_scope" : reportedIssue ? "reported_issue" : ownerMissing || publicAsset ? "needs_review" : "baseline";
  return {
    urn: `urn:cerebro:${tenantID}:${entityType}:asset-${index}`,
    entity_type: entityType,
    surface: "asset",
    label: `Asset ${String(index).padStart(5, "0")}`,
    source_id: `source-${index % 8}`,
    runtime_id: `runtime-${index % 32}`,
    risk_score: 30 + (index % 70),
    risk_level: riskLevel,
    risk_reasons: [publicAsset ? "public exposure" : "graph relationship"],
    scope_state: scopedOut ? "out_of_scope" : "in_scope",
    scope_reason: scopedOut ? "Support record" : undefined,
    asset_report_count: reportedIssue ? 1 : 0,
    latest_asset_report_status: reportedIssue ? "submitted" : undefined,
    latest_asset_report_reason: reportedIssue ? "Reviewer reported an inventory issue" : undefined,
    review_disposition: {
      state: reviewState,
      label: inventoryReviewLabel(reviewState),
      detail: inventoryReviewDetail(reviewState),
    },
    accountability: {
      state: accountabilityState,
      label: accountabilityState === "known" ? "Owner known" : accountabilityState === "required_missing" ? "Owner required" : "Owner not required",
      principal: owner || undefined,
    },
    attributes: {
      owner,
      provider: `Provider ${index % 8}`,
      region: `us-east-${1 + (index % 2)}`,
      account_id: `acct-${index % 12}`,
      resource_id: `asset-${index}`,
      resource_type: entityType,
      public: publicAsset ? "true" : "false",
      framework_refs: index % 2 === 0 ? "SOC 2,FedRAMP Rev. 5" : "SOC 2",
      graph_size: String(recordCount),
    },
  };
}

function makeConnector(index) {
  const status = index % 5 === 0 ? "degraded" : index % 7 === 0 ? "needs_attention" : "connected";
  return {
    source_id: `source-${index}`,
    name: `Source ${String(index).padStart(5, "0")}`,
    display_name: `Source ${String(index).padStart(5, "0")}`,
    description: "Synthetic connector generated for scale benchmark.",
    status,
    catalog_status: "catalog_ready",
    auth_model: "api_key",
    runtime_executable: true,
    setup_allowed: true,
    access_status: "available",
    readiness_stage: "setup_enabled",
    configured_runtimes: 1,
    healthy_runtimes: status === "connected" ? 1 : 0,
    needs_attention_runtimes: status === "connected" ? 0 : 1,
    emitted_kinds: ["asset", "identity", "finding"],
    catalog_categories: ["cloud", "identity"],
    resource_families: [
      {
        id: `resource-family-${index}`,
        label: `Resource family ${index % 20}`,
        projection: { template: `scale.resource.${index % 20}` },
      },
    ],
    integration_depth: {
      resource_types: 1 + (index % 6),
      coverage_dimensions: 2 + (index % 4),
      high_value_families: index % 3,
    },
  };
}

function makeConnectorRuntime(index) {
  const degraded = index % 5 === 0;
  const stale = index % 7 === 0;
  return {
    id: `runtime-${index}`,
    runtime_id: `runtime-${index}`,
    source_id: `source-${index}`,
    tenant_id: tenantID,
    family: "default",
    status: degraded ? "degraded" : stale ? "stale" : "healthy",
    health: degraded ? "degraded" : stale ? "stale" : "healthy",
    last_activity_at: isoDay(-1 * (index % 10)),
    cursor_pending: stale,
    checkpoint_cursor_present: !stale,
    watermark_lag_seconds: stale ? 86_400 + index : 300,
    schedule_context_configured: index % 11 !== 0,
    latest_graph_run: {
      id: `graph-run-${index}`,
      status: degraded ? "failed" : "succeeded",
      finished_at: isoDay(-1 * (index % 5)),
      error: degraded ? "Synthetic graph projection failure" : undefined,
      graph_nodes_after: 1000 + index,
      graph_links_after: 2000 + index,
    },
    latest_finding_evaluation: {
      id: `finding-eval-${index}`,
      runtime_id: `runtime-${index}`,
      status: degraded ? "failed" : "succeeded",
      finished_at: isoDay(-1 * (index % 5)),
      error: degraded ? "Synthetic finding evaluation failure" : undefined,
      findings_emitted: index % 9,
    },
    config: {},
  };
}

function makeConnectorResourceFamily(index, sourceID = "source-0") {
  const template = [
    "identity_user",
    "identity_group",
    "app_entitlement",
    "asset",
    "cloud_resource",
    "repository",
    "deployment",
    "finding",
  ][index % 8];
  return {
    id: `${sourceID}-family-${index}`,
    label: `Resource family ${index}`,
    method: "GET",
    path: `/scale/${sourceID}/resources/${index}`,
    default_enabled: index % 11 !== 0,
    projection: { template },
    coverage: [
      {
        id: `coverage-${index}`,
        label: `Coverage dimension ${index % 12}`,
        dimension_type: index % 2 === 0 ? "resource" : "identity",
        support_level: index % 5 === 0 ? "partial" : "supported",
      },
    ],
    high_value: index % 9 === 0,
  };
}

function makeConnectorDefinition(index, count) {
  const sourceID = `source-${index}`;
  const largeDefinition = index === 0;
  const familyCount = largeDefinition ? count : 4 + (index % 5);
  const reviewCount = largeDefinition ? count : 2 + (index % 4);
  const openCheckCount = largeDefinition ? count : 3 + (index % 4);
  return {
    id: `definition-${index}`,
    tenant_id: tenantID,
    source_id: sourceID,
    display_name: `Source ${String(index).padStart(5, "0")}`,
    description: "Synthetic source definition generated for scale benchmarking.",
    runtime: "json_api",
    stage: index % 5 === 0 ? "pilot" : "sandbox",
    auth: {
      model: "api_key",
      credential_fields: [{ key: "api_key", label: "API key", reference_only: true }],
      supported_store_ids: ["cerebro_vault", "aws_secrets_manager"],
      requires_references: true,
    },
    ingest: { mode: "pull" },
    resource_families: Array.from({ length: familyCount }, (_, familyIndex) => makeConnectorResourceFamily(familyIndex, sourceID)),
    scope_options: Array.from({ length: reviewCount }, (_, scopeIndex) => ({
      id: `${sourceID}-scope-${scopeIndex}`,
      label: `Scope ${scopeIndex}`,
      needs_user_review: true,
      permission_note: "Confirm this collection scope is approved for the tenant.",
      families: [`${sourceID}-family-${scopeIndex % Math.max(1, familyCount)}`],
      support_level: scopeIndex % 5 === 0 ? "partial" : "supported",
    })),
    validation: {
      status: index % 5 === 0 ? "warning" : "ready",
      summary: "Synthetic validation checks for scale benchmarking.",
      checks: Array.from({ length: openCheckCount }, (_, checkIndex) => ({
        id: `${sourceID}-check-${checkIndex}`,
        label: `Check ${checkIndex}`,
        status: checkIndex % 5 === 0 ? "blocked" : "warning",
        severity: checkIndex % 5 === 0 ? "error" : "warning",
        detail: "Synthetic setup check.",
        next_action: "Review the generated source definition before relying on it.",
        blocking: checkIndex % 5 === 0,
      })),
      observed_at: generatedAt,
    },
    promotion: {
      eligible_stages: ["sandbox", "pilot", "approved"],
      required_gates: ["definition_validation", "sandbox_probe", "admin_review"],
      next_action: "Run a bounded source validation.",
    },
    created_at: isoDay(-14),
    updated_at: isoDay(-1 * (index % 7)),
  };
}

function connectorDefinitionListItem(definition) {
  return {
    ...definition,
    resource_families: (definition.resource_families ?? []).slice(0, 3),
    scope_options: (definition.scope_options ?? []).slice(0, 3),
    validation: definition.validation ? {
      ...definition.validation,
      checks: (definition.validation.checks ?? []).slice(0, 3),
    } : undefined,
  };
}

function makeConnectorConnection(sourceID, index) {
  const needsAttention = index % 7 === 0;
  return {
    runtime_id: `runtime-${index}`,
    source_id: sourceID,
    tenant_id: tenantID,
    family: `family-${index % 24}`,
    status: needsAttention ? "needs_refresh" : "healthy",
    graph_status: needsAttention ? "behind" : "current",
    contract_probe_state: needsAttention ? "warning" : "passed",
    last_activity_at: isoDay(-1 * (index % 12)),
    checkpoint_watermark: isoDay(-1 * (index % 10)),
    watermark_lag_seconds: needsAttention ? 86_400 + index : 300 + index,
    records_accepted: 1000 + index,
    records_rejected: needsAttention ? index % 11 : 0,
    entities_projected: 500 + index,
    links_projected: 900 + index,
    cursor_pending: needsAttention,
    checkpoint_cursor_present: !needsAttention,
    next_action: needsAttention ? "inspect_runtime" : "monitor",
    scope_policy: index % 4 === 0 ? {
      excluded_families: [`family-${index % 24}`],
      excluded_asset_classes: [`asset-class-${index % 8}`],
      excluded_kinds: [`kind-${index % 10}`],
      excluded_resource_urns: [`urn:cerebro:${tenantID}:asset:asset-${index}`],
      excluded_resources: [{ type: "asset", id: `asset-${index}` }],
    } : undefined,
  };
}

function makeConnectorActivity(sourceID, index) {
  const failed = index % 9 === 0;
  return {
    id: `${sourceID}-activity-${index}`,
    runtime_id: `runtime-${index}`,
    source_id: sourceID,
    tenant_id: tenantID,
    family: `family-${index % 24}`,
    type: index % 2 === 0 ? "sync" : "graph",
    status: failed ? "failed" : "success",
    title: failed ? "Runtime sync failed" : "Runtime sync completed",
    description: failed ? "Synthetic runtime failure for scale benchmark." : "Synthetic runtime event for scale benchmark.",
    occurred_at: isoDay(-1 * (index % 10)),
    duration_seconds: 30 + (index % 300),
    records_accepted: 100 + index,
    records_rejected: failed ? index % 10 : 0,
    entities_projected: 200 + index,
    links_projected: 350 + index,
    failure_class: failed ? "synthetic_failure" : undefined,
  };
}

function makeConnectorDiagnostic(sourceID, index) {
  const stages = ["setup", "preflight", "source_sync", "contract_probe", "graph_projection", "finding_evaluation"];
  const stage = stages[index % stages.length];
  const failed = index % 11 === 0;
  return {
    stage,
    stage_order: index,
    status: failed ? "failed" : index % 5 === 0 ? "warning" : "success",
    title: `${humanize(stage)} ${index}`,
    description: failed ? "Synthetic diagnostic failure for scale benchmark." : "Synthetic diagnostic stage for scale benchmark.",
    occurred_at: isoDay(-1 * (index % 12)),
    runtime_id: `runtime-${index}`,
    correlation_id: `${sourceID}-correlation-${index}`,
    next_action: failed ? "inspect_runtime" : "monitor",
    failure_class: failed ? "synthetic_failure" : undefined,
    records_accepted: 100 + index,
    records_rejected: failed ? index % 10 : 0,
    entities_projected: 200 + index,
    links_projected: 300 + index,
    findings_evaluated: 20 + (index % 50),
    findings_opened: index % 7,
    duration_seconds: 15 + (index % 120),
  };
}

function connectorDetailFixture(data, sourceID, searchParams, bounded) {
  const baseConnector = data.connectors.find((connector) => connector.source_id === sourceID) ?? data.connectors[0];
  const limit = positiveInteger(searchParams.get("limit"), 100);
  const allFamilies = Array.from({ length: recordCount }, (_, index) => makeConnectorResourceFamily(index, sourceID));
  const allKinds = Array.from({ length: recordCount }, (_, index) => `scale.kind.${index}`);
  const allConnections = Array.from({ length: recordCount }, (_, index) => makeConnectorConnection(sourceID, index));
  const allActivity = Array.from({ length: recordCount }, (_, index) => makeConnectorActivity(sourceID, index));
  const allDiagnostics = Array.from({ length: recordCount }, (_, index) => makeConnectorDiagnostic(sourceID, index));
  return {
    generated_at: generatedAt,
    tenant_id: tenantID,
    connector: {
      ...baseConnector,
      source_id: sourceID,
      emitted_kinds: bounded ? allKinds.slice(0, limit) : allKinds,
      resource_families: bounded ? allFamilies.slice(0, limit) : allFamilies,
    },
    summary: {
      status: "healthy",
      status_reason: "Synthetic connector detail is current.",
      total_connections: allConnections.length,
      healthy_connections: allConnections.filter((connection) => connection.status === "healthy").length,
      needs_attention: allConnections.filter((connection) => connection.status !== "healthy").length,
      last_activity_at: isoDay(-1),
      sync_frequency_seconds: 3600,
      resource_types: allFamilies.length,
      emitted_kinds: allKinds.length,
    },
    connections: bounded ? allConnections.slice(0, limit) : allConnections,
    activity: bounded ? allActivity.slice(0, limit) : allActivity,
    diagnostic_timeline: bounded ? allDiagnostics.slice(0, limit) : allDiagnostics,
  };
}

function connectorLibraryFixture(data, searchParams, bounded) {
  if (!bounded) {
    return {
      connectors: data.connectors,
      runtimes: data.connectorRuntimes,
      source_runtimes: data.connectorRuntimes,
      tenant_id: tenantID,
      runtime_store: "scale",
      credential_transport: { available: true, algorithm: "sealed_box" },
      credential_vault: { available: true, detail: "benchmark vault" },
      generated_at: generatedAt,
      view: "full",
    };
  }

  const limit = Math.min(200, positiveInteger(searchParams.get("limit"), 200));
  const cursor = Math.max(0, Number.parseInt(searchParams.get("cursor") ?? "0", 10) || 0);
  const end = Math.min(cursor + limit, data.connectors.length);
  const pageConnectors = data.connectors.slice(cursor, end);
  const view = searchParams.get("view") === "summary" ? "summary" : "full";
  const connectors = view === "summary" ? pageConnectors.map((connector) => ({
    source_id: connector.source_id,
    display_name: connector.display_name ?? connector.name,
    status: connector.status,
    configured_runtimes: connector.configured_runtimes,
    healthy_runtimes: connector.healthy_runtimes,
    needs_attention_runtimes: connector.needs_attention_runtimes,
    catalog_status: connector.catalog_status,
    classifier_output: connector.classifier_output,
    auth_model: connector.auth_model,
    runtime_executable: connector.runtime_executable,
    catalog_categories: connector.catalog_categories,
    definition_origin: connector.definition_origin,
    readiness_stage: connector.readiness_stage,
    access_status: connector.access_status,
    setup_allowed: connector.setup_allowed,
    requestable: connector.requestable,
    integration_level: connector.integration_depth?.level,
    integration_score: connector.integration_depth?.score,
    resource_family_count: connector.integration_depth?.resource_families,
    emitted_kind_count: connector.integration_depth?.emitted_kinds,
    scope_option_count: connector.integration_depth?.scope_options,
  })) : pageConnectors;
  return {
    connectors,
    tenant_id: tenantID,
    runtime_store: "scale",
    generated_at: generatedAt,
    view,
    ...(view === "full"
      ? {
          credential_transport: { available: true, algorithm: "sealed_box" },
          credential_vault: { available: true, detail: "benchmark vault" },
        }
      : {}),
    page: {
      total: data.connectors.length,
      returned: connectors.length,
      limit,
      has_more: end < data.connectors.length,
      ...(end < data.connectors.length ? { next_cursor: String(end) } : {}),
    },
  };
}

function connectorPromotionPlanFixture(data, definitionID) {
  const definition = data.connectorDefinitions.find((item) => item.id === definitionID) ?? data.connectorDefinitions[0];
  const blockers = Array.from({ length: recordCount }, (_, index) => `definition-check-${index}`);
  return {
    generated_at: generatedAt,
    plan: {
      generated_at: generatedAt,
      definition,
      status: "blocked",
      summary: "Synthetic runtime activation plan generated for scale benchmarking.",
      next_stage: "pilot",
      blockers,
      warnings: blockers.slice(0, 20),
      metrics: {
        resource_families: definition?.resource_families?.length ?? 0,
        config_fields: definition?.config_fields?.length ?? 0,
        credential_fields: definition?.auth?.credential_fields?.length ?? 0,
        scope_options: definition?.scope_options?.length ?? 0,
        blocked_checks: blockers.length,
        warning_checks: 20,
        ready_checks: 0,
      },
      checklist: blockers.map((blocker, index) => ({
        id: blocker,
        title: `Activation check ${index}`,
        category: index % 2 === 0 ? "runtime" : "governance",
        status: index % 5 === 0 ? "blocked" : "warning",
        detail: "Synthetic activation check.",
        action: "Review before runtime activation.",
        blocking: index % 5 === 0,
      })),
    },
  };
}

function inventoryReviewLabel(state) {
  if (state === "needs_review") return "Needs review";
  if (state === "reported_issue") return "Reported issue";
  if (state === "out_of_scope") return "Scoped out";
  return "Baseline";
}

function inventoryReviewDetail(state) {
  if (state === "needs_review") return "Asset needs an accountable owner or exposure review.";
  if (state === "reported_issue") return "A reviewer reported this asset for triage.";
  if (state === "out_of_scope") return "Excluded from current GRC review.";
  return "No immediate GRC action required.";
}

function makeRisk(index) {
  return {
    id: `risk-${index}`,
    urn: `urn:cerebro:${tenantID}:risk:risk-${index}`,
    title: `Risk scenario ${index}`,
    status: index % 5 === 0 ? "open" : "monitored",
    owner: `owner-${index % 40}@example.com`,
    category: "operational",
    residual_risk: ["critical", "high", "medium", "low"][index % 4],
    inherent_risk: ["critical", "high", "medium", "low"][(index + 1) % 4],
    treatment: index % 3 === 0 ? "mitigate" : "monitor",
    review_due_at: isoDay(index % 90),
    treatment_due_at: isoDay(index % 120),
    policies: [{ id: `policy-${index}`, title: `Policy ${index}` }],
    controls: [],
    evidence: [],
  };
}

function makeGovernanceGap(index) {
  return {
    id: `gap-${index}`,
    subject: "policy",
    subject_id: `policy-${index}`,
    title: `Governance gap ${index}`,
    status: "open",
    gap_state: index % 4 === 0 ? "acknowledged" : "open",
    owner: `owner-${index % 40}@example.com`,
    severity: ["critical", "high", "medium", "low"][index % 4],
    reason: "Synthetic policy graph record is missing evidence.",
    action: "Attach evidence",
    action_id: "governance_gap.attach_evidence",
    rule_id: "policy.evidence",
    due_at: isoDay(index % 90),
    policy_id: `policy-${index}`,
    trace: [],
  };
}

function makePolicyWork(index) {
  return {
    id: `work-${index}`,
    policy_id: `policy-${index}`,
    policy: `Policy ${index}`,
    policy_version_id: `policy-${index}-v1`,
    record_urn: `urn:cerebro:${tenantID}:policy_work:work-${index}`,
    record_type: "policy.approval",
    action: "approval.approve",
    label: "Approve version",
    type: "approval",
    status: index % 5 === 0 ? "overdue" : "pending",
    owner: `owner-${index % 40}@example.com`,
    due_at: isoDay(index % 60),
    reason: "Pending policy approval",
  };
}

function makeDocumentWork(index) {
  return {
    id: `document-work-${index}`,
    document_id: `document-${index}`,
    risk_id: `risk-${index}`,
    policy_id: `policy-${index}`,
    document: `Policy document ${index}`,
    action: "document.review",
    type: "review",
    status: index % 5 === 0 ? "overdue" : "pending",
    owner: `owner-${index % 40}@example.com`,
    due_at: isoDay(index % 60),
    reason: "Document review due",
  };
}

function policyLifecycleFixture(data, searchParams, bounded) {
  const policies = boundedList(data.policies, searchParams, bounded);
  const documents = boundedList(data.documents, searchParams, bounded);
  const riskRegister = boundedList(data.riskRegister, searchParams, bounded);
  const governanceGaps = boundedList(data.governanceGaps, searchParams, bounded);
  const workQueue = boundedList(data.workQueue, searchParams, bounded);
  const documentWorkQueue = boundedList(data.documentWorkQueue, searchParams, bounded);
  return {
    summary: {
      policies: data.policies.length,
      templates: 4,
      lifecycle_events: data.workQueue.length,
      policy_documents: data.documents.length,
      risk_register_items: data.riskRegister.length,
      draft_versions: Math.ceil(data.policies.length / 5),
      draft_documents: Math.ceil(data.documents.length / 5),
      pending_approvals: Math.ceil(data.policies.length / 4),
      overdue_reviews: Math.ceil(data.policies.length / 5),
      documents_due_for_review: Math.ceil(data.documents.length / 5),
      governance_gaps: data.governanceGaps.length,
      open_governance_gaps: Math.ceil(data.governanceGaps.length * 0.7),
      in_progress_governance_gaps: Math.ceil(data.governanceGaps.length * 0.1),
      acknowledged_governance_gaps: Math.ceil(data.governanceGaps.length * 0.1),
      snoozed_governance_gaps: 0,
      resolved_governance_gaps: Math.ceil(data.governanceGaps.length * 0.1),
      high_governance_gaps: Math.ceil(data.governanceGaps.length / 4),
      open_exceptions: Math.ceil(data.policies.length / 4),
      expiring_exceptions: Math.ceil(data.policies.length / 8),
      open_risks: data.riskRegister.length,
      high_risks: Math.ceil(data.riskRegister.length / 4),
      attestation_coverage_pct: 82,
      overdue_attestations: Math.ceil(data.policies.length / 5),
      next_reminders: Math.ceil(data.policies.length / 6),
      mapped_controls: data.policies.length,
      evidence_items: data.evidence.length,
    },
    templates: Array.from({ length: 4 }, (_, index) => ({
      id: `template-${index}`,
      title: `Template ${index}`,
      status: "published",
      category: "policy",
      owner: "security@example.com",
      frameworks: ["SOC 2"],
      controls: [{ urn: `urn:cerebro:${tenantID}:control:template-${index}`, control_id: `CC${index}.1`, framework: "SOC 2", title: "Template control" }],
      evidence: [],
    })),
    policies,
    documents,
    risk_register: riskRegister,
    governance_gaps: governanceGaps,
    governance_rules: [{ id: "policy.evidence", label: "Policy evidence", severity: "medium", required: true, action_id: "governance_gap.attach_evidence", action: "Attach evidence" }],
    governance_gap_rollups: {
      by_state: [{ key: "open", label: "Open", count: governanceGaps.length }],
      by_owner: [{ key: "security", label: "Security", count: governanceGaps.length }],
      by_severity: [{ key: "high", label: "High", count: Math.ceil(governanceGaps.length / 4) }],
      by_subject: [{ key: "policy", label: "Policy", count: governanceGaps.length }],
    },
    work_queue: workQueue,
    document_work_queue: documentWorkQueue,
    reminders: [],
    events: workQueue.map((item) => ({
      id: `${item.id}:event`,
      event_kind: "grc.policy_lifecycle_event",
      record_type: item.record_type,
      record_id: item.id,
      policy_id: item.policy_id,
      action: item.action,
      status: item.status,
      actor: item.owner,
      reason: item.reason,
      occurred_at: generatedAt,
    })),
    available_actions: [{ id: "governance_gap.attach_evidence", action: "governance_gap.attach_evidence", label: "Attach evidence", event_kind: "grc.policy_lifecycle_event", record_type: "governance.gap", status: "in_progress" }],
    version_diffs: [],
    reminder_plan: [],
    mappings: policies.map((policy, index) => ({
      policy_id: policy.id,
      policy_title: policy.title,
      source_urn: policy.urn,
      source_type: "policy",
      target: { urn: `urn:cerebro:${tenantID}:service:service-${index % 200}`, entity_type: "service", label: `service-${index % 200}` },
      controls: policy.controls,
      evidence: policy.evidence,
    })),
    generated_at: generatedAt,
  };
}

function evidencePacketsFixture(data, searchParams, bounded) {
  const evidenceItems = boundedList(data.evidence, searchParams, bounded);
  const controls = evidenceItems.slice(0, 200).map((item, index) => ({
    id: `control-${index}`,
    control_id: `CC${Math.floor(index / 4)}.${index % 4}`,
    framework_name: "SOC 2",
    title: `Control ${index}`,
    status: index % 6 === 0 ? "missing" : "passing",
    evidence_score: 70 + (index % 30),
    missing_evidence_items: index % 6 === 0 ? 1 : 0,
    stale_evidence_items: index % 7 === 0 ? 1 : 0,
    evidence_request_ids: [`request-${index}`],
  }));
  const requests = evidenceItems.slice(0, 200).map((item, index) => ({
    id: `request-${index}`,
    title: `Evidence request ${index}`,
    control_id: controls[index % controls.length]?.control_id,
    status: index % 6 === 0 ? "missing" : "ready",
    quality: index % 7 === 0 ? "stale" : "ready",
    review_status: index % 5 === 0 ? "needs_review" : "accepted",
    evidence_packet_ids: [`packet-${index}`],
  }));
  return {
    version: "scale-v1",
    generated_at: generatedAt,
    program: { id: "scale-program", name: "Scale program", status: "ready", readiness_score: 82, open_review_count: Math.ceil(requests.length / 5) },
    frameworks: [{ framework_name: "SOC 2", framework_id: "soc2", framework_version: "2024", status: "ready", score: 82, controls: controls.length }],
    controls,
    evidence_requests: requests,
    evidence_packets: requests.map((request, index) => ({ id: `packet-${index}`, title: `Packet ${index}`, status: request.status === "missing" ? "needs_review" : "ready", control_id: request.control_id, evidence_request_ids: [request.id] })),
    evidence_reviews: [],
    activity: [],
    collection_sources: Array.from({ length: 8 }, (_, index) => ({ source_id: `source-${index}`, runtime_id: `runtime-${index}`, status: "collected", evidence_item_count: Math.ceil(evidenceItems.length / 8), finding_count: 20, last_synced_at: generatedAt })),
    evidence_items: evidenceItems,
    resource_subjects: evidenceItems.slice(0, 200).map((item, index) => ({ urn: item.graph_root_urns[0], entity_type: "service", label: `service-${index}` })),
    evidence_lineage: evidenceItems.slice(0, 200).map((item, index) => ({ evidence_id: item.id, control_ids: [controls[index % controls.length]?.id], evidence_packet_ids: [`packet-${index}`], claim_ids: item.claim_ids, event_ids: item.event_ids, graph_root_urns: item.graph_root_urns })),
    claim_records: evidenceItems.slice(0, 200).map((item) => ({ id: item.claim_ids[0], evidence_ids: [item.id] })),
    evaluation_runs: Array.from({ length: Math.min(120, evidenceItems.length) }, (_, index) => ({ id: `run-${index}`, runtime_id: `runtime-${index % 32}`, source_id: `source-${index % 8}` })),
    graph_path_records: evidenceItems.slice(0, 200).map((item, index) => ({ id: `path-${index}`, evidence_id: item.id, from_urn: item.graph_root_urns[0], relation: "HAS_EVIDENCE", to_urn: item.id, observed_at: generatedAt })),
    exceptions_acceptances: [],
    export_artifacts: [],
    export: { formats: ["markdown"], redaction_modes: ["share_safe"] },
    snapshot: { id: "snapshot-scale", hash: "scale", generated_at: generatedAt, control_count: controls.length, evidence_request_count: requests.length, evidence_packet_count: requests.length, collection_source_count: 8, evidence_item_count: evidenceItems.length, resource_subject_count: Math.min(200, evidenceItems.length), lineage_count: Math.min(200, evidenceItems.length), claim_record_count: Math.min(200, evidenceItems.length), evaluation_run_count: Math.min(120, evidenceItems.length), graph_path_count: Math.min(200, evidenceItems.length), open_review_count: Math.ceil(requests.length / 5) },
    metadata: reportMetadata("ready"),
  };
}

function controlPacketsFixture(data, searchParams, bounded) {
  const allControls = Array.from({ length: recordCount }, (_, index) => ({
    id: `control-${index}`,
    framework_name: "SOC 2",
    framework_id: "soc2",
    framework_version: "2024",
    family_id: `family-${index % 8}`,
    family_name: `Family ${index % 8}`,
    control_id: `CC${Math.floor(index / 4)}.${index % 4}`,
    title: `Control ${index}`,
    owner_domain: `owner-${index % 24}@example.com`,
    status: index % 6 === 0 ? "failing" : "passing",
    open_findings: index % 6 === 0 ? 1 + (index % 4) : index % 9 === 0 ? 1 : 0,
    critical_findings: index % 24 === 0 ? 1 : 0,
    high_findings: index % 12 === 0 ? 1 : 0,
    evidence_score: 72 + (index % 26),
    evidence_items: index % 9,
    missing_evidence_items: index % 6 === 0 ? 1 : 0,
    stale_evidence_items: index % 7 === 0 ? 1 : 0,
    evidence_expectations: 3,
    evidence_quality: index % 7 === 0 ? "stale" : "ready",
    audit_summary: "Synthetic control generated for scale benchmark.",
    mapped_rules: [`rule-${index % 80}`],
    reasons: index % 6 === 0 ? ["Missing evidence"] : [],
  }));
  const controls = boundedList(allControls, searchParams, bounded);
  const packetControls = controls.map((control, index) => ({
    control: {
      framework_id: control.framework_id,
      framework_name: control.framework_name,
      framework_version: control.framework_version,
      family_id: control.family_id,
      family_name: control.family_name,
      control_id: control.control_id,
      title: control.title,
    },
    status: control.status,
    reasons: control.status === "failing" ? ["Missing evidence"] : [],
    mapped_rules: [`rule-${index % 80}`],
    evidence: {
      summary: {
        evidence_ids: [`evidence-${index}`],
        evidence_expectation_ids: [`expectation-${index}`],
      },
      expectations: [{ id: `expectation-${index}`, title: "Evidence expectation", required: true, status: control.status === "failing" ? "missing" : "ready" }],
      items: [{ id: `evidence-${index}`, rule_id: `rule-${index % 80}`, status: "ready", quality: "ready", observed_at: generatedAt }],
    },
    audit_readiness: {
      score: control.evidence_score,
      rating: control.status === "failing" ? "needs_attention" : "ready",
      summary: control.status === "failing" ? "Missing evidence" : "Ready",
      evidence_items: control.evidence_items,
      required_expectations: control.evidence_expectations,
      missing_evidence: control.missing_evidence_items,
      stale_evidence: control.stale_evidence_items,
    },
  }));
  return {
    profile: { id: "baseline", name: "Baseline controls" },
    packet: {
      version: "scale-v1",
      selection_id: "baseline",
      generated_at: generatedAt,
      summary: {
        selection_id: "baseline",
        total: allControls.length,
        by_status: {
          passing: allControls.filter((control) => control.status === "passing").length,
          failing: allControls.filter((control) => control.status === "failing").length,
          missing_evidence: allControls.filter((control) => control.missing_evidence_items > 0).length,
          stale_evidence: allControls.filter((control) => control.stale_evidence_items > 0).length,
        },
      },
      controls: packetControls,
    },
    controls,
    metadata: reportMetadata("ready"),
    generated_at: generatedAt,
  };
}

function filterInventoryAssets(assets, searchParams, options = {}) {
  const includeCategory = options.includeCategory ?? true;
  const includeQuery = options.includeQuery ?? true;
  const sourceID = searchParams.get("source_id")?.trim();
  const surface = searchParams.get("surface")?.trim() || "asset";
  const categoryID = includeCategory ? searchParams.get("category_id")?.trim() : "";
  const query = includeQuery ? searchParams.get("q")?.trim().toLowerCase() : "";
  const scopeState = searchParams.get("scope_state")?.trim();
  const reviewState = searchParams.get("review_state")?.trim();
  const accountabilityState = searchParams.get("accountability_state")?.trim();

  return assets.filter((asset) => {
    if (sourceID && asset.source_id !== sourceID) return false;
    if (surface && surface !== "all" && asset.surface !== surface) return false;
    if (categoryID && asset.entity_type !== categoryID && asset.attributes?.resource_type !== categoryID) return false;
    if (scopeState && asset.scope_state !== scopeState) return false;
    if (reviewState && asset.review_disposition?.state !== reviewState) return false;
    if (accountabilityState && asset.accountability?.state !== accountabilityState) return false;
    if (query) {
      const haystack = [
        asset.label,
        asset.urn,
        asset.entity_type,
        asset.source_id,
        asset.runtime_id,
        ...Object.values(asset.attributes ?? {}),
      ].join(" ").toLowerCase();
      if (!haystack.includes(query)) return false;
    }
    return true;
  });
}

function inventoryCategories(assets) {
  const categories = new Map();
  for (const asset of assets) {
    const id = asset.entity_type;
    const category = categories.get(id) ?? { id, label: humanize(id), surface: asset.surface, entity_types: [id], count: 0 };
    category.count += 1;
    categories.set(id, category);
  }
  return Array.from(categories.values()).sort((left, right) => right.count - left.count || left.label.localeCompare(right.label));
}

function inventorySummary(assets) {
  const total = assets.length;
  const inScope = assets.filter((asset) => asset.scope_state !== "out_of_scope").length;
  const outOfScope = total - inScope;
  const highRisk = assets.filter((asset) => ["critical", "high"].includes(asset.risk_level)).length;
  const needsReview = assets.filter((asset) => asset.review_disposition?.state === "needs_review").length;
  const reportedIssue = assets.filter((asset) => asset.review_disposition?.state === "reported_issue").length;
  const baseline = assets.filter((asset) => asset.review_disposition?.state === "baseline").length;
  const ownerRequired = assets.filter((asset) => asset.accountability?.state === "required_missing").length;
  const accountable = assets.filter((asset) => asset.accountability?.state === "known").length;
  const publicAssets = assets.filter((asset) => (asset.attributes?.public || "").toLowerCase() === "true").length;
  const surfaceCounts = {};
  for (const asset of assets) {
    const surface = asset.surface || "asset";
    surfaceCounts[surface] = (surfaceCounts[surface] ?? 0) + 1;
  }

  return {
    total_assets: total,
    in_scope_assets: inScope,
    out_of_scope_assets: outOfScope,
    high_risk_assets: highRisk,
    unassigned_assets: ownerRequired,
    baseline_assets: baseline,
    needs_review_assets: needsReview,
    owner_required_assets: ownerRequired,
    accountable_assets: accountable,
    reported_issue_assets: reportedIssue,
    org_groups: new Set(assets.map((asset) => asset.attributes?.account_id).filter(Boolean)).size,
    public_assets: publicAssets,
    scoped_coverage_pct: total ? Math.round((inScope / total) * 100) : 0,
    assigned_coverage_pct: total ? Math.round((accountable / total) * 100) : 0,
    surface_counts: surfaceCounts,
  };
}

function entityImpactFixture(data, searchParams, bounded) {
  const rootURN = searchParams.get("root_urn")?.trim() || impactRootURN;
  const allNeighbors = Array.from({ length: recordCount }, (_, index) => ({
    urn: `urn:cerebro:${tenantID}:asset:asset-${index}`,
    entity_type: ["service", "repository", "identity_user", "storage_bucket", "vendor"][index % 5],
    label: `Impact asset ${String(index).padStart(5, "0")}`,
    attributes: {
      risk_score: String(30 + (index % 70)),
      source_id: `source-${index % 8}`,
      runtime_id: `runtime-${index % 32}`,
    },
  }));
  const allRelations = allNeighbors.flatMap((node, index) => {
    const direct = {
      from_urn: rootURN,
      relation: index % 3 === 0 ? "depends_on" : "affects",
      to_urn: node.urn,
      attributes: { risk_score: String(40 + (index % 60)) },
    };
    if (index === 0) return [direct];
    return [
      direct,
      {
        from_urn: allNeighbors[index - 1].urn,
        relation: "related_to",
        to_urn: node.urn,
        attributes: { risk_score: String(20 + (index % 60)) },
      },
    ];
  });
  const limit = positiveInteger(searchParams.get("limit"), 75);
  const neighbors = bounded ? allNeighbors.slice(0, limit) : allNeighbors;
  const visibleURNs = new Set([rootURN, ...neighbors.map((node) => node.urn)]);
  const relations = (bounded ? allRelations.filter((relation) => visibleURNs.has(relation.from_urn) && visibleURNs.has(relation.to_urn)).slice(0, limit * 2) : allRelations);
  const findings = boundedList(data.findings, new URLSearchParams({ limit: String(Math.min(limit, 100)) }), bounded);
  return {
    entity_urn: rootURN,
    graph: {
      root: {
        urn: rootURN,
        entity_type: "service",
        label: "Impact root",
        attributes: { risk_score: "88", source_id: "source-root", runtime_id: "runtime-root" },
      },
      neighbors,
      relations,
    },
    findings,
    generated_at: generatedAt,
  };
}

function humanize(value) {
  return String(value || "")
    .replace(/[_./-]+/g, " ")
    .replace(/\b\w/g, (char) => char.toUpperCase());
}

function vendorDetail(vendor) {
  return {
    vendor,
    relationships: {
      contracts: [{ urn: `${vendor.urn}:contract`, entity_type: "contract", label: `${vendor.name} contract`, source_id: vendor.source_id, runtime_id: vendor.runtime_id, relation: "contract" }],
      security_reviews: [{ urn: `${vendor.urn}:review`, entity_type: "security_review", label: `${vendor.name} review`, source_id: vendor.source_id, runtime_id: vendor.runtime_id, relation: "review" }],
      owners: vendor.owner ? [{ urn: `${vendor.urn}:owner`, entity_type: "identity_user", label: vendor.owner, source_id: vendor.source_id, runtime_id: vendor.runtime_id, relation: "owner" }] : [],
    },
    findings: [],
    evidence: [],
    generated_at: generatedAt,
  };
}

function vendorSummary(vendors) {
  return {
    total_vendors: vendors.length,
    active_vendors: vendors.filter((vendor) => vendor.status === "active").length,
    high_risk_vendors: vendors.filter((vendor) => ["critical", "high"].includes(vendor.risk_level)).length,
    owner_missing_vendors: vendors.filter((vendor) => vendor.owner_state === "missing").length,
    review_overdue_vendors: vendors.filter((vendor) => vendor.review_state === "overdue").length,
    review_due_soon_vendors: vendors.filter((vendor) => vendor.review_state === "due_soon").length,
    review_not_scheduled: vendors.filter((vendor) => vendor.review_state === "not_scheduled").length,
    risk_queue_vendors: vendors.filter((vendor) => (vendor.queue_reasons?.length ?? 0) > 0).length,
    stale_evidence_vendors: vendors.filter((vendor) => vendor.evidence_freshness_state === "stale").length,
    restricted_vendors: vendors.filter((vendor) => ["restricted", "conditionally_approved"].includes(vendor.lifecycle_state)).length,
    critical_tier_vendors: vendors.filter((vendor) => vendor.risk_tier === "tier_1").length,
    assessment_due_vendors: vendors.filter((vendor) => ["overdue", "due_soon", "in_progress"].includes(vendor.assessment_state)).length,
    monitoring_alert_vendors: vendors.filter((vendor) => ["alert", "critical"].includes(vendor.monitoring_state)).length,
    renewal_due_vendors: vendors.filter((vendor) => ["notice_due", "due_soon", "overdue"].includes(vendor.renewal_state)).length,
    packet_blocked_vendors: vendors.filter((vendor) => ["blocked", "needs_work"].includes(vendor.packet_state)).length,
    high_exposure_vendors: vendors.filter((vendor) => ["critical", "high"].includes(vendor.exposure_level)).length,
    remediation_due_vendors: vendors.filter((vendor) => ["overdue", "due_soon"].includes(vendor.remediation_state)).length,
    offboarding_due_vendors: vendors.filter((vendor) => ["overdue", "due_soon"].includes(vendor.offboarding_state)).length,
    open_findings: vendors.reduce((sum, vendor) => sum + (vendor.open_findings ?? 0), 0),
    critical_findings: vendors.reduce((sum, vendor) => sum + (vendor.critical_findings ?? 0), 0),
    high_findings: vendors.reduce((sum, vendor) => sum + (vendor.high_findings ?? 0), 0),
    evidence_items: vendors.reduce((sum, vendor) => sum + (vendor.evidence_items ?? 0), 0),
  };
}

function discoverySummary(discoveries) {
  return {
    total_discoveries: discoveries.length,
    discovered: discoveries.filter((item) => item.decision_state === "discovered").length,
    approved: discoveries.filter((item) => item.decision_state === "approved").length,
    rejected: discoveries.filter((item) => item.decision_state === "rejected").length,
    ignored: discoveries.filter((item) => item.decision_state === "ignored").length,
    linked: discoveries.filter((item) => item.linked_vendor_urn || item.decision_state === "linked").length,
    source_count: new Set(discoveries.map((item) => item.source_id)).size,
    evidence_signals: discoveries.reduce((sum, item) => sum + (item.signals?.length ?? 0), 0),
  };
}

function sourceSummaries(discoveries) {
  const bySource = new Map();
  for (const discovery of discoveries) {
    const sourceID = discovery.source_id ?? "unknown";
    const existing = bySource.get(sourceID) ?? { source_id: sourceID, provider: discovery.provider, runtime_id: discovery.runtime_id, status: "ready", freshness: "current", total: 0, discovered: 0, approved: 0, rejected: 0, ignored: 0, linked: 0, last_synced_at: generatedAt };
    existing.total += 1;
    existing[discovery.decision_state] = (existing[discovery.decision_state] ?? 0) + 1;
    if (discovery.linked_vendor_urn) existing.linked += 1;
    bySource.set(sourceID, existing);
  }
  return Array.from(bySource.values());
}

function reportMetadata(status) {
  return {
    readiness: { status, score: 82, blockers: [] },
    scope: { exclusions: { total: 0 }, incremental_fetch: { summary: "Scale benchmark data" } },
    generated_by: "grc-scale-benchmark",
  };
}

function boundedList(items, searchParams, bounded) {
  if (!bounded) return items;
  const limit = positiveInteger(searchParams.get("limit"), 200);
  return items.slice(0, limit);
}

function listMeta(returnedItems, allItems, searchParams, bounded) {
  const limit = bounded ? positiveInteger(searchParams.get("limit"), returnedItems.length) : allItems.length;
  return {
    limit,
    returned: returnedItems.length,
    total: allItems.length,
    truncated: returnedItems.length < allItems.length,
  };
}

function sendJSON(response, stats, normalizedPath, payload, status = 200) {
  const body = JSON.stringify(payload);
  const existing = stats.get(normalizedPath) ?? { path: normalizedPath, requests: 0, bytes: 0 };
  existing.requests += 1;
  existing.bytes += Buffer.byteLength(body);
  stats.set(normalizedPath, existing);
  response.writeHead(status, {
    "content-type": "application/json; charset=utf-8",
    "cache-control": "no-store",
    "x-cerebro-scale-records": String(recordCount),
  });
  response.end(body);
}

function apiStatsSnapshot(stats) {
  return Array.from(stats.values()).sort((left, right) => left.path.localeCompare(right.path));
}

function isoDay(offsetDays) {
  const date = new Date(generatedAt);
  date.setUTCDate(date.getUTCDate() + offsetDays);
  return date.toISOString();
}

function positiveInteger(value, fallback) {
  const parsed = Number.parseInt(String(value ?? ""), 10);
  return Number.isFinite(parsed) && parsed > 0 ? parsed : fallback;
}

async function freePort() {
  return new Promise((resolve, reject) => {
    const server = net.createServer();
    server.once("error", reject);
    server.listen(0, "127.0.0.1", () => {
      const address = server.address();
      server.close(() => {
        if (address && typeof address === "object") resolve(address.port);
        else reject(new Error("Could not allocate a free port"));
      });
    });
  });
}

async function listen(server, port) {
  await new Promise((resolve, reject) => {
    server.once("error", reject);
    server.listen(port, "127.0.0.1", resolve);
  });
}

async function closeServer(server) {
  if (!server) return;
  await new Promise((resolve) => server.close(resolve));
}

async function requireCommand(command, commandArgs) {
  await run(command, commandArgs, { quiet: true });
}

async function run(command, commandArgs, options = {}) {
  const child = spawn(command, commandArgs, {
    cwd: options.cwd ?? webRoot,
    env: options.env ?? process.env,
    stdio: ["ignore", "pipe", "pipe"],
  });
  let stdout = "";
  let stderr = "";
  child.stdout.on("data", (chunk) => { stdout += chunk.toString(); });
  child.stderr.on("data", (chunk) => { stderr += chunk.toString(); });
  return new Promise((resolve, reject) => {
    child.on("error", reject);
    child.on("close", (code) => {
      if (code === 0) {
        resolve({ stdout, stderr });
      } else {
        reject(new Error(`${command} ${commandArgs.join(" ")} exited ${code}\n${stdout}\n${stderr}`));
      }
    });
  });
}

function spawnLogged(name, command, commandArgs, options = {}) {
  const child = spawn(command, commandArgs, {
    cwd: options.cwd ?? webRoot,
    env: options.env ?? process.env,
    stdio: ["ignore", "pipe", "pipe"],
  });
  const logPath = path.join(workDir, "logs", `${name}.log`);
  const chunks = [];
  const capture = (chunk) => {
    const value = chunk.toString();
    chunks.push(value);
    if (chunks.length > 200) chunks.shift();
    void writeFile(logPath, chunks.join(""), "utf8");
  };
  child.stdout.on("data", capture);
  child.stderr.on("data", capture);
  child.on("error", (error) => {
    chunks.push(`\n${error.message}\n`);
    void writeFile(logPath, chunks.join(""), "utf8");
  });
  return child;
}

async function waitFor(label, action, timeoutMs) {
  const started = Date.now();
  let lastError;
  while (Date.now() - started < timeoutMs) {
    try {
      await action();
      return;
    } catch (error) {
      lastError = error;
      await sleep(500);
    }
  }
  const logs = currentWebProcess ? await tailLog(`${currentWebProcess.spawnargs?.[0] ?? "web"}`).catch(() => "") : "";
  throw new Error(`${label} timed out after ${timeoutMs}ms: ${lastError?.message ?? "unknown error"}${logs ? `\n${logs}` : ""}`);
}

async function tailLog() {
  const logsDir = path.join(workDir, "logs");
  const candidates = [`bounded-web.log`, `stress-web.log`];
  const parts = [];
  for (const candidate of candidates) {
    const filePath = path.join(logsDir, candidate);
    const content = await readFile(filePath, "utf8").catch(() => "");
    if (content) parts.push(`\n--- ${candidate} ---\n${content.slice(-4000)}`);
  }
  return parts.join("");
}

async function stopChild(child) {
  if (!child || child.exitCode !== null) return;
  child.kill("SIGTERM");
  await Promise.race([
    new Promise((resolve) => child.once("close", resolve)),
    sleep(5000).then(() => {
      if (child.exitCode === null) child.kill("SIGKILL");
    }),
  ]);
}

async function shutdown(code) {
  await stopChild(currentWebProcess);
  await closeServer(currentApiServer);
  if (!retainArtifacts && !keepServices && workDir) {
    await rm(workDir, { recursive: true, force: true });
  }
  process.exit(code);
}

main().catch(async (error) => {
  console.error(`\n[grc-scale] failed: ${error instanceof Error ? error.stack || error.message : String(error)}`);
  await shutdown(1);
});
