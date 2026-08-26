import { spawn } from "node:child_process";
import { EventEmitter } from "node:events";
import { rm } from "node:fs/promises";
import path from "node:path";
import { PassThrough, Writable } from "node:stream";
import { describe, expect, it, vi } from "vitest";

import {
  assertDashboardScope,
  assertHomepageAPIScope,
  assertHomepageP95,
  assertPageContract,
  assertPublicConfig,
  closeLogStream,
  createDeadline,
  discoverPageRoutes,
  isExpectedLocal404,
  isExpectedRouteRedirect,
  parseArgs,
  parseFixtureReadyLine,
  routeBugbashFindings,
  routeWithScope,
  runPortableWebFixtureE2E,
  sameOriginApplicationRoute,
  stopProcessTree,
  validateHttpContracts,
  waitForFixtureEndpoint,
  windowsTaskkillArgs,
} from "./portable-web-fixture-e2e.mjs";

const headers = (values = {}) => new Headers(values);

describe("portable web fixture E2E options", () => {
  it("uses child-owned port allocation, Chromium, and a hard deadline by default", () => {
    expect(parseArgs([])).toEqual({
      allRoutes: false,
      browser: true,
      homeSamples: 5,
      maxHomeP95Ms: 1_000,
      port: 0,
      timeoutMs: 180_000,
    });
  });

  it("parses explicit browser, port, and timeout options", () => {
    expect(parseArgs(["--no-browser", "--port=43123", "--timeout-ms", "1200", "--home-samples=9", "--max-home-p95-ms", "999"]))
      .toEqual({
        allRoutes: false,
        browser: false,
        homeSamples: 9,
        maxHomeP95Ms: 999,
        port: 43123,
        timeoutMs: 1200,
      });
  });

  it("enables the bounded full-route harness with a longer default deadline", () => {
    expect(parseArgs(["--all-routes"]))
      .toEqual({
        allRoutes: true,
        browser: true,
        homeSamples: 5,
        maxHomeP95Ms: 1_000,
        port: 0,
        timeoutMs: 420_000,
      });
    expect(parseArgs(["--timeout-ms=1200", "--all-routes"]).timeoutMs).toBe(1200);
  });

  it("keeps the former readiness flag as an overall-timeout alias", () => {
    expect(parseArgs(["--ready-timeout-ms=1200"]).timeoutMs).toBe(1200);
  });

  it("rejects unknown and invalid options", () => {
    expect(() => parseArgs(["--keep"])).toThrow("Unknown option");
    expect(() => parseArgs(["--port", "70000"])).toThrow("between 0 and 65535");
    expect(() => parseArgs(["--timeout-ms=0"])).toThrow("between 1");
    expect(() => parseArgs(["--home-samples=0"])).toThrow("between 1 and 100");
    expect(() => parseArgs(["--max-home-p95-ms=0"])).toThrow("between 1 and 60000");
  });
});

describe("portable web fixture route bug bash", () => {
  it("hard-fails homepage data-ready p95 at one second", () => {
    expect(assertHomepageP95([120, 140, 180, 250, 999], 1_000)).toBe(999);
    expect(() => assertHomepageP95([120, 140, 180, 250, 1_000], 1_000))
      .toThrow("must be below 1000ms");
  });

  it("requires both tenant and workspace on the dashboard request", () => {
    const url = "http://127.0.0.1:43123/api/cerebro/grc/dashboard?tenant_id=tenant-a&workspace_id=workspace-b";
    expect(() => assertDashboardScope(url, { tenantID: "tenant-a", workspaceID: "workspace-b" }))
      .not.toThrow();
    expect(() => assertDashboardScope(url, { tenantID: "tenant-a", workspaceID: "workspace-a" }))
      .toThrow("workspace scope mismatch");
  });

  it("requires tenant and workspace scope on every homepage API read", () => {
    const scope = { tenantID: "tenant-a", workspaceID: "workspace-a" };
    expect(() => assertHomepageAPIScope(
      "readiness",
      "http://127.0.0.1:43123/api/cerebro/grc/program-readiness?tenant_id=tenant-a&workspace_id=workspace-a",
      scope,
    )).not.toThrow();
    expect(() => assertHomepageAPIScope(
      "coverage",
      "http://127.0.0.1:43123/api/cerebro/connectors/coverage?tenant_id=tenant-a&workspace_id=workspace-b",
      scope,
    )).toThrow("Homepage coverage workspace scope mismatch");
    expect(() => assertHomepageAPIScope(
      "dashboard",
      "http://127.0.0.1:43123/api/cerebro/grc/program-readiness?tenant_id=tenant-a&workspace_id=workspace-a",
      scope,
    )).toThrow("Expected homepage dashboard request");
    expect(() => assertHomepageAPIScope("unknown", "http://127.0.0.1:43123/", scope))
      .toThrow("Unknown homepage API unknown");
  });

  it("discovers every app page with safe concrete dynamic route samples", async () => {
    const webRoot = path.resolve(import.meta.dirname, "..");
    const routes = await discoverPageRoutes(webRoot);
    expect(routes).toContain("/actions/fixture-operation");
    expect(routes).toContain("/connectors/okta/setup");
    expect(routes).toContain("/findings/demo-finding-critical");
    expect(routes).toContain("/inventory/urn%3Acerebro%3Ademo-tenant%3Aidentity%3Aplatform-admin");
    expect(routes).toContain("/vendors/urn%3Acerebro%3Ademo-tenant%3Avendor%3Acore-sso");
    expect(routes).not.toContain(expect.stringMatching(/\[[^\]]+\]/));
  });

  it("adds tenant and application workspace scope without dropping route state", () => {
    expect(routeWithScope("/inventory?owner=unassigned#table", "tenant-a", "workspace-a"))
      .toBe("/inventory?owner=unassigned&tenant_id=tenant-a&workspace_id=workspace-a");
  });

  it("keeps only same-origin application routes for the browser crawl", () => {
    const baseUrl = "http://127.0.0.1:43123";
    expect(sameOriginApplicationRoute("/vendors#queue", baseUrl)).toBe("/vendors");
    expect(sameOriginApplicationRoute("/api/cerebro/grc/vendors", baseUrl)).toBeNull();
    expect(sameOriginApplicationRoute("https://example.com/vendors", baseUrl)).toBeNull();
    expect(sameOriginApplicationRoute("/_next/static/chunk.js", baseUrl)).toBeNull();
    expect(sameOriginApplicationRoute("/impact?root_urn=%5Bidentity-user-1%5D", baseUrl)).toBeNull();
  });

  it("allows only the two optional local evaluation reports to be absent", () => {
    expect(isExpectedLocal404("/evals/ask/latest.json", 404)).toBe(true);
    expect(isExpectedLocal404("/evals/security-agent/latest.json", 404)).toBe(true);
    expect(isExpectedLocal404("/api/cerebro/grc/vendors", 404)).toBe(false);
    expect(isExpectedLocal404("/evals/ask/latest.json", 500)).toBe(false);
  });

  it("reports document 404s, overlays, console errors, page errors, and missing backend paths", () => {
    expect(routeBugbashFindings({
      body: "This page could not be found",
      consoleErrors: ["Failed to load resource"],
      documentStatus: 404,
      pageErrors: ["render exploded"],
      response404s: ["/api/cerebro/grc/vendors"],
      responseFailures: [{ pathname: "/api/audit-log", status: 502 }],
      route: "/vendors",
    })).toEqual([
      "/vendors returned document status 404",
      "/vendors rendered an application or framework error",
      "/vendors raised a page error: render exploded",
      "/vendors logged a console error: Failed to load resource",
      "/vendors requested missing backend path /api/cerebro/grc/vendors",
      "/vendors requested 502 response at /api/audit-log",
    ]);
  });

  it("reports redirects, dropped scope, and browser network failures", () => {
    expect(routeBugbashFindings({
      body: "Ready",
      consoleErrors: [],
      documentStatus: 200,
      finalURL: "http://127.0.0.1:43123/login?tenant_id=tenant-a",
      pageErrors: [],
      requestFailures: [{ error: "net::ERR_CONNECTION_RESET", url: "/api/cerebro/grc/vendors" }],
      route: "/vendors?tenant_id=tenant-a&workspace_id=workspace-a",
    })).toEqual([
      "/vendors?tenant_id=tenant-a&workspace_id=workspace-a navigated to unexpected path /login",
      "/vendors?tenant_id=tenant-a&workspace_id=workspace-a dropped workspace_id during navigation",
      "/vendors?tenant_id=tenant-a&workspace_id=workspace-a had a network failure at /api/cerebro/grc/vendors: net::ERR_CONNECTION_RESET",
    ]);
  });

  it("accepts declared legacy redirects and requires scope on the preserving redirect", () => {
    expect(isExpectedRouteRedirect(
      "/developer/codegen?tenant_id=tenant-a&workspace_id=workspace-a",
      "http://127.0.0.1:43123/developer",
    )).toBe(true);
    expect(isExpectedRouteRedirect(
      "/developer/codegen?tenant_id=tenant-a&workspace_id=workspace-a",
      "http://127.0.0.1:43123/login",
    )).toBe(false);
    expect(routeBugbashFindings({
      body: "Ready",
      consoleErrors: [],
      documentStatus: 200,
      finalURL: "http://127.0.0.1:43123/developer",
      pageErrors: [],
      route: "/developer/codegen?tenant_id=tenant-a&workspace_id=workspace-a",
    })).toEqual([]);
    expect(routeBugbashFindings({
      body: "Ready",
      consoleErrors: [],
      documentStatus: 200,
      finalURL: "http://127.0.0.1:43123/connectors/activation?tenant_id=tenant-a",
      pageErrors: [],
      route: "/connectors/source-cdk?tenant_id=tenant-a&workspace_id=workspace-a",
    })).toEqual([
      "/connectors/source-cdk?tenant_id=tenant-a&workspace_id=workspace-a dropped workspace_id during navigation",
    ]);
  });
});

describe("portable web fixture E2E endpoint ownership", () => {
  it("accepts only the matching run readiness record", () => {
    const line = 'CEREBRO_FIXTURE_READY {"nonce":"run-a","port":43123}';
    expect(parseFixtureReadyLine(line, "run-a")).toBe(43123);
    expect(() => parseFixtureReadyLine(line, "run-b")).toThrow("did not match this run");
  });

  it("fails closed on malformed readiness output", async () => {
    const stream = new PassThrough();
    const pending = waitForFixtureEndpoint(stream, "run-a", createDeadline(250));
    stream.end("CEREBRO_FIXTURE_READY not-json\n");
    await expect(pending).rejects.toThrow("not valid JSON");
  });
});

describe("portable web fixture E2E contracts", () => {
  it("accepts same-origin, private public configuration", () => {
    expect(() => assertPublicConfig({
      body: JSON.stringify({ apiBase: "/api/cerebro", serverAuthConfigured: false }),
      headers: headers({ "cache-control": "private, no-store" }),
      status: 200,
    })).not.toThrow();
  });

  it("rejects absolute service addresses in public configuration", () => {
    expect(() => assertPublicConfig({
      body: JSON.stringify({ apiBase: "https://service.example" }),
      headers: headers({ "cache-control": "private, no-store" }),
      status: 200,
    })).toThrow("same-origin API path");
  });

  it("requires the route status, page marker, and error-free body", () => {
    const contract = { heading: "Overview", pageId: "overview", route: "/" };
    expect(() => assertPageContract(contract, {
      body: '<main data-grc-page="overview">Ready</main>',
      status: 200,
    })).not.toThrow();
    expect(() => assertPageContract(contract, { body: "missing", status: 200 }))
      .toThrow("missing page contract");
    expect(() => assertPageContract(contract, {
      body: '<main data-grc-page="overview">Application error</main>',
      status: 200,
    })).toThrow("application error");
  });

  it("checks public config before every declared route", async () => {
    const contracts = [
      { heading: "Overview", pageId: "overview", route: "/" },
      { heading: "Controls", pageId: "controls", route: "/controls" },
    ];
    const fetchPage = vi.fn(async (url) => {
      const pathname = new URL(url).pathname;
      if (pathname === "/api/config") {
        return {
          body: JSON.stringify({ apiBase: "/api/cerebro" }),
          headers: headers({ "cache-control": "private, no-store" }),
          status: 200,
        };
      }
      const contract = contracts.find((candidate) => candidate.route === pathname);
      return {
        body: `<main data-grc-page="${contract.pageId}">Ready</main>`,
        headers: headers(),
        status: 200,
      };
    });

    await expect(validateHttpContracts("http://127.0.0.1:43123", { contracts, fetchPage }))
      .resolves.toEqual(contracts);
    expect(fetchPage.mock.calls.map(([url]) => new URL(url).pathname))
      .toEqual(["/api/config", "/", "/controls"]);
  });
});

const processExists = (pid) => {
  try {
    process.kill(pid, 0);
    return true;
  } catch (error) {
    if (error.code === "ESRCH") return false;
    throw error;
  }
};

const waitForProcessExit = async (pid, timeoutMs = 2_000) => {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    if (!processExists(pid)) return;
    await new Promise((resolve) => setTimeout(resolve, 20));
  }
  throw new Error(`Process ${pid} did not exit`);
};

describe("portable web fixture E2E cleanup", () => {
  it.runIf(process.platform !== "win32")("owns fixture cleanup when the log stream fails before readiness", async () => {
    let child;
    const createLogStream = () => {
      const stream = new Writable({
        write(_chunk, _encoding, callback) { callback(); },
      });
      queueMicrotask(() => stream.emit("error", new Error("simulated log open failure")));
      return stream;
    };
    const spawnFixture = () => {
      child = spawn(process.execPath, ["-e", "setInterval(() => {}, 1000)"], {
        detached: true,
        stdio: ["ignore", "pipe", "pipe"],
      });
      return child;
    };
    let caught;
    try {
      await runPortableWebFixtureE2E({
        browser: false,
        createLogStream,
        spawnFixture,
        timeoutMs: 2_000,
      });
    } catch (error) {
      caught = error;
    }
    expect(caught?.message).toContain("Portable fixture E2E log stream failed: simulated log open failure");
    expect(child.exitCode !== null || child.signalCode !== null).toBe(true);
    const logPath = caught?.message.match(/Portable fixture E2E log: (.+)$/m)?.[1];
    if (logPath) await rm(path.dirname(path.dirname(logPath)), { force: true, recursive: true });
  });

  it.runIf(process.platform !== "win32")("terminates a real descendant in the fixture process group", async () => {
    const program = [
      'const { spawn } = require("node:child_process");',
      'const child = spawn(process.execPath, ["-e", "setInterval(() => {}, 1000)"], { stdio: "ignore" });',
      'console.log(child.pid);',
      'setInterval(() => {}, 1000);',
    ].join("\n");
    const child = spawn(process.execPath, ["-e", program], {
      detached: true,
      stdio: ["ignore", "pipe", "ignore"],
    });
    const descendantPid = await new Promise((resolve, reject) => {
      child.once("error", reject);
      child.stdout.once("data", (chunk) => resolve(Number.parseInt(chunk.toString(), 10)));
    });
    try {
      await stopProcessTree(child, { deadlineAt: Date.now() + 2_000, graceMs: 500 });
      await waitForProcessExit(descendantPid);
      expect(processExists(descendantPid)).toBe(false);
    } finally {
      try { process.kill(-child.pid, "SIGKILL"); } catch {}
      try { process.kill(descendantPid, "SIGKILL"); } catch {}
    }
  });

  it.runIf(process.platform !== "win32")("waits for the owned fixture tree before a second run reuses its resource", async () => {
    const delayedServer = [
      'const net = require("node:net");',
      'const port = Number(process.argv[1]);',
      'process.on("SIGTERM", () => setTimeout(() => process.exit(0), 5_000));',
      'const server = net.createServer();',
      'server.on("error", (error) => { console.error(error.message); process.exitCode = 1; process.exit(1); });',
      'server.listen(port, "127.0.0.1", () => console.log(JSON.stringify({ pid: process.pid, port: server.address().port })));',
      'setInterval(() => {}, 1_000);',
    ].join("\n");
    const startFixture = (port) => {
      const launcher = [
        'const { spawn } = require("node:child_process");',
        `const child = spawn(process.execPath, ["-e", ${JSON.stringify(delayedServer)}, ${JSON.stringify(String(port))}], { stdio: ["ignore", "pipe", "ignore"] });`,
        'child.stdout.pipe(process.stdout);',
        'child.once("exit", (code, signal) => { if (code !== 0 || signal) process.exitCode = 1; process.exit(); });',
        'setInterval(() => {}, 1_000);',
      ].join("\n");
      return spawn(process.execPath, ["-e", launcher], {
        detached: true,
        stdio: ["ignore", "pipe", "ignore"],
      });
    };
    const waitForReady = (fixture) => new Promise((resolve, reject) => {
      let buffer = "";
      const onData = (chunk) => {
        buffer += chunk.toString();
        const lines = buffer.split(/\r?\n/);
        buffer = lines.pop() ?? "";
        for (const line of lines) {
          try {
            const record = JSON.parse(line);
            if (record?.pid && record?.port) {
              fixture.stdout.off("data", onData);
              resolve(record);
              return;
            }
          } catch {}
        }
      };
      fixture.stdout.on("data", onData);
      fixture.once("error", reject);
      fixture.once("exit", (code, signal) => reject(new Error(`fixture exited before readiness (${code ?? signal})`)));
    });
    let first;
    let second;
    try {
      first = startFixture(0);
      const firstReady = await waitForReady(first);
      await stopProcessTree(first, { deadlineAt: Date.now() + 1_000, graceMs: 25 });
      expect(processExists(firstReady.pid)).toBe(false);

      second = startFixture(firstReady.port);
      await expect(waitForReady(second)).resolves.toMatchObject({ port: firstReady.port });
    } finally {
      for (const fixture of [first, second]) {
        if (!fixture) continue;
        try {
          await stopProcessTree(fixture, { deadlineAt: Date.now() + 1_000, graceMs: 25 });
        } catch {
          try { process.kill(-fixture.pid, "SIGKILL"); } catch {}
        }
      }
    }
  });

  it("uses tree-aware Windows termination before forced tree termination", async () => {
    const child = Object.assign(new EventEmitter(), { exitCode: null, pid: 43123, signalCode: null });
    const calls = [];
    const taskkillProcess = vi.fn(async (_pid, force) => {
      calls.push(force);
      if (force) {
        child.exitCode = 1;
        child.emit("exit", 1, null);
      }
    });
    await stopProcessTree(child, {
      deadlineAt: Date.now() + 500,
      graceMs: 10,
      platform: "win32",
      taskkillProcess,
    });
    expect(calls).toEqual([false, true]);
    expect(windowsTaskkillArgs(43123, false)).toEqual(["/PID", "43123", "/T"]);
    expect(windowsTaskkillArgs(43123, true)).toEqual(["/PID", "43123", "/T", "/F"]);
  });

  it("escalates when graceful Windows tree termination stalls", async () => {
    const child = Object.assign(new EventEmitter(), { exitCode: null, pid: 43123, signalCode: null });
    const calls = [];
    const taskkillProcess = vi.fn(async (_pid, force) => {
      calls.push(force);
      if (!force) return new Promise(() => {});
      child.exitCode = 1;
      child.emit("exit", 1, null);
    });
    await stopProcessTree(child, {
      deadlineAt: Date.now() + 250,
      graceMs: 20,
      platform: "win32",
      taskkillProcess,
    });
    expect(calls).toEqual([false, true]);
  });

  it("bounds the final process-exit wait after forced termination", async () => {
    const child = Object.assign(new EventEmitter(), { exitCode: null, pid: 43123, signalCode: null });
    const startedAt = Date.now();
    await expect(stopProcessTree(child, {
      deadlineAt: Date.now() + 40,
      graceMs: 5,
      signalProcessGroup: vi.fn(),
    })).rejects.toThrow("forced fixture process-tree termination");
    expect(Date.now() - startedAt).toBeLessThan(250);
  });

  it("bounds log closure and destroys a stalled stream", async () => {
    const stalled = new Writable({
      final() {},
      write(_chunk, _encoding, callback) { callback(); },
    });
    await expect(closeLogStream(stalled, Date.now() + 25)).rejects.toThrow("E2E log closure");
    expect(stalled.destroyed).toBe(true);
  });
});
