import { spawn } from "node:child_process";
import { EventEmitter } from "node:events";
import { PassThrough, Writable } from "node:stream";
import { describe, expect, it, vi } from "vitest";

import {
  assertPageContract,
  assertPublicConfig,
  closeLogStream,
  createDeadline,
  parseArgs,
  parseFixtureReadyLine,
  stopProcessTree,
  validateHttpContracts,
  waitForFixtureEndpoint,
  windowsTaskkillArgs,
} from "./local-grc-e2e.mjs";

const headers = (values = {}) => new Headers(values);

describe("local GRC E2E options", () => {
  it("uses child-owned port allocation, Chromium, and a hard deadline by default", () => {
    expect(parseArgs([])).toEqual({ browser: true, port: 0, timeoutMs: 180_000 });
  });

  it("parses explicit browser, port, and timeout options", () => {
    expect(parseArgs(["--no-browser", "--port=43123", "--timeout-ms", "1200"]))
      .toEqual({ browser: false, port: 43123, timeoutMs: 1200 });
  });

  it("keeps the former readiness flag as an overall-timeout alias", () => {
    expect(parseArgs(["--ready-timeout-ms=1200"]).timeoutMs).toBe(1200);
  });

  it("rejects unknown and invalid options", () => {
    expect(() => parseArgs(["--keep"])).toThrow("Unknown option");
    expect(() => parseArgs(["--port", "70000"])).toThrow("between 0 and 65535");
    expect(() => parseArgs(["--timeout-ms=0"])).toThrow("between 1");
  });
});

describe("local GRC E2E endpoint ownership", () => {
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

describe("local GRC E2E contracts", () => {
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

describe("local GRC E2E cleanup", () => {
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
