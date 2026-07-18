import { EventEmitter } from "node:events";
import { readFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";

import { describe, expect, it, vi } from "vitest";

import {
  allocateLoopbackPort,
  assertChildHealthy,
  assertConcurrentProxyResponses,
  componentReady,
  createDeadlineAt,
  parseArgs,
  parseDockerLoopbackPort,
  portableChildEnvironment,
  stopProcessTree,
  windowsTaskkillArgs,
} from "./local-grc-e2e.mjs";

const response = (state, summary = { open_findings: 3 }) => ({
  headers: new Headers({ "x-cerebro-cache": state }),
  json: { summary },
  status: 200,
});

describe("real-service E2E options", () => {
  it("requires Chromium and a hard overall deadline by default", () => {
    expect(parseArgs([])).toEqual({ artifactRoot: undefined, browser: true, timeoutMs: 900_000 });
  });

  it("parses diagnostics and artifact options without accepting service overrides", () => {
    expect(parseArgs(["--no-browser", "--timeout-ms=1200", "--artifact-dir", "artifacts"]))
      .toEqual({ artifactRoot: "artifacts", browser: false, timeoutMs: 1200 });
    for (const arg of ["--keep", "--agent-browser", "--api-port=8080", "--hostname=0.0.0.0"]) {
      expect(() => parseArgs([arg])).toThrow("Unknown option");
    }
  });

  it("rejects missing and malformed option values", () => {
    expect(() => parseArgs(["--timeout-ms"])).toThrow("requires an integer");
    expect(() => parseArgs(["--timeout-ms=0"])).toThrow("positive integer");
    expect(() => parseArgs(["--artifact-dir"])).toThrow("requires a value");
  });
});

describe("real-service E2E isolation", () => {
  it("passes only portable tool settings plus explicit synthetic service values", () => {
    const environment = portableChildEnvironment({
      CLOUD_ACCESS_TOKEN: "must-not-pass",
      CEREBRO_POSTGRES_DSN: "must-not-pass",
      DOCKER_HOST: "unix:///local/docker.sock",
      HOME: "/tmp/example-home",
      PATH: "/usr/bin",
    }, { CEREBRO_DEV_MODE: "1" });

    expect(environment).toEqual({
      CEREBRO_DEV_MODE: "1",
      DOCKER_HOST: "unix:///local/docker.sock",
      HOME: "/tmp/example-home",
      PATH: "/usr/bin",
    });
  });

  it("accepts only a single loopback Docker endpoint", () => {
    expect(parseDockerLoopbackPort("127.0.0.1:49152\n")).toBe(49_152);
    for (const value of ["0.0.0.0:49152", "[::]:49152", "127.0.0.1:0", "127.0.0.1:70000", "127.0.0.1:1\n127.0.0.1:2"]) {
      expect(() => parseDockerLoopbackPort(value)).toThrow();
    }
  });

  it("allocates an ephemeral loopback port", async () => {
    const port = await allocateLoopbackPort();
    expect(port).toBeGreaterThan(0);
    expect(port).toBeLessThanOrEqual(65_535);
  });

  it("keeps checked-in seed data synthetic and portable", async () => {
    const seedPath = fileURLToPath(new URL("./testdata/grc-e2e-seed/main.go", import.meta.url));
    const seed = await readFile(seedPath, "utf8");
    expect(seed).toContain("e2e-local");
    expect(seed).toContain("example.org");
    expect(seed).not.toMatch(/\breplace\s|GOPRIVATE|example\.com|unused-local/);
  });

  it("keeps the browser on the same-origin proxy", async () => {
    const runnerPath = fileURLToPath(new URL("./local-grc-e2e.mjs", import.meta.url));
    const runner = await readFile(runnerPath, "utf8");
    expect(runner).toContain('NEXT_PUBLIC_CEREBRO_API_BASE: "/api/cerebro"');
    expect(runner).not.toContain("NEXT_PUBLIC_CEREBRO_API_BASE: apiBase");
  });
});

describe("real-service E2E contracts", () => {
  it("requires every declared health component to report ready", () => {
    expect(componentReady({ components: [{ name: "state_store", status: "ready" }] }, "state_store")).toBe(true);
    expect(componentReady({ components: [{ name: "state_store", status: "degraded" }] }, "state_store")).toBe(false);
    expect(componentReady({}, "state_store")).toBe(false);
  });

  it("accepts one miss and identical hit or deduplicated responses", () => {
    expect(() => assertConcurrentProxyResponses([
      response("miss"),
      response("dedupe"),
      response("hit"),
    ])).not.toThrow();
  });

  it("rejects multiple misses, invalid states, and divergent payloads", () => {
    expect(() => assertConcurrentProxyResponses([response("miss"), response("miss")])).toThrow("at most one upstream miss");
    expect(() => assertConcurrentProxyResponses([response("miss"), response("bypass")])).toThrow("unexpected cache states");
    expect(() => assertConcurrentProxyResponses([response("miss"), response("hit", { open_findings: 4 })])).toThrow("diverged");
  });
});

describe("real-service E2E deadlines and cleanup", () => {
  it("fails readiness immediately on process, exit, and log errors", () => {
    expect(() => assertChildHealthy({ exitCode: null, logError: new Error("disk closed"), signalCode: null, spawnError: null }, "web"))
      .toThrow("web log stream failed");
    expect(() => assertChildHealthy({ exitCode: 1, logError: null, signalCode: null, spawnError: null }, "web"))
      .toThrow("web stopped before validation completed");
    expect(() => assertChildHealthy({ exitCode: null, logError: null, signalCode: null, spawnError: new Error("missing") }, "web"))
      .toThrow("web failed to start");
  });

  it("rejects work after the absolute deadline", async () => {
    await expect(createDeadlineAt(Date.now() - 1).run(Promise.resolve(), "expired work"))
      .rejects.toThrow("Timed out during expired work");
  });

  it("builds argumentized Windows descendant cleanup commands", () => {
    expect(windowsTaskkillArgs(4312, false)).toEqual(["/PID", "4312", "/T"]);
    expect(windowsTaskkillArgs(4312, true)).toEqual(["/PID", "4312", "/T", "/F"]);
  });

  it("escalates when graceful Windows descendant cleanup stalls", async () => {
    const child = new EventEmitter();
    Object.assign(child, { exitCode: null, pid: 4312, signalCode: null });
    const calls = [];
    const taskkillProcess = vi.fn((_pid, force) => {
      calls.push(force);
      if (!force) return new Promise(() => {});
      queueMicrotask(() => child.emit("exit", 0, null));
      return Promise.resolve();
    });

    await stopProcessTree(child, {
      deadlineAt: Date.now() + 250,
      graceMs: 20,
      platform: "win32",
      taskkillProcess,
    });

    expect(calls).toEqual([false, true]);
  });
});
