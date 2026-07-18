import { EventEmitter } from "node:events";
import { readFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";

import { describe, expect, it, vi } from "vitest";

import {
  acquireAbortableResource,
  assertChildHealthy,
  assertConcurrentProxyResponses,
  browserDataContract,
  componentReady,
  createDeadlineAt,
  createRunControl,
  handoffLoopbackReservation,
  internalLoopbackPort,
  localRelayPath,
  parseArgs,
  parseDockerLoopbackPort,
  portableChildEnvironment,
  reserveDistinctLoopbackPort,
  startAfterPrerequisite,
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
  it("keeps relay requests on a relative path", () => {
    expect(localRelayPath("/grc/findings?tenant_id=e2e-local#ignored")).toBe("/grc/findings?tenant_id=e2e-local");
    for (const target of ["grc/findings", "//example.test/grc/findings", "https://example.test/grc/findings", "/\\example.test/grc/findings"]) {
      expect(() => localRelayPath(target)).toThrow(/relative|absolute/);
    }
  });

  it("accepts only an internally reserved numeric loopback port", () => {
    expect(internalLoopbackPort(49152)).toBe(49152);
    for (const port of ["49152", 0, -1, 65_536, Number.NaN]) {
      expect(() => internalLoopbackPort(port)).toThrow("delay relay upstream port is invalid");
    }
  });

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

  it("releases colliding reservations and retries until the port is distinct", async () => {
    const control = createRunControl(Date.now() + 10_000);
    const releases = [];
    const candidates = [4312, 4312, 5312];
    const reservation = await reserveDistinctLoopbackPort(new Set([4312]), {
      control,
      reserve: async () => {
        const port = candidates.shift();
        return { port, release: async () => releases.push(port) };
      },
    });

    expect(reservation.port).toBe(5312);
    expect(releases).toEqual([4312, 4312]);
    await reservation.release();
    control.disposeDeadline();
  });

  it("refuses a reserved-port handoff when abort wins before spawn", async () => {
    const control = createRunControl(Date.now() + 10_000);
    const start = vi.fn();
    const reservation = {
      port: 4312,
      release: async () => control.abort(new Error("interrupted before bind")),
    };

    await expect(handoffLoopbackReservation(reservation, start, control, "service spawn"))
      .rejects.toThrow("interrupted before bind");
    expect(start).not.toHaveBeenCalled();
    control.disposeDeadline();
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

  it("builds and pins the native admission worker for the local API", async () => {
    const runnerPath = fileURLToPath(new URL("./local-grc-e2e.mjs", import.meta.url));
    const runner = await readFile(runnerPath, "utf8");
    expect(runner).toContain('requireCommand("cargo", ["--version"])');
    expect(runner).toContain('"cerebro-sourceruntime-eventadmission"');
    expect(runner).toContain("CEREBRO_EVENT_ADMISSION_WORKER: eventAdmissionBinary");
  });

  it("requires visible seeded data and a successful API response in Chromium", () => {
    expect(browserDataContract("/risk-inbox")).toEqual({
      apiPath: "/api/cerebro/grc/findings",
      findingID: "e2e-finding-critical",
      navigationPath: "/risk-inbox?tenant_id=e2e-local",
      tenantID: "e2e-local",
      visibleText: "Privileged identity missing verification",
    });
    expect(browserDataContract("/reports")).toBeNull();
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
    expect(() => assertConcurrentProxyResponses([response("miss"), response("miss")])).toThrow("exactly one upstream miss");
    expect(() => assertConcurrentProxyResponses([response("dedupe"), response("hit")])).toThrow("exactly one upstream miss");
    expect(() => assertConcurrentProxyResponses([response("miss"), response("hit")])).toThrow("at least one deduplicated response");
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

  it("awaits an interrupted build before cleanup and never performs the deferred spawn", async () => {
    const control = createRunControl(Date.now() + 10_000);
    let finishBuild;
    const build = new Promise((resolve) => { finishBuild = resolve; });
    const spawnedResources = new Set();
    const main = startAfterPrerequisite(build, () => {
      spawnedResources.add("service");
    }, control, "deferred service spawn");
    let cleanupFinished = false;
    const cleanup = (async () => {
      await Promise.allSettled([main]);
      await control.quiesce();
      cleanupFinished = true;
    })();

    control.abort(new Error("interrupted during build"));
    await Promise.resolve();
    expect(cleanupFinished).toBe(false);
    finishBuild();
    await cleanup;

    expect(spawnedResources.size).toBe(0);
    expect(cleanupFinished).toBe(true);
    control.disposeDeadline();
  });

  it("disposes a resource that finishes creating after abort before quiescence completes", async () => {
    const control = createRunControl(Date.now() + 10_000);
    let finishCreation;
    const created = new Promise((resolve) => { finishCreation = resolve; });
    const liveResources = new Set();
    const acquisition = acquireAbortableResource(async () => {
      const resource = await created;
      liveResources.add(resource);
      return resource;
    }, async (resource) => {
      liveResources.delete(resource);
    }, control, "deferred resource");

    await Promise.resolve();
    control.abort(new Error("interrupted during resource creation"));
    await expect(acquisition).rejects.toThrow("interrupted during resource creation");
    finishCreation("resource");
    await control.quiesce();

    expect(liveResources.size).toBe(0);
    control.disposeDeadline();
  });

  it("rejects work after the absolute deadline", async () => {
    await expect(createDeadlineAt(Date.now() - 1).run(Promise.resolve(), "expired work"))
      .rejects.toThrow("Timed out during expired work");
  });

  it("builds argumentized Windows descendant cleanup commands", () => {
    expect(windowsTaskkillArgs(4312, false)).toEqual(["/PID", "4312", "/T"]);
    expect(windowsTaskkillArgs(4312, true)).toEqual(["/PID", "4312", "/T", "/F"]);
  });

  it("signals a detached process group even when its leader already exited", async () => {
    const child = new EventEmitter();
    Object.assign(child, { exitCode: 0, pid: 4312, processGroupId: 4312, signalCode: null });
    let groupAlive = true;
    const signals = [];

    await stopProcessTree(child, {
      deadlineAt: Date.now() + 250,
      graceMs: 50,
      platform: "darwin",
      pollMs: 1,
      processGroupAlive: () => groupAlive,
      signalProcessGroup: (_pid, signal) => {
        signals.push(signal);
        groupAlive = false;
      },
    });

    expect(signals).toEqual(["SIGTERM"]);
  });

  it("escalates when the leader exits but a detached descendant survives", async () => {
    const child = new EventEmitter();
    Object.assign(child, { exitCode: null, pid: 4312, processGroupId: 4312, signalCode: null });
    let groupAlive = true;
    const signals = [];

    await stopProcessTree(child, {
      deadlineAt: Date.now() + 250,
      graceMs: 10,
      platform: "linux",
      pollMs: 1,
      processGroupAlive: () => groupAlive,
      signalProcessGroup: (_pid, signal) => {
        signals.push(signal);
        if (signal === "SIGTERM") child.exitCode = 0;
        if (signal === "SIGKILL") groupAlive = false;
      },
    });

    expect(child.exitCode).toBe(0);
    expect(signals).toEqual(["SIGTERM", "SIGKILL"]);
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
