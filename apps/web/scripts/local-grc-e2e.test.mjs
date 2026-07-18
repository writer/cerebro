import { spawn } from "node:child_process";
import { describe, expect, it, vi } from "vitest";

import {
  assertPageContract,
  assertPublicConfig,
  parseArgs,
  stopProcessTree,
  validateHttpContracts,
} from "./local-grc-e2e.mjs";

const headers = (values = {}) => new Headers(values);

describe("local GRC E2E options", () => {
  it("uses an ephemeral port and bounded readiness by default", () => {
    expect(parseArgs([])).toEqual({ browser: false, port: 0, readyTimeoutMs: 90_000 });
  });

  it("parses explicit browser, port, and timeout options", () => {
    expect(parseArgs(["--browser", "--port=43123", "--ready-timeout-ms", "1200"]))
      .toEqual({ browser: true, port: 43123, readyTimeoutMs: 1200 });
  });

  it("rejects unknown and invalid options", () => {
    expect(() => parseArgs(["--keep"])).toThrow("Unknown option");
    expect(() => parseArgs(["--port", "70000"])).toThrow("between 0 and 65535");
    expect(() => parseArgs(["--ready-timeout-ms=0"])).toThrow("between 1");
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
    const contract = { pageId: "overview", route: "/" };
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
      { pageId: "overview", route: "/" },
      { pageId: "controls", route: "/controls" },
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

describe("local GRC E2E cleanup", () => {
  it("terminates the complete fixture process group", async () => {
    const child = spawn(process.execPath, ["-e", "setInterval(() => {}, 1000)"], {
      detached: process.platform !== "win32",
      stdio: "ignore",
    });
    await new Promise((resolve, reject) => {
      child.once("error", reject);
      child.once("spawn", resolve);
    });

    await stopProcessTree(child, 1_000);

    expect(child.exitCode !== null || child.signalCode !== null).toBe(true);
  });
});
