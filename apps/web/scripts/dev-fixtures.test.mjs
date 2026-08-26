import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";

import {
  createFixtureEnvironment,
  extractLoopbackPort,
  normalizeFixtureDevArgs,
} from "./dev-fixtures.mjs";

describe("fixture development launcher", () => {
  it("binds to loopback and delegates dynamic port allocation to Next", () => {
    expect(normalizeFixtureDevArgs([])).toEqual([
      "dev", "--hostname", "127.0.0.1", "--port", "0",
    ]);
    expect(normalizeFixtureDevArgs(["--port=43123", "--webpack"])).toEqual([
      "dev", "--hostname", "127.0.0.1", "--port", "43123", "--webpack",
    ]);
    expect(normalizeFixtureDevArgs(["-p43124"])).toEqual([
      "dev", "--hostname", "127.0.0.1", "--port", "43124",
    ]);
    for (const argv of [
      ["--hostname", "0.0.0.0"],
      ["--hostname=0.0.0.0"],
      ["-H", "0.0.0.0"],
      ["-H0.0.0.0"],
      ["-H=0.0.0.0"],
    ]) {
      expect(() => normalizeFixtureDevArgs(argv)).toThrow("restricted to 127.0.0.1");
    }
  });

  it("passes only portable process settings and synthetic fixture configuration", () => {
    const environment = createFixtureEnvironment({
      HOME: "/tmp/test-home",
      INTERNAL_ONLY_SETTING: "test-only",
      PATH: "/test-bin",
    }, "run-a");
    expect(environment).toMatchObject({
      CEREBRO_API_BASE: "fixture://local",
      CEREBRO_E2E_RUN_NONCE: "run-a",
      CEREBRO_TRUSTED_IDENTITY_HEADERS: "x-user-email",
      CEREBRO_WEB_FIXTURE_MODE: "1",
      HOME: "/tmp/test-home",
      PATH: "/test-bin",
    });
    expect(environment.INTERNAL_ONLY_SETTING).toBeUndefined();
  });

  it("extracts only a valid loopback port from Next startup output", () => {
    expect(extractLoopbackPort("\u001b[32m- Local: http://127.0.0.1:43123\u001b[0m")).toBe(43123);
    expect(extractLoopbackPort("- Network: http://0.0.0.0:43123")).toBeNull();
    expect(extractLoopbackPort("- Local: http://127.0.0.1:0")).toBeNull();
  });

  it("rejects an attached hostname override in the real launcher before Next starts", () => {
    const launcher = fileURLToPath(new URL("./dev-fixtures.mjs", import.meta.url));
    const result = spawnSync(process.execPath, [launcher, "-H0.0.0.0"], {
      cwd: fileURLToPath(new URL("..", import.meta.url)),
      encoding: "utf8",
    });
    expect(result.status).toBe(1);
    expect(result.stderr).toContain("restricted to 127.0.0.1");
    expect(`${result.stdout}${result.stderr}`).not.toContain("Network:");
  });
});
