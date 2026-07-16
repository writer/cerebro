import { describe, expect, it } from "vitest";

import { doctorExitCode, parseNodeMajor, truthyEnv } from "./doctor.mjs";

describe("doctor helpers", () => {
  it("parses Node major versions", () => {
    expect(parseNodeMajor("v22.13.1")).toBe(22);
    expect(parseNodeMajor("23.0.0")).toBe(23);
    expect(parseNodeMajor("unknown")).toBe(0);
  });

  it("recognizes common truthy environment values", () => {
    expect(truthyEnv("1")).toBe(true);
    expect(truthyEnv("YES")).toBe(true);
    expect(truthyEnv("false")).toBe(false);
    expect(truthyEnv(undefined)).toBe(false);
  });

  it("fails only when a check has failed", () => {
    expect(doctorExitCode([{ status: "ok" }, { status: "warn" }])).toBe(0);
    expect(doctorExitCode([{ status: "fail" }])).toBe(1);
  });
});
