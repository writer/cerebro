import { describe, expect, it } from "vitest";

import { appVersion, appVersionLabel } from "./app-version";

describe("app version", () => {
  it("defaults to a semver-shaped fallback", () => {
    expect(appVersion).toMatch(/^\d+\.\d+\.\d+|^v?\d/);
  });

  it("prepends v to bare semver strings", () => {
    expect(appVersionLabel).toMatch(/^v/);
  });
});
