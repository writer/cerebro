import { beforeEach, describe, expect, it } from "vitest";

import {
  configureSettingsLoader,
  createSettingsProxy,
  getSettings,
  refreshSettings,
} from "../src/config";

interface TestSettings {
  logLevel: string;
  featureFlags: Record<string, boolean>;
}

const initialSettings: TestSettings = {
  logLevel: "info",
  featureFlags: { beta: false },
};

describe("config", () => {
  beforeEach(() => {
    configureSettingsLoader(() => ({ ...initialSettings }));
  });

  it("caches settings from the configured loader", () => {
    const first = getSettings<TestSettings>();
    first.featureFlags.beta = true;

    const second = getSettings<TestSettings>();
    expect(second.featureFlags.beta).toBe(true);
  });

  it("refreshSettings replaces the cached instance", () => {
    const original = getSettings<TestSettings>();
    original.featureFlags.beta = true;

    const refreshed = refreshSettings<TestSettings>(() => ({
      logLevel: "debug",
      featureFlags: { beta: false },
    }));

    expect(refreshed.logLevel).toBe("debug");
    expect(getSettings<TestSettings>().featureFlags.beta).toBe(false);
  });

  it("provides a proxy with live access to current settings", () => {
    const proxy = createSettingsProxy<TestSettings>();
    expect(proxy.logLevel).toBe("info");

    refreshSettings<TestSettings>(() => ({
      logLevel: "warn",
      featureFlags: { beta: true },
    }));

    expect(proxy.logLevel).toBe("warn");
    expect(proxy.snapshot().featureFlags.beta).toBe(true);
  });
});
