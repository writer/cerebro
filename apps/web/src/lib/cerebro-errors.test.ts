import { describe, expect, it } from "vitest";

import { isApiUnavailableError } from "./cerebro-errors";

describe("cerebro error classification", () => {
  it("recognizes unavailable API failures", () => {
    expect(isApiUnavailableError("Cerebro request failed (502)")).toBe(true);
    expect(isApiUnavailableError("Unable to reach Cerebro API")).toBe(true);
    expect(isApiUnavailableError("request timed out")).toBe(true);
    expect(isApiUnavailableError("fetch failed")).toBe(true);
  });

  it("leaves validation errors as hard errors", () => {
    expect(isApiUnavailableError("Cerebro request failed (400)")).toBe(false);
    expect(isApiUnavailableError("Connector source was not found.")).toBe(false);
    expect(isApiUnavailableError(null)).toBe(false);
  });
});
