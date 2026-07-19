import { describe, expect, it } from "vitest";

import { LIVE_SEARCH_TIMEOUT_MS, LIVE_SEARCH_UNAVAILABLE_COPY } from "./live-search";

describe("live search status copy", () => {
  it("finishes unavailable searches with page-action fallback copy", () => {
    expect(LIVE_SEARCH_TIMEOUT_MS).toBe(8_000);
    expect(LIVE_SEARCH_UNAVAILABLE_COPY).toBe("Page actions are ready. Live search is unavailable.");
  });
});
