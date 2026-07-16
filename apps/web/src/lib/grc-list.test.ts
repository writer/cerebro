import { describe, expect, it } from "vitest";

import { grcBoundedRows, grcLoadedRows, grcLoadedRowsCopy } from "./grc-list";

describe("grc loaded row copy", () => {
  it("uses response totals when the API returns list metadata", () => {
    expect(grcLoadedRows({ loaded: 200, meta: { limit: 200, returned: 200, total: 1240, truncated: true } })).toEqual({
      limit: 200,
      loaded: 200,
      total: 1240,
      truncated: true,
    });
    expect(grcLoadedRowsCopy({ loaded: 200, meta: { limit: 200, returned: 200, total: 1240, truncated: true }, noun: "findings" })).toBe(
      "Showing 200 of 1,240 findings. Narrow filters or export the full file.",
    );
  });

  it("falls back to first-page copy when only the request cap is known", () => {
    expect(grcLoadedRowsCopy({ loaded: 200, limit: 200, noun: "assets" })).toBe(
      "Showing first 200 assets. Narrow filters or export the full file.",
    );
  });

  it("uses singular nouns when the loaded total is one", () => {
    expect(grcLoadedRowsCopy({ loaded: 1, meta: { limit: 100, returned: 1, total: 1, truncated: false }, noun: "findings" })).toBe(
      "Showing 1 of 1 finding.",
    );
  });
});

describe("grc bounded rows", () => {
  it("caps rows to the requested limit and keeps response totals", () => {
    const result = grcBoundedRows({
      rows: [{ id: "a" }, { id: "b" }, { id: "c" }],
      limit: 2,
      meta: { limit: 500, returned: 3, total: 42, truncated: true },
    });

    expect(result.rows).toEqual([{ id: "a" }, { id: "b" }]);
    expect(result.meta).toEqual({
      limit: 2,
      returned: 2,
      total: 42,
      truncated: true,
    });
  });

  it("marks rows truncated when the response exceeds the local cap", () => {
    const result = grcBoundedRows({
      rows: [{ id: "a" }, { id: "b" }, { id: "c" }],
      limit: 2,
    });

    expect(result.rows).toHaveLength(2);
    expect(result.meta).toEqual({
      limit: 2,
      returned: 2,
      total: 3,
      truncated: true,
    });
  });

  it("handles missing rows", () => {
    expect(grcBoundedRows({ rows: null, limit: 2 })).toEqual({
      rows: [],
      meta: {
        limit: 2,
        returned: 0,
        total: 0,
        truncated: false,
      },
    });
  });
});
