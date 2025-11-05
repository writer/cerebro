import { describe, expect, it } from "vitest";

import { collectCursor, decodeCursor, encodeCursor, iterateCursor } from "../src/pagination";

describe("pagination", () => {
  it("encodes and decodes cursor payloads", () => {
    const cursor = encodeCursor({ last_seen: "2024-01-01T00:00:00Z", finding_id: "id" });
    expect(typeof cursor).toBe("string");

    const decoded = decodeCursor(cursor);
    expect(decoded.version).toBe(1);
    expect(decoded.payload.last_seen).toBe("2024-01-01T00:00:00Z");
    expect(decoded.payload.finding_id).toBe("id");
  });

  it("throws on invalid cursor", () => {
    expect(() => decodeCursor("invalid")).toThrowError();
  });

  it("iterates across cursor pages", async () => {
    const pages = [
      { items: [1, 2], nextCursor: "cursor-2" },
      { items: [3], nextCursor: null },
    ];
    let index = 0;

    const results: number[] = [];
    for await (const value of iterateCursor(async () => pages[index++])) {
      results.push(value);
    }

    expect(results).toEqual([1, 2, 3]);
  });

  it("collects cursor pages into an array", async () => {
    const pages = [
      { items: ["a"], nextCursor: "next" },
      { items: ["b", "c"], nextCursor: null },
    ];
    let index = 0;

    const values = await collectCursor(async () => pages[index++]);
    expect(values).toEqual(["a", "b", "c"]);
  });
});
