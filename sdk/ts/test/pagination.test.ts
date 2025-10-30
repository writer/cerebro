import { describe, expect, it } from "vitest";

import { decodeCursor, encodeCursor } from "../src/pagination";

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
});
