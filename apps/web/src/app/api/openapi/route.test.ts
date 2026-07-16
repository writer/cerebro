import { describe, expect, it } from "vitest";

import { parseOpenApiDocument } from "./route";

describe("OpenAPI document parsing", () => {
  it("returns a parsed document for valid YAML", () => {
    expect(parseOpenApiDocument("openapi: 3.1.0\ninfo:\n  title: Cerebro\n  version: 1.0.0\n")).toMatchObject({
      openapi: "3.1.0",
    });
  });

  it("rejects malformed and non-document YAML", () => {
    expect(parseOpenApiDocument("openapi: [unterminated")).toBeNull();
    expect(parseOpenApiDocument("plain scalar")).toBeNull();
  });
});
