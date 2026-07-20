import { describe, expect, it } from "vitest";

import {
  currentUserWriteFieldForPath,
  normalizeProxyPath,
  stampCurrentUserOnWriteBody,
} from "./identity-write-stamp";

describe("current user write stamping", () => {
  it("normalizes proxied write paths before matching", () => {
    expect(normalizeProxyPath("/grc/inventory/asset-reports/")).toBe("grc/inventory/asset-reports");
    expect(currentUserWriteFieldForPath("/grc/inventory/asset-reports/")).toBe("reporter");
    expect(currentUserWriteFieldForPath("/grc/inventory/asset-reports/report-123/triage/")).toBe("triaged_by");
  });

  it("stamps new asset reports with the current authenticated actor", () => {
    const body = stampCurrentUserOnWriteBody(
      JSON.stringify({ urn: "asset-1", reporter: "client-supplied" }),
      "grc/inventory/asset-reports",
      "person@example.com",
    );

    expect(JSON.parse(body)).toEqual({
      urn: "asset-1",
      reporter: "person@example.com",
    });
  });

  it("stamps triage updates with the current authenticated actor", () => {
    const body = stampCurrentUserOnWriteBody(
      JSON.stringify({ status: "needs_review", triaged_by: "client-supplied" }),
      "grc/inventory/asset-reports/report-123/triage",
      "person@example.com",
    );

    expect(JSON.parse(body)).toEqual({
      status: "needs_review",
      triaged_by: "person@example.com",
    });
  });

  it("leaves unrelated, unauthenticated, or non-object payloads untouched", () => {
    expect(stampCurrentUserOnWriteBody("{", "grc/inventory/asset-reports", "person@example.com")).toBe("{");
    expect(stampCurrentUserOnWriteBody("[]", "grc/inventory/asset-reports", "person@example.com")).toBe("[]");
    expect(stampCurrentUserOnWriteBody("{\"ok\":true}", "grc/inventory/asset-reports", "  ")).toBe("{\"ok\":true}");
    expect(stampCurrentUserOnWriteBody("{\"ok\":true}", "grc/other", "person@example.com")).toBe("{\"ok\":true}");
  });
});
