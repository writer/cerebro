import { describe, expect, it } from "vitest";

import { redactReportIdentifier, redactReportText, reportReadinessIntent } from "./grc-report-packets";

describe("GRC report packet helpers", () => {
  it("redacts sensitive packet identifiers in share-safe mode", () => {
    const longNumericID = "1234".repeat(3);
    const body = [
      "Entity: urn:cerebro:tenant:aws_s3_bucket:customer-data",
      "Owner: reviewer@example.com",
      "Finding: finding-secret-123",
      "Hash: 0123456789abcdef0123456789abcdef",
      `Account: ${longNumericID}`,
      "Host: internal-api.dev.example.com",
    ].join("\n");

    expect(redactReportText(body, "share_safe")).toBe([
      "Entity: [resource]",
      "Owner: [identity]",
      "Finding: [id]",
      "Hash: [id]",
      "Account: [id]",
      "Host: [resource]",
    ].join("\n"));
    expect(redactReportText(body, "internal")).toBe(body);
  });

  it("redacts known identifier fields even when they do not match a pattern", () => {
    expect(redactReportIdentifier("prod-source-alpha", "share_safe", "[source]")).toBe("[source]");
    expect(redactReportIdentifier("prod-source-alpha", "internal", "[source]")).toBe("prod-source-alpha");
  });

  it("maps readiness statuses to review intent", () => {
    expect(reportReadinessIntent("ready")).toBe("success");
    expect(reportReadinessIntent("needs_attention")).toBe("warning");
    expect(reportReadinessIntent("blocked")).toBe("danger");
  });
});
