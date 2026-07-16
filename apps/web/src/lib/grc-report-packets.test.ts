import { describe, expect, it } from "vitest";

import { redactReportGraph, redactReportIdentifier, redactReportText, reportReadinessIntent } from "./grc-report-packets";

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

  it("redacts graph identifiers with stable placeholders in share-safe mode", () => {
    const graph = {
      root: {
        urn: "urn:cerebro:tenant:endpoint:host-01",
        entity_type: "endpoint",
        label: "host-01.internal-api.dev.example.com",
        attributes: { owner: "reviewer@example.com" },
      },
      neighbors: [{
        urn: "urn:cerebro:tenant:finding:0123456789abcdef0123456789abcdef",
        entity_type: "finding",
        label: "finding-0123456789abcdef0123456789abcdef",
      }],
      relations: [{
        from_urn: "urn:cerebro:tenant:endpoint:host-01",
        relation: "has_finding",
        to_urn: "urn:cerebro:tenant:finding:0123456789abcdef0123456789abcdef",
      }],
    };

    expect(redactReportGraph(graph, "share_safe")).toEqual({
      root: {
        urn: "[endpoint-1]",
        entity_type: "endpoint",
        label: "[endpoint-1]",
        attributes: { owner: "[identity]" },
      },
      neighbors: [{
        urn: "[finding-2]",
        entity_type: "finding",
        label: "[finding-2]",
      }],
      relations: [{
        from_urn: "[endpoint-1]",
        relation: "has_finding",
        to_urn: "[finding-2]",
      }],
    });
    expect(redactReportGraph(graph, "internal")).toBe(graph);
  });

  it("maps readiness statuses to review intent", () => {
    expect(reportReadinessIntent("ready")).toBe("success");
    expect(reportReadinessIntent("needs_attention")).toBe("warning");
    expect(reportReadinessIntent("blocked")).toBe("danger");
  });
});
