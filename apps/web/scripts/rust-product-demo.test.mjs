import { describe, expect, it } from "vitest";

import {
  expectedNeighborhoodProof,
  parseArgs,
  parseDemoNeighborhood,
  portableEnvironment,
  tenantBearer,
} from "./rust-product-demo.mjs";

describe("Rust product demo helpers", () => {
  it("parses check and evidence options", () => {
    const options = parseArgs([
      "--check",
      "--timeout-ms=120000",
      "--artifact-dir",
      "tmp/demo-artifacts",
      "--receipt=tmp/demo-receipt.json",
    ]);

    expect(options).toMatchObject({ check: true, timeoutMs: 120000 });
    expect(options.artifactRoot).toMatch(/tmp\/demo-artifacts$/);
    expect(options.receiptPath).toMatch(/tmp\/demo-receipt\.json$/);
    expect(() => parseArgs(["--timeout-ms", "0"])).toThrow(
      "requires a positive integer",
    );
    expect(() => parseArgs(["--unknown"])).toThrow("Unknown option");
  });

  it("does not inherit provider credentials", () => {
    expect(
      portableEnvironment(
        {
          HOME: "/tmp/home",
          PATH: "/bin",
          DDESK_CARGO_EMERGENCY_FREE_BYTES: "17179869184",
          DDESK_CARGO_RESERVATION_BYTES: "8589934592",
          CEREBRO_SOURCE_GITHUB_TOKEN: "must-not-cross-process-boundary",
          UNRELATED_SECRET: "must-not-cross-process-boundary",
        },
        { CEREBRO_RUST_BIND: "127.0.0.1:8001" },
      ),
    ).toEqual({
      CEREBRO_RUST_BIND: "127.0.0.1:8001",
      DDESK_CARGO_EMERGENCY_FREE_BYTES: "17179869184",
      DDESK_CARGO_RESERVATION_BYTES: "8589934592",
      HOME: "/tmp/home",
      PATH: "/bin",
    });
  });

  it("derives a deterministic tenant bearer without recording the secret", () => {
    expect(tenantBearer("0123456789abcdef0123456789abcdef", "tenant-demo")).toBe(
      "77ca954c207c6a3ffcfed6a22eca02b49d0607e05610ce30bf0676dbe3176dea",
    );
  });

  it("reads the product root from Rust demo output", () => {
    const rootURN = "urn:cerebro:tenant-demo:organizational_entity:provider-okta-demo-00u-demo";
    expect(
      parseDemoNeighborhood(JSON.stringify({ root: { agent_key: rootURN } })),
    ).toMatchObject({ rootURN });
    expect(() =>
      parseDemoNeighborhood(JSON.stringify({ root: { agent_key: "other" } })),
    ).toThrow("tenant-scoped product root");
  });

  it("derives receipt counts from the trusted local Rust fixture", () => {
    expect(
      expectedNeighborhoodProof({
        root: { entity_id: "root", label: "Provider identity" },
        edges: [
          { from: "root", relation: "represents", to: "person" },
          { from: "group", relation: "can_access", to: "repository" },
        ],
      }),
    ).toEqual({
      node_count: 2,
      relation_count: 1,
      root_label: "Provider identity",
    });
  });
});
