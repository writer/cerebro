import { describe, expect, it } from "vitest";

import {
  defaultSecurityProducers,
  mergeSecurityProducers,
  parseSecurityProducerCatalog,
  securityProducerCatalogFromValue,
} from "./security-producers";

describe("security producer configuration", () => {
  it("has no built-in environment producers", () => {
    expect(defaultSecurityProducers).toEqual([]);
    expect(parseSecurityProducerCatalog()).toEqual({ state: "ready", producers: [] });
    expect(parseSecurityProducerCatalog("not-json")).toEqual({ state: "invalid" });
    expect(securityProducerCatalogFromValue({ producers: [] })).toEqual({ state: "invalid" });
  });

  it("keeps only portable catalog fields", () => {
    expect(securityProducerCatalogFromValue([
      {
        id: "producer-one",
        label: "Producer One",
        extra: "not-portable",
        responseActions: [
          {
            id: "OPEN_TICKET",
            label: "Open ticket",
            extra: "not-portable-either",
          },
        ],
      },
    ])).toEqual({
      state: "ready",
      producers: [
        {
          id: "producer-one",
          label: "Producer One",
          description: undefined,
          repo: "",
          runtimeIds: [],
          sourceIds: [],
          mcpTools: [],
          resourceTemplates: [],
          contextKeys: [],
          responseActions: [
            {
              id: "OPEN_TICKET",
              label: "Open ticket",
              providers: [],
              targetTypes: [],
              requiredContextKeys: [],
              mode: "external_workflow",
              mcpTool: undefined,
              runtimeAction: undefined,
              externalOwner: undefined,
              dryRun: true,
              requiresApproval: true,
            },
          ],
        },
      ],
    });
  });

  it("normalizes configured security producers and proposal actions", () => {
    expect(parseSecurityProducerCatalog(JSON.stringify([
      {
        id: "producer-one",
        label: "Producer One",
        repo: "example/security-producer",
        runtimeIds: ["runtime-one"],
        sourceIds: ["source-one"],
        mcpTools: ["producer.propose"],
        resourceTemplates: ["cerebro://producer/{finding_id}"],
        contextKeys: ["finding_id"],
        responseActions: [
          {
            id: "OPEN_TICKET",
            label: "Open ticket",
            providers: ["ALL"],
            targetTypes: ["finding"],
            requiredContextKeys: ["finding_id"],
            mode: "proposal",
            mcpTool: "producer.propose",
            dryRun: true,
            requiresApproval: true,
          },
        ],
      },
    ]))).toEqual({
      state: "ready",
      producers: [
        {
          id: "producer-one",
          label: "Producer One",
          description: undefined,
          repo: "example/security-producer",
          runtimeIds: ["runtime-one"],
          sourceIds: ["source-one"],
          mcpTools: ["producer.propose"],
          resourceTemplates: ["cerebro://producer/{finding_id}"],
          contextKeys: ["finding_id"],
          responseActions: [
            {
              id: "OPEN_TICKET",
              label: "Open ticket",
              providers: ["ALL"],
              targetTypes: ["finding"],
              requiredContextKeys: ["finding_id"],
              mode: "proposal",
              mcpTool: "producer.propose",
              runtimeAction: undefined,
              externalOwner: undefined,
              dryRun: true,
              requiresApproval: true,
            },
          ],
        },
      ],
    });
  });

  it("rejects a partial catalog instead of silently dropping records or actions", () => {
    expect(parseSecurityProducerCatalog(JSON.stringify([
      { id: "producer-one", label: "Producer One" },
      { id: "", label: "Partial record" },
    ]))).toEqual({ state: "invalid" });
    expect(parseSecurityProducerCatalog(JSON.stringify([
      {
        id: "producer-one",
        label: "Producer One",
        responseActions: [{ id: "OPEN_TICKET" }],
      },
    ]))).toEqual({ state: "invalid" });
  });

  it("rejects duplicate action ids across producers", () => {
    expect(securityProducerCatalogFromValue([
      {
        id: "producer-one",
        label: "Producer One",
        responseActions: [{ id: "SHARED_ACTION", label: "First action" }],
      },
      {
        id: "producer-two",
        label: "Producer Two",
        responseActions: [{ id: "SHARED_ACTION", label: "Second action" }],
      },
    ])).toEqual({ state: "invalid" });
  });

  it("rejects overlapping source and runtime ownership", () => {
    expect(securityProducerCatalogFromValue([
      { id: "producer-one", label: "Producer One", sourceIds: ["shared-source"] },
      { id: "producer-two", label: "Producer Two", sourceIds: ["shared-source"] },
    ])).toEqual({ state: "invalid" });
    expect(securityProducerCatalogFromValue([
      { id: "producer-one", label: "Producer One", runtimeIds: ["shared-runtime"] },
      { id: "producer-two", label: "Producer Two", runtimeIds: ["shared-runtime"] },
    ])).toEqual({ state: "invalid" });
  });

  it("lets configured producers override the same id", () => {
    const base = parseSecurityProducerCatalog('[{"id":"producer-one","label":"Base"}]');
    const configured = parseSecurityProducerCatalog('[{"id":"producer-one","label":"Configured"}]');
    expect(base.state).toBe("ready");
    expect(configured.state).toBe("ready");
    if (base.state !== "ready" || configured.state !== "ready") return;
    expect(mergeSecurityProducers(base.producers, configured.producers)).toEqual([
      expect.objectContaining({ id: "producer-one", label: "Configured" }),
    ]);
  });
});
