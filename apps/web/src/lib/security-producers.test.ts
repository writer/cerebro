import { describe, expect, it } from "vitest";

import { defaultSecurityProducers, mergeSecurityProducers, parseSecurityProducers } from "./security-producers";

describe("security producer configuration", () => {
  it("has no built-in environment producers", () => {
    expect(defaultSecurityProducers).toEqual([]);
    expect(parseSecurityProducers()).toEqual([]);
    expect(parseSecurityProducers("not-json")).toEqual([]);
  });

  it("normalizes configured security producers and proposal actions", () => {
    expect(parseSecurityProducers(JSON.stringify([
      {
        id: "producer-one",
        label: "Producer One",
        repo: "example/security-producer",
        runtimeIds: ["runtime-one", "", 3],
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
      { id: "", label: "Ignored" },
    ]))).toEqual([
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
            runtimeAction: undefined,
            externalOwner: undefined,
            dryRun: true,
            requiresApproval: true,
          },
        ],
      },
    ]);
  });

  it("lets configured producers override the same id", () => {
    const base = parseSecurityProducers('[{"id":"producer-one","label":"Base"}]');
    const configured = parseSecurityProducers('[{"id":"producer-one","label":"Configured"}]');
    expect(mergeSecurityProducers(base, configured)).toEqual([
      expect.objectContaining({ id: "producer-one", label: "Configured" }),
    ]);
  });
});
