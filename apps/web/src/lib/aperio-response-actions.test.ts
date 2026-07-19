import { describe, expect, it } from "vitest";

import {
  aperioResponseActionCandidates,
  aperioResponseOwner,
  isAperioOwnedFinding,
} from "./aperio-response-actions";
import type { SecurityProducer } from "./security-producers";

const producers: SecurityProducer[] = [{
  id: "aperio",
  label: "Response producer",
  repo: "",
  runtimeIds: [],
  sourceIds: ["portable-source"],
  mcpTools: ["producer.propose"],
  resourceTemplates: [],
  contextKeys: [],
  responseActions: [
    { id: "REVOKE_GRANT", label: "Revoke grant", providers: ["GENERIC_SAAS"], targetTypes: ["grant"], requiredContextKeys: ["grant_id"], mode: "proposal", mcpTool: "producer.propose", dryRun: true, requiresApproval: true },
    { id: "OPEN_TICKET", label: "Open ticket", providers: ["ALL"], targetTypes: ["finding"], requiredContextKeys: ["finding_id"], mode: "proposal", dryRun: false, requiresApproval: false },
  ],
}];

describe("response producer compatibility helpers", () => {
  it("selects the named producer through the portable registry", () => {
    const finding = { source_id: "portable-source", runtime_id: "", attributes: { provider: "GENERIC_SAAS" }, external_refs: [] };
    expect(isAperioOwnedFinding(finding, producers)).toBe(true);
    expect(aperioResponseOwner(finding, producers)).toBe("aperio");
    expect(aperioResponseActionCandidates(finding, producers)).toEqual(["REVOKE_GRANT", "OPEN_TICKET"]);
  });

  it("does not claim work owned by another producer", () => {
    const finding = { source_id: "other-source", runtime_id: "", attributes: {}, external_refs: [] };
    expect(isAperioOwnedFinding(finding, producers)).toBe(false);
    expect(aperioResponseOwner(finding, producers)).toBeUndefined();
    expect(aperioResponseActionCandidates(finding, producers)).toEqual([]);
  });
});
