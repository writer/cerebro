import { describe, expect, it } from "vitest";

import { triageBatchesByTenant } from "@/lib/finding-triage";
import { GRCFinding } from "@/lib/grc";

const finding = (id: string, tenant_id?: string): GRCFinding =>
  ({ id, title: id, severity: "HIGH", status: "open", evidence_count: 0, owner: "Unassigned", sla_status: "on_track", tenant_id }) as GRCFinding;

describe("triageBatchesByTenant", () => {
  it("groups selected findings by tenant", () => {
    const findings = [finding("a", "writer"), finding("b", "writer"), finding("c", "acme"), finding("d", "writer")];
    const batches = triageBatchesByTenant(findings, ["a", "b", "c"], "risk_accepted");

    expect(batches).toHaveLength(2);
    const writer = batches.find((b) => b.tenant_id === "writer");
    const acme = batches.find((b) => b.tenant_id === "acme");
    expect(writer?.finding_ids).toEqual(["a", "b"]);
    expect(writer?.disposition).toBe("risk_accepted");
    expect(acme?.finding_ids).toEqual(["c"]);
  });

  it("ignores findings without tenant context and unselected findings", () => {
    const findings = [finding("a", "writer"), finding("b", ""), finding("c")];
    const batches = triageBatchesByTenant(findings, ["a", "b", "c"], "resolved");

    expect(batches).toHaveLength(1);
    expect(batches[0]).toEqual({ tenant_id: "writer", finding_ids: ["a"], disposition: "resolved" });
  });

  it("returns no batches when nothing selected", () => {
    const findings = [finding("a", "writer")];
    expect(triageBatchesByTenant(findings, [], "in_triage")).toEqual([]);
  });
});
