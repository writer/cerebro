import { describe, expect, it } from "vitest";

import {
  GRAPH_VIEWPOINT_IDS,
  cloudAttackPathRows,
  crownJewelPathRows,
  effectiveAccessPathRows,
  graphPathCounts,
  graphPathNode,
  graphPathRows,
  graphPathRowsToGraph,
  graphPathsTruncated,
  graphRevisionOf,
  graphViewpointFor,
  graphViewpointList,
  personAccessPathRows,
} from "@/lib/graph-viewpoints";

// ContextEntity keeps the URN in properties.entity_urn and has no top-level urn field.
const contextEntity = (urn: string, kind: string, label: string) => ({
  entity_id: { value: urn },
  agent_key: `key:${label}`,
  entity_kind: kind,
  authority: {},
  label,
  properties: { entity_urn: urn },
});

const attackNode = (urn: string, kind: string, label: string) => ({ urn, entity_kind: kind, label });

describe("graph viewpoint catalog", () => {
  it("exposes a question for every viewpoint and falls back to the entity view", () => {
    const list = graphViewpointList();
    expect(list).toHaveLength(GRAPH_VIEWPOINT_IDS.length);
    list.forEach((viewpoint) => {
      expect(viewpoint.question.length).toBeGreaterThan(10);
      expect(viewpoint.label.length).toBeLessThanOrEqual(20);
    });
    expect(graphViewpointFor("attack-paths").id).toBe("attack-paths");
    expect(graphViewpointFor("not-a-viewpoint").id).toBe("connections");
    expect(graphViewpointFor(null).id).toBe("connections");
  });

  it("only routes the connections viewpoint to the neighborhood read", () => {
    expect(graphViewpointFor("connections").method).toBeNull();
    GRAPH_VIEWPOINT_IDS.filter((id) => id !== "connections").forEach((id) => {
      expect(graphViewpointFor(id).method).toContain("OrganizationalGraphService/");
    });
  });
});

describe("graphPathNode", () => {
  it("reads a URN from either wire shape", () => {
    expect(graphPathNode(attackNode("urn:a", "aws.s3_bucket", "bucket"))?.urn).toBe("urn:a");
    expect(graphPathNode(contextEntity("urn:b", "identity.okta.user", "ana"))?.urn).toBe("urn:b");
  });

  it("rejects a node with no identity rather than inventing one", () => {
    expect(graphPathNode({ label: "nameless" })).toBeNull();
    expect(graphPathNode(null)).toBeNull();
    expect(graphPathNode("urn:a")).toBeNull();
  });

  it("falls back to the agent key when properties carry no URN", () => {
    expect(graphPathNode({ agent_key: "key:x", label: "x" })?.urn).toBe("key:x");
  });
});

describe("cloudAttackPathRows", () => {
  const payload = {
    graph_revision: 42,
    truncated: true,
    paths: [{
      public_principal: attackNode("urn:public", "internet.principal", "0.0.0.0/0"),
      exposed_resource: attackNode("urn:bucket", "aws.s3_bucket", "audit-bucket"),
      cloud_account: attackNode("urn:acct", "aws.account", "prod"),
      principal: attackNode("urn:role", "aws.iam_role", "deploy-role"),
      permission: attackNode("urn:perm", "aws.iam_permission", "s3:*"),
      relation_chain: ["reachable_from", "assumes", "grants"],
      reach_relation: "reachable_from",
      access_relation: "grants",
      ownerships: [{ owner: attackNode("urn:owner", "identity.okta.user", "ana"), edge: {} }],
      exposure_edge: { relation: "reachable_from", source_id: "aws-prod", source_runtime_id: "rt-1" },
      privilege_edge: { relation: "grants", source_id: "aws-prod", source_runtime_id: "rt-1" },
      traversal_edges: [{ relation: "assumes", source_id: "aws-prod", source_runtime_id: "rt-2" }],
    }],
  };

  it("orders the chain from public exposure to the permission", () => {
    const [row] = cloudAttackPathRows(payload);
    expect(row.nodes.map((node) => node.label)).toEqual(["0.0.0.0/0", "audit-bucket", "deploy-role", "s3:*"]);
    expect(row.nodes[1].role).toBe("exposed_resource");
  });

  it("keeps the owner and names the account without putting the account in the chain", () => {
    const [row] = cloudAttackPathRows(payload);
    expect(row.owners.map((owner) => owner.label)).toEqual(["ana"]);
    expect(row.detail).toBe("In prod");
    expect(row.nodes.some((node) => node.urn === "urn:acct")).toBe(false);
  });

  it("collects proof evidence from every edge slot", () => {
    const [row] = cloudAttackPathRows(payload);
    expect(row.evidence).toHaveLength(3);
    expect(row.evidence.map((entry) => entry.runtimeID).sort()).toEqual(["rt-1", "rt-1", "rt-2"]);
  });

  it("reads revision and truncation off the page, not the paths", () => {
    expect(graphRevisionOf(payload)).toBe(42);
    expect(graphPathsTruncated(payload)).toBe(true);
    expect(graphRevisionOf({ paths: [] })).toBeUndefined();
    expect(graphPathsTruncated({ paths: [] })).toBe(false);
  });

  it("drops a path that cannot form an edge", () => {
    expect(cloudAttackPathRows({ paths: [{ public_principal: attackNode("urn:a", "k", "a") }] })).toEqual([]);
  });
});

describe("effectiveAccessPathRows", () => {
  it("skips an absent mediator instead of leaving a gap in the chain", () => {
    const [row] = effectiveAccessPathRows({
      paths: [{
        identity: contextEntity("urn:id", "identity.okta.user", "ana"),
        principal: contextEntity("urn:sa", "aws.iam_role", "svc"),
        mediator: null,
        access_target: contextEntity("urn:app", "app", "payments"),
        entitlement: contextEntity("urn:ent", "entitlement", "admin"),
        capability: contextEntity("urn:cap", "capability", "write"),
        assignment_kind: "group",
        identity_relation_chain: ["member_of"],
        relation_chain: ["grants", "allows"],
        identity_edges: [{ relation: "member_of", source_id: "okta", runtime_id: "rt-9" }],
        edges: [],
      }],
    });
    expect(row.nodes.map((node) => node.label)).toEqual(["ana", "svc", "payments", "admin", "write"]);
    expect(row.relations).toEqual(["member_of", "grants", "allows"]);
    expect(row.detail).toBe("Granted by group");
    expect(row.evidence[0].runtimeID).toBe("rt-9");
  });
});

describe("personAccessPathRows", () => {
  it("builds the person chain", () => {
    const [row] = personAccessPathRows({
      paths: [{
        person: contextEntity("urn:p", "person", "Ana"),
        identity: contextEntity("urn:i", "identity.okta.user", "ana@x"),
        principal: contextEntity("urn:r", "aws.iam_role", "role"),
        access_target: contextEntity("urn:t", "aws.s3_bucket", "bucket"),
        relation_chain: ["has_identity", "assumes", "reads"],
      }],
    });
    expect(row.nodes).toHaveLength(4);
    expect(row.relations).toEqual(["has_identity", "assumes", "reads"]);
  });
});

describe("crownJewelPathRows", () => {
  it("does not repeat the seed when nodes already begin with it", () => {
    const seed = contextEntity("urn:jewel", "aws.rds_instance", "customer-db");
    const [row] = crownJewelPathRows({
      paths: [{
        seed,
        nodes: [seed, contextEntity("urn:svc", "service", "api")],
        relations: ["read_by"],
      }],
    });
    expect(row.nodes.map((node) => node.urn)).toEqual(["urn:jewel", "urn:svc"]);
    expect(row.nodes[0].role).toBe("crown_jewel");
  });

  it("prepends the seed when nodes omit it", () => {
    const [row] = crownJewelPathRows({
      paths: [{
        seed: contextEntity("urn:jewel", "k", "db"),
        nodes: [contextEntity("urn:svc", "service", "api")],
        relations: ["read_by"],
      }],
    });
    expect(row.nodes.map((node) => node.urn)).toEqual(["urn:jewel", "urn:svc"]);
  });
});

describe("graphPathRowsToGraph", () => {
  const rows = cloudAttackPathRows({
    paths: [{
      public_principal: attackNode("urn:public", "internet.principal", "any"),
      exposed_resource: attackNode("urn:bucket", "aws.s3_bucket", "bucket"),
      principal: attackNode("urn:role", "aws.iam_role", "role"),
      permission: attackNode("urn:perm", "aws.iam_permission", "s3:*"),
      relation_chain: ["reachable_from", "assumes", "grants"],
      ownerships: [{ owner: attackNode("urn:owner", "identity.okta.user", "ana"), edge: {} }],
    }],
  });

  it("turns a path set into one connected graph with the chain preserved", () => {
    const graph = graphPathRowsToGraph(rows);
    expect(graph?.root?.urn).toBe("urn:public");
    expect(graph?.relations?.map((relation) => relation.relation)).toEqual(["reachable_from", "assumes", "grants", "owns"]);
    expect(graph?.neighbors?.map((node) => node.urn).sort()).toEqual(["urn:bucket", "urn:owner", "urn:perm", "urn:role"]);
  });

  it("honours a requested root so a deep link keeps its anchor", () => {
    expect(graphPathRowsToGraph(rows, "urn:role")?.root?.urn).toBe("urn:role");
    expect(graphPathRowsToGraph(rows, "urn:absent")?.root?.urn).toBe("urn:public");
  });

  it("returns nothing for an empty path set so the page can show an empty state", () => {
    expect(graphPathRowsToGraph([])).toBeUndefined();
  });

  it("counts distinct nodes and relations rather than path positions", () => {
    expect(graphPathCounts(rows)).toEqual({ paths: 1, nodes: 4, relations: 3, owners: 1 });
    expect(graphPathCounts([])).toEqual({ paths: 0, nodes: 0, relations: 0, owners: 0 });
  });
});

describe("graphPathRows dispatch", () => {
  it("routes each viewpoint to its own adapter and yields nothing for the connections view", () => {
    expect(graphPathRows("connections", { paths: [{}] })).toEqual([]);
    expect(graphPathRows("human-access", {
      paths: [{
        person: contextEntity("urn:p", "person", "Ana"),
        identity: contextEntity("urn:i", "identity", "ana"),
        relation_chain: ["has_identity"],
      }],
    })).toHaveLength(1);
  });
});
