import { describe, expect, it } from "vitest";

import { GRCGraph } from "@/lib/grc";
import {
  emptyExploreState,
  exploreExpandedCount,
  exploreNodeCount,
  exploreRelationCount,
  isExploreNodeExpanded,
  mergeNeighborhood,
  relationKey,
  removeExploreNode,
  toGRCGraph,
} from "@/lib/graph-explore";

const seed = "urn:cerebro:local:asset:web-1";

const seedGraph: GRCGraph = {
  root: { urn: seed, entity_type: "asset", label: "web-1", attributes: { risk_score: "80" } },
  neighbors: [
    { urn: "urn:cerebro:local:package:left-pad", entity_type: "package", label: "left-pad", attributes: {} },
    { urn: "urn:cerebro:local:identity:alice", entity_type: "identity", label: "alice", attributes: {} },
  ],
  relations: [
    { from_urn: seed, relation: "depends_on", to_urn: "urn:cerebro:local:package:left-pad" },
    { from_urn: "urn:cerebro:local:identity:alice", relation: "owns", to_urn: seed },
  ],
};

const packageGraph: GRCGraph = {
  root: { urn: "urn:cerebro:local:package:left-pad", entity_type: "package", label: "left-pad", attributes: { risk_score: "60" } },
  neighbors: [
    { urn: "urn:cerebro:local:vulnerability:cve-1", entity_type: "vulnerability", label: "CVE-1", attributes: {} },
    { urn: "urn:cerebro:local:identity:alice", entity_type: "identity", label: "alice", attributes: { team: "platform" } },
  ],
  relations: [
    { from_urn: "urn:cerebro:local:package:left-pad", relation: "has_vuln", to_urn: "urn:cerebro:local:vulnerability:cve-1" },
    { from_urn: seed, relation: "depends_on", to_urn: "urn:cerebro:local:package:left-pad" },
  ],
};

describe("relationKey", () => {
  it("identifies a relation by endpoints and verb", () => {
    expect(relationKey({ from_urn: "a", relation: "owns", to_urn: "b" })).toBe("a|owns|b");
  });
});

describe("mergeNeighborhood", () => {
  it("seeds the graph and marks the seed expanded", () => {
    const state = mergeNeighborhood(emptyExploreState(seed), seed, seedGraph);
    expect(exploreNodeCount(state)).toBe(3);
    expect(exploreRelationCount(state)).toBe(2);
    expect(isExploreNodeExpanded(state, seed)).toBe(true);
    expect(exploreExpandedCount(state)).toBe(1);
  });

  it("deduplicates nodes and relations while merging attributes", () => {
    const seeded = mergeNeighborhood(emptyExploreState(seed), seed, seedGraph);
    const expanded = mergeNeighborhood(seeded, "urn:cerebro:local:package:left-pad", packageGraph);

    // alice already existed; cve-1 is new. left-pad/web-1 stay deduplicated.
    expect(exploreNodeCount(expanded)).toBe(4);
    // The duplicate depends_on relation is collapsed; has_vuln is added.
    expect(exploreRelationCount(expanded)).toBe(3);
    expect(isExploreNodeExpanded(expanded, "urn:cerebro:local:package:left-pad")).toBe(true);
    expect(exploreExpandedCount(expanded)).toBe(2);
    // Merged attributes keep both the original and the newly discovered field.
    expect(expanded.nodes["urn:cerebro:local:identity:alice"].attributes).toEqual({ team: "platform" });
    expect(expanded.nodes["urn:cerebro:local:package:left-pad"].attributes).toEqual({ risk_score: "60" });
  });

  it("preserves distinct relation evidence between the same endpoints", () => {
    const first = mergeNeighborhood(emptyExploreState(seed), seed, {
      root: seedGraph.root,
      neighbors: seedGraph.neighbors,
      relations: [
        { from_urn: seed, relation: "supports", to_urn: "urn:cerebro:local:identity:alice", attributes: { evidence_id: "ev-1" } },
      ],
    });
    const expanded = mergeNeighborhood(first, seed, {
      root: seedGraph.root,
      neighbors: seedGraph.neighbors,
      relations: [
        { from_urn: seed, relation: "supports", to_urn: "urn:cerebro:local:identity:alice", attributes: { evidence_id: "ev-2" } },
      ],
    });

    expect(exploreRelationCount(expanded)).toBe(2);
    expect(toGRCGraph(expanded).relations?.map((relation) => relation.attributes?.evidence_id).sort()).toEqual(["ev-1", "ev-2"]);
  });

  it("marks a node expanded and present even when the neighborhood is empty", () => {
    const seeded = mergeNeighborhood(emptyExploreState(seed), seed, seedGraph);
    const expanded = mergeNeighborhood(seeded, "urn:cerebro:local:identity:alice", undefined);
    expect(isExploreNodeExpanded(expanded, "urn:cerebro:local:identity:alice")).toBe(true);
    expect(expanded.nodes["urn:cerebro:local:identity:alice"]).toBeDefined();
  });

  it("does not mutate the previous state", () => {
    const seeded = mergeNeighborhood(emptyExploreState(seed), seed, seedGraph);
    const before = exploreNodeCount(seeded);
    mergeNeighborhood(seeded, "urn:cerebro:local:package:left-pad", packageGraph);
    expect(exploreNodeCount(seeded)).toBe(before);
  });
});

describe("removeExploreNode", () => {
  it("removes a node and its incident relations", () => {
    const seeded = mergeNeighborhood(emptyExploreState(seed), seed, seedGraph);
    const pruned = removeExploreNode(seeded, "urn:cerebro:local:package:left-pad");
    expect(pruned.nodes["urn:cerebro:local:package:left-pad"]).toBeUndefined();
    expect(exploreNodeCount(pruned)).toBe(2);
    expect(exploreRelationCount(pruned)).toBe(1);
  });

  it("never removes the seed node", () => {
    const seeded = mergeNeighborhood(emptyExploreState(seed), seed, seedGraph);
    expect(removeExploreNode(seeded, seed)).toBe(seeded);
  });

  it("is a no-op for an unknown node", () => {
    const seeded = mergeNeighborhood(emptyExploreState(seed), seed, seedGraph);
    expect(removeExploreNode(seeded, "urn:cerebro:local:asset:missing")).toBe(seeded);
  });
});

describe("toGRCGraph", () => {
  it("roots the graph on the seed and excludes it from neighbors", () => {
    const seeded = mergeNeighborhood(emptyExploreState(seed), seed, seedGraph);
    const graph = toGRCGraph(seeded);
    expect(graph.root?.urn).toBe(seed);
    expect(graph.neighbors?.some((node) => node.urn === seed)).toBe(false);
    expect(graph.neighbors).toHaveLength(2);
    expect(graph.relations).toHaveLength(2);
  });

  it("drops relations whose endpoints were pruned", () => {
    const seeded = mergeNeighborhood(emptyExploreState(seed), seed, seedGraph);
    const pruned = removeExploreNode(seeded, "urn:cerebro:local:package:left-pad");
    const graph = toGRCGraph(pruned);
    expect(graph.relations?.every((relation) => relation.to_urn !== "urn:cerebro:local:package:left-pad")).toBe(true);
  });
});
