import { GRCGraph, GRCGraphNode, GRCGraphRelation } from "@/lib/grc";

// ExploreGraphState accumulates the subgraph an analyst has built by expanding
// entity neighborhoods one node at a time. It is intentionally plain data so the
// merge/remove transitions stay pure and unit-testable.
export type ExploreGraphState = {
  seedURN: string;
  nodes: Record<string, GRCGraphNode>;
  relations: Record<string, GRCGraphRelation>;
  expanded: Record<string, true>;
};

export const relationKey = (relation: Pick<GRCGraphRelation, "from_urn" | "relation" | "to_urn">) =>
  `${relation.from_urn}|${relation.relation}|${relation.to_urn}`;

const relationAttributeKey = (attributes: Record<string, string> | undefined) => {
  const entries = Object.entries(attributes ?? {}).sort(([left], [right]) => left.localeCompare(right));
  return entries.map(([key, value]) => `${key}=${value}`).join("&");
};

const relationInstanceKey = (relation: GRCGraphRelation) => {
  const attributes = relationAttributeKey(relation.attributes);
  return attributes ? `${relationKey(relation)}|${attributes}` : relationKey(relation);
};

export const emptyExploreState = (seedURN: string): ExploreGraphState => ({
  seedURN: seedURN.trim(),
  nodes: {},
  relations: {},
  expanded: {},
});

const mergeNode = (existing: GRCGraphNode | undefined, incoming: GRCGraphNode): GRCGraphNode => ({
  urn: incoming.urn,
  entity_type: incoming.entity_type || existing?.entity_type || "entity",
  label: incoming.label || existing?.label || incoming.urn,
  attributes: { ...(existing?.attributes ?? {}), ...(incoming.attributes ?? {}) },
});

const addNode = (nodes: Record<string, GRCGraphNode>, node: GRCGraphNode | undefined) => {
  if (!node || !node.urn || node.urn.trim() === "") return;
  nodes[node.urn] = mergeNode(nodes[node.urn], node);
};

// mergeNeighborhood folds one entity neighborhood into the accumulated graph,
// deduplicating nodes and relations by identity and marking the expanded entity
// so the UI can hide its expand affordance and avoid refetching it.
export const mergeNeighborhood = (
  state: ExploreGraphState,
  urn: string,
  graph: GRCGraph | undefined,
): ExploreGraphState => {
  const nodes = { ...state.nodes };
  const relations = { ...state.relations };
  const expanded = { ...state.expanded };
  const trimmed = urn.trim();

  addNode(nodes, graph?.root);
  (graph?.neighbors ?? []).forEach((node) => addNode(nodes, node));
  (graph?.relations ?? []).forEach((relation) => {
    if (!relation || !relation.from_urn || !relation.to_urn) return;
    relations[relationInstanceKey(relation)] = {
      from_urn: relation.from_urn,
      relation: relation.relation,
      to_urn: relation.to_urn,
      ...(relation.attributes ? { attributes: { ...relation.attributes } } : {}),
    };
  });

  if (trimmed !== "") {
    if (!nodes[trimmed]) {
      addNode(nodes, { urn: trimmed, entity_type: "entity", label: trimmed });
    }
    expanded[trimmed] = true;
  }

  return { ...state, nodes, relations, expanded };
};

// removeExploreNode drops a node and every relation incident to it. The seed is
// protected so the explorer always retains an anchor to grow from.
export const removeExploreNode = (state: ExploreGraphState, urn: string): ExploreGraphState => {
  const trimmed = urn.trim();
  if (trimmed === "" || trimmed === state.seedURN || !state.nodes[trimmed]) {
    return state;
  }
  const nodes = { ...state.nodes };
  delete nodes[trimmed];
  const expanded = { ...state.expanded };
  delete expanded[trimmed];
  const relations: Record<string, GRCGraphRelation> = {};
  Object.entries(state.relations).forEach(([key, relation]) => {
    if (relation.from_urn === trimmed || relation.to_urn === trimmed) return;
    relations[key] = relation;
  });
  return { ...state, nodes, relations, expanded };
};

const visibleRelations = (state: ExploreGraphState) =>
  Object.values(state.relations).filter((relation) => state.nodes[relation.from_urn] && state.nodes[relation.to_urn]);

// toGRCGraph renders the accumulated state into the GRCGraph shape the shared
// GraphViewer already understands, rooted on the seed entity.
export const toGRCGraph = (state: ExploreGraphState): GRCGraph => {
  const root = state.nodes[state.seedURN]
    ?? (state.seedURN ? { urn: state.seedURN, entity_type: "entity", label: state.seedURN } : undefined);
  const neighbors = Object.values(state.nodes).filter((node) => node.urn !== state.seedURN);
  return {
    root,
    neighbors,
    relations: visibleRelations(state),
  };
};

export const exploreNodeCount = (state: ExploreGraphState) => Object.keys(state.nodes).length;

export const exploreRelationCount = (state: ExploreGraphState) => visibleRelations(state).length;

export const exploreExpandedCount = (state: ExploreGraphState) => Object.keys(state.expanded).length;

export const isExploreNodeExpanded = (state: ExploreGraphState, urn: string) =>
  Boolean(state.expanded[urn.trim()]);
